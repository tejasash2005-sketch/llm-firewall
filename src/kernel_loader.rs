//! Loads the C eBPF object with Aya, attaches the cgroup/connect4+connect6 redirectors,
//! keeps the target-IP maps in sync with DNS, and drains the audit ring buffer
//! asynchronously.

use std::{
    collections::HashSet,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context, Result};
use aya::{
    maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray, RingBuf},
    programs::{CgroupAttachMode, CgroupSockAddr},
    Ebpf, Pod,
};
use tokio::{io::unix::AsyncFd, sync::watch};
use tracing::{debug, info, warn};

const MAX_TARGETS: usize = 4096;
const MAX_AUDIT_EVENTS_PER_TURN: usize = 256;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const _: () = assert!(MAX_TARGETS == 4096);

#[repr(C)]
#[derive(Clone, Copy)]
struct FwConfig {
    proxy_ip: u32,
    proxy_pid: u32,
    proxy_port: u16,
    _pad: u16,
}
unsafe impl Pod for FwConfig {}

const _: () = {
    assert!(size_of::<FwConfig>() == 12);
    assert!(offset_of!(FwConfig, proxy_ip) == 0);
    assert!(offset_of!(FwConfig, proxy_pid) == 4);
    assert!(offset_of!(FwConfig, proxy_port) == 8);
    assert!(offset_of!(FwConfig, _pad) == 10);
};

#[repr(C)]
#[derive(Clone, Copy)]
struct In6Key {
    addr: [u32; 4],
}
unsafe impl Pod for In6Key {}

const _: () = {
    assert!(size_of::<In6Key>() == 16);
    assert!(offset_of!(In6Key, addr) == 0);
};

/// Mirrors `struct fw_event` in firewall_kernel.bpf.c (56 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RedirectEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub dst_ip4: u32,
    pub dst_ip6: [u32; 4],
    pub dst_port: u16,
    pub family: u16,
    pub comm: [u8; 16],
    pub _pad: u32,
}

const _: () = {
    assert!(size_of::<RedirectEvent>() == 56);
    assert!(offset_of!(RedirectEvent, ts_ns) == 0);
    assert!(offset_of!(RedirectEvent, pid) == 8);
    assert!(offset_of!(RedirectEvent, dst_ip4) == 12);
    assert!(offset_of!(RedirectEvent, dst_ip6) == 16);
    assert!(offset_of!(RedirectEvent, dst_port) == 32);
    assert!(offset_of!(RedirectEvent, family) == 34);
    assert!(offset_of!(RedirectEvent, comm) == 36);
    assert!(offset_of!(RedirectEvent, _pad) == 52);
};

impl RedirectEvent {
    fn destination(&self) -> Option<IpAddr> {
        match self.family {
            AF_INET => Some(Ipv4Addr::from(self.dst_ip4.to_ne_bytes()).into()),
            AF_INET6 => {
                let mut octets = [0; 16];
                for (word, bytes) in self.dst_ip6.iter().zip(octets.chunks_exact_mut(4)) {
                    bytes.copy_from_slice(&word.to_ne_bytes());
                }
                Some(Ipv6Addr::from(octets).into())
            }
            _ => None,
        }
    }
}

#[derive(Default)]
pub struct KernelStats {
    pub redirected: AtomicU64,
}

pub struct KernelConfig {
    pub object_path: PathBuf,
    pub cgroup_path: PathBuf,
    pub proxy_addr: SocketAddr,
    pub proxy_pid: u32,
    pub hosts: Vec<String>,
    pub refresh_interval: Duration,
}

pub struct KernelFirewall {
    ebpf: Ebpf,
    ring: Option<RingBuf<MapData>>,
    audit_drops: PerCpuArray<MapData, u64>,
    cfg: KernelConfig,
    known_v4: HashSet<u32>,
    known_v6: HashSet<[u32; 4]>,
    pub stats: Arc<KernelStats>,
}

fn raise_memlock_limit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: plain syscall with a valid pointer to a stack-allocated struct.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("failed to raise RLIMIT_MEMLOCK (fine on kernels with memcg accounting)");
    }
}

fn v6_words(ip: &Ipv6Addr) -> [u32; 4] {
    let o = ip.octets();
    let mut w = [0u32; 4];
    for (i, word) in w.iter_mut().enumerate() {
        *word = u32::from_ne_bytes([o[4 * i], o[4 * i + 1], o[4 * i + 2], o[4 * i + 3]]);
    }
    w
}

async fn resolve_hosts(hosts: &[String]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for h in hosts {
        match tokio::net::lookup_host((h.as_str(), 443)).await {
            Ok(addrs) => {
                for a in addrs {
                    if !out.contains(&a.ip()) {
                        out.push(a.ip());
                    }
                }
            }
            Err(e) => warn!(host = %h, error = %e, "DNS resolution failed"),
        }
    }
    out
}

fn decode_event(bytes: &[u8]) -> Option<RedirectEvent> {
    if bytes.len() != size_of::<RedirectEvent>() {
        return None;
    }
    // SAFETY: length checked above; RedirectEvent is repr(C) plain integers, valid for any bit
    // pattern, and read_unaligned makes no alignment assumption about the ring buffer slot.
    let event = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const RedirectEvent) };
    matches!(event.family, AF_INET | AF_INET6).then_some(event)
}

/// Drains a bounded number of records so a continuously busy audit ring cannot monopolize the
/// daemon task and delay DNS refresh or shutdown processing. `true` means the budget was used.
fn drain_batch(budget: usize, mut process_next: impl FnMut() -> bool) -> bool {
    for _ in 0..budget {
        if !process_next() {
            return false;
        }
    }
    true
}

impl KernelFirewall {
    /// Loads and attaches everything. Call this *after* the proxy socket is bound so redirected
    /// connections always have a listener.
    pub fn load(cfg: KernelConfig) -> Result<Self> {
        raise_memlock_limit();

        let mut ebpf = Ebpf::load_file(&cfg.object_path)
            .with_context(|| format!("loading eBPF object {}", cfg.object_path.display()))?;

        let proxy_ip = match cfg.proxy_addr.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => Ipv4Addr::LOCALHOST,
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => bail!("the transparent-redirect proxy address must be IPv4"),
        };

        {
            let mut conf: Array<_, FwConfig> = Array::try_from(
                ebpf.map_mut("fw_config")
                    .context("map `fw_config` not found in object")?,
            )?;
            conf.set(
                0,
                FwConfig {
                    proxy_ip: u32::from_ne_bytes(proxy_ip.octets()),
                    proxy_pid: cfg.proxy_pid,
                    proxy_port: cfg.proxy_addr.port().to_be(),
                    _pad: 0,
                },
                0,
            )?;
        }

        let cgroup = std::fs::File::open(&cfg.cgroup_path)
            .with_context(|| format!("opening cgroup {}", cfg.cgroup_path.display()))?;
        for name in ["firewall_connect4", "firewall_connect6"] {
            let prog: &mut CgroupSockAddr = ebpf
                .program_mut(name)
                .with_context(|| format!("program `{name}` not found in object"))?
                .try_into()?;
            prog.load()
                .with_context(|| format!("loading program `{name}`"))?;
        }

        // Prepare both maps before attaching either hook. Aya retains each attached link in the
        // program's LinkMap, whose Drop implementation detaches it if a later attach fails.
        let ring = RingBuf::try_from(
            ebpf.take_map("events")
                .context("map `events` not found in object")?,
        )?;
        let audit_drops = PerCpuArray::try_from(
            ebpf.take_map("audit_drops")
                .context("map `audit_drops` not found in object")?,
        )?;

        for name in ["firewall_connect4", "firewall_connect6"] {
            let prog: &mut CgroupSockAddr = ebpf
                .program_mut(name)
                .with_context(|| format!("program `{name}` not found in object"))?
                .try_into()?;
            prog.attach(&cgroup, CgroupAttachMode::Single)
                .with_context(|| format!("attaching `{name}` to {}", cfg.cgroup_path.display()))?;
            info!(program = name, cgroup = %cfg.cgroup_path.display(), "eBPF program attached");
        }

        Ok(Self {
            ebpf,
            ring: Some(ring),
            audit_drops,
            cfg,
            known_v4: HashSet::new(),
            known_v6: HashSet::new(),
            stats: Arc::new(KernelStats::default()),
        })
    }

    /// Re-resolves the LLM hostnames and adds any new addresses to the kernel target maps.
    /// Entries are only ever added (never evicted) so a flapping DNS answer cannot open a gap.
    pub async fn refresh(&mut self) -> Result<()> {
        let addrs = resolve_hosts(&self.cfg.hosts).await;
        if addrs.is_empty() {
            bail!("DNS produced no addresses for {:?}", self.cfg.hosts);
        }

        {
            let mut map: BpfHashMap<_, u32, u8> = BpfHashMap::try_from(
                self.ebpf
                    .map_mut("target_v4")
                    .context("map `target_v4` not found")?,
            )?;
            for a in &addrs {
                if let IpAddr::V4(ip) = a {
                    let key = u32::from_ne_bytes(ip.octets());
                    if self.known_v4.contains(&key) {
                        continue;
                    }
                    if self.known_v4.len() >= MAX_TARGETS {
                        warn!("IPv4 target map is full; ignoring {ip}");
                        continue;
                    }
                    map.insert(key, 1u8, 0)?;
                    self.known_v4.insert(key);
                    info!(%ip, "added IPv4 interception target");
                }
            }
        }

        {
            let mut map: BpfHashMap<_, In6Key, u8> = BpfHashMap::try_from(
                self.ebpf
                    .map_mut("target_v6")
                    .context("map `target_v6` not found")?,
            )?;
            for a in &addrs {
                if let IpAddr::V6(ip) = a {
                    let words = v6_words(ip);
                    if self.known_v6.contains(&words) {
                        continue;
                    }
                    if self.known_v6.len() >= MAX_TARGETS {
                        warn!("IPv6 target map is full; ignoring {ip}");
                        continue;
                    }
                    map.insert(In6Key { addr: words }, 1u8, 0)?;
                    self.known_v6.insert(words);
                    info!(%ip, "added IPv6 interception target");
                }
            }
        }
        Ok(())
    }

    fn handle_event(&self, ev: &RedirectEvent) {
        self.stats.redirected.fetch_add(1, Ordering::Relaxed);
        let end = ev
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(ev.comm.len());
        let comm = String::from_utf8_lossy(&ev.comm[..end]);
        let port = u16::from_be(ev.dst_port);
        let dst = ev.destination().map_or_else(
            || format!("unknown-family-{}", ev.family),
            |ip| ip.to_string(),
        );
        info!(target: "ebpf_audit", pid = ev.pid, comm = %comm, dst = %dst, port, "redirected connect() to firewall proxy");
    }

    fn report_dropped_audit_events(&self, last_reported: &mut u64) {
        match self.audit_drops.get(&0, 0) {
            Ok(per_cpu) => {
                let total = per_cpu.iter().copied().fold(0u64, u64::saturating_add);
                if total > *last_reported {
                    warn!(
                        dropped = total - *last_reported,
                        total, "audit ring buffer reservation failed; redirecting continues"
                    );
                    *last_reported = total;
                }
            }
            Err(error) => warn!(%error, "failed to read audit ring buffer drop counter"),
        }
    }

    /// Drains the ring buffer and refreshes targets until `shutdown` fires. Dropping `self` on
    /// return detaches the programs.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let ring = self.ring.take().context("ring buffer already taken")?;
        // `ring` owns its map and keeps the backing fd open and stable until it is dropped.
        // `AsyncFd::register_with_interest` takes ownership, so the fd remains valid for the
        // full registration lifetime as required by Tokio's safety contract.
        let mut ring_fd =
            unsafe { AsyncFd::register_with_interest(ring, tokio::io::Interest::READABLE)? };
        let mut ticker = tokio::time::interval(self.cfg.refresh_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // first tick fires immediately; targets were seeded by the caller
        let mut last_reported_drops = 0;

        loop {
            tokio::select! {
                guard = ring_fd.readable_mut() => {
                    let mut guard = guard.context("waiting for ring buffer readiness")?;
                    let rb = guard.get_inner_mut();
                    let budget_used = drain_batch(
                        MAX_AUDIT_EVENTS_PER_TURN,
                        || {
                            let Some(item) = rb.next() else { return false };
                        match decode_event(&item) {
                            Some(ev) => self.handle_event(&ev),
                            None => warn!(len = item.len(), "malformed or unsupported audit record"),
                        }
                            true
                        },
                    );
                    if !budget_used {
                        guard.clear_ready();
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.refresh().await {
                        warn!(error = %e, "target refresh failed; keeping existing targets");
                    }
                    self.report_dropped_audit_events(&mut last_reported_drops);
                }
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        self.report_dropped_audit_events(&mut last_reported_drops);
        info!("eBPF layer shutting down; detaching programs");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(bytes: &mut [u8], offset: usize, value: &[u8]) {
        bytes[offset..offset + value.len()].copy_from_slice(value);
    }

    fn event_bytes(family: u16, dst_ip4: u32, dst_ip6: [u32; 4]) -> Vec<u8> {
        let mut bytes = vec![0; size_of::<RedirectEvent>()];
        put(
            &mut bytes,
            offset_of!(RedirectEvent, ts_ns),
            &123u64.to_ne_bytes(),
        );
        put(
            &mut bytes,
            offset_of!(RedirectEvent, pid),
            &456u32.to_ne_bytes(),
        );
        put(
            &mut bytes,
            offset_of!(RedirectEvent, dst_ip4),
            &dst_ip4.to_ne_bytes(),
        );
        for (index, word) in dst_ip6.iter().enumerate() {
            put(
                &mut bytes,
                offset_of!(RedirectEvent, dst_ip6) + index * size_of::<u32>(),
                &word.to_ne_bytes(),
            );
        }
        put(
            &mut bytes,
            offset_of!(RedirectEvent, dst_port),
            &443u16.to_be_bytes(),
        );
        put(
            &mut bytes,
            offset_of!(RedirectEvent, family),
            &family.to_ne_bytes(),
        );
        bytes
    }

    #[test]
    fn decodes_ipv4_audit_destination() {
        let ip = Ipv4Addr::new(192, 0, 2, 10);
        let raw = event_bytes(AF_INET, u32::from_ne_bytes(ip.octets()), [0; 4]);
        let event = decode_event(&raw).unwrap();

        assert_eq!(event.destination(), Some(IpAddr::V4(ip)));
        assert_eq!(event.destination().unwrap().to_string(), "192.0.2.10");
    }

    #[test]
    fn decodes_full_ipv6_audit_destination() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0xabcd, 0x12, 0, 0, 0, 0x34);
        let raw = event_bytes(AF_INET6, 0, v6_words(&ip));
        let event = decode_event(&raw).unwrap();

        assert_eq!(event.destination(), Some(IpAddr::V6(ip)));
        assert_eq!(
            event.destination().unwrap().to_string(),
            "2001:db8:abcd:12::34"
        );
    }

    #[test]
    fn decodes_ipv4_mapped_ipv6_audit_destination() {
        let ip = Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 33]);
        let raw = event_bytes(AF_INET6, 0, v6_words(&ip));
        let event = decode_event(&raw).unwrap();

        assert_eq!(event.destination(), Some(IpAddr::V6(ip)));
        assert_eq!(
            event.destination().unwrap().to_string(),
            "::ffff:192.0.2.33"
        );
    }

    #[test]
    fn rejects_short_audit_records() {
        assert!(decode_event(&[0; size_of::<RedirectEvent>() - 1]).is_none());
    }

    #[test]
    fn rejects_oversized_and_unsupported_audit_records() {
        let mut oversized = event_bytes(AF_INET, 0, [0; 4]);
        oversized.push(0);
        assert!(decode_event(&oversized).is_none());

        let unsupported = event_bytes(99, 0, [0; 4]);
        assert!(decode_event(&unsupported).is_none());
    }

    #[test]
    fn missing_ebpf_object_fails_startup_before_kernel_attachment() {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let object_path = std::env::temp_dir().join(format!(
            "llm-firewall-missing-object-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(!object_path.exists());

        let error = KernelFirewall::load(KernelConfig {
            object_path: object_path.clone(),
            cgroup_path: PathBuf::from("/sys/fs/cgroup"),
            proxy_addr: "127.0.0.1:8443".parse().unwrap(),
            proxy_pid: std::process::id(),
            hosts: vec!["api.example.test".to_string()],
            refresh_interval: Duration::from_secs(30),
        })
        .err()
        .expect("missing eBPF object must fail startup");

        assert!(error.to_string().contains("loading eBPF object"));
        assert!(error
            .to_string()
            .contains(&object_path.display().to_string()));
    }

    #[test]
    fn audit_drain_budget_preserves_remaining_records_for_the_next_turn() {
        let mut pending = std::collections::VecDeque::from([1, 2, 3, 4]);
        let mut handled = Vec::new();
        let exhausted = {
            let mut drain_next = || match pending.pop_front() {
                Some(event) => {
                    handled.push(event);
                    true
                }
                None => false,
            };
            drain_batch(2, &mut drain_next)
        };
        assert!(exhausted);
        assert_eq!(handled, [1, 2]);
        assert_eq!(pending, [3, 4]);

        let exhausted = {
            let mut drain_next = || match pending.pop_front() {
                Some(event) => {
                    handled.push(event);
                    true
                }
                None => false,
            };
            drain_batch(2, &mut drain_next)
        };
        assert!(exhausted);
        assert_eq!(handled, [1, 2, 3, 4]);
        assert!(pending.is_empty());

        let exhausted = {
            let mut drain_next = || match pending.pop_front() {
                Some(event) => {
                    handled.push(event);
                    true
                }
                None => false,
            };
            drain_batch(2, &mut drain_next)
        };
        assert!(!exhausted);
    }
}
