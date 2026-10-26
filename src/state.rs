//! Thread-safe, per-session placeholder registry.
//!
//! Placeholders are deterministic within a session: SHA-256(session_salt || raw)
//! is truncated to 8+ hex characters (extended on the astronomically unlikely
//! prefix collision). The forward index is keyed by the digest, so the only
//! place raw values live is the reverse map, which is zeroized on drop.
//! Nothing here is ever persisted or logged.

use std::{
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dashmap::{mapref::entry::Entry, DashMap};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::{sync::watch, task::JoinHandle};
use zeroize::Zeroize;

pub type SessionId = u64;

const MIN_HEX_LEN: usize = 8;
const MAX_HEX_LEN: usize = 64;
const MAX_SESSION_MAPPINGS: usize = 8192;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_prefix(digest: &[u8; 32], hex_len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let n = (hex_len / 2).min(32);
    let mut s = String::with_capacity(n * 2);
    for b in &digest[..n] {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn sanitize_kind(kind: &str) -> String {
    let mut k: String = kind
        .chars()
        .map(|c| {
            let u = c.to_ascii_uppercase();
            if u.is_ascii_uppercase() || u.is_ascii_digit() {
                u
            } else {
                '_'
            }
        })
        .collect();
    if k.is_empty() || !k.as_bytes()[0].is_ascii_uppercase() {
        k.insert(0, 'X');
    }
    k
}

pub struct Session {
    id: SessionId,
    salt: [u8; 32],
    /// digest(raw) -> placeholder
    forward: DashMap<[u8; 32], String>,
    /// placeholder -> raw
    reverse: DashMap<String, String>,
    mapping_count: AtomicUsize,
    last_used: AtomicU64,
}

impl Session {
    fn new(id: SessionId) -> Self {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        Self {
            id,
            salt,
            forward: DashMap::new(),
            reverse: DashMap::new(),
            mapping_count: AtomicUsize::new(0),
            last_used: AtomicU64::new(now_secs()),
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn last_used(&self) -> u64 {
        self.last_used.load(Ordering::Relaxed)
    }

    fn touch(&self) {
        self.last_used.store(now_secs(), Ordering::Relaxed);
    }

    fn digest(&self, raw: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.salt);
        h.update(raw.as_bytes());
        h.finalize().into()
    }

    /// Returns the stable placeholder for `raw`, registering it if new.
    pub fn tokenize(&self, kind: &str, raw: &str) -> String {
        self.touch();
        let digest = self.digest(raw);
        if let Some(existing) = self.forward.get(&digest) {
            // Do not treat a digest collision as identity. Verify the raw value behind
            // the indexed placeholder before reusing it; otherwise extend the token below.
            if self
                .reverse
                .get(existing.value())
                .is_some_and(|stored| stored.as_str() == raw)
            {
                return existing.value().clone();
            }
        }
        let kind = sanitize_kind(kind);
        let mut hex_len = MIN_HEX_LEN;
        loop {
            let placeholder = format!("[{kind}_{}]", hex_prefix(&digest, hex_len));
            match self.reverse.entry(placeholder.clone()) {
                Entry::Occupied(o) => {
                    if o.get().as_str() == raw {
                        self.forward.insert(digest, placeholder.clone());
                        return placeholder;
                    }
                    hex_len += 4;
                    if hex_len > MAX_HEX_LEN {
                        // Full SHA-256 collision: unreachable in practice. The marker
                        // intentionally fails the placeholder shape check, so it is
                        // never "restored" to the wrong value.
                        return format!("[{kind}_REDACTED]");
                    }
                }
                Entry::Vacant(v) => {
                    let reserved = self
                        .mapping_count
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                            (count < MAX_SESSION_MAPPINGS).then_some(count + 1)
                        })
                        .is_ok();
                    if !reserved {
                        return format!("[{kind}_REDACTED]");
                    }
                    v.insert(raw.to_owned());
                    self.forward.insert(digest, placeholder.clone());
                    return placeholder;
                }
            }
        }
    }

    /// Looks up the raw value behind a placeholder (e.g. `[SECRET_ab12cd34]`).
    pub fn resolve(&self, placeholder: &str) -> Option<String> {
        self.touch();
        self.reverse.get(placeholder).map(|v| v.value().clone())
    }

    pub fn has_mappings(&self) -> bool {
        !self.reverse.is_empty()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        for mut entry in self.reverse.iter_mut() {
            entry.value_mut().zeroize();
        }
        self.salt.zeroize();
    }
}

pub struct SessionRegistry {
    sessions: DashMap<SessionId, Arc<Session>>,
    next_id: AtomicU64,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn create(&self) -> Arc<Session> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(Session::new(id));
        self.sessions.insert(id, session.clone());
        session
    }

    pub fn remove(&self, id: SessionId) {
        self.sessions.remove(&id);
    }

    /// Drops sessions idle for longer than `ttl`. Sessions still referenced by a live
    /// connection stay alive through their `Arc` until that connection ends.
    pub fn sweep(&self, ttl: Duration) -> usize {
        let cutoff = now_secs().saturating_sub(ttl.as_secs());
        let stale: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|e| e.value().last_used() < cutoff)
            .map(|e| *e.key())
            .collect();
        for id in &stale {
            self.sessions.remove(id);
        }
        stale.len()
    }

    pub fn spawn_sweeper(
        self: &Arc<Self>,
        interval: Duration,
        ttl: Duration,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        let registry = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let n = registry.sweep(ttl);
                        if n > 0 {
                            tracing::debug!(evicted = n, "evicted idle sessions");
                        }
                    }
                    res = shutdown.changed() => {
                        if res.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_is_stable_and_reversible() {
        let reg = SessionRegistry::new();
        let s = reg.create();
        let a = s.tokenize("aws_access_key", "AKIAABCDEFGHIJKLMNOP");
        let b = s.tokenize("aws_access_key", "AKIAABCDEFGHIJKLMNOP");
        assert_eq!(a, b);
        assert!(a.starts_with("[AWS_ACCESS_KEY_"));
        assert_eq!(s.resolve(&a).as_deref(), Some("AKIAABCDEFGHIJKLMNOP"));
    }

    #[test]
    fn sessions_are_isolated() {
        let reg = SessionRegistry::new();
        let s1 = reg.create();
        let s2 = reg.create();
        let p = s1.tokenize("SECRET", "hunter2hunter2");
        assert!(s2.resolve(&p).is_none());
    }

    #[test]
    fn digest_index_collision_extends_placeholder_without_wrong_restoration() {
        let reg = SessionRegistry::new();
        let s = reg.create();
        let original = s.tokenize("SECRET", "first-value");
        let second_digest = s.digest("second-value");
        // Simulate a digest collision in the forward index without needing to find one.
        s.forward.insert(second_digest, original.clone());
        let second = s.tokenize("SECRET", "second-value");
        assert_ne!(original, second);
        assert_eq!(s.resolve(&original).as_deref(), Some("first-value"));
        assert_eq!(s.resolve(&second).as_deref(), Some("second-value"));
    }

    #[test]
    fn session_mapping_limit_keeps_new_values_redacted_without_growth() {
        let session = SessionRegistry::new().create();
        for i in 0..MAX_SESSION_MAPPINGS {
            session.tokenize("TERM", &format!("value-{i}"));
        }
        assert_eq!(
            session.mapping_count.load(Ordering::Relaxed),
            MAX_SESSION_MAPPINGS
        );
        let overflow = session.tokenize("TERM", "overflow-value");
        assert_eq!(overflow, "[TERM_REDACTED]");
        assert!(session.resolve(&overflow).is_none());
        assert_eq!(
            session.mapping_count.load(Ordering::Relaxed),
            MAX_SESSION_MAPPINGS
        );
    }
}
