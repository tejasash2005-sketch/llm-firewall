//! Local root CA and on-the-fly leaf certificate minting for TLS interception.
//!
//! The CA key is written once with mode 0600. Install `llm-firewall-ca.pem` into the trust
//! store of the clients you want to protect (or point NODE_EXTRA_CA_CERTS / SSL_CERT_FILE /
//! REQUESTS_CA_BUNDLE at it). Anyone holding the key can impersonate any site to those
//! clients, so guard it accordingly.

use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use dashmap::DashMap;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::error::FirewallError;

pub struct CertAuthority {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    cert_path: PathBuf,
    cache: DashMap<String, Arc<ServerConfig>>,
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), FirewallError> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn check_private_key_file(path: &Path) -> Result<(), FirewallError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CA private key must be a regular file, not a symlink",
        )
        .into());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "CA private key permissions are too broad; run chmod 600 on the key",
        )
        .into());
    }
    Ok(())
}

impl CertAuthority {
    pub fn load_or_create(dir: &Path) -> Result<Self, FirewallError> {
        fs::create_dir_all(dir)?;
        let cert_path = dir.join("llm-firewall-ca.pem");
        let key_path = dir.join("llm-firewall-ca.key");

        let (ca_cert, ca_key) = if cert_path.exists() && key_path.exists() {
            check_private_key_file(&key_path)?;
            let cert_pem = fs::read_to_string(&cert_path)?;
            let key_pem = fs::read_to_string(&key_path)?;
            let key = KeyPair::from_pem(&key_pem)?;
            let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
            // Re-materialises the issuer (same subject + key) so it can sign leaves; the
            // on-disk certificate that clients trust is left untouched.
            let cert = params.self_signed(&key)?;
            (cert, key)
        } else {
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            let mut dn = DistinguishedName::new();
            dn.push(
                DnType::CommonName,
                "LLM Data Leakage Firewall Local Root CA",
            );
            dn.push(DnType::OrganizationName, "llm-firewall");
            params.distinguished_name = dn;
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let now = OffsetDateTime::now_utc();
            params.not_before = now - TimeDuration::days(1);
            params.not_after = now + TimeDuration::days(3650);
            let cert = params.self_signed(&key)?;
            write_private(&key_path, key.serialize_pem().as_bytes())?;
            fs::write(&cert_path, cert.pem())?;
            (cert, key)
        };

        Ok(Self {
            ca_cert,
            ca_key,
            cert_path,
            cache: DashMap::new(),
        })
    }

    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// Returns the public root certificate for clients that configure trust programmatically.
    #[cfg(test)]
    pub fn certificate_der(&self) -> rustls::pki_types::CertificateDer<'static> {
        self.ca_cert.der().clone()
    }

    /// Returns (and caches) a rustls server config presenting a freshly minted leaf for `host`.
    pub fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>, FirewallError> {
        if let Some(cfg) = self.cache.get(host) {
            return Ok(cfg.clone());
        }

        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        let mut dn = DistinguishedName::new();
        if host.len() <= 64 {
            dn.push(DnType::CommonName, host);
        }
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - TimeDuration::days(1);
        params.not_after = now + TimeDuration::days(397);

        let leaf = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;
        let chain = vec![leaf.der().clone()];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key_der)?;
        // HTTP/1.1 only: keeps the interception path simple and fully inspectable.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

        let cfg = Arc::new(cfg);
        self.cache.insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{symlink, PermissionsExt},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "llm-firewall-ca-test-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn generated_private_key_is_mode_600_and_ca_reloads() {
        let dir = TestDirectory::new();
        let ca = CertAuthority::load_or_create(&dir.0).unwrap();
        let key_path = dir.0.join("llm-firewall-ca.key");

        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(ca);
        assert!(CertAuthority::load_or_create(&dir.0).is_ok());
    }

    #[test]
    fn rejects_ca_private_key_with_group_or_world_permissions() {
        let dir = TestDirectory::new();
        drop(CertAuthority::load_or_create(&dir.0).unwrap());
        let key_path = dir.0.join("llm-firewall-ca.key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o640)).unwrap();

        let err = CertAuthority::load_or_create(&dir.0).err().unwrap();
        assert!(err.to_string().contains("permissions are too broad"));
    }

    #[test]
    fn rejects_symlink_ca_private_key() {
        let dir = TestDirectory::new();
        drop(CertAuthority::load_or_create(&dir.0).unwrap());
        let key_path = dir.0.join("llm-firewall-ca.key");
        let target_path = dir.0.join("private-key-target.pem");
        fs::rename(&key_path, &target_path).unwrap();
        symlink(&target_path, &key_path).unwrap();

        let err = CertAuthority::load_or_create(&dir.0).err().unwrap();
        assert!(err
            .to_string()
            .contains("must be a regular file, not a symlink"));
    }
}
