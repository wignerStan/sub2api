//! TLS configuration types.
//!
//! Pure data types for describing TLS settings — no actual TLS handshake logic.
//! A transport layer consumes these to build the appropriate connector.

use std::path::PathBuf;

/// Supported TLS backend implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsBackend {
    /// rustls with aws-lc-rs crypto provider (default).
    #[default]
    RustlsAwsLcRs,
    /// rustls with ring crypto provider.
    RustlsRing,
    /// native-tls (platform TLS: `SChannel` / Security.framework / OpenSSL).
    NativeTls,
    /// `BoringSSL`.
    BoringSsl,
}

impl std::fmt::Display for TlsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RustlsAwsLcRs => f.write_str("rustls-aws-lc-rs"),
            Self::RustlsRing => f.write_str("rustls-ring"),
            Self::NativeTls => f.write_str("native-tls"),
            Self::BoringSsl => f.write_str("boringssl"),
        }
    }
}

/// TLS client configuration.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Which TLS backend to use.
    pub backend: TlsBackend,
    /// Path to a custom CA certificate (PEM).
    pub ca_cert_path: Option<PathBuf>,
    /// Path to a client certificate (PEM) for mutual TLS.
    pub cert_path: Option<PathBuf>,
    /// Path to the private key matching `cert_path`.
    pub key_path: Option<PathBuf>,
    /// Skip certificate verification (insecure — dev/test only).
    pub skip_verify: bool,
}

impl TlsConfig {
    /// Create a default config with the given backend.
    #[must_use]
    pub const fn new(backend: TlsBackend) -> Self {
        Self {
            backend,
            ca_cert_path: None,
            cert_path: None,
            key_path: None,
            skip_verify: false,
        }
    }

    /// Create a config for development that skips verification.
    #[must_use]
    pub fn dev_insecure() -> Self {
        Self {
            backend: TlsBackend::default(),
            ca_cert_path: None,
            cert_path: None,
            key_path: None,
            skip_verify: true,
        }
    }

    /// Set a custom CA certificate path.
    #[must_use]
    pub fn with_ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }

    /// Set client certificate and key paths for mutual TLS.
    #[must_use]
    pub fn with_client_cert(mut self, cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        self.cert_path = Some(cert.into());
        self.key_path = Some(key.into());
        self
    }

    /// Returns `true` if mutual TLS (client cert + key) is configured.
    #[must_use]
    pub const fn has_client_auth(&self) -> bool {
        self.cert_path.is_some() && self.key_path.is_some()
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self::new(TlsBackend::default())
    }
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVersion {
    /// TLS 1.2 — allow only where a peer cannot do 1.3.
    Tls1_2,
    /// TLS 1.3 — the only version enabled by default in [`SafeTlsConfig`].
    Tls1_3,
}

/// A TLS configuration that enforces verification by construction.
///
/// Unlike [`TlsConfig`] (which carries an unsafe `skip_verify` escape hatch),
/// `SafeTlsConfig` has NO verification-skip field: the only way to build one is
/// with verification on, a minimum protocol, and an optional custom root store
/// / mTLS pair. The dangerous "dangerous verifier" APIs that rustls gates behind
/// `#[cfg(feature = "dangerous_configuration")]` never enter the picture because
/// this type cannot express "skip verification". Use [`TlsConfig::dev_insecure`]
/// at a clearly-marked dev/test boundary if you truly must skip — never this.
#[derive(Debug, Clone)]
pub struct SafeTlsConfig {
    /// Which TLS backend to use.
    pub backend: TlsBackend,
    /// Lowest protocol version permitted. Defaults to TLS 1.3.
    pub min_version: TlsVersion,
    /// Path to an additional custom CA certificate (PEM) for the root store.
    /// Verification uses the platform/system roots PLUS this cert.
    pub ca_cert_path: Option<PathBuf>,
    /// Path to a client certificate (PEM) for mutual TLS.
    pub cert_path: Option<PathBuf>,
    /// Path to the private key matching `cert_path`.
    pub key_path: Option<PathBuf>,
}

impl SafeTlsConfig {
    /// A safe default: rustls (aws-lc-rs), TLS 1.3 minimum, system roots,
    /// verification on, no client auth.
    #[must_use]
    pub const fn safe_default() -> Self {
        Self {
            backend: TlsBackend::RustlsAwsLcRs,
            min_version: TlsVersion::Tls1_3,
            ca_cert_path: None,
            cert_path: None,
            key_path: None,
        }
    }

    /// Set the minimum protocol version. Prefer [`TlsVersion::Tls1_3`].
    #[must_use]
    pub const fn with_min_version(mut self, v: TlsVersion) -> Self {
        self.min_version = v;
        self
    }

    /// Add a custom CA certificate path (augments the system root store).
    #[must_use]
    pub fn with_ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }

    /// Set client certificate + key for mutual TLS.
    #[must_use]
    pub fn with_client_cert(mut self, cert: impl Into<PathBuf>, key: impl Into<PathBuf>) -> Self {
        self.cert_path = Some(cert.into());
        self.key_path = Some(key.into());
        self
    }

    /// Select the TLS backend.
    #[must_use]
    pub const fn with_backend(mut self, b: TlsBackend) -> Self {
        self.backend = b;
        self
    }

    /// `true` if mutual TLS (client cert + key) is configured.
    #[must_use]
    pub const fn has_client_auth(&self) -> bool {
        self.cert_path.is_some() && self.key_path.is_some()
    }
}

impl Default for SafeTlsConfig {
    fn default() -> Self {
        Self::safe_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_backend_is_rustls_aws_lc_rs() {
        assert_eq!(TlsBackend::default(), TlsBackend::RustlsAwsLcRs);
    }

    #[test]
    fn default_config_has_no_optional_fields() {
        let config = TlsConfig::default();
        assert!(config.ca_cert_path.is_none());
        assert!(config.cert_path.is_none());
        assert!(config.key_path.is_none());
        assert!(!config.skip_verify);
        assert!(!config.has_client_auth());
    }

    #[test]
    fn builder_pattern() {
        let config = TlsConfig::new(TlsBackend::RustlsRing)
            .with_ca_cert("/etc/ssl/ca.pem")
            .with_client_cert("/etc/ssl/client.pem", "/etc/ssl/client.key");
        assert_eq!(config.backend, TlsBackend::RustlsRing);
        assert_eq!(
            config.ca_cert_path.as_ref().unwrap(),
            &PathBuf::from("/etc/ssl/ca.pem")
        );
        assert!(config.has_client_auth());
    }

    #[test]
    fn dev_insecure_skips_verify() {
        let config = TlsConfig::dev_insecure();
        assert!(config.skip_verify);
        assert!(!config.has_client_auth());
    }

    #[test]
    fn display_backend_names() {
        assert_eq!(TlsBackend::RustlsAwsLcRs.to_string(), "rustls-aws-lc-rs");
        assert_eq!(TlsBackend::RustlsRing.to_string(), "rustls-ring");
        assert_eq!(TlsBackend::NativeTls.to_string(), "native-tls");
        assert_eq!(TlsBackend::BoringSsl.to_string(), "boringssl");
    }

    #[test]
    fn safe_default_enforces_tls_1_3_and_verification() {
        let c = SafeTlsConfig::default();
        assert_eq!(c.min_version, TlsVersion::Tls1_3);
        assert_eq!(c.backend, TlsBackend::RustlsAwsLcRs);
        assert!(c.ca_cert_path.is_none());
        assert!(!c.has_client_auth());
        // No skip_verify field exists on SafeTlsConfig — the type cannot
        // express disabling verification.
    }

    #[test]
    fn safe_config_builder_chain() {
        let c = SafeTlsConfig::safe_default()
            .with_min_version(TlsVersion::Tls1_2)
            .with_ca_cert("/etc/ssl/extra-ca.pem")
            .with_client_cert("/c.pem", "/c.key")
            .with_backend(TlsBackend::RustlsRing);
        assert_eq!(c.min_version, TlsVersion::Tls1_2);
        assert_eq!(c.backend, TlsBackend::RustlsRing);
        assert!(c.has_client_auth());
        assert_eq!(
            c.ca_cert_path.as_deref(),
            Some(std::path::Path::new("/etc/ssl/extra-ca.pem"))
        );
    }
}
