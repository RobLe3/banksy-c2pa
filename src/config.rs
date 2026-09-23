use std::{
    fs,
    path::{Path, PathBuf},
};

use directories::BaseDirs;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

pub const CONFIG_ENV: &str = "BANKSY_C2PA_CONFIG_DIR";
pub const DEFAULT_ATTEST_DESCRIPTION: &str = "Editorial / publication attestation";
pub const DEFAULT_DERIVATIVE_DESCRIPTION: &str = "Derivative / editorial work";

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub certs_dir: PathBuf,
    pub profile_file: PathBuf,
}

impl AppPaths {
    pub fn discover() -> AppResult<Self> {
        if let Some(override_path) = std::env::var_os(CONFIG_ENV) {
            return Ok(Self::from_config_dir(PathBuf::from(override_path)));
        }

        let home = BaseDirs::new()
            .ok_or_else(|| AppError::runtime("cannot determine the home directory"))?
            .home_dir()
            .to_path_buf();
        Ok(Self::from_config_dir(
            home.join(".config").join("banksy-c2pa"),
        ))
    }

    pub fn from_config_dir(config_dir: PathBuf) -> Self {
        Self {
            certs_dir: config_dir.join("certs"),
            profile_file: config_dir.join("profile.toml"),
            config_dir,
        }
    }

    pub fn root_certificate(&self, profile: &Profile) -> PathBuf {
        self.config_dir.join(&profile.credential.root_certificate)
    }

    pub fn signer_certificate(&self, profile: &Profile) -> AppResult<PathBuf> {
        let relative = profile
            .credential
            .active_signer_certificate
            .as_ref()
            .ok_or_else(|| {
                AppError::runtime("no active signer is configured; run `banksy-c2pa init`")
            })?;
        Ok(self.config_dir.join(relative))
    }

    pub fn ensure_directories(&self) -> AppResult<()> {
        fs::create_dir_all(&self.certs_dir).map_err(|e| {
            AppError::runtime(format!(
                "cannot create configuration directory {}: {e}",
                self.config_dir.display()
            ))
        })?;
        set_dir_mode(&self.config_dir)?;
        set_dir_mode(&self.certs_dir)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub identity: Identity,
    pub credential: Credential,
    pub manifest: ManifestSettings,
    pub timestamp: TimestampSettings,
    pub security: SecuritySettings,
    pub signers: Vec<SignerRecord>,
}

impl Profile {
    pub fn load(paths: &AppPaths) -> AppResult<Self> {
        let source = fs::read_to_string(&paths.profile_file).map_err(|e| {
            AppError::runtime(format!(
                "cannot read {}: {e}; run `banksy-c2pa init` first",
                paths.profile_file.display()
            ))
        })?;
        let profile: Self = toml::from_str(&source).map_err(|e| {
            AppError::runtime(format!(
                "cannot parse {}: {e}",
                paths.profile_file.display()
            ))
        })?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn load_or_default(paths: &AppPaths) -> AppResult<Self> {
        if paths.profile_file.exists() {
            Self::load(paths)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, paths: &AppPaths) -> AppResult<()> {
        self.validate()?;
        let encoded = toml::to_string_pretty(self)
            .map_err(|e| AppError::runtime(format!("cannot serialize profile: {e}")))?;
        atomic_write(&paths.profile_file, encoded.as_bytes(), 0o600)
    }

    fn validate(&self) -> AppResult<()> {
        if self.identity.signer_name.trim().is_empty() {
            return Err(AppError::runtime("identity signer_name must not be empty"));
        }
        for (field, value) in [
            ("organization", &self.identity.organization),
            ("domain", &self.identity.domain),
            ("uri", &self.identity.uri),
            ("vendor", &self.identity.vendor),
        ] {
            if value.as_ref().is_some_and(|value| value.trim().is_empty()) {
                return Err(AppError::runtime(format!(
                    "identity {field} must be omitted rather than empty"
                )));
            }
        }
        if self.credential.mode != "local-private" {
            return Err(AppError::runtime(format!(
                "unsupported credential mode `{}`; version 1 supports only `local-private`",
                self.credential.mode
            )));
        }
        if !self.credential.algorithm.eq_ignore_ascii_case("es256") {
            return Err(AppError::runtime(format!(
                "unsupported signing algorithm `{}`; version 1 supports only `es256`",
                self.credential.algorithm
            )));
        }
        if self.timestamp.enabled {
            return Err(AppError::runtime(
                "RFC 3161 timestamps are not implemented in version 1; set timestamp.enabled=false",
            ));
        }
        if !self.security.require_user_presence {
            return Err(AppError::runtime(
                "security.require_user_presence must be true in version 1",
            ));
        }
        if self.security.allow_source_overwrite {
            return Err(AppError::runtime(
                "security.allow_source_overwrite is not supported in version 1",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Identity {
    #[serde(alias = "service_name")]
    pub signer_name: String,
    pub organization: Option<String>,
    pub domain: Option<String>,
    pub uri: Option<String>,
    pub vendor: Option<String>,
}

impl Default for Identity {
    fn default() -> Self {
        Self {
            signer_name: "banksy-c2pa local signer".into(),
            organization: None,
            domain: None,
            uri: None,
            vendor: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Credential {
    pub mode: String,
    pub algorithm: String,
    pub keychain_backend: KeychainBackend,
    pub keychain_service: String,
    pub root_key_account: String,
    pub root_certificate: String,
    pub active_signer_key_account: Option<String>,
    pub active_signer_certificate: Option<String>,
}

impl Default for Credential {
    fn default() -> Self {
        Self {
            mode: "local-private".into(),
            algorithm: "es256".into(),
            keychain_backend: KeychainBackend::default(),
            keychain_service: "com.roblemumin.banksy-c2pa".into(),
            root_key_account: "root-ca-v1".into(),
            root_certificate: "certs/root-ca.pem".into(),
            active_signer_key_account: None,
            active_signer_certificate: None,
        }
    }
}

/// The macOS key store used by the unentitled command-line executable.
///
/// Data Protection Keychain items with biometric access controls require a
/// provisioned application identifier on macOS. A normal Cargo-installed CLI
/// does not have that entitlement, so version 1 uses the local login Keychain
/// and performs a LocalAuthentication check immediately before every read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeychainBackend {
    #[default]
    LoginKeychainLocalAuthentication,
}

impl KeychainBackend {
    pub const fn storage_description(self) -> &'static str {
        match self {
            Self::LoginKeychainLocalAuthentication => {
                "macOS login Keychain (local; no private key files)"
            }
        }
    }

    pub const fn authentication_description(self) -> &'static str {
        match self {
            Self::LoginKeychainLocalAuthentication => {
                "macOS user authentication immediately before retrieval; Touch ID is offered when available, with login-password fallback"
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ManifestSettings {
    pub attest_description: String,
    pub default_description: String,
    pub publisher_action: bool,
}

impl Default for ManifestSettings {
    fn default() -> Self {
        Self {
            attest_description: DEFAULT_ATTEST_DESCRIPTION.into(),
            default_description: DEFAULT_DERIVATIVE_DESCRIPTION.into(),
            // A publication claim must be requested explicitly on the command line.
            publisher_action: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TimestampSettings {
    pub enabled: bool,
    pub tsa_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecuritySettings {
    pub require_user_presence: bool,
    pub allow_source_overwrite: bool,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            require_user_presence: true,
            allow_source_overwrite: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerRecord {
    pub fingerprint_sha256: String,
    pub certificate: String,
    pub keychain_account: String,
    pub issued_at: String,
    pub not_after: String,
}

pub(crate) fn atomic_write(path: &Path, data: &[u8], mode: u32) -> AppResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::runtime(format!("{} has no parent directory", path.display())))?;
    fs::create_dir_all(parent)
        .map_err(|e| AppError::runtime(format!("cannot create {}: {e}", parent.display())))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
        AppError::runtime(format!(
            "cannot create temporary file in {}: {e}",
            parent.display()
        ))
    })?;
    use std::io::Write;
    tmp.write_all(data)
        .and_then(|_| tmp.as_file().sync_all())
        .map_err(|e| AppError::runtime(format!("cannot write {}: {e}", path.display())))?;
    set_file_mode(tmp.path(), mode)?;
    tmp.persist(path)
        .map_err(|e| AppError::runtime(format!("cannot commit {}: {}", path.display(), e.error)))?;
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| AppError::runtime(format!("cannot secure directory {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn set_dir_mode(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| {
        AppError::runtime(format!("cannot set permissions on {}: {e}", path.display()))
    })
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) -> AppResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_has_safe_identity_and_no_automatic_publish_claim() {
        let p = Profile::default();
        assert_eq!(p.identity.signer_name, "banksy-c2pa local signer");
        assert_eq!(p.identity.organization, None);
        assert!(!p.manifest.publisher_action);
        assert!(p.security.require_user_presence);
        assert_eq!(
            p.credential.keychain_backend,
            KeychainBackend::LoginKeychainLocalAuthentication
        );
    }

    #[test]
    fn profile_round_trip() {
        let p = Profile::default();
        let encoded = toml::to_string(&p).unwrap();
        let decoded: Profile = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.identity.uri, p.identity.uri);
    }

    #[test]
    fn example_profile_parses() {
        let profile: Profile = toml::from_str(include_str!("../examples/profile.toml")).unwrap();
        profile.validate().unwrap();
    }

    #[test]
    fn old_service_name_profiles_remain_compatible() {
        let profile: Profile = toml::from_str(
            r#"
                [identity]
                service_name = "Legacy image signer"
                organization = "Existing organization"
                domain = "example.test"
                uri = "https://example.test"
                vendor = "example.test"
            "#,
        )
        .unwrap();
        profile.validate().unwrap();
        assert_eq!(profile.identity.signer_name, "Legacy image signer");
    }
}
