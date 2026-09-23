use std::{fmt, fs};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, string::Ia5String,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};
use zeroize::Zeroizing;

use crate::{
    config::{AppPaths, Identity, Profile, SignerRecord, atomic_write},
    error::{AppError, AppResult},
    keychain,
};

pub const C2PA_CLAIM_SIGNING_EKU: &[u64] = &[1, 3, 6, 1, 4, 1, 62558, 2, 1];

#[derive(Debug, Serialize)]
pub struct InitReport {
    pub status: &'static str,
    pub profile: String,
    pub root_created: bool,
    pub signer_created: bool,
    pub signer_rotated: bool,
    pub signer_fingerprint_sha256: String,
    pub key_storage: &'static str,
    pub user_presence: &'static str,
    pub trust_mode: &'static str,
    pub public_c2pa_trust: &'static str,
}

impl fmt::Display for InitReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Local identity ready")?;
        writeln!(f)?;
        writeln!(f, "Profile\n  {}", self.profile)?;
        writeln!(f)?;
        writeln!(f, "Signer SHA-256\n  {}", self.signer_fingerprint_sha256)?;
        writeln!(f)?;
        writeln!(f, "Private keys\n  {}", self.key_storage)?;
        writeln!(f)?;
        writeln!(f, "Authentication\n  {}", self.user_presence)?;
        writeln!(f)?;
        writeln!(f, "Trust\n  private/local")?;
        write!(
            f,
            "\nPublic C2PA trust\n  not established (a local root is not a public trust credential)"
        )
    }
}

#[derive(Debug, Serialize)]
pub struct IdentityReport {
    pub status: &'static str,
    pub signer_name: String,
    pub organization: Option<String>,
    pub domain: Option<String>,
    pub uri: Option<String>,
    pub vendor: Option<String>,
    pub signer_subject: String,
    pub signer_issuer: String,
    pub signer_fingerprint_sha256: String,
    pub signer_not_before: String,
    pub signer_not_after: String,
    pub algorithm: String,
    pub key_storage: &'static str,
    pub trust_mode: &'static str,
    pub public_c2pa_trust: &'static str,
}

impl fmt::Display for IdentityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Signer name\n  {}", self.signer_name)?;
        writeln!(
            f,
            "\nOrganization\n  {}",
            display_optional(&self.organization)
        )?;
        writeln!(f, "\nDomain\n  {}", display_optional(&self.domain))?;
        writeln!(f, "\nURI\n  {}", display_optional(&self.uri))?;
        writeln!(f, "\nManifest vendor\n  {}", display_optional(&self.vendor))?;
        writeln!(f, "\nSigner subject\n  {}", self.signer_subject)?;
        writeln!(f, "\nSigner issuer\n  {}", self.signer_issuer)?;
        writeln!(f, "\nSigner SHA-256\n  {}", self.signer_fingerprint_sha256)?;
        writeln!(
            f,
            "\nSigner validity\n  {} to {}",
            self.signer_not_before, self.signer_not_after
        )?;
        writeln!(f, "\nPrivate key\n  {}", self.key_storage)?;
        writeln!(f, "\nTrust mode\n  {}", self.trust_mode)?;
        write!(f, "\nPublic C2PA trust\n  {}", self.public_c2pa_trust)
    }
}

pub struct GeneratedHierarchy {
    pub root_certificate_pem: String,
    pub root_key_pem: Zeroizing<Vec<u8>>,
    pub signer_certificate_pem: String,
    pub signer_key_pem: Zeroizing<Vec<u8>>,
    pub signer_not_after: String,
}

pub struct GeneratedSigner {
    pub certificate_pem: String,
    pub key_pem: Zeroizing<Vec<u8>>,
    pub not_after: String,
}

pub fn initialize(
    paths: &AppPaths,
    rotate_signer: bool,
    new_identity: Option<Identity>,
) -> AppResult<InitReport> {
    if !paths.profile_file.exists() && new_identity.is_none() {
        return Err(AppError::usage(
            "a signer identity is required when creating a new profile",
        ));
    }
    paths.ensure_directories()?;
    let mut profile = Profile::load_or_default(paths)?;
    if let Some(identity) = new_identity {
        if paths.profile_file.exists() {
            return Err(AppError::usage(
                "refusing to replace the identity in an existing profile",
            ));
        }
        profile.identity = identity;
    }

    if !profile.security.require_user_presence {
        return Err(AppError::runtime(
            "security.require_user_presence must remain true for the macOS version 1 signer",
        ));
    }

    let root_path = paths.root_certificate(&profile);
    let root_created = !root_path.exists();
    let signer_missing = profile.credential.active_signer_key_account.is_none()
        || profile.credential.active_signer_certificate.is_none()
        || profile
            .credential
            .active_signer_certificate
            .as_ref()
            .is_some_and(|p| !paths.config_dir.join(p).exists());
    let should_issue_signer = root_created || signer_missing || rotate_signer;

    let mut generated_root_key: Option<Zeroizing<Vec<u8>>> = None;
    if root_created {
        let hierarchy = generate_hierarchy(&profile)?;
        keychain::store_secret(
            profile.credential.keychain_backend,
            &profile.credential.keychain_service,
            &profile.credential.root_key_account,
            &hierarchy.root_key_pem,
            "banksy-c2pa local C2PA root key",
        )?;
        atomic_write(&root_path, hierarchy.root_certificate_pem.as_bytes(), 0o644)?;
        generated_root_key = Some(hierarchy.root_key_pem);
        install_signer(
            paths,
            &mut profile,
            hierarchy.signer_certificate_pem,
            hierarchy.signer_key_pem,
            hierarchy.signer_not_after,
        )?;
    } else if should_issue_signer {
        let root_pem = fs::read_to_string(&root_path)
            .map_err(|e| AppError::runtime(format!("cannot read {}: {e}", root_path.display())))?;
        let root_key = keychain::retrieve_secret(
            profile.credential.keychain_backend,
            &profile.credential.keychain_service,
            &profile.credential.root_key_account,
        )?;
        let signer = issue_signer(&profile, &root_pem, &root_key)?;
        install_signer(
            paths,
            &mut profile,
            signer.certificate_pem,
            signer.key_pem,
            signer.not_after,
        )?;
    }

    // Keep the generated key alive only through signer issuance and erase it now.
    drop(generated_root_key);
    profile.save(paths)?;

    let identity = identity_report(paths, &profile)?;
    Ok(InitReport {
        status: "ok",
        profile: paths.profile_file.display().to_string(),
        root_created,
        signer_created: should_issue_signer,
        signer_rotated: rotate_signer && !root_created,
        signer_fingerprint_sha256: identity.signer_fingerprint_sha256,
        key_storage: profile.credential.keychain_backend.storage_description(),
        user_presence: profile
            .credential
            .keychain_backend
            .authentication_description(),
        trust_mode: "local-private",
        public_c2pa_trust: "not-established",
    })
}

fn install_signer(
    paths: &AppPaths,
    profile: &mut Profile,
    certificate_pem: String,
    key_pem: Zeroizing<Vec<u8>>,
    not_after: String,
) -> AppResult<()> {
    let fingerprint = certificate_fingerprint(certificate_pem.as_bytes())?;
    let compact = fingerprint.replace(':', "").to_ascii_lowercase();
    let key_account = format!("signer-{}", &compact[..20]);
    let archive_relative = format!("certs/signer-{}.pem", &compact[..16]);
    let active_relative = "certs/signer-chain.pem".to_string();

    keychain::store_secret(
        profile.credential.keychain_backend,
        &profile.credential.keychain_service,
        &key_account,
        &key_pem,
        "banksy-c2pa active C2PA signer key",
    )?;
    atomic_write(
        &paths.config_dir.join(&archive_relative),
        certificate_pem.as_bytes(),
        0o644,
    )?;
    atomic_write(
        &paths.config_dir.join(&active_relative),
        certificate_pem.as_bytes(),
        0o644,
    )?;

    profile.credential.active_signer_key_account = Some(key_account.clone());
    profile.credential.active_signer_certificate = Some(active_relative);
    profile.signers.push(SignerRecord {
        fingerprint_sha256: fingerprint,
        certificate: archive_relative,
        keychain_account: key_account,
        issued_at: now_rfc3339(),
        not_after,
    });
    Ok(())
}

pub fn generate_hierarchy(profile: &Profile) -> AppResult<GeneratedHierarchy> {
    let now = OffsetDateTime::now_utc();
    let root_key = Zeroizing::new(
        KeyPair::generate()
            .map_err(|e| AppError::runtime(format!("cannot generate the root ES256 key: {e}")))?,
    );
    let root_params = root_params(profile, now);
    let root_certificate = root_params
        .self_signed(&*root_key)
        .map_err(|e| AppError::runtime(format!("cannot create the root certificate: {e}")))?;
    let root_pem = root_certificate.pem();
    let signer = issue_signer_with_key(profile, &root_params, &root_key)?;

    Ok(GeneratedHierarchy {
        root_certificate_pem: root_pem,
        root_key_pem: Zeroizing::new(root_key.serialize_pem().into_bytes()),
        signer_certificate_pem: signer.certificate_pem,
        signer_key_pem: signer.key_pem,
        signer_not_after: signer.not_after,
    })
}

pub fn issue_signer(
    profile: &Profile,
    root_certificate_pem: &str,
    root_key_pem: &[u8],
) -> AppResult<GeneratedSigner> {
    let key_text = std::str::from_utf8(root_key_pem)
        .map_err(|e| AppError::runtime(format!("root key is not valid PKCS#8 PEM: {e}")))?;
    let root_key = Zeroizing::new(
        KeyPair::from_pem(key_text)
            .map_err(|e| AppError::runtime(format!("cannot decode the root PKCS#8 key: {e}")))?,
    );
    let issuer = Issuer::from_ca_cert_pem(root_certificate_pem, &*root_key).map_err(|e| {
        AppError::runtime(format!(
            "cannot reconstruct the configured root certificate for signer rotation: {e}"
        ))
    })?;
    issue_signer_with_issuer(profile, &issuer)
}

fn issue_signer_with_key(
    profile: &Profile,
    root_params: &CertificateParams,
    root_key: &KeyPair,
) -> AppResult<GeneratedSigner> {
    let issuer = Issuer::from_params(root_params, root_key);
    issue_signer_with_issuer(profile, &issuer)
}

fn issue_signer_with_issuer<S: rcgen::SigningKey>(
    profile: &Profile,
    issuer: &Issuer<'_, S>,
) -> AppResult<GeneratedSigner> {
    let now = OffsetDateTime::now_utc();
    let signer_key =
        Zeroizing::new(KeyPair::generate().map_err(|e| {
            AppError::runtime(format!("cannot generate the signer ES256 key: {e}"))
        })?);
    let params = signer_params(profile, now)?;
    let not_after = format_time(params.not_after);
    let certificate = params
        .signed_by(&*signer_key, issuer)
        .map_err(|e| AppError::runtime(format!("cannot issue the signer certificate: {e}")))?;

    Ok(GeneratedSigner {
        certificate_pem: certificate.pem(),
        key_pem: Zeroizing::new(signer_key.serialize_pem().into_bytes()),
        not_after,
    })
}

fn root_params(profile: &Profile, now: OffsetDateTime) -> CertificateParams {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(
        DnType::CommonName,
        format!("{} Local C2PA Root", profile.identity.signer_name),
    );
    distinguished_name.push(
        DnType::OrganizationName,
        certificate_organization(&profile.identity),
    );

    let mut params = CertificateParams::default();
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(3652);
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.use_authority_key_identifier_extension = true;
    params
}

fn signer_params(profile: &Profile, now: OffsetDateTime) -> AppResult<CertificateParams> {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, profile.identity.signer_name.clone());
    distinguished_name.push(
        DnType::OrganizationName,
        certificate_organization(&profile.identity),
    );

    let mut params = CertificateParams::default();
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(397);
    let mut subject_alt_names = Vec::new();
    if let Some(domain) = &profile.identity.domain {
        subject_alt_names.push(SanType::DnsName(
            Ia5String::try_from(domain.clone()).map_err(|e| {
                AppError::runtime(format!(
                    "identity.domain cannot be encoded as a DNS SAN: {e}"
                ))
            })?,
        ));
    }
    if let Some(uri) = &profile.identity.uri {
        subject_alt_names.push(SanType::URI(Ia5String::try_from(uri.clone()).map_err(
            |e| AppError::runtime(format!("identity.uri cannot be encoded as a URI SAN: {e}")),
        )?));
    }
    params.subject_alt_names = subject_alt_names;
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::Other(C2PA_CLAIM_SIGNING_EKU.to_vec()),
        // Retained for interoperability with older validators while the
        // dedicated C2PA EKU remains the authoritative purpose.
        ExtendedKeyUsagePurpose::EmailProtection,
    ];
    params.use_authority_key_identifier_extension = true;
    Ok(params)
}

pub fn identity_report(paths: &AppPaths, profile: &Profile) -> AppResult<IdentityReport> {
    let certificate_path = paths.signer_certificate(profile)?;
    let pem = fs::read(&certificate_path).map_err(|e| {
        AppError::runtime(format!("cannot read {}: {e}", certificate_path.display()))
    })?;
    let info = certificate_summary(&pem)?;

    Ok(IdentityReport {
        status: "ok",
        signer_name: profile.identity.signer_name.clone(),
        organization: profile.identity.organization.clone(),
        domain: profile.identity.domain.clone(),
        uri: profile.identity.uri.clone(),
        vendor: profile.identity.vendor.clone(),
        signer_subject: info.subject,
        signer_issuer: info.issuer,
        signer_fingerprint_sha256: info.fingerprint_sha256,
        signer_not_before: info.not_before,
        signer_not_after: info.not_after,
        algorithm: "ES256 (ECDSA P-256 with SHA-256)".into(),
        key_storage: profile.credential.keychain_backend.storage_description(),
        trust_mode: "local-private",
        public_c2pa_trust: "not established",
    })
}

fn display_optional(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("not configured")
}

// c2pa-rs 0.90 requires an Organization attribute while extracting verified
// signing-certificate information. Reusing the required signer name avoids
// inventing a separate organization when the user leaves that field unset.
fn certificate_organization(identity: &Identity) -> String {
    identity
        .organization
        .clone()
        .unwrap_or_else(|| identity.signer_name.clone())
}

struct CertificateSummary {
    subject: String,
    issuer: String,
    fingerprint_sha256: String,
    not_before: String,
    not_after: String,
}

fn certificate_summary(pem_bytes: &[u8]) -> AppResult<CertificateSummary> {
    let (_, pem) = parse_x509_pem(pem_bytes)
        .map_err(|e| AppError::runtime(format!("cannot parse signer certificate PEM: {e}")))?;
    let (_, cert) = parse_x509_certificate(&pem.contents)
        .map_err(|e| AppError::runtime(format!("cannot parse signer certificate DER: {e}")))?;

    Ok(CertificateSummary {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        fingerprint_sha256: fingerprint_der(&pem.contents),
        not_before: format_time(cert.validity().not_before.to_datetime()),
        not_after: format_time(cert.validity().not_after.to_datetime()),
    })
}

pub fn certificate_fingerprint(pem_bytes: &[u8]) -> AppResult<String> {
    let (_, pem) = parse_x509_pem(pem_bytes)
        .map_err(|e| AppError::runtime(format!("cannot parse certificate PEM: {e}")))?;
    Ok(fingerprint_der(&pem.contents))
}

fn fingerprint_der(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn now_rfc3339() -> String {
    format_time(OffsetDateTime::now_utc())
}

fn format_time(time: OffsetDateTime) -> String {
    time.format(&Rfc3339)
        .unwrap_or_else(|_| time.unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_requires_an_explicit_new_identity() {
        let directory = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_config_dir(directory.path().join("config"));
        let error = initialize(&paths, false, None).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert!(!paths.config_dir.exists());
    }

    #[test]
    fn generated_leaf_has_expected_identity_and_eku() {
        let mut p = Profile::default();
        p.identity.signer_name = "Example image signer".into();
        p.identity.organization = Some("Example Studio".into());
        p.identity.domain = Some("example.test".into());
        p.identity.uri = Some("https://example.test/provenance".into());
        let generated = generate_hierarchy(&p).unwrap();
        let (_, pem) = parse_x509_pem(generated.signer_certificate_pem.as_bytes()).unwrap();
        let (_, cert) = parse_x509_certificate(&pem.contents).unwrap();

        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        let org = cert
            .subject()
            .iter_organization()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(cn, p.identity.signer_name);
        assert_eq!(org, p.identity.organization.as_deref().unwrap());
        assert!(!cert.is_ca());
        let eku = cert.extended_key_usage().unwrap().unwrap();
        assert!(
            eku.value
                .other
                .iter()
                .any(|oid| oid.to_id_string() == "1.3.6.1.4.1.62558.2.1")
        );
    }

    #[test]
    fn generated_leaf_uses_the_signer_name_when_organization_is_absent() {
        let p = Profile::default();
        let generated = generate_hierarchy(&p).unwrap();
        let (_, pem) = parse_x509_pem(generated.signer_certificate_pem.as_bytes()).unwrap();
        let (_, cert) = parse_x509_certificate(&pem.contents).unwrap();

        let organization = cert
            .subject()
            .iter_organization()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(organization, p.identity.signer_name);
        assert!(cert.subject_alternative_name().unwrap().is_none());
    }

    #[test]
    fn private_keys_are_not_part_of_certificates() {
        let generated = generate_hierarchy(&Profile::default()).unwrap();
        assert!(!generated.root_certificate_pem.contains("PRIVATE KEY"));
        assert!(!generated.signer_certificate_pem.contains("PRIVATE KEY"));
        assert!(
            std::str::from_utf8(&generated.signer_key_pem)
                .unwrap()
                .contains("BEGIN PRIVATE KEY")
        );
    }
}
