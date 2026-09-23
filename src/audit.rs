use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{
    bundle::{self, BundleAuditReport},
    config::AppPaths,
    container::{ContainerCredentialReport, inspect_container},
    display_path,
    error::{AppError, AppResult},
    image_info::file_sha256,
    provenance::inspect_asset,
    scan::{self, is_managed_output},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditState {
    ValidLocal,
    ValidExternal,
    MissingCredential,
    Invalid,
    HashMismatch,
}

impl AuditState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidLocal => "valid-local",
            Self::ValidExternal => "valid-external",
            Self::MissingCredential => "missing-credential",
            Self::Invalid => "invalid",
            Self::HashMismatch => "hash-mismatch",
        }
    }

    pub const fn passed(self) -> bool {
        matches!(self, Self::ValidLocal | Self::ValidExternal)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageAuditReport {
    pub path: String,
    pub state: AuditState,
    pub file_size: u64,
    pub file_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_matches: Option<bool>,
    pub container: ContainerCredentialReport,
    pub manifest_present: bool,
    pub manifest_count: usize,
    pub active_manifest: Option<String>,
    pub signer_common_name: Option<String>,
    pub signer_issuer: Option<String>,
    pub signature_valid: bool,
    pub local_trust: bool,
    pub published: bool,
    pub upstream_manifest_count: usize,
    pub upstream_preserved: bool,
    pub detail: String,
}

impl ImageAuditReport {
    pub fn passed(&self) -> bool {
        self.state.passed()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AuditTargetReport {
    Image(ImageAuditReport),
    Bundle(BundleAuditReport),
}

impl AuditTargetReport {
    fn passed(&self) -> bool {
        match self {
            Self::Image(report) => report.passed(),
            Self::Bundle(report) => report.passed,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditSummary {
    pub targets: usize,
    pub images: usize,
    pub bundles: usize,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub status: &'static str,
    pub recursive: bool,
    pub targets: Vec<AuditTargetReport>,
    pub summary: AuditSummary,
}

impl AuditReport {
    pub fn exit_code(&self) -> u8 {
        if self.summary.failed == 0 { 0 } else { 3 }
    }
}

impl fmt::Display for AuditReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for target in &self.targets {
            match target {
                AuditTargetReport::Image(image) => {
                    writeln!(f, "{:<19} {}", image.state.as_str(), image.path)?;
                    writeln!(f, "  SHA-256: {}", image.file_sha256)?;
                    writeln!(
                        f,
                        "  embedded: {} ({}; {} bytes)",
                        yes_no(image.container.embedded),
                        image.container.location,
                        image.container.store_bytes
                    )?;
                    writeln!(
                        f,
                        "  signature: {}; local trust: {}; manifests: {}; upstream preserved: {}",
                        valid_invalid(image.signature_valid),
                        yes_no(image.local_trust),
                        image.manifest_count,
                        yes_no(image.upstream_preserved)
                    )?;
                    if !image.passed() {
                        writeln!(f, "  {}", image.detail)?;
                    }
                }
                AuditTargetReport::Bundle(bundle) => {
                    writeln!(
                        f,
                        "{:<19} {}",
                        if bundle.passed {
                            "valid-bundle"
                        } else {
                            "invalid-bundle"
                        },
                        bundle.path
                    )?;
                    writeln!(f, "  SHA-256: {}", bundle.file_sha256)?;
                    writeln!(
                        f,
                        "  {} image{}; trust basis: {}; bundled root matches local identity: {}",
                        bundle.images.len(),
                        if bundle.images.len() == 1 { "" } else { "s" },
                        bundle.trust_basis,
                        yes_no(bundle.local_root_match)
                    )?;
                    for issue in &bundle.issues {
                        writeln!(f, "  {issue}")?;
                    }
                }
            }
        }
        write!(
            f,
            "\nSummary: {} target{}, {} passed, {} failed",
            self.summary.targets,
            if self.summary.targets == 1 { "" } else { "s" },
            self.summary.passed,
            self.summary.failed
        )
    }
}

pub fn audit_paths(
    app_paths: &AppPaths,
    roots: &[PathBuf],
    recursive: bool,
    expected_sha256: Option<&str>,
) -> AppResult<AuditReport> {
    let roots = if roots.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        roots.to_vec()
    };
    let mut candidates = Vec::new();
    for root in &roots {
        collect_targets(root, recursive, &mut candidates)?;
    }
    candidates.sort();
    candidates.dedup_by(|left, right| {
        left.canonicalize().unwrap_or_else(|_| left.clone())
            == right.canonicalize().unwrap_or_else(|_| right.clone())
    });
    if candidates.is_empty() {
        return Err(AppError::runtime(
            "no PNG, JPEG, or evidence ZIP files found",
        ));
    }
    if expected_sha256.is_some() && candidates.len() != 1 {
        return Err(AppError::runtime(
            "--expect-sha256 requires exactly one image or bundle",
        ));
    }
    let expected = expected_sha256.map(normalize_sha256).transpose()?;
    let local_root = scan::load_local_root(app_paths)?;
    let mut targets = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if is_zip(&candidate) {
            let mut report = bundle::audit_bundle(&candidate, local_root.as_deref())?;
            if let Some(expected) = &expected {
                report.expected_sha256 = Some(expected.clone());
                report.hash_matches = Some(report.file_sha256.eq_ignore_ascii_case(expected));
                if report.hash_matches == Some(false) {
                    report.passed = false;
                    report
                        .issues
                        .push("bundle SHA-256 does not match --expect-sha256".into());
                }
            }
            targets.push(AuditTargetReport::Bundle(report));
        } else {
            targets.push(AuditTargetReport::Image(audit_image(
                &candidate,
                local_root.as_deref(),
                expected.as_deref(),
            )?));
        }
    }
    let summary = AuditSummary {
        targets: targets.len(),
        images: targets
            .iter()
            .map(|target| match target {
                AuditTargetReport::Image(_) => 1,
                AuditTargetReport::Bundle(bundle) => bundle.images.len(),
            })
            .sum(),
        bundles: targets
            .iter()
            .filter(|target| matches!(target, AuditTargetReport::Bundle(_)))
            .count(),
        passed: targets.iter().filter(|target| target.passed()).count(),
        failed: targets.iter().filter(|target| !target.passed()).count(),
    };
    Ok(AuditReport {
        status: if summary.failed == 0 { "ok" } else { "invalid" },
        recursive,
        targets,
        summary,
    })
}

pub fn audit_image(
    path: &Path,
    local_root_pem: Option<&str>,
    expected_sha256: Option<&str>,
) -> AppResult<ImageAuditReport> {
    let file_size = fs::metadata(path)
        .map_err(|error| {
            AppError::runtime(format!("cannot inspect {}: {error}", display_path(path)))
        })?
        .len();
    let hash = file_sha256(path)?;
    let expected = expected_sha256.map(normalize_sha256).transpose()?;
    let hash_matches = expected
        .as_ref()
        .map(|expected| hash.eq_ignore_ascii_case(expected));
    let container = inspect_container(path)?;
    let inspection = inspect_asset(path, local_root_pem);

    let mut report = ImageAuditReport {
        path: display_path(path),
        state: AuditState::Invalid,
        file_size,
        file_sha256: hash,
        expected_sha256: expected,
        hash_matches,
        container,
        manifest_present: false,
        manifest_count: 0,
        active_manifest: None,
        signer_common_name: None,
        signer_issuer: None,
        signature_valid: false,
        local_trust: false,
        published: false,
        upstream_manifest_count: 0,
        upstream_preserved: false,
        detail: String::new(),
    };

    if let Ok(inspection) = inspection {
        let c2pa = inspection.c2pa;
        report.manifest_present = c2pa.present;
        report.manifest_count = c2pa.manifest_count;
        report.active_manifest = c2pa.active_manifest;
        report.signer_common_name = c2pa.signer_common_name;
        report.signer_issuer = c2pa.signer_issuer;
        report.signature_valid = c2pa.present && c2pa.validation_state != "invalid";
        report.local_trust = c2pa.validation_state == "trusted";
        report.published = c2pa.actions.iter().any(|action| action == "c2pa.published");
        report.upstream_manifest_count = c2pa.manifest_count.saturating_sub(1);
        report.upstream_preserved = report.upstream_manifest_count > 0
            && c2pa.ingredients.iter().any(|ingredient| {
                ingredient.relationship == "parentOf" && ingredient.active_manifest.is_some()
            });
    } else if let Err(error) = inspection {
        report.detail = error.to_string();
    }

    let managed = is_managed_output(path);
    report.state = if report.hash_matches == Some(false) {
        report.detail = "file SHA-256 does not match --expect-sha256".into();
        AuditState::HashMismatch
    } else if !report.container.structure_valid {
        report.detail = report.container.issues.join("; ");
        AuditState::Invalid
    } else if !report.container.embedded {
        report.detail = if managed {
            "a .banksy-signed file has no embedded Content Credential; it was stripped or replaced"
                .into()
        } else {
            "no embedded Content Credential was found".into()
        };
        AuditState::MissingCredential
    } else if !report.manifest_present {
        if report.detail.is_empty() {
            report.detail =
                "an embedded credential store was found, but it is not a readable C2PA manifest"
                    .into();
        }
        AuditState::Invalid
    } else if !report.signature_valid {
        if report.detail.is_empty() {
            report.detail = "the C2PA signature or asset binding is invalid".into();
        }
        AuditState::Invalid
    } else if managed && local_root_pem.is_some() && !report.local_trust {
        report.detail =
            "the .banksy-signed file does not validate against the configured local identity"
                .into();
        AuditState::Invalid
    } else if report.local_trust {
        report.detail = "embedded credential and local signature are valid".into();
        AuditState::ValidLocal
    } else {
        report.detail = "embedded credential and cryptographic signature are valid".into();
        AuditState::ValidExternal
    };
    Ok(report)
}

fn collect_targets(path: &Path, recursive: bool, out: &mut Vec<PathBuf>) -> AppResult<()> {
    if path.is_file() {
        if is_supported_image(path) || is_zip(path) {
            out.push(path.to_path_buf());
            return Ok(());
        }
        return Err(AppError::runtime(format!(
            "unsupported audit target: {}",
            display_path(path)
        )));
    }
    if !path.is_dir() {
        return Err(AppError::runtime(format!(
            "audit target does not exist: {}",
            display_path(path)
        )));
    }
    for entry in fs::read_dir(path).map_err(|error| {
        AppError::runtime(format!("cannot read {}: {error}", display_path(path)))
    })? {
        let entry = entry
            .map_err(|error| AppError::runtime(format!("cannot read directory entry: {error}")))?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let child = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            AppError::runtime(format!("cannot inspect {}: {error}", display_path(&child)))
        })?;
        if file_type.is_file() && (is_supported_image(&child) || is_zip(&child)) {
            out.push(child);
        } else if recursive && file_type.is_dir() {
            collect_targets(&child, true, out)?;
        }
    }
    Ok(())
}

fn is_supported_image(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "png" | "jpg" | "jpeg"))
}

fn is_zip(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("zip"))
}

fn normalize_sha256(value: &str) -> AppResult<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::runtime(
            "expected SHA-256 must contain exactly 64 hexadecimal characters",
        ));
    }
    Ok(normalized)
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn valid_invalid(value: bool) -> &'static str {
    if value { "valid" } else { "invalid" }
}

#[cfg(test)]
mod tests {
    use image::{ImageBuffer, Rgba};

    use super::*;

    #[test]
    fn sha256_validation_is_strict() {
        assert!(normalize_sha256(&"A".repeat(64)).is_ok());
        assert!(normalize_sha256("abc").is_err());
        assert!(normalize_sha256(&"g".repeat(64)).is_err());
    }

    #[test]
    fn missing_credential_and_hash_mismatch_are_distinct_failures() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("plain.banksy-signed.png");
        ImageBuffer::from_pixel(2, 2, Rgba([1_u8, 2, 3, 255]))
            .save(&path)
            .unwrap();

        let missing = audit_image(&path, None, None).unwrap();
        assert_eq!(missing.state, AuditState::MissingCredential);
        assert!(!missing.container.embedded);
        assert!(missing.detail.contains("stripped or replaced"));

        let mismatch = audit_image(&path, None, Some(&"0".repeat(64))).unwrap();
        assert_eq!(mismatch.state, AuditState::HashMismatch);
        assert_eq!(mismatch.hash_matches, Some(false));
    }
}
