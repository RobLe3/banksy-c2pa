use std::{fmt, path::Path};

use c2pa::{Context, Reader, assertions::Actions, validation_results::ValidationState};
use serde::Serialize;
use serde_json::json;

use crate::{
    display_path,
    error::{AppError, AppResult},
    image_info::{ImageInfo, inspect_image},
};

#[derive(Debug, Clone, Serialize)]
pub struct IngredientReport {
    pub title: Option<String>,
    pub format: Option<String>,
    pub relationship: String,
    pub active_manifest: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct C2paReport {
    pub present: bool,
    pub active_manifest: Option<String>,
    pub claim_version: Option<u8>,
    pub claim_generator: Option<String>,
    pub actions: Vec<String>,
    pub all_actions_included: Option<bool>,
    pub ingredients: Vec<IngredientReport>,
    pub manifest_count: usize,
    pub existing_parent_chain_depth: usize,
    pub signer_common_name: Option<String>,
    pub signer_issuer: Option<String>,
    pub signature_time: Option<String>,
    pub validation_state: String,
    pub validation_failures: Vec<String>,
    pub timestamp_trusted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectionReport {
    pub status: &'static str,
    pub file: ImageInfo,
    pub c2pa: C2paReport,
}

impl fmt::Display for InspectionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "File\n  {}", self.file.path)?;
        writeln!(f, "\nFormat\n  {}", self.file.format)?;
        writeln!(f, "\nDimensions\n  {}", self.file.dimensions())?;
        writeln!(f, "\nFile SHA-256\n  {}", self.file.file_sha256)?;
        writeln!(f, "\nPixel SHA-256\n  {}", self.file.pixel_sha256)?;
        if !self.c2pa.present {
            return write!(f, "\nC2PA\n  no embedded manifest");
        }

        writeln!(
            f,
            "\nC2PA active manifest\n  {}",
            self.c2pa.active_manifest.as_deref().unwrap_or("unknown")
        )?;
        writeln!(
            f,
            "\nClaim generator\n  {}",
            self.c2pa
                .claim_generator
                .as_deref()
                .unwrap_or("not reported")
        )?;
        writeln!(
            f,
            "\nSigner\n  {}",
            self.c2pa
                .signer_common_name
                .as_deref()
                .unwrap_or("not reported")
        )?;
        writeln!(
            f,
            "\nActions\n  {}",
            if self.c2pa.actions.is_empty() {
                "none reported".into()
            } else {
                self.c2pa.actions.join(", ")
            }
        )?;
        writeln!(f, "\nIngredients\n  {}", self.c2pa.ingredients.len())?;
        writeln!(f, "\nValidation\n  {}", self.c2pa.validation_state)?;
        write!(
            f,
            "\nPublic C2PA trust\n  not evaluated by this offline, local-trust tool"
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub status: &'static str,
    pub file: String,
    pub manifest_present: bool,
    pub signature_valid: bool,
    pub certificate_chain_valid: bool,
    pub validation_state: String,
    pub validation_failures: Vec<String>,
    pub local_trust_requested: bool,
    pub local_trust: bool,
    pub public_trust: bool,
    pub public_trust_status: &'static str,
    pub timestamp_trusted: bool,
}

impl fmt::Display for VerifyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "C2PA manifest\n  {}", yes_no(self.manifest_present))?;
        writeln!(
            f,
            "\nClaim signature and asset binding\n  {}",
            if self.signature_valid {
                "valid"
            } else {
                "invalid"
            }
        )?;
        writeln!(
            f,
            "\nCertificate chain\n  {}",
            if self.certificate_chain_valid {
                "cryptographically valid"
            } else {
                "invalid or unavailable"
            }
        )?;
        if self.local_trust_requested {
            writeln!(
                f,
                "\nLocal trust\n  {}",
                if self.local_trust {
                    "valid against the configured private root"
                } else {
                    "not established"
                }
            )?;
        } else {
            writeln!(f, "\nLocal trust\n  not requested")?;
        }
        writeln!(f, "\nPublic C2PA trust\n  not claimed or established")?;
        writeln!(
            f,
            "\nTrusted RFC 3161 timestamp\n  {}",
            yes_no(self.timestamp_trusted)
        )?;
        if !self.validation_failures.is_empty() {
            writeln!(f, "\nValidation failures")?;
            for failure in &self.validation_failures {
                writeln!(f, "  - {failure}")?;
            }
        }
        Ok(())
    }
}

pub fn inspect_asset(path: &Path, local_root_pem: Option<&str>) -> AppResult<InspectionReport> {
    let file = inspect_image(path)?;
    let c2pa = load_c2pa_report(path, local_root_pem)?;
    Ok(InspectionReport {
        status: "ok",
        file,
        c2pa,
    })
}

pub fn verify_asset(
    path: &Path,
    local_root_pem: Option<&str>,
    local_trust_requested: bool,
) -> AppResult<VerifyReport> {
    // Decode first so a malformed or unsupported image cannot pass only because
    // it happens to contain recognizable metadata bytes.
    inspect_image(path)?;
    let c2pa = load_c2pa_report(path, local_root_pem)?;
    let signature_valid = c2pa.present && c2pa.validation_state != "invalid";
    let local_trust = local_trust_requested && c2pa.validation_state == "trusted";

    Ok(VerifyReport {
        status: if signature_valid { "ok" } else { "invalid" },
        file: display_path(path),
        manifest_present: c2pa.present,
        signature_valid,
        certificate_chain_valid: signature_valid,
        validation_state: c2pa.validation_state,
        validation_failures: c2pa.validation_failures,
        local_trust_requested,
        local_trust,
        public_trust: false,
        public_trust_status: "not-established-offline",
        timestamp_trusted: c2pa.timestamp_trusted,
    })
}

pub(crate) fn load_c2pa_report(path: &Path, local_root_pem: Option<&str>) -> AppResult<C2paReport> {
    let mut settings = json!({
        "core": { "allowed_network_hosts": [] },
        "verify": { "verify_trust": true }
    });
    if let Some(root) = local_root_pem {
        settings["trust"] = json!({ "user_anchors": root });
    }
    let context = Context::new()
        .with_settings(settings)
        .map_err(|e| AppError::runtime(format!("cannot configure the C2PA validator: {e}")))?;
    let reader = match Reader::from_context(context).with_file(path) {
        Ok(reader) => reader,
        Err(c2pa::Error::JumbfNotFound) => return Ok(no_manifest_report()),
        Err(error) => {
            return Err(AppError::verification(format!(
                "cannot read C2PA provenance from {}: {error}",
                display_path(path)
            )));
        }
    };

    let state = reader.validation_state();
    let manifest = reader.active_manifest();
    let actions_assertion = manifest.and_then(|m| m.find_assertion::<Actions>(Actions::LABEL).ok());
    let actions = actions_assertion
        .as_ref()
        .map(|a| a.actions().iter().map(|a| a.action().to_owned()).collect())
        .unwrap_or_default();
    let ingredients = manifest
        .map(|m| {
            m.ingredients()
                .iter()
                .map(|i| IngredientReport {
                    title: i.title().map(str::to_owned),
                    format: i.format().map(str::to_owned),
                    relationship: i.relationship().as_str().to_owned(),
                    active_manifest: i.active_manifest().map(str::to_owned),
                })
                .collect()
        })
        .unwrap_or_default();
    let validation_failures = failures(&reader);
    let timestamp_trusted = status_codes(&reader)
        .iter()
        .any(|code| code == "timeStamp.trusted");
    let manifest_count = reader.manifests().len();
    let generator = manifest.and_then(|m| {
        m.claim_generator_info
            .as_ref()
            .and_then(|values| values.first())
            .map(|info| {
                if let Some(version) = &info.version {
                    format!("{} {version}", info.name)
                } else {
                    info.name.clone()
                }
            })
            .or_else(|| m.claim_generator().map(str::to_owned))
    });

    Ok(C2paReport {
        present: manifest.is_some(),
        active_manifest: reader.active_label().map(str::to_owned),
        claim_version: manifest.and_then(|m| m.claim_version()),
        claim_generator: generator,
        actions,
        all_actions_included: actions_assertion.and_then(|a| a.all_actions_included),
        ingredients,
        manifest_count,
        existing_parent_chain_depth: manifest_count.saturating_sub(1),
        signer_common_name: manifest.and_then(|m| m.common_name()),
        signer_issuer: manifest.and_then(|m| m.issuer()),
        signature_time: manifest.and_then(|m| m.time()),
        validation_state: state_name(state).into(),
        validation_failures,
        timestamp_trusted,
    })
}

fn status_codes(reader: &Reader) -> Vec<String> {
    let mut codes = Vec::new();
    if let Some(results) = reader.validation_results()
        && let Some(active) = results.active_manifest()
    {
        codes.extend(active.success().iter().map(|s| s.code().to_owned()));
        codes.extend(active.informational().iter().map(|s| s.code().to_owned()));
        codes.extend(active.failure().iter().map(|s| s.code().to_owned()));
    }
    if let Some(legacy) = reader.validation_status() {
        codes.extend(legacy.iter().map(|s| s.code().to_owned()));
    }
    codes
}

fn failures(reader: &Reader) -> Vec<String> {
    let mut failures = Vec::new();
    if let Some(results) = reader.validation_results()
        && let Some(active) = results.active_manifest()
    {
        failures.extend(active.failure().iter().map(format_status));
    }
    if let Some(legacy) = reader.validation_status() {
        failures.extend(legacy.iter().filter(|s| !s.passed()).map(format_status));
    }
    failures.sort();
    failures.dedup();
    failures
}

fn format_status(status: &c2pa::validation_status::ValidationStatus) -> String {
    status
        .explanation()
        .map(|e| format!("{}: {e}", status.code()))
        .unwrap_or_else(|| status.code().to_owned())
}

fn no_manifest_report() -> C2paReport {
    C2paReport {
        present: false,
        active_manifest: None,
        claim_version: None,
        claim_generator: None,
        actions: Vec::new(),
        all_actions_included: None,
        ingredients: Vec::new(),
        manifest_count: 0,
        existing_parent_chain_depth: 0,
        signer_common_name: None,
        signer_issuer: None,
        signature_time: None,
        validation_state: "absent".into(),
        validation_failures: Vec::new(),
        timestamp_trusted: false,
    }
}

fn state_name(state: ValidationState) -> &'static str {
    match state {
        ValidationState::Invalid => "invalid",
        ValidationState::Valid => "valid",
        ValidationState::Trusted => "trusted",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
