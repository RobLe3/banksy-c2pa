use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use c2pa::{
    Builder, BuilderIntent, ClaimGeneratorInfo, Context,
    assertions::{Action, Actions, c2pa_action},
    create_signer,
};
use serde::Serialize;
use serde_json::json;
use tempfile::Builder as TempBuilder;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::{
    config::{AppPaths, Profile},
    container::{ContainerCredentialReport, inspect_container},
    display_path,
    error::{AppError, AppResult},
    image_info::{extension_for_mime, file_sha256, mime_for_path, pixels_equal},
    keychain,
    provenance::{InspectionReport, inspect_asset, verify_asset},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignMode {
    Attest,
    Derivative,
}

impl SignMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Attest => "attest",
            Self::Derivative => "derivative",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SigningIdentityReport {
    pub claim_generator: &'static str,
    pub signer_name: String,
    pub organization: Option<String>,
    pub domain: Option<String>,
    pub uri: Option<String>,
    pub vendor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SigningValidationReport {
    pub signature_valid: bool,
    pub certificate_chain_valid: bool,
    pub local_trust: bool,
    pub public_trust: bool,
    pub public_trust_status: &'static str,
    pub trusted_timestamp: bool,
    pub embedded: bool,
    pub credential_location: &'static str,
    pub credential_bytes: u64,
    pub manifest_count: usize,
    pub upstream_manifest_count: usize,
    pub upstream_preserved: bool,
    pub post_commit_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct SigningReport {
    pub status: &'static str,
    pub mode: &'static str,
    pub input: String,
    pub parent: Option<String>,
    pub output: String,
    pub output_sha256: String,
    pub description: String,
    pub pixels_changed_from_parent: Option<bool>,
    pub output_pixels_equal_input: bool,
    pub parent_relationship: &'static str,
    pub upstream_provenance: &'static str,
    pub actions: Vec<String>,
    pub identity: SigningIdentityReport,
    pub c2pa: SigningValidationReport,
    pub key_authentication: &'static str,
}

impl fmt::Display for SigningReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Signed successfully")?;
        writeln!(f, "\nMode\n  {}", self.mode)?;
        writeln!(f, "\nClaim generator\n  {}", self.identity.claim_generator)?;
        writeln!(f, "\nSigner name\n  {}", self.identity.signer_name)?;
        writeln!(
            f,
            "\nOrganization\n  {}",
            display_optional(&self.identity.organization)
        )?;
        writeln!(
            f,
            "\nIdentity URI\n  {}",
            display_optional(&self.identity.uri)
        )?;
        writeln!(f, "\nEditorial description\n  {}", self.description)?;
        writeln!(f, "\nActions\n  {}", self.actions.join(", "))?;
        writeln!(
            f,
            "\nOutput pixels equal input\n  {}",
            yes_no(self.output_pixels_equal_input)
        )?;
        if let Some(changed) = self.pixels_changed_from_parent {
            writeln!(f, "\nPixels differ from parent\n  {}", yes_no(changed))?;
        }
        writeln!(f, "\nParent provenance\n  {}", self.upstream_provenance)?;
        writeln!(
            f,
            "\nEmbedded credential\n  {}",
            self.c2pa.credential_location
        )?;
        writeln!(
            f,
            "\nManifest store bytes\n  {}",
            self.c2pa.credential_bytes
        )?;
        writeln!(f, "\nManifest count\n  {}", self.c2pa.manifest_count)?;
        writeln!(
            f,
            "\nUpstream manifests preserved\n  {}",
            yes_no(self.c2pa.upstream_preserved)
        )?;
        writeln!(f, "\nC2PA claim signature and asset binding\n  valid")?;
        writeln!(f, "\nSigning credential\n  locally valid")?;
        writeln!(f, "\nPublic C2PA trust\n  not established")?;
        writeln!(
            f,
            "\nTimestamp\n  local claim time; RFC 3161 TSA not configured"
        )?;
        writeln!(f, "\nPost-commit verification\n  passed")?;
        writeln!(f, "\nOutput SHA-256\n  {}", self.output_sha256)?;
        write!(f, "\nOutput\n  {}", self.output)
    }
}

struct SigningMaterial {
    certificate_pem: String,
    key_pem: Zeroizing<Vec<u8>>,
    root_certificate_pem: String,
}

/// Holds one authenticated signing-key retrieval for one CLI process.
/// Dropping the session zeroizes the PKCS#8 retrieval buffer.
pub struct SigningSession {
    material: SigningMaterial,
}

impl SigningSession {
    pub fn open(paths: &AppPaths, profile: &Profile) -> AppResult<Self> {
        Ok(Self {
            material: load_signing_material(paths, profile)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn attest(
        &self,
        profile: &Profile,
        input: &Path,
        output: &Path,
        description: Option<&str>,
        published: bool,
        force: bool,
    ) -> AppResult<SigningReport> {
        let source = preflight_attest(input, output, force)?;
        self.attest_with_source(
            profile,
            input,
            output,
            description,
            published,
            force,
            &source,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn attest_with_source(
        &self,
        profile: &Profile,
        input: &Path,
        output: &Path,
        description: Option<&str>,
        published: bool,
        force: bool,
        source: &InspectionReport,
    ) -> AppResult<SigningReport> {
        let description = description.unwrap_or(&profile.manifest.attest_description);
        sign_core(
            profile,
            SignMode::Attest,
            None,
            input,
            output,
            description,
            published,
            force,
            source,
            &self.material,
        )
    }
}

pub fn default_output_path(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new(""));
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".into());
    match input.extension() {
        Some(extension) => parent.join(format!(
            "{stem}.banksy-signed.{}",
            extension.to_string_lossy()
        )),
        None => parent.join(format!("{stem}.banksy-signed")),
    }
}

pub fn attest(
    paths: &AppPaths,
    profile: &Profile,
    input: &Path,
    output: &Path,
    description: Option<&str>,
    published: bool,
    force: bool,
) -> AppResult<SigningReport> {
    let source = preflight_attest(input, output, force)?;
    SigningSession::open(paths, profile)?.attest_with_source(
        profile,
        input,
        output,
        description,
        published,
        force,
        &source,
    )
}

/// Performs every deterministic attestation check that can run before a
/// protected signing key is requested.
pub fn preflight_attest(input: &Path, output: &Path, force: bool) -> AppResult<InspectionReport> {
    preflight_output(input, None, output, force)?;
    let source = inspect_asset(input, None)?;
    reject_invalid_existing_provenance(&source, "input")?;
    let mime = mime_for_path(input)?;
    validate_output_extension(output, mime)?;
    validate_output_directory(output)?;
    Ok(source)
}

#[allow(clippy::too_many_arguments)]
pub fn derivative(
    paths: &AppPaths,
    profile: &Profile,
    parent: &Path,
    input: &Path,
    output: &Path,
    description: Option<&str>,
    published: bool,
    force: bool,
) -> AppResult<SigningReport> {
    preflight_output(input, Some(parent), output, force)?;
    let parent_report = inspect_asset(parent, None)?;
    reject_invalid_existing_provenance(&parent_report, "parent")?;
    let input_report = inspect_asset(input, None)?;
    if input_report.c2pa.present {
        return Err(AppError::verification(
            "the derivative input already has an active C2PA manifest. Refusing to create an ambiguous second parent chain; use that signed asset as --parent or provide the unsigned edited result",
        ));
    }
    if pixels_equal(parent, input)? {
        return Err(AppError::verification(
            "parent and derivative pixels are identical. Use `attest` instead",
        ));
    }

    let material = load_signing_material(paths, profile)?;
    let description = description.unwrap_or(&profile.manifest.default_description);
    sign_core(
        profile,
        SignMode::Derivative,
        Some(parent),
        input,
        output,
        description,
        published,
        force,
        &parent_report,
        &material,
    )
}

#[allow(clippy::too_many_arguments)]
fn sign_core(
    profile: &Profile,
    mode: SignMode,
    parent: Option<&Path>,
    input: &Path,
    output: &Path,
    description: &str,
    published: bool,
    force: bool,
    provenance_source: &InspectionReport,
    material: &SigningMaterial,
) -> AppResult<SigningReport> {
    let mime = mime_for_path(input)?;
    validate_output_extension(output, mime)?;

    let context = Context::new()
        .with_settings(json!({
            "core": { "allowed_network_hosts": [] },
            "verify": { "verify_after_sign": false, "verify_trust": true }
        }))
        .map_err(|e| AppError::runtime(format!("cannot configure C2PA signing: {e}")))?;

    let title = input
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".into());
    let mut definition = json!({
        "claim_version": 2,
        "title": title,
        "format": mime,
        "hash_alg": "sha256"
    });
    if let Some(vendor) = &profile.identity.vendor {
        definition["vendor"] = json!(vendor);
    }
    let mut builder = Builder::from_context(context)
        .with_definition(definition)
        .map_err(|e| AppError::runtime(format!("cannot create C2PA manifest definition: {e}")))?;

    let mut generator = ClaimGeneratorInfo::new("banksy-c2pa");
    generator.set_version(env!("CARGO_PKG_VERSION"));
    generator.operating_system = Some(format!("macOS {}", macos_version()));
    generator.insert("specVersion", "2.4.0");
    if let Some(domain) = &profile.identity.domain {
        generator.insert("com.roblemumin.banksy-c2pa.domain", domain.clone());
    }
    if let Some(uri) = &profile.identity.uri {
        generator.insert("com.roblemumin.banksy-c2pa.uri", uri.clone());
    }
    builder.set_claim_generator_info(generator);

    let action_time = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string());
    let primary_action = match mode {
        SignMode::Attest => Action::new("c2pa.edited.metadata"),
        SignMode::Derivative => Action::new(c2pa_action::EDITED),
    }
    .set_when(action_time.clone())
    .set_description(description);
    let mut actions = Actions::new().add_action(primary_action);
    actions.all_actions_included = Some(false);
    if published {
        actions = actions.add_action(Action::new(c2pa_action::PUBLISHED).set_when(action_time));
    }
    builder
        .add_assertion(Actions::LABEL_VERSIONED, &actions)
        .map_err(|e| AppError::runtime(format!("cannot add C2PA actions: {e}")))?;

    match mode {
        SignMode::Attest => {
            if provenance_source.c2pa.present {
                builder.set_intent(BuilderIntent::Update);
            } else {
                builder.set_intent(BuilderIntent::Edit);
            }
        }
        SignMode::Derivative => {
            builder.set_intent(BuilderIntent::Edit);
            let parent = parent.expect("derivative mode has a parent");
            let parent_mime = mime_for_path(parent)?;
            let mut parent_file = fs::File::open(parent).map_err(|e| {
                AppError::runtime(format!("cannot open parent {}: {e}", display_path(parent)))
            })?;
            let parent_title = parent
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "parent".into());
            builder
                .add_ingredient_from_stream(
                    json!({
                        "title": parent_title,
                        "relationship": "parentOf"
                    })
                    .to_string(),
                    parent_mime,
                    &mut parent_file,
                )
                .map_err(|e| {
                    AppError::verification(format!(
                        "cannot preserve parent provenance from {}: {e}",
                        display_path(parent)
                    ))
                })?;
        }
    }

    let signer = create_signer::from_keys(
        material.certificate_pem.as_bytes(),
        &material.key_pem,
        c2pa::SigningAlg::Es256,
        None,
    )
    .map_err(|e| AppError::runtime(format!("cannot initialize the ES256 C2PA signer: {e}")))?;

    let output_dir = output_directory(output);
    let suffix = format!(".{}", extension_for_mime(mime));
    let temp_dir = TempBuilder::new()
        .prefix(".banksy-c2pa-")
        .tempdir_in(output_dir)
        .map_err(|e| {
            AppError::runtime(format!(
                "cannot create a temporary output in {}: {e}",
                display_path(output_dir)
            ))
        })?;
    let temp_path = temp_dir.path().join(format!("signed{suffix}"));

    builder
        .sign_file(signer.as_ref(), input, &temp_path)
        .map_err(|e| AppError::runtime(format!("C2PA signing failed: {e}")))?;
    fs::File::open(&temp_path)
        .map_err(|e| AppError::runtime(format!("cannot reopen temporary output: {e}")))?
        .sync_all()
        .map_err(|e| AppError::runtime(format!("cannot sync temporary output: {e}")))?;

    if !pixels_equal(input, &temp_path)? {
        return Err(AppError::verification(
            "C2PA embedding changed decoded pixels; output was not committed",
        ));
    }

    let validation = verify_asset(&temp_path, Some(&material.root_certificate_pem), true)?;
    if !validation.signature_valid || !validation.local_trust {
        return Err(AppError::verification(format!(
            "C2PA manifest validation failed after write; output was not committed ({}){}",
            validation.validation_state,
            if validation.validation_failures.is_empty() {
                String::new()
            } else {
                format!(": {}", validation.validation_failures.join(", "))
            }
        )));
    }
    let signed_inspection = inspect_asset(&temp_path, Some(&material.root_certificate_pem))?;
    validate_signed_semantics(mode, &signed_inspection, published)?;
    validate_upstream_semantics(provenance_source, &signed_inspection)?;
    let container = inspect_container(&temp_path)?;
    require_generated_embedding(&container)?;
    let temp_sha256 = file_sha256(&temp_path)?;

    if force {
        fs::rename(&temp_path, output).map_err(|e| {
            AppError::runtime(format!(
                "cannot atomically replace {}: {e}",
                display_path(output),
            ))
        })?;
    } else {
        // This creates the destination name atomically and refuses to replace
        // a path that appeared after the preflight check. The temporary file
        // is in the destination directory, so both names share a filesystem.
        fs::hard_link(&temp_path, output).map_err(|e| {
            AppError::runtime(format!(
                "cannot commit {} without replacing it: {e}",
                display_path(output),
            ))
        })?;
    }

    let output_sha256 = file_sha256(output)?;
    if output_sha256 != temp_sha256 {
        return Err(AppError::verification(
            "committed output SHA-256 differs from the validated temporary output",
        ));
    }
    let committed_container = inspect_container(output)?;
    require_generated_embedding(&committed_container)?;
    let committed_validation = verify_asset(output, Some(&material.root_certificate_pem), true)?;
    if !committed_validation.signature_valid || !committed_validation.local_trust {
        return Err(AppError::verification(
            "committed output failed local C2PA signature validation",
        ));
    }
    let committed_inspection = inspect_asset(output, Some(&material.root_certificate_pem))?;
    validate_signed_semantics(mode, &committed_inspection, published)?;
    validate_upstream_semantics(provenance_source, &committed_inspection)?;
    let upstream_preserved = upstream_is_preserved(provenance_source, &committed_inspection);

    let mut report_actions = vec!["c2pa.opened".to_string()];
    report_actions.push(match mode {
        SignMode::Attest => "c2pa.edited.metadata".into(),
        SignMode::Derivative => "c2pa.edited".into(),
    });
    if published {
        report_actions.push("c2pa.published".into());
    }

    Ok(SigningReport {
        status: "ok",
        mode: mode.as_str(),
        input: display_path(input),
        parent: parent.map(display_path),
        output: display_path(output),
        output_sha256,
        description: description.into(),
        pixels_changed_from_parent: parent.map(|_| true),
        output_pixels_equal_input: true,
        parent_relationship: "parentOf",
        upstream_provenance: if provenance_source.c2pa.present {
            "preserved and reachable through the parent ingredient"
        } else {
            "source recorded as a parent ingredient; no upstream manifest was present"
        },
        actions: report_actions,
        identity: SigningIdentityReport {
            claim_generator: "banksy-c2pa",
            signer_name: profile.identity.signer_name.clone(),
            organization: profile.identity.organization.clone(),
            domain: profile.identity.domain.clone(),
            uri: profile.identity.uri.clone(),
            vendor: profile.identity.vendor.clone(),
        },
        c2pa: SigningValidationReport {
            signature_valid: true,
            certificate_chain_valid: true,
            local_trust: true,
            public_trust: false,
            public_trust_status: "not-established",
            trusted_timestamp: false,
            embedded: true,
            credential_location: committed_container.location,
            credential_bytes: committed_container.store_bytes,
            manifest_count: committed_inspection.c2pa.manifest_count,
            upstream_manifest_count: provenance_source.c2pa.manifest_count,
            upstream_preserved,
            post_commit_verified: true,
        },
        key_authentication: profile
            .credential
            .keychain_backend
            .authentication_description(),
    })
}

fn load_signing_material(paths: &AppPaths, profile: &Profile) -> AppResult<SigningMaterial> {
    let account = profile
        .credential
        .active_signer_key_account
        .as_deref()
        .ok_or_else(|| AppError::runtime("no active signer key; run `banksy-c2pa init`"))?;
    let certificate_path = paths.signer_certificate(profile)?;
    let certificate_pem = fs::read_to_string(&certificate_path).map_err(|e| {
        AppError::runtime(format!("cannot read {}: {e}", certificate_path.display()))
    })?;
    let root_path = paths.root_certificate(profile);
    let root_certificate_pem = fs::read_to_string(&root_path)
        .map_err(|e| AppError::runtime(format!("cannot read {}: {e}", root_path.display())))?;
    // This is the only signer-secret retrieval in a signing command.
    let key_pem = keychain::retrieve_secret(
        profile.credential.keychain_backend,
        &profile.credential.keychain_service,
        account,
    )?;
    Ok(SigningMaterial {
        certificate_pem,
        key_pem,
        root_certificate_pem,
    })
}

fn reject_invalid_existing_provenance(report: &InspectionReport, role: &str) -> AppResult<()> {
    if report.c2pa.present && report.c2pa.validation_state == "invalid" {
        return Err(AppError::verification(format!(
            "{role} has invalid C2PA provenance; refusing to extend a broken chain"
        )));
    }
    Ok(())
}

fn validate_signed_semantics(
    mode: SignMode,
    report: &InspectionReport,
    published: bool,
) -> AppResult<()> {
    if !report.c2pa.present || report.c2pa.validation_state == "invalid" {
        return Err(AppError::verification(
            "the temporary output has no valid active C2PA manifest",
        ));
    }
    let expected = match mode {
        SignMode::Attest => "c2pa.edited.metadata",
        SignMode::Derivative => "c2pa.edited",
    };
    if !report.c2pa.actions.iter().any(|action| action == expected)
        || !report
            .c2pa
            .actions
            .iter()
            .any(|action| action == "c2pa.opened")
    {
        return Err(AppError::verification(format!(
            "the temporary output is missing required {mode:?} actions"
        )));
    }
    if mode == SignMode::Attest
        && report
            .c2pa
            .actions
            .iter()
            .any(|action| action == "c2pa.edited")
    {
        return Err(AppError::verification(
            "attestation output falsely contains c2pa.edited",
        ));
    }
    if published
        != report
            .c2pa
            .actions
            .iter()
            .any(|action| action == "c2pa.published")
    {
        return Err(AppError::verification(
            "publication action in temporary output does not match the request",
        ));
    }
    if !report
        .c2pa
        .ingredients
        .iter()
        .any(|ingredient| ingredient.relationship == "parentOf")
    {
        return Err(AppError::verification(
            "the temporary output is missing its parentOf ingredient",
        ));
    }
    Ok(())
}

fn validate_upstream_semantics(
    source: &InspectionReport,
    signed: &InspectionReport,
) -> AppResult<()> {
    let expected_count = source.c2pa.manifest_count.saturating_add(1);
    if signed.c2pa.manifest_count != expected_count {
        return Err(AppError::verification(format!(
            "signed output has {} manifests; expected {expected_count} after preserving {} upstream manifests",
            signed.c2pa.manifest_count, source.c2pa.manifest_count
        )));
    }
    let parent_is_linked = match source.c2pa.active_manifest.as_deref() {
        Some(active) => signed.c2pa.ingredients.iter().any(|ingredient| {
            ingredient.relationship == "parentOf"
                && ingredient.active_manifest.as_deref() == Some(active)
        }),
        None => signed
            .c2pa
            .ingredients
            .iter()
            .any(|ingredient| ingredient.relationship == "parentOf"),
    };
    if !parent_is_linked {
        return Err(AppError::verification(
            "signed output does not reference the source active manifest as its parent ingredient",
        ));
    }
    Ok(())
}

fn upstream_is_preserved(source: &InspectionReport, signed: &InspectionReport) -> bool {
    match source.c2pa.active_manifest.as_deref() {
        Some(active) => signed.c2pa.ingredients.iter().any(|ingredient| {
            ingredient.relationship == "parentOf"
                && ingredient.active_manifest.as_deref() == Some(active)
        }),
        None => false,
    }
}

fn require_generated_embedding(container: &ContainerCredentialReport) -> AppResult<()> {
    if container.valid_generated_embedding() {
        return Ok(());
    }
    let detail = if container.issues.is_empty() {
        format!(
            "expected exactly one {} credential before image data",
            container.location
        )
    } else {
        container.issues.join("; ")
    };
    Err(AppError::verification(format!(
        "output container credential validation failed: {detail}"
    )))
}

fn preflight_output(
    input: &Path,
    parent: Option<&Path>,
    output: &Path,
    force: bool,
) -> AppResult<()> {
    if !input.is_file() {
        return Err(AppError::runtime(format!(
            "input is not a regular file: {}",
            display_path(input)
        )));
    }
    if let Some(parent) = parent
        && !parent.is_file()
    {
        return Err(AppError::runtime(format!(
            "parent is not a regular file: {}",
            display_path(parent)
        )));
    }
    let overwrites_parent = match parent {
        Some(parent) => paths_equivalent(parent, output)?,
        None => false,
    };
    if paths_equivalent(input, output)? || overwrites_parent {
        return Err(AppError::runtime(
            "refusing to overwrite an input or parent asset; choose a separate output path",
        ));
    }
    if output.exists() && !force {
        return Err(AppError::runtime(format!(
            "existing output file found: {}. Use --force to replace it",
            display_path(output)
        )));
    }
    Ok(())
}

fn paths_equivalent(left: &Path, right: &Path) -> AppResult<bool> {
    if left == right {
        return Ok(true);
    }
    let absolute = |path: &Path| -> AppResult<PathBuf> {
        if path.is_absolute() {
            Ok(path.to_path_buf())
        } else {
            Ok(std::env::current_dir()
                .map_err(|e| AppError::runtime(format!("cannot read current directory: {e}")))?
                .join(path))
        }
    };
    let left = absolute(left)?;
    let right = absolute(right)?;
    if left == right {
        return Ok(true);
    }
    if left.exists() && right.exists() {
        return Ok(left.canonicalize().ok() == right.canonicalize().ok());
    }
    Ok(false)
}

fn validate_output_extension(output: &Path, input_mime: &str) -> AppResult<()> {
    let extension = output
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let valid = match input_mime {
        "image/png" => extension == "png",
        "image/jpeg" => matches!(extension.as_str(), "jpg" | "jpeg"),
        _ => false,
    };
    if !valid {
        return Err(AppError::runtime(format!(
            "output extension must match the source format {input_mime}"
        )));
    }
    Ok(())
}

fn output_directory(output: &Path) -> &Path {
    output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn validate_output_directory(output: &Path) -> AppResult<()> {
    let output_dir = output_directory(output);
    if !output_dir.is_dir() {
        return Err(AppError::runtime(format!(
            "output directory does not exist: {}",
            display_path(output_dir)
        )));
    }
    Ok(())
}

fn macos_version() -> String {
    std::process::Command::new("sw_vers")
        .args(["-productVersion"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn display_optional(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("not configured")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::atomic_write, pki::generate_hierarchy};
    use image::{ImageBuffer, Rgba};

    fn image(path: &Path, color: [u8; 4]) {
        ImageBuffer::from_pixel(4, 3, Rgba(color))
            .save(path)
            .unwrap();
    }

    fn material(profile: &Profile) -> SigningMaterial {
        let generated = generate_hierarchy(profile).unwrap();
        SigningMaterial {
            certificate_pem: generated.signer_certificate_pem,
            key_pem: generated.signer_key_pem,
            root_certificate_pem: generated.root_certificate_pem,
        }
    }

    #[test]
    fn default_name_preserves_extension() {
        assert_eq!(
            default_output_path(Path::new("photo.jpeg")),
            PathBuf::from("photo.banksy-signed.jpeg")
        );
    }

    #[test]
    fn attest_signs_without_a_content_edit_claim() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.png");
        let output = dir.path().join("signed.png");
        image(&input, [10, 20, 30, 255]);
        let profile = Profile::default();
        let source = inspect_asset(&input, None).unwrap();
        let report = sign_core(
            &profile,
            SignMode::Attest,
            None,
            &input,
            &output,
            "Editorial / publication attestation",
            false,
            false,
            &source,
            &material(&profile),
        )
        .unwrap();

        assert!(report.output_pixels_equal_input);
        assert_eq!(report.identity.claim_generator, "banksy-c2pa");
        assert_eq!(report.identity.organization, None);
        assert_eq!(report.identity.domain, None);
        let report_json = serde_json::to_value(&report).unwrap();
        assert!(report_json["identity"]["organization"].is_null());
        assert!(report_json["identity"]["domain"].is_null());
        assert!(report.c2pa.embedded);
        assert_eq!(report.c2pa.credential_location, "PNG caBX");
        assert!(report.c2pa.credential_bytes > 0);
        assert_eq!(report.c2pa.manifest_count, 1);
        assert_eq!(report.c2pa.upstream_manifest_count, 0);
        assert!(!report.c2pa.upstream_preserved);
        assert!(report.c2pa.post_commit_verified);
        assert_eq!(report.output_sha256, file_sha256(&output).unwrap());
        let inspected = inspect_asset(&output, None).unwrap();
        assert_eq!(
            inspected.c2pa.claim_generator.as_deref(),
            Some(concat!("banksy-c2pa ", env!("CARGO_PKG_VERSION")))
        );
        let untrusted = verify_asset(&output, None, false).unwrap();
        assert!(untrusted.signature_valid);
        assert!(!untrusted.local_trust);
        assert!(!untrusted.public_trust);
        assert!(inspected.c2pa.actions.contains(&"c2pa.opened".into()));
        assert!(
            inspected
                .c2pa
                .actions
                .contains(&"c2pa.edited.metadata".into())
        );
        assert!(!inspected.c2pa.actions.contains(&"c2pa.edited".into()));
    }

    #[test]
    fn status_recognizes_a_local_signed_copy_and_covered_original() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.png");
        let output = default_output_path(&input);
        image(&input, [10, 20, 30, 255]);
        let profile = Profile::default();
        let material = material(&profile);
        let source = inspect_asset(&input, None).unwrap();
        sign_core(
            &profile,
            SignMode::Attest,
            None,
            &input,
            &output,
            "Attestation",
            false,
            false,
            &source,
            &material,
        )
        .unwrap();

        let status = crate::scan::scan_paths(
            &[dir.path().to_path_buf()],
            false,
            Some(&material.root_certificate_pem),
        )
        .unwrap();
        assert_eq!(status.summary.total, 2);
        assert_eq!(status.summary.covered, 1);
        assert_eq!(status.summary.signed_local, 1);
        assert_eq!(status.summary.needs_signing, 0);
    }

    #[test]
    fn batch_rerun_skips_covered_and_local_files_without_key_access() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.png");
        let output = default_output_path(&input);
        image(&input, [10, 20, 30, 255]);
        let profile = Profile::default();
        let material = material(&profile);
        let source = inspect_asset(&input, None).unwrap();
        sign_core(
            &profile,
            SignMode::Attest,
            None,
            &input,
            &output,
            "Attestation",
            false,
            false,
            &source,
            &material,
        )
        .unwrap();

        let paths = AppPaths::from_config_dir(dir.path().join("config"));
        paths.ensure_directories().unwrap();
        atomic_write(
            &paths.root_certificate(&profile),
            material.root_certificate_pem.as_bytes(),
            0o644,
        )
        .unwrap();
        let report = crate::batch::sign_paths(
            &paths,
            &profile,
            &[dir.path().to_path_buf()],
            false,
            None,
            false,
            false,
        )
        .unwrap();
        assert_eq!(report.authentication_prompts, 0);
        assert_eq!(report.summary.signed, 0);
        assert_eq!(report.summary.skipped, 2);
    }

    #[test]
    fn preflight_rejects_bad_destination_before_key_access() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.png");
        image(&input, [10, 20, 30, 255]);

        let wrong_extension = dir.path().join("output.jpg");
        let error = preflight_attest(&input, &wrong_extension, false).unwrap_err();
        assert_eq!(error.exit_code(), 1);
        assert!(error.to_string().contains("extension must match"));

        let missing_directory = dir.path().join("missing/output.png");
        let error = preflight_attest(&input, &missing_directory, false).unwrap_err();
        assert_eq!(error.exit_code(), 1);
        assert!(
            error
                .to_string()
                .contains("output directory does not exist")
        );
    }

    #[test]
    fn attest_supports_jpeg_and_forced_atomic_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.JPG");
        let output = dir.path().join("output.JPG");
        image::RgbImage::from_pixel(4, 3, image::Rgb([10_u8, 20, 30]))
            .save(&input)
            .unwrap();
        fs::write(&output, b"existing destination").unwrap();
        let profile = Profile::default();
        let source = inspect_asset(&input, None).unwrap();
        let report = sign_core(
            &profile,
            SignMode::Attest,
            None,
            &input,
            &output,
            "JPEG attestation",
            false,
            true,
            &source,
            &material(&profile),
        )
        .unwrap();

        assert_eq!(report.c2pa.credential_location, "JPEG APP11 JUMBF");
        assert!(report.c2pa.credential_bytes > 0);
        assert!(report.c2pa.post_commit_verified);
        let verified = verify_asset(&output, None, false).unwrap();
        assert!(verified.signature_valid);
        assert!(pixels_equal(&input, &output).unwrap());
    }

    #[test]
    fn evidence_bundle_preserves_signed_bytes_and_detects_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input.png");
        let output = directory.path().join("input.banksy-signed.png");
        image(&input, [10, 20, 30, 255]);
        let profile = Profile::default();
        let material = material(&profile);
        let source = inspect_asset(&input, None).unwrap();
        sign_core(
            &profile,
            SignMode::Attest,
            None,
            &input,
            &output,
            "Attestation",
            true,
            false,
            &source,
            &material,
        )
        .unwrap();

        let paths = AppPaths::from_config_dir(directory.path().join("config"));
        paths.ensure_directories().unwrap();
        profile.save(&paths).unwrap();
        atomic_write(
            &paths.root_certificate(&profile),
            material.root_certificate_pem.as_bytes(),
            0o644,
        )
        .unwrap();
        let bundle = directory.path().join("evidence.zip");
        let created = crate::bundle::create_bundle(
            &paths,
            std::slice::from_ref(&output),
            false,
            &bundle,
            false,
        )
        .unwrap();
        assert!(created.verified);
        assert_eq!(created.images, 1);
        let audited =
            crate::bundle::audit_bundle(&bundle, Some(&material.root_certificate_pem)).unwrap();
        assert!(audited.passed);
        assert!(audited.local_root_match);
        assert_eq!(audited.trust_basis, "configured-local-root");
        assert_eq!(audited.images[0].file_sha256, file_sha256(&output).unwrap());
        let self_contained = crate::bundle::audit_bundle(&bundle, None).unwrap();
        assert!(self_contained.passed);
        assert_eq!(self_contained.trust_basis, "bundled-self-declared-root");
        let other_root = generate_hierarchy(&Profile::default())
            .unwrap()
            .root_certificate_pem;
        let wrong_identity = crate::bundle::audit_bundle(&bundle, Some(&other_root)).unwrap();
        assert!(!wrong_identity.passed);
        assert_eq!(wrong_identity.trust_basis, "configured-local-root-mismatch");

        let signed_bytes = fs::read(&output).unwrap();
        let mut bundle_bytes = fs::read(&bundle).unwrap();
        let offset = bundle_bytes
            .windows(signed_bytes.len())
            .position(|window| window == signed_bytes)
            .expect("stored ZIP contains the exact signed image bytes");
        bundle_bytes[offset + signed_bytes.len() / 2] ^= 1;
        let tampered = directory.path().join("tampered.zip");
        fs::write(&tampered, bundle_bytes).unwrap();
        match crate::bundle::audit_bundle(&tampered, Some(&material.root_certificate_pem)) {
            Ok(report) => assert!(!report.passed),
            Err(error) => assert_eq!(error.exit_code(), 3),
        }
    }

    #[test]
    fn derivative_links_parent_and_claims_edit() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("parent.png");
        let input = dir.path().join("edited.png");
        let output = dir.path().join("signed.png");
        image(&parent, [10, 20, 30, 255]);
        image(&input, [11, 20, 30, 255]);
        let profile = Profile::default();
        let source = inspect_asset(&parent, None).unwrap();
        let report = sign_core(
            &profile,
            SignMode::Derivative,
            Some(&parent),
            &input,
            &output,
            "Derivative / editorial work",
            true,
            false,
            &source,
            &material(&profile),
        )
        .unwrap();

        assert_eq!(report.pixels_changed_from_parent, Some(true));
        let inspected = inspect_asset(&output, None).unwrap();
        assert!(inspected.c2pa.actions.contains(&"c2pa.edited".into()));
        assert!(inspected.c2pa.actions.contains(&"c2pa.published".into()));
        assert!(
            inspected
                .c2pa
                .ingredients
                .iter()
                .any(|i| i.relationship == "parentOf")
        );
    }

    #[test]
    fn second_attestation_uses_update_manifest_and_keeps_history() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.png");
        let first = dir.path().join("first.png");
        let second = dir.path().join("second.png");
        image(&input, [10, 20, 30, 255]);
        let profile = Profile::default();
        let material = material(&profile);

        let unsigned = inspect_asset(&input, None).unwrap();
        sign_core(
            &profile,
            SignMode::Attest,
            None,
            &input,
            &first,
            "First attestation",
            false,
            false,
            &unsigned,
            &material,
        )
        .unwrap();
        let signed = inspect_asset(&first, None).unwrap();
        sign_core(
            &profile,
            SignMode::Attest,
            None,
            &first,
            &second,
            "Second attestation",
            true,
            false,
            &signed,
            &material,
        )
        .unwrap();

        let result = inspect_asset(&second, Some(&material.root_certificate_pem)).unwrap();
        assert_eq!(result.c2pa.manifest_count, 2);
        assert!(result.c2pa.actions.contains(&"c2pa.edited.metadata".into()));
        assert!(pixels_equal(&input, &second).unwrap());
    }

    #[test]
    fn verification_detects_a_pixel_change_with_manifest_retained() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.png");
        let signed = dir.path().join("signed.png");
        let changed_container = dir.path().join("changed.png");
        let tampered = dir.path().join("tampered.png");
        image(&input, [10, 20, 30, 255]);
        image(&changed_container, [11, 20, 30, 255]);
        let profile = Profile::default();
        let material = material(&profile);
        let source = inspect_asset(&input, None).unwrap();
        sign_core(
            &profile,
            SignMode::Attest,
            None,
            &input,
            &signed,
            "Attestation",
            false,
            false,
            &source,
            &material,
        )
        .unwrap();

        transplant_png_c2pa_chunks(&signed, &changed_container, &tampered);
        let report = verify_asset(&tampered, Some(&material.root_certificate_pem), true).unwrap();
        assert!(report.manifest_present);
        assert!(!report.signature_valid);
        assert_eq!(report.validation_state, "invalid");
    }

    fn transplant_png_c2pa_chunks(signed: &Path, changed: &Path, destination: &Path) {
        const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

        fn chunks(bytes: &[u8]) -> Vec<&[u8]> {
            assert!(bytes.starts_with(PNG_SIGNATURE));
            let mut result = Vec::new();
            let mut offset = PNG_SIGNATURE.len();
            while offset + 12 <= bytes.len() {
                let length =
                    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
                let end = offset + 12 + length;
                assert!(end <= bytes.len());
                result.push(&bytes[offset..end]);
                offset = end;
            }
            result
        }

        let signed_bytes = fs::read(signed).unwrap();
        let changed_bytes = fs::read(changed).unwrap();
        let c2pa: Vec<Vec<u8>> = chunks(&signed_bytes)
            .into_iter()
            .filter(|chunk| &chunk[4..8] == b"caBX")
            .map(<[u8]>::to_vec)
            .collect();
        assert!(!c2pa.is_empty());

        let mut output = PNG_SIGNATURE.to_vec();
        for chunk in chunks(&changed_bytes) {
            if &chunk[4..8] == b"IEND" {
                for manifest_chunk in &c2pa {
                    output.extend_from_slice(manifest_chunk);
                }
            }
            output.extend_from_slice(chunk);
        }
        fs::write(destination, output).unwrap();
    }

    #[test]
    fn refuses_identical_derivative_before_key_access() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("parent.png");
        let input = dir.path().join("edited.png");
        let output = dir.path().join("signed.png");
        image(&parent, [10, 20, 30, 255]);
        fs::copy(&parent, &input).unwrap();
        assert!(pixels_equal(&parent, &input).unwrap());
        assert!(!output.exists());
    }
}
