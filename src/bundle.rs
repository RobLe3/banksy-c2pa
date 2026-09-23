use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tempfile::Builder as TempBuilder;
use time::{OffsetDateTime, format_description::well_known::Rfc3339, macros::format_description};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{
    audit::{AuditState, ImageAuditReport, audit_image},
    config::{AppPaths, Profile},
    display_path,
    error::{AppError, AppResult},
    image_info::file_sha256,
    pki::certificate_fingerprint,
    scan::{self, AssetState},
};

const BUNDLE_SCHEMA: &str = "banksy-c2pa-evidence/v1";
const MAX_ARCHIVE_ENTRIES: usize = 512;
const MAX_IMAGE_SIZE: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_SIZE: u64 = 2 * 1024 * 1024 * 1024;
const MAX_METADATA_SIZE: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleFileRecord {
    pub archive_path: String,
    pub source_name: String,
    pub size: u64,
    pub sha256: String,
    pub format: String,
    pub credential_location: String,
    pub credential_bytes: u64,
    pub manifest_count: usize,
    pub active_manifest: Option<String>,
    pub signer_common_name: Option<String>,
    pub signer_issuer: Option<String>,
    pub published: bool,
    pub upstream_manifest_count: usize,
    pub upstream_preserved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleTrustRecord {
    pub mode: String,
    pub public_trust: bool,
    pub root_certificate: String,
    pub root_fingerprint_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema: String,
    pub created_at: String,
    pub tool: String,
    pub trust: BundleTrustRecord,
    pub files: Vec<BundleFileRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleCreationReport {
    pub status: &'static str,
    pub output: String,
    pub file_sha256: String,
    pub images: usize,
    pub root_fingerprint_sha256: String,
    pub verified: bool,
}

impl fmt::Display for BundleCreationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Evidence bundle created")?;
        writeln!(f, "\nOutput\n  {}", self.output)?;
        writeln!(f, "\nImages\n  {}", self.images)?;
        writeln!(f, "\nBundle SHA-256\n  {}", self.file_sha256)?;
        writeln!(
            f,
            "\nBundled local root SHA-256\n  {}",
            self.root_fingerprint_sha256
        )?;
        write!(f, "\nArchive verification\n  passed")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleAuditReport {
    pub path: String,
    pub passed: bool,
    pub file_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_matches: Option<bool>,
    pub schema: Option<String>,
    pub bundled_root_fingerprint_sha256: Option<String>,
    pub local_root_match: bool,
    pub trust_basis: &'static str,
    pub images: Vec<ImageAuditReport>,
    pub issues: Vec<String>,
}

pub fn default_bundle_path(directory: &Path) -> AppResult<PathBuf> {
    let format = format_description!("[year][month][day]T[hour][minute][second]Z");
    let timestamp = OffsetDateTime::now_utc()
        .format(format)
        .map_err(|error| AppError::runtime(format!("cannot format bundle timestamp: {error}")))?;
    Ok(directory.join(format!("banksy-c2pa-evidence-{timestamp}.zip")))
}

pub fn create_bundle(
    app_paths: &AppPaths,
    roots: &[PathBuf],
    recursive: bool,
    output: &Path,
    force: bool,
) -> AppResult<BundleCreationReport> {
    if !output
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
    {
        return Err(AppError::runtime(
            "evidence bundle output must use the .zip extension",
        ));
    }
    let profile = Profile::load(app_paths)?;
    let root_path = app_paths.root_certificate(&profile);
    let root_pem = fs::read_to_string(&root_path).map_err(|error| {
        AppError::runtime(format!("cannot read {}: {error}", display_path(&root_path)))
    })?;
    let root_fingerprint = certificate_fingerprint(root_pem.as_bytes())?;
    let roots = if roots.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        roots.to_vec()
    };
    let files = collect_local_files(&roots, recursive, &root_pem)?;
    if files.is_empty() {
        return Err(AppError::verification(
            "no files signed by the configured local identity were found",
        ));
    }
    if output.exists() && !force {
        return Err(AppError::runtime(format!(
            "existing bundle found: {}; use --force to replace it",
            display_path(output)
        )));
    }
    let output_directory = output.parent().unwrap_or_else(|| Path::new("."));
    if !output_directory.is_dir() {
        return Err(AppError::runtime(format!(
            "bundle output directory does not exist: {}",
            display_path(output_directory)
        )));
    }

    let mut records = Vec::with_capacity(files.len());
    for file in &files {
        let audit = audit_image(&file.source, Some(&root_pem), None)?;
        if audit.state != AuditState::ValidLocal || !audit.container.valid_generated_embedding() {
            return Err(AppError::verification(format!(
                "refusing to package {}: {}",
                display_path(&file.source),
                audit.detail
            )));
        }
        records.push(BundleFileRecord {
            archive_path: file.archive_path.clone(),
            source_name: file
                .source
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "image".into()),
            size: audit.file_size,
            sha256: audit.file_sha256,
            format: audit.container.format.into(),
            credential_location: audit.container.location.into(),
            credential_bytes: audit.container.store_bytes,
            manifest_count: audit.manifest_count,
            active_manifest: audit.active_manifest,
            signer_common_name: audit.signer_common_name,
            signer_issuer: audit.signer_issuer,
            published: audit.published,
            upstream_manifest_count: audit.upstream_manifest_count,
            upstream_preserved: audit.upstream_preserved,
        });
    }

    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| AppError::runtime(format!("cannot format bundle time: {error}")))?;
    let manifest = BundleManifest {
        schema: BUNDLE_SCHEMA.into(),
        created_at,
        tool: format!("banksy-c2pa {}", env!("CARGO_PKG_VERSION")),
        trust: BundleTrustRecord {
            mode: "local-private".into(),
            public_trust: false,
            root_certificate: "trust/root-ca.pem".into(),
            root_fingerprint_sha256: root_fingerprint.clone(),
        },
        files: records,
    };
    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| AppError::runtime(format!("cannot serialize bundle evidence: {error}")))?;
    let checksums = manifest
        .files
        .iter()
        .map(|file| format!("{}  {}", file.sha256, file.archive_path))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    let temp = TempBuilder::new()
        .prefix(".banksy-c2pa-evidence-")
        .suffix(".zip")
        .tempfile_in(output_directory)
        .map_err(|error| AppError::runtime(format!("cannot create temporary bundle: {error}")))?;
    let temp_path = temp.path().to_path_buf();
    let file = temp.reopen().map_err(|error| {
        AppError::runtime(format!("cannot open temporary bundle for writing: {error}"))
    })?;
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o644);
    write_zip_bytes(&mut writer, "evidence.json", &manifest_json, options)?;
    write_zip_bytes(&mut writer, "SHA256SUMS", checksums.as_bytes(), options)?;
    write_zip_bytes(
        &mut writer,
        "README.txt",
        bundle_readme().as_bytes(),
        options,
    )?;
    write_zip_bytes(
        &mut writer,
        "trust/root-ca.pem",
        root_pem.as_bytes(),
        options,
    )?;
    for (file, record) in files.iter().zip(&manifest.files) {
        writer
            .start_file(&record.archive_path, options)
            .map_err(zip_runtime_error("cannot start image entry"))?;
        let mut input = fs::File::open(&file.source).map_err(|error| {
            AppError::runtime(format!(
                "cannot read {}: {error}",
                display_path(&file.source)
            ))
        })?;
        io::copy(&mut input, &mut writer)
            .map_err(|error| AppError::runtime(format!("cannot write image to bundle: {error}")))?;
    }
    let completed = writer
        .finish()
        .map_err(zip_runtime_error("cannot finish evidence bundle"))?;
    completed
        .sync_all()
        .map_err(|error| AppError::runtime(format!("cannot sync evidence bundle: {error}")))?;

    let validation = audit_bundle(&temp_path, Some(&root_pem))?;
    if !validation.passed || validation.images.len() != files.len() {
        return Err(AppError::verification(format!(
            "temporary evidence bundle failed validation: {}",
            validation.issues.join("; ")
        )));
    }
    if force {
        fs::rename(&temp_path, output).map_err(|error| {
            AppError::runtime(format!("cannot replace {}: {error}", display_path(output)))
        })?;
    } else {
        fs::hard_link(&temp_path, output).map_err(|error| {
            AppError::runtime(format!("cannot commit {}: {error}", display_path(output)))
        })?;
    }
    let committed = audit_bundle(output, Some(&root_pem))?;
    if !committed.passed {
        return Err(AppError::verification(
            "committed evidence bundle failed verification",
        ));
    }
    Ok(BundleCreationReport {
        status: "ok",
        output: display_path(output),
        file_sha256: committed.file_sha256,
        images: committed.images.len(),
        root_fingerprint_sha256: root_fingerprint,
        verified: true,
    })
}

pub fn audit_bundle(path: &Path, local_root_pem: Option<&str>) -> AppResult<BundleAuditReport> {
    let bundle_hash = file_sha256(path)?;
    let file = fs::File::open(path).map_err(|error| {
        AppError::runtime(format!("cannot open {}: {error}", display_path(path)))
    })?;
    let mut archive =
        ZipArchive::new(file).map_err(zip_verification_error("cannot read evidence ZIP"))?;
    let mut issues = Vec::new();
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(AppError::verification(format!(
            "archive has more than {MAX_ARCHIVE_ENTRIES} entries"
        )));
    }
    let mut total_size = 0_u64;
    let mut names = HashSet::new();
    let mut image_entries = HashSet::new();
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(zip_verification_error("cannot inspect ZIP entry"))?;
        let name = entry.name().to_string();
        if !safe_archive_path(&name) {
            issues.push(format!("unsafe archive entry path: {name}"));
        }
        if !names.insert(name.clone()) {
            issues.push(format!("duplicate archive entry: {name}"));
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            issues.push(format!(
                "symbolic-link archive entry is not allowed: {name}"
            ));
        }
        total_size = total_size.saturating_add(entry.size());
        if name.starts_with("images/") && !name.ends_with('/') {
            image_entries.insert(name);
            if entry.size() > MAX_IMAGE_SIZE {
                issues.push(format!("image entry exceeds {MAX_IMAGE_SIZE} bytes"));
            }
        }
    }
    if total_size > MAX_TOTAL_SIZE {
        return Err(AppError::verification(format!(
            "archive expands beyond {MAX_TOTAL_SIZE} bytes"
        )));
    }

    let manifest_bytes = read_small_entry(&mut archive, "evidence.json")?;
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| AppError::verification(format!("invalid evidence.json: {error}")))?;
    if manifest.schema != BUNDLE_SCHEMA {
        issues.push(format!("unsupported bundle schema: {}", manifest.schema));
    }
    if manifest.files.len() > MAX_ARCHIVE_ENTRIES {
        return Err(AppError::verification(format!(
            "evidence.json lists more than {MAX_ARCHIVE_ENTRIES} images"
        )));
    }
    if manifest.files.is_empty() {
        issues.push("evidence.json contains no image records".into());
    }
    if manifest.trust.mode != "local-private" || manifest.trust.public_trust {
        issues.push("unsupported or misleading bundle trust declaration".into());
    }
    if !safe_archive_path(&manifest.trust.root_certificate)
        || manifest.trust.root_certificate.starts_with("images/")
    {
        issues.push("invalid bundled root certificate path".into());
    }
    let checksum_text = String::from_utf8(read_small_entry(&mut archive, "SHA256SUMS")?)
        .map_err(|error| AppError::verification(format!("SHA256SUMS is not UTF-8: {error}")))?;
    let checksums = parse_checksums(&checksum_text, &mut issues);
    let root_pem = String::from_utf8(read_small_entry(
        &mut archive,
        &manifest.trust.root_certificate,
    )?)
    .map_err(|error| AppError::verification(format!("bundled root is not UTF-8 PEM: {error}")))?;
    let bundled_fingerprint = certificate_fingerprint(root_pem.as_bytes()).map_err(|error| {
        AppError::verification(format!("invalid bundled root certificate: {error}"))
    })?;
    if bundled_fingerprint != manifest.trust.root_fingerprint_sha256 {
        issues.push("bundled root fingerprint does not match evidence.json".into());
    }
    let local_root_match = local_root_pem
        .and_then(|root| certificate_fingerprint(root.as_bytes()).ok())
        .is_some_and(|fingerprint| fingerprint == bundled_fingerprint);
    if local_root_pem.is_some() && !local_root_match {
        issues.push("bundled root does not match the configured local identity".into());
    }

    let expected_entries: HashSet<_> = manifest
        .files
        .iter()
        .map(|record| record.archive_path.clone())
        .collect();
    if expected_entries.len() != manifest.files.len() {
        issues.push("evidence.json contains duplicate image paths".into());
    }
    if expected_entries != image_entries {
        issues.push("images/ entries do not exactly match evidence.json".into());
    }
    let checksum_entries: HashSet<_> = checksums.keys().cloned().collect();
    if checksum_entries != expected_entries {
        issues.push("SHA256SUMS entries do not exactly match evidence.json".into());
    }
    let mut allowed_entries = expected_entries.clone();
    allowed_entries.extend([
        "evidence.json".to_string(),
        "SHA256SUMS".to_string(),
        "README.txt".to_string(),
        manifest.trust.root_certificate.clone(),
    ]);
    if names != allowed_entries {
        issues.push("archive entries do not exactly match the evidence bundle format".into());
    }
    let temp_dir = tempfile::tempdir().map_err(|error| {
        AppError::runtime(format!("cannot create bundle audit directory: {error}"))
    })?;
    let mut images = Vec::new();
    for (index, record) in manifest.files.iter().enumerate() {
        if !safe_archive_path(&record.archive_path) || !record.archive_path.starts_with("images/") {
            issues.push(format!(
                "invalid image archive path: {}",
                record.archive_path
            ));
            continue;
        }
        if checksums.get(&record.archive_path) != Some(&record.sha256) {
            issues.push(format!(
                "SHA256SUMS does not match evidence.json for {}",
                record.archive_path
            ));
        }
        let mut entry = match archive.by_name(&record.archive_path) {
            Ok(entry) => entry,
            Err(_) => {
                issues.push(format!("missing image entry: {}", record.archive_path));
                continue;
            }
        };
        if entry.size() > MAX_IMAGE_SIZE {
            continue;
        }
        let extension = Path::new(&record.archive_path)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("bin");
        let extracted = temp_dir.path().join(format!("entry-{index}.{extension}"));
        let mut output = fs::File::create(&extracted).map_err(|error| {
            AppError::runtime(format!("cannot create temporary audited image: {error}"))
        })?;
        let copied = io::copy(&mut entry, &mut output).map_err(|error| {
            AppError::verification(format!("cannot extract bundle image: {error}"))
        })?;
        if copied != record.size || copied > MAX_IMAGE_SIZE {
            issues.push(format!("image size mismatch for {}", record.archive_path));
        }
        drop(output);
        let mut audit =
            audit_image(&extracted, Some(&root_pem), Some(&record.sha256)).map_err(|error| {
                AppError::verification(format!(
                    "cannot audit bundled image {}: {error}",
                    record.archive_path
                ))
            })?;
        audit.path = format!("{}!{}", display_path(path), record.archive_path);
        if !audit.passed() {
            issues.push(format!(
                "image audit failed for {}: {}",
                record.archive_path, audit.detail
            ));
        }
        if audit.file_size != record.size
            || audit.container.format != record.format
            || audit.container.location != record.credential_location
            || audit.container.store_bytes != record.credential_bytes
            || audit.manifest_count != record.manifest_count
            || audit.active_manifest != record.active_manifest
            || audit.signer_common_name != record.signer_common_name
            || audit.signer_issuer != record.signer_issuer
            || audit.published != record.published
            || audit.upstream_manifest_count != record.upstream_manifest_count
            || audit.upstream_preserved != record.upstream_preserved
        {
            issues.push(format!(
                "evidence metadata mismatch for {}",
                record.archive_path
            ));
        }
        images.push(audit);
    }

    Ok(BundleAuditReport {
        path: display_path(path),
        passed: issues.is_empty(),
        file_sha256: bundle_hash,
        expected_sha256: None,
        hash_matches: None,
        schema: Some(manifest.schema),
        bundled_root_fingerprint_sha256: Some(bundled_fingerprint),
        local_root_match,
        trust_basis: if local_root_match {
            "configured-local-root"
        } else if local_root_pem.is_some() {
            "configured-local-root-mismatch"
        } else {
            "bundled-self-declared-root"
        },
        images,
        issues,
    })
}

#[derive(Debug)]
struct PackageFile {
    source: PathBuf,
    archive_path: String,
}

fn collect_local_files(
    roots: &[PathBuf],
    recursive: bool,
    root_pem: &str,
) -> AppResult<Vec<PackageFile>> {
    let mut files = Vec::new();
    let multiple_roots = roots.len() > 1;
    for (index, root) in roots.iter().enumerate() {
        if root.is_file() {
            let audit = audit_image(root, Some(root_pem), None)?;
            if audit.state != AuditState::ValidLocal {
                return Err(AppError::verification(format!(
                    "{} is not signed by the configured local identity",
                    display_path(root)
                )));
            }
            let name = root.file_name().ok_or_else(|| {
                AppError::runtime(format!("cannot name bundle input {}", display_path(root)))
            })?;
            let relative = PathBuf::from(name);
            files.push(PackageFile {
                source: root.clone(),
                archive_path: archive_image_path(index, multiple_roots, &relative)?,
            });
        } else if root.is_dir() {
            let report = scan::scan_paths(std::slice::from_ref(root), recursive, Some(root_pem))?;
            let base = root.canonicalize().unwrap_or_else(|_| root.clone());
            for item in report
                .items
                .into_iter()
                .filter(|item| item.state == AssetState::SignedLocal)
            {
                let source = PathBuf::from(item.path);
                let canonical = source.canonicalize().unwrap_or_else(|_| source.clone());
                let relative = canonical
                    .strip_prefix(&base)
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|_| {
                        source
                            .file_name()
                            .map(PathBuf::from)
                            .unwrap_or_else(|| source.clone())
                    });
                let archive_path = archive_image_path(index, multiple_roots, &relative)?;
                files.push(PackageFile {
                    source,
                    archive_path,
                });
            }
        } else {
            return Err(AppError::runtime(format!(
                "package input does not exist: {}",
                display_path(root)
            )));
        }
    }
    files.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    let mut names = HashSet::new();
    let mut sources = HashSet::new();
    for file in &files {
        let source = file
            .source
            .canonicalize()
            .unwrap_or_else(|_| file.source.clone());
        if !sources.insert(source) {
            return Err(AppError::runtime(format!(
                "input was included more than once: {}",
                display_path(&file.source)
            )));
        }
        if !names.insert(file.archive_path.clone()) {
            return Err(AppError::runtime(format!(
                "multiple inputs map to the same archive path: {}",
                file.archive_path
            )));
        }
    }
    Ok(files)
}

fn archive_image_path(index: usize, multiple_roots: bool, relative: &Path) -> AppResult<String> {
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => {
                return Err(AppError::runtime(format!(
                    "unsafe archive source path: {}",
                    display_path(relative)
                )));
            }
        }
    }
    if parts.is_empty() {
        return Err(AppError::runtime("empty archive image path"));
    }
    let relative = parts.join("/");
    Ok(if multiple_roots {
        format!("images/root-{:02}/{relative}", index + 1)
    } else {
        format!("images/{relative}")
    })
}

fn safe_archive_path(name: &str) -> bool {
    let path = Path::new(name);
    !name.contains('\\')
        && !name.is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn parse_checksums(contents: &str, issues: &mut Vec<String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (line_number, line) in contents.lines().enumerate() {
        let Some((hash, path)) = line.split_once("  ") else {
            issues.push(format!("invalid SHA256SUMS line {}", line_number + 1));
            continue;
        };
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            issues.push(format!(
                "invalid checksum on SHA256SUMS line {}",
                line_number + 1
            ));
            continue;
        }
        if out.insert(path.into(), hash.to_ascii_lowercase()).is_some() {
            issues.push(format!("duplicate checksum entry: {path}"));
        }
    }
    out
}

fn read_small_entry<R: Read + io::Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
) -> AppResult<Vec<u8>> {
    let mut entry = archive
        .by_name(name)
        .map_err(|_| AppError::verification(format!("missing bundle entry: {name}")))?;
    if entry.size() > MAX_METADATA_SIZE {
        return Err(AppError::verification(format!(
            "bundle metadata entry is too large: {name}"
        )));
    }
    let mut bytes = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut bytes).map_err(|error| {
        AppError::verification(format!("cannot read bundle entry {name}: {error}"))
    })?;
    Ok(bytes)
}

fn write_zip_bytes<W: Write + io::Seek>(
    writer: &mut ZipWriter<W>,
    name: &str,
    bytes: &[u8],
    options: SimpleFileOptions,
) -> AppResult<()> {
    writer
        .start_file(name, options)
        .map_err(zip_runtime_error("cannot start bundle entry"))?;
    writer
        .write_all(bytes)
        .map_err(|error| AppError::runtime(format!("cannot write bundle entry {name}: {error}")))
}

fn bundle_readme() -> &'static str {
    "Banksy C2PA evidence bundle\n\nThe images in this ZIP contain embedded C2PA Content Credentials. Send the ZIP as an opaque file or document. Uploading an extracted image through an image-processing service can re-encode it and remove its credential.\n\nSHA256SUMS detects changed bytes. The bundled root certificate is private/local verification material, not public C2PA trust. A recipient must compare its fingerprint through a separately trusted channel. evidence.json and SHA256SUMS are supporting metadata; the embedded image signatures provide the cryptographic asset binding.\n"
}

fn zip_runtime_error(context: &'static str) -> impl FnOnce(zip::result::ZipError) -> AppError {
    move |error| AppError::runtime(format!("{context}: {error}"))
}

fn zip_verification_error(context: &'static str) -> impl FnOnce(zip::result::ZipError) -> AppError {
    move |error| AppError::verification(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_paths_reject_traversal_and_backslashes() {
        assert!(safe_archive_path("images/a.png"));
        assert!(!safe_archive_path("../a.png"));
        assert!(!safe_archive_path("/a.png"));
        assert!(!safe_archive_path("images\\a.png"));
    }

    #[test]
    fn checksum_parser_rejects_malformed_lines() {
        let mut issues = Vec::new();
        let parsed = parse_checksums("nope\n", &mut issues);
        assert!(parsed.is_empty());
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn package_destination_requires_zip_extension_before_loading_identity() {
        let directory = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_config_dir(directory.path().join("config"));
        let error = create_bundle(
            &paths,
            &[],
            false,
            &directory.path().join("not-an-archive.png"),
            false,
        )
        .unwrap_err();
        assert_eq!(error.exit_code(), 1);
        assert!(error.to_string().contains(".zip extension"));
    }
}
