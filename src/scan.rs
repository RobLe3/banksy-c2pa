use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{
    config::{AppPaths, Profile},
    display_path,
    error::{AppError, AppResult},
    provenance::{InspectionReport, inspect_asset},
    signing::default_output_path,
};

pub fn load_local_root(paths: &AppPaths) -> AppResult<Option<String>> {
    if !paths.profile_file.exists() {
        return Ok(None);
    }
    let profile = Profile::load(paths)?;
    let root_path = paths.root_certificate(&profile);
    let root = fs::read_to_string(&root_path).map_err(|error| {
        AppError::runtime(format!(
            "cannot read configured local root {}: {error}",
            display_path(&root_path)
        ))
    })?;
    Ok(Some(root))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssetState {
    Unsigned,
    SignedExternal,
    SignedLocal,
    Covered,
    Invalid,
    Unreadable,
}

impl AssetState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::SignedExternal => "signed-external",
            Self::SignedLocal => "signed-local",
            Self::Covered => "covered",
            Self::Invalid => "invalid",
            Self::Unreadable => "unreadable",
        }
    }

    pub const fn needs_signing(self) -> bool {
        matches!(self, Self::Unsigned | Self::SignedExternal)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusItem {
    pub path: String,
    pub state: AssetState,
    pub needs_signing: bool,
    pub signature_present: bool,
    pub signature_valid: bool,
    pub local_trust: bool,
    pub covered_by: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StatusSummary {
    pub total: usize,
    pub needs_signing: usize,
    pub unsigned: usize,
    pub signed_external: usize,
    pub signed_local: usize,
    pub covered: usize,
    pub invalid: usize,
    pub unreadable: usize,
}

impl StatusSummary {
    pub fn has_policy_issues(&self) -> bool {
        self.needs_signing > 0 || self.invalid > 0
    }

    pub fn has_runtime_issues(&self) -> bool {
        self.unreadable > 0
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusReport {
    pub status: &'static str,
    pub roots: Vec<String>,
    pub recursive: bool,
    pub local_identity_configured: bool,
    pub items: Vec<StatusItem>,
    pub summary: StatusSummary,
}

impl fmt::Display for StatusReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.items.is_empty() {
            writeln!(f, "No supported images found")?;
        } else {
            writeln!(f, "STATE              ACTION  FILE")?;
            for item in &self.items {
                let action = if item.needs_signing { "sign" } else { "-" };
                writeln!(f, "{:<18} {:<7} {}", item.state.as_str(), action, item.path)?;
                if let Some(covered_by) = &item.covered_by {
                    writeln!(f, "  covered by {covered_by}")?;
                }
                if matches!(item.state, AssetState::Invalid | AssetState::Unreadable) {
                    writeln!(f, "  {}", item.detail)?;
                }
            }
        }

        write!(
            f,
            "\nSummary: {} total, {} need signing, {} locally signed, {} covered, {} invalid, {} unreadable",
            self.summary.total,
            self.summary.needs_signing,
            self.summary.signed_local,
            self.summary.covered,
            self.summary.invalid,
            self.summary.unreadable,
        )
    }
}

pub fn scan_paths(
    roots: &[PathBuf],
    recursive: bool,
    local_root_pem: Option<&str>,
) -> AppResult<StatusReport> {
    let roots = if roots.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        roots.to_vec()
    };
    let mut candidates = Vec::new();
    for root in &roots {
        collect(root, recursive, &mut candidates);
    }
    candidates.sort_by(|left, right| left.path.cmp(&right.path));

    let mut seen = HashSet::new();
    candidates.retain(|candidate| seen.insert(candidate.identity()));

    let mut classified = Vec::with_capacity(candidates.len());
    let mut by_path = HashMap::new();
    for candidate in candidates {
        let identity = candidate.identity();
        let result = match candidate.error {
            Some(detail) => Classified::unreadable(&candidate.path, detail),
            None => classify_image(&candidate.path, local_root_pem),
        };
        by_path.insert(identity, classified.len());
        classified.push((candidate.path, result));
    }

    for index in 0..classified.len() {
        let (path, current) = &classified[index];
        if !current.item.state.needs_signing() || is_managed_output(path) {
            continue;
        }
        let sibling = default_output_path(path);
        if !sibling.is_file() {
            continue;
        }
        let sibling_identity = sibling.canonicalize().unwrap_or_else(|_| sibling.clone());
        let sibling_result = by_path
            .get(&sibling_identity)
            .map(|sibling_index| classified[*sibling_index].1.clone())
            .unwrap_or_else(|| classify_image(&sibling, local_root_pem));
        if sibling_result.covers(current) {
            let item = &mut classified[index].1.item;
            item.state = AssetState::Covered;
            item.needs_signing = false;
            item.covered_by = Some(display_path(&sibling));
            item.detail = "a valid, locally trusted, pixel-identical signed copy exists".into();
        }
    }

    let items: Vec<_> = classified
        .into_iter()
        .map(|(_, classified)| classified.item)
        .collect();
    let summary = summarize(&items);
    Ok(StatusReport {
        status: "ok",
        roots: roots.iter().map(|path| display_path(path)).collect(),
        recursive,
        local_identity_configured: local_root_pem.is_some(),
        items,
        summary,
    })
}

#[derive(Debug, Clone)]
struct Classified {
    item: StatusItem,
    pixel_sha256: Option<String>,
    has_parent: bool,
}

impl Classified {
    fn unreadable(path: &Path, detail: String) -> Self {
        Self {
            item: unreadable_item(path, detail),
            pixel_sha256: None,
            has_parent: false,
        }
    }

    fn covers(&self, original: &Self) -> bool {
        self.item.state == AssetState::SignedLocal
            && self.has_parent
            && self.pixel_sha256.is_some()
            && self.pixel_sha256 == original.pixel_sha256
    }
}

fn classify_image(path: &Path, local_root_pem: Option<&str>) -> Classified {
    match inspect_asset(path, local_root_pem) {
        Ok(report) => {
            let mut item = item_from_inspection(path, &report);
            if is_managed_output(path) {
                if item.state == AssetState::Unsigned {
                    item.state = AssetState::Invalid;
                    item.needs_signing = false;
                    item.detail = "a .banksy-signed file has no embedded Content Credential; it was stripped or replaced".into();
                } else if local_root_pem.is_some() && item.state == AssetState::SignedExternal {
                    item.state = AssetState::Invalid;
                    item.needs_signing = false;
                    item.detail = "the .banksy-signed file does not validate against the configured local identity".into();
                }
            }
            Classified {
                item,
                pixel_sha256: Some(report.file.pixel_sha256.clone()),
                has_parent: report
                    .c2pa
                    .ingredients
                    .iter()
                    .any(|ingredient| ingredient.relationship == "parentOf"),
            }
        }
        Err(error) => Classified {
            item: StatusItem {
                path: display_path(path),
                state: if error.exit_code() == 3 {
                    AssetState::Invalid
                } else {
                    AssetState::Unreadable
                },
                needs_signing: false,
                signature_present: error.exit_code() == 3,
                signature_valid: false,
                local_trust: false,
                covered_by: None,
                detail: error.to_string(),
            },
            pixel_sha256: None,
            has_parent: false,
        },
    }
}

fn item_from_inspection(path: &Path, report: &InspectionReport) -> StatusItem {
    let (state, detail) = if !report.c2pa.present {
        (AssetState::Unsigned, "no embedded C2PA manifest")
    } else if report.c2pa.validation_state == "invalid" {
        (AssetState::Invalid, "the active C2PA manifest is invalid")
    } else if report.c2pa.validation_state == "trusted" {
        (
            AssetState::SignedLocal,
            "valid active manifest trusted by the configured local root",
        )
    } else {
        (
            AssetState::SignedExternal,
            "valid C2PA provenance without the configured local signature",
        )
    };

    StatusItem {
        path: display_path(path),
        state,
        needs_signing: state.needs_signing(),
        signature_present: report.c2pa.present,
        signature_valid: report.c2pa.present && report.c2pa.validation_state != "invalid",
        local_trust: report.c2pa.validation_state == "trusted",
        covered_by: None,
        detail: detail.into(),
    }
}

fn summarize(items: &[StatusItem]) -> StatusSummary {
    let mut summary = StatusSummary {
        total: items.len(),
        needs_signing: items.iter().filter(|item| item.needs_signing).count(),
        ..StatusSummary::default()
    };
    for item in items {
        match item.state {
            AssetState::Unsigned => summary.unsigned += 1,
            AssetState::SignedExternal => summary.signed_external += 1,
            AssetState::SignedLocal => summary.signed_local += 1,
            AssetState::Covered => summary.covered += 1,
            AssetState::Invalid => summary.invalid += 1,
            AssetState::Unreadable => summary.unreadable += 1,
        }
    }
    summary
}

fn unreadable_item(path: &Path, detail: String) -> StatusItem {
    StatusItem {
        path: display_path(path),
        state: AssetState::Unreadable,
        needs_signing: false,
        signature_present: false,
        signature_valid: false,
        local_trust: false,
        covered_by: None,
        detail,
    }
}

#[derive(Debug)]
struct Candidate {
    path: PathBuf,
    error: Option<String>,
}

impl Candidate {
    fn identity(&self) -> PathBuf {
        self.path
            .canonicalize()
            .unwrap_or_else(|_| self.path.clone())
    }
}

fn collect(path: &Path, recursive: bool, candidates: &mut Vec<Candidate>) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            candidates.push(Candidate {
                path: path.to_path_buf(),
                error: Some(format!("cannot inspect {}: {error}", display_path(path))),
            });
            return;
        }
    };
    if metadata.file_type().is_symlink() {
        candidates.push(Candidate {
            path: path.to_path_buf(),
            error: Some("symbolic links are not followed".into()),
        });
    } else if metadata.is_file() {
        candidates.push(Candidate {
            path: path.to_path_buf(),
            error: None,
        });
    } else if metadata.is_dir() {
        collect_directory(path, recursive, candidates);
    } else {
        candidates.push(Candidate {
            path: path.to_path_buf(),
            error: Some("path is not a regular file or directory".into()),
        });
    }
}

fn collect_directory(path: &Path, recursive: bool, candidates: &mut Vec<Candidate>) {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            candidates.push(Candidate {
                path: path.to_path_buf(),
                error: Some(format!("cannot read directory: {error}")),
            });
            return;
        }
    };

    for entry in entries {
        let Ok(entry) = entry else { continue };
        let child = entry.path();
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() && is_supported_image_path(&child) {
            candidates.push(Candidate {
                path: child,
                error: None,
            });
        } else if recursive && file_type.is_dir() {
            collect_directory(&child, true, candidates);
        }
    }
}

fn is_supported_image_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "png" | "jpg" | "jpeg"
            )
        })
}

pub(crate) fn is_managed_output(path: &Path) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem.ends_with(".banksy-signed"))
}

#[cfg(test)]
mod tests {
    use image::{ImageBuffer, Rgba};

    use super::*;

    #[test]
    fn directory_scan_is_non_recursive_by_default() {
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("one.PNG");
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).unwrap();
        let nested_image = nested.join("two.png");
        ImageBuffer::from_pixel(1, 1, Rgba([1_u8, 2, 3, 255]))
            .save(&image)
            .unwrap();
        ImageBuffer::from_pixel(1, 1, Rgba([1_u8, 2, 3, 255]))
            .save(&nested_image)
            .unwrap();

        let shallow = scan_paths(&[directory.path().into()], false, None).unwrap();
        let deep = scan_paths(&[directory.path().into()], true, None).unwrap();
        assert_eq!(shallow.summary.total, 1);
        assert_eq!(deep.summary.total, 2);
        assert_eq!(deep.summary.unsigned, 2);
    }

    #[test]
    fn explicit_unsupported_file_is_reported() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notes.txt");
        fs::write(&path, "not an image").unwrap();
        let report = scan_paths(&[path], false, None).unwrap();
        assert_eq!(report.summary.unreadable, 1);
    }

    #[test]
    fn managed_name_without_a_credential_is_invalid_and_never_resigned() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image.banksy-signed.png");
        ImageBuffer::from_pixel(1, 1, Rgba([1_u8, 2, 3, 255]))
            .save(&path)
            .unwrap();

        let report = scan_paths(&[path], false, None).unwrap();
        assert_eq!(report.summary.invalid, 1);
        assert_eq!(report.summary.needs_signing, 0);
        assert!(!report.items[0].needs_signing);
        assert!(report.items[0].detail.contains("stripped or replaced"));
    }
}
