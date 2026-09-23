use std::{fmt, path::PathBuf};

use serde::Serialize;

use crate::{
    config::{AppPaths, Profile},
    error::AppResult,
    scan::{AssetState, is_managed_output, scan_paths},
    signing::{SigningSession, default_output_path, preflight_attest},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BatchItemResult {
    Signed,
    Skipped,
    Failed,
}

impl BatchItemResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchItem {
    pub input: String,
    pub source_state: AssetState,
    pub result: BatchItemResult,
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_preserved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_commit_verified: Option<bool>,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_exit_code: Option<u8>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct BatchSummary {
    pub scanned: usize,
    pub signed: usize,
    pub skipped: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchSigningReport {
    pub status: &'static str,
    pub recursive: bool,
    pub authentication_prompts: usize,
    pub items: Vec<BatchItem>,
    pub summary: BatchSummary,
}

impl BatchSigningReport {
    pub fn exit_code(&self) -> u8 {
        if self
            .items
            .iter()
            .any(|item| item.error_exit_code == Some(1))
        {
            1
        } else if self.summary.failed > 0 {
            3
        } else {
            0
        }
    }
}

impl fmt::Display for BatchSigningReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for item in &self.items {
            writeln!(
                f,
                "{:<8} {:<18} {}",
                item.result.as_str(),
                item.source_state.as_str(),
                item.input
            )?;
            if let Some(output) = &item.output {
                writeln!(f, "  output: {output}")?;
            }
            if let Some(hash) = &item.output_sha256 {
                writeln!(f, "  SHA-256: {hash}")?;
            }
            if item.post_commit_verified == Some(true) {
                writeln!(
                    f,
                    "  embedded credential verified; {} manifest{}; upstream: {}",
                    item.manifest_count.unwrap_or_default(),
                    if item.manifest_count == Some(1) {
                        ""
                    } else {
                        "s"
                    },
                    if item.upstream_preserved == Some(true) {
                        "preserved"
                    } else {
                        "no source credential"
                    },
                )?;
            }
            if item.result == BatchItemResult::Failed {
                writeln!(f, "  {}", item.detail)?;
            }
        }
        write!(
            f,
            "\nSummary: {} scanned, {} signed, {} skipped, {} failed; {} authentication prompt{}",
            self.summary.scanned,
            self.summary.signed,
            self.summary.skipped,
            self.summary.failed,
            self.authentication_prompts,
            if self.authentication_prompts == 1 {
                ""
            } else {
                "s"
            },
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub fn sign_paths(
    app_paths: &AppPaths,
    profile: &Profile,
    roots: &[PathBuf],
    recursive: bool,
    description: Option<&str>,
    published: bool,
    force: bool,
) -> AppResult<BatchSigningReport> {
    let root_pem =
        std::fs::read_to_string(app_paths.root_certificate(profile)).map_err(|error| {
            crate::error::AppError::runtime(format!(
                "cannot read the configured local root certificate: {error}"
            ))
        })?;
    let scan = scan_paths(roots, recursive, Some(&root_pem))?;
    let mut items = Vec::with_capacity(scan.items.len());
    let mut ready = Vec::new();

    for item in scan.items {
        if item.needs_signing {
            let input = PathBuf::from(&item.path);
            let output = default_output_path(&input);
            if is_managed_output(&input) {
                items.push(BatchItem {
                    input: item.path,
                    source_state: AssetState::Invalid,
                    result: BatchItemResult::Failed,
                    output: None,
                    output_sha256: None,
                    credential_location: None,
                    credential_bytes: None,
                    manifest_count: None,
                    upstream_preserved: None,
                    post_commit_verified: None,
                    detail: "refusing to sign a managed output name; audit or restore the original signed bytes".into(),
                    error_exit_code: Some(3),
                });
                continue;
            }
            match preflight_attest(&input, &output, force) {
                Ok(_) => {
                    let index = items.len();
                    ready.push((index, input, output));
                    items.push(BatchItem {
                        input: item.path,
                        source_state: item.state,
                        result: BatchItemResult::Skipped,
                        output: None,
                        output_sha256: None,
                        credential_location: None,
                        credential_bytes: None,
                        manifest_count: None,
                        upstream_preserved: None,
                        post_commit_verified: None,
                        detail: "ready to sign".into(),
                        error_exit_code: None,
                    });
                }
                Err(error) => items.push(BatchItem {
                    input: item.path,
                    source_state: item.state,
                    result: BatchItemResult::Failed,
                    output: Some(output.to_string_lossy().into_owned()),
                    output_sha256: None,
                    credential_location: None,
                    credential_bytes: None,
                    manifest_count: None,
                    upstream_preserved: None,
                    post_commit_verified: None,
                    detail: error.to_string(),
                    error_exit_code: Some(error.exit_code()),
                }),
            }
        } else if matches!(item.state, AssetState::Invalid | AssetState::Unreadable) {
            items.push(BatchItem {
                input: item.path,
                source_state: item.state,
                result: BatchItemResult::Failed,
                output: None,
                output_sha256: None,
                credential_location: None,
                credential_bytes: None,
                manifest_count: None,
                upstream_preserved: None,
                post_commit_verified: None,
                detail: item.detail,
                error_exit_code: Some(if item.state == AssetState::Unreadable {
                    1
                } else {
                    3
                }),
            });
        } else {
            items.push(BatchItem {
                input: item.path,
                source_state: item.state,
                result: BatchItemResult::Skipped,
                output: item.covered_by,
                output_sha256: None,
                credential_location: None,
                credential_bytes: None,
                manifest_count: None,
                upstream_preserved: None,
                post_commit_verified: None,
                detail: item.detail,
                error_exit_code: None,
            });
        }
    }

    let authentication_prompts = usize::from(!ready.is_empty());
    if !ready.is_empty() {
        let session = SigningSession::open(app_paths, profile)?;
        for (index, input, output) in ready {
            match session.attest(profile, &input, &output, description, published, force) {
                Ok(report) => {
                    items[index].result = BatchItemResult::Signed;
                    items[index].output = Some(output.to_string_lossy().into_owned());
                    items[index].output_sha256 = Some(report.output_sha256);
                    items[index].credential_location = Some(report.c2pa.credential_location.into());
                    items[index].credential_bytes = Some(report.c2pa.credential_bytes);
                    items[index].manifest_count = Some(report.c2pa.manifest_count);
                    items[index].upstream_preserved = Some(report.c2pa.upstream_preserved);
                    items[index].post_commit_verified = Some(report.c2pa.post_commit_verified);
                    items[index].detail = "signed and validated".into();
                }
                Err(error) => {
                    items[index].result = BatchItemResult::Failed;
                    items[index].output = Some(output.to_string_lossy().into_owned());
                    items[index].detail = error.to_string();
                    items[index].error_exit_code = Some(error.exit_code());
                }
            }
        }
    }

    let summary = BatchSummary {
        scanned: items.len(),
        signed: items
            .iter()
            .filter(|item| item.result == BatchItemResult::Signed)
            .count(),
        skipped: items
            .iter()
            .filter(|item| item.result == BatchItemResult::Skipped)
            .count(),
        failed: items
            .iter()
            .filter(|item| item.result == BatchItemResult::Failed)
            .count(),
    };
    let status = if summary.failed == 0 {
        "ok"
    } else if summary.signed == 0 {
        "failed"
    } else {
        "partial"
    };

    Ok(BatchSigningReport {
        status,
        recursive,
        authentication_prompts,
        items,
        summary,
    })
}
