use std::{
    fs,
    path::{Path, PathBuf},
};

use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};

use crate::{
    cli::{Cli, Command},
    config::{AppPaths, DEFAULT_ATTEST_DESCRIPTION, DEFAULT_DERIVATIVE_DESCRIPTION, Profile},
    error::{AppError, AppResult},
    scan::{self, AssetState, StatusReport},
    signing::default_output_path,
};

const MAIN_ACTIONS: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MainAction {
    Status,
    Sign,
    Audit,
    Package,
    Inspect,
    Verify,
    ChangeFolder,
    Advanced,
    Quit,
}

impl MainAction {
    const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Status),
            1 => Some(Self::Sign),
            2 => Some(Self::Audit),
            3 => Some(Self::Package),
            4 => Some(Self::Inspect),
            5 => Some(Self::Verify),
            6 => Some(Self::ChangeFolder),
            7 => Some(Self::Advanced),
            8 => Some(Self::Quit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdvancedAction {
    Initialize,
    Identity,
    Attest,
    Derivative,
    RotateSigner,
    Back,
}

impl AdvancedAction {
    const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Initialize),
            1 => Some(Self::Identity),
            2 => Some(Self::Attest),
            3 => Some(Self::Derivative),
            4 => Some(Self::RotateSigner),
            5 => Some(Self::Back),
            _ => None,
        }
    }
}

/// Run the interactive no-argument interface.
pub fn run() -> AppResult<u8> {
    let theme = ColorfulTheme::default();
    let mut working_directory = std::env::current_dir().map_err(|error| {
        AppError::runtime(format!("cannot determine current directory: {error}"))
    })?;
    let mut report = match scan_working_directory(&working_directory) {
        Ok(report) => Some(report),
        Err(error) => {
            eprintln!("WARNING: initial image scan failed: {error}");
            None
        }
    };

    println!("banksy-c2pa — local image signing");
    println!("Use the arrow keys and Enter. Press Escape or q to go back or quit.\n");

    loop {
        println!("Folder: {}", working_directory.display());
        if let Some(current) = &report {
            println!("{}", summary_line(current));
        } else {
            println!("Image status is unavailable; choose Refresh image status to try again.");
        }

        let pending = report
            .as_ref()
            .map_or(0, |current| current.summary.needs_signing);
        let total = report.as_ref().map_or(0, |current| current.summary.total);
        let actions = vec![
            format!("Refresh and show image status ({total} found)"),
            format!("Sign pending images ({pending}) — includes publication"),
            "Audit an image or evidence ZIP".to_string(),
            "Package locally signed images for safe transfer".to_string(),
            "Inspect an image".to_string(),
            "Verify an image".to_string(),
            "Change working folder".to_string(),
            "Advanced actions".to_string(),
            "Quit".to_string(),
        ];
        debug_assert_eq!(actions.len(), MAIN_ACTIONS);

        let Some(selection) = Select::with_theme(&theme)
            .with_prompt("Choose an action")
            .items(&actions)
            .default(0)
            .interact_opt()
            .map_err(prompt_error)?
        else {
            return Ok(0);
        };

        let action = MainAction::from_index(selection)
            .ok_or_else(|| AppError::runtime("invalid menu selection"))?;
        let result = match action {
            MainAction::Status => match scan_working_directory(&working_directory) {
                Ok(current) => {
                    print_status(&current, &working_directory);
                    report = Some(current);
                    Ok(())
                }
                Err(error) => {
                    report = None;
                    Err(error)
                }
            },
            MainAction::Sign => {
                let result = sign_pending(&theme, &working_directory);
                report = scan_working_directory(&working_directory).ok();
                result
            }
            MainAction::Audit => audit_target(&theme, &working_directory),
            MainAction::Package => package_folder(&theme, &working_directory),
            MainAction::Inspect => inspect_image(&theme, &working_directory),
            MainAction::Verify => verify_image(&theme, &working_directory),
            MainAction::ChangeFolder => {
                match choose_working_directory(&theme, &working_directory)? {
                    Some(path) => {
                        working_directory = path;
                        report = scan_working_directory(&working_directory).ok();
                    }
                    None => println!("Folder change cancelled.\n"),
                }
                Ok(())
            }
            MainAction::Advanced => {
                let result = advanced_menu(&theme, &working_directory);
                report = scan_working_directory(&working_directory).ok();
                result
            }
            MainAction::Quit => return Ok(0),
        };

        if let Err(error) = result {
            eprintln!("\nERROR: {error}\n");
        }
    }
}

fn scan_working_directory(working_directory: &Path) -> AppResult<StatusReport> {
    let app_paths = AppPaths::discover()?;
    let local_root = match scan::load_local_root(&app_paths) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("WARNING: local identity could not be loaded: {error}");
            None
        }
    };
    scan::scan_paths(
        &[working_directory.to_path_buf()],
        true,
        local_root.as_deref(),
    )
}

fn summary_line(report: &StatusReport) -> String {
    format!(
        "{} images: {} need signing ({} unsigned, {} foreign signed), {} local signed, {} covered, {} invalid, {} unreadable",
        report.summary.total,
        report.summary.needs_signing,
        report.summary.unsigned,
        report.summary.signed_external,
        report.summary.signed_local,
        report.summary.covered,
        report.summary.invalid,
        report.summary.unreadable,
    )
}

fn print_status(report: &StatusReport, working_directory: &Path) {
    println!("\nImage status under {}", working_directory.display());
    if report.items.is_empty() {
        println!("  No supported PNG or JPEG images found.");
    } else {
        println!("{:<34} FILE", "STATUS");
        for item in &report.items {
            let path = menu_path(Path::new(&item.path), working_directory);
            println!("{:<34} {path}", state_label(item.state));
            if let Some(covered_by) = &item.covered_by {
                println!(
                    "  covered by {}",
                    menu_path(Path::new(covered_by), working_directory)
                );
            }
            if matches!(item.state, AssetState::Invalid | AssetState::Unreadable) {
                println!("  {}", item.detail);
            }
        }
    }
    println!("{}", summary_line(report));
    if !report.local_identity_configured {
        println!(
            "Local identity is not configured, so existing signatures cannot yet be classified as local."
        );
    }
    println!();
}

const fn state_label(state: AssetState) -> &'static str {
    match state {
        AssetState::Unsigned => "Unsigned — needs signing",
        AssetState::SignedExternal => "Foreign signed — needs local signature",
        AssetState::SignedLocal => "Local signed — already signed locally",
        AssetState::Covered => "Covered — signed sibling exists",
        AssetState::Invalid => "Invalid — needs attention",
        AssetState::Unreadable => "Unreadable — needs attention",
    }
}

fn menu_path(path: &Path, working_directory: &Path) -> String {
    path.strip_prefix(working_directory)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn sign_pending(theme: &ColorfulTheme, working_directory: &Path) -> AppResult<()> {
    if !ensure_identity(theme)? {
        println!("Signing cancelled.\n");
        return Ok(());
    }

    let report = scan_working_directory(working_directory)?;
    print_status(&report, working_directory);
    if report.summary.needs_signing == 0 {
        println!("Nothing needs signing. Touch ID was not requested.\n");
        return Ok(());
    }

    let pending_outputs: Vec<_> = report
        .items
        .iter()
        .filter(|item| item.needs_signing)
        .map(|item| default_output_path(Path::new(&item.path)))
        .collect();
    let pending = pending_outputs.len();
    let prompt = format!(
        "Sign {pending} pending image{} and create published .banksy-signed copies?",
        if pending == 1 { "" } else { "s" }
    );
    let confirmed = Confirm::with_theme(theme)
        .with_prompt(prompt)
        .default(false)
        .interact_opt()
        .map_err(prompt_error)?
        .unwrap_or(false);
    if !confirmed {
        println!("Signing cancelled. Touch ID was not requested.\n");
        return Ok(());
    }

    let exit_code = crate::run(pending_sign_command(working_directory))?;
    if exit_code != 0 {
        println!("Signing finished with exit code {exit_code}.\n");
    } else {
        let outputs: Vec<_> = pending_outputs
            .into_iter()
            .filter(|path| path.is_file())
            .collect();
        if !outputs.is_empty()
            && Confirm::with_theme(theme)
                .with_prompt("Create a byte-preserving evidence ZIP for safe upload or transfer?")
                .default(true)
                .interact_opt()
                .map_err(prompt_error)?
                .unwrap_or(false)
        {
            let output = crate::bundle::default_bundle_path(working_directory)?;
            run_simple(Command::Package {
                paths: outputs,
                recursive: false,
                output: Some(output),
                force: false,
            })?;
        } else {
            println!();
        }
    }
    Ok(())
}

fn pending_sign_command(working_directory: &Path) -> Cli {
    Cli {
        json: false,
        command: Command::Sign {
            paths: vec![working_directory.to_path_buf()],
            recursive: true,
            published: true,
            description: None,
            force: false,
        },
    }
}

fn ensure_identity(theme: &ColorfulTheme) -> AppResult<bool> {
    let app_paths = AppPaths::discover()?;
    if app_paths.profile_file.exists() {
        Profile::load(&app_paths)?;
        return Ok(true);
    }

    println!("\nNo local signing identity is configured.");
    println!(
        "Setup creates public certificates under {} and keeps private keys in the macOS login Keychain.",
        app_paths.config_dir.display()
    );
    let create = Confirm::with_theme(theme)
        .with_prompt("Create the local identity now?")
        .default(true)
        .interact_opt()
        .map_err(prompt_error)?
        .unwrap_or(false);
    if !create {
        return Ok(false);
    }

    let exit_code = crate::run(Cli {
        json: false,
        command: Command::Init {
            name: None,
            organization: None,
            domain: None,
            uri: None,
            vendor: None,
            rotate_signer: false,
        },
    })?;
    Ok(exit_code == 0 && app_paths.profile_file.exists())
}

fn inspect_image(theme: &ColorfulTheme, working_directory: &Path) -> AppResult<()> {
    let Some(image) = select_image(theme, working_directory, "Choose an image to inspect")? else {
        return Ok(());
    };
    crate::run(Cli {
        json: false,
        command: Command::Inspect { image },
    })?;
    println!();
    Ok(())
}

fn verify_image(theme: &ColorfulTheme, working_directory: &Path) -> AppResult<()> {
    let Some(image) = select_image(theme, working_directory, "Choose an image to verify")? else {
        return Ok(());
    };
    let trust_local_root = AppPaths::discover()?.profile_file.exists();
    crate::run(Cli {
        json: false,
        command: Command::Verify {
            image,
            trust_local_root,
        },
    })?;
    println!();
    Ok(())
}

fn audit_target(theme: &ColorfulTheme, working_directory: &Path) -> AppResult<()> {
    let Some(target) = select_audit_target(theme, working_directory)? else {
        return Ok(());
    };
    run_simple(Command::Audit {
        paths: vec![target],
        recursive: false,
        expect_sha256: None,
    })
}

fn package_folder(theme: &ColorfulTheme, working_directory: &Path) -> AppResult<()> {
    if !ensure_identity(theme)? {
        return Ok(());
    }
    let confirmed = Confirm::with_theme(theme)
        .with_prompt("Package all locally signed images in this folder and its subfolders?")
        .default(true)
        .interact_opt()
        .map_err(prompt_error)?
        .unwrap_or(false);
    if !confirmed {
        println!("Packaging cancelled.\n");
        return Ok(());
    }
    let output = crate::bundle::default_bundle_path(working_directory)?;
    run_simple(Command::Package {
        paths: vec![working_directory.to_path_buf()],
        recursive: true,
        output: Some(output),
        force: false,
    })
}

fn select_audit_target(
    theme: &ColorfulTheme,
    working_directory: &Path,
) -> AppResult<Option<PathBuf>> {
    let mut paths = Vec::new();
    collect_audit_files(working_directory, &mut paths)?;
    paths.sort();
    let mut labels: Vec<_> = paths
        .iter()
        .map(|path| menu_path(path, working_directory))
        .collect();
    labels.push("Enter another path".into());
    labels.push("Back".into());
    let Some(selection) = Select::with_theme(theme)
        .with_prompt("Choose an image or evidence ZIP to audit")
        .items(&labels)
        .default(0)
        .interact_opt()
        .map_err(prompt_error)?
    else {
        return Ok(None);
    };
    if selection < paths.len() {
        return Ok(Some(paths.swap_remove(selection)));
    }
    if selection == paths.len() {
        let entered = Input::<String>::with_theme(theme)
            .with_prompt("Image or evidence ZIP path")
            .allow_empty(false)
            .interact_text()
            .map_err(prompt_error)?;
        return Ok(Some(resolve_path(&entered, working_directory)));
    }
    Ok(None)
}

fn collect_audit_files(directory: &Path, out: &mut Vec<PathBuf>) -> AppResult<()> {
    let entries = fs::read_dir(directory).map_err(|error| {
        AppError::runtime(format!("cannot read {}: {error}", directory.display()))
    })?;
    for entry in entries {
        let entry = entry
            .map_err(|error| AppError::runtime(format!("cannot read directory entry: {error}")))?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            AppError::runtime(format!("cannot inspect {}: {error}", path.display()))
        })?;
        if file_type.is_dir() {
            collect_audit_files(&path, out)?;
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| {
                    matches!(
                        extension.to_ascii_lowercase().as_str(),
                        "png" | "jpg" | "jpeg" | "zip"
                    )
                })
        {
            out.push(path);
        }
    }
    Ok(())
}

fn choose_working_directory(
    theme: &ColorfulTheme,
    working_directory: &Path,
) -> AppResult<Option<PathBuf>> {
    let entered = Input::<String>::with_theme(theme)
        .with_prompt("Working folder")
        .default(working_directory.to_string_lossy().into_owned())
        .allow_empty(false)
        .interact_text()
        .map_err(prompt_error)?;
    let candidate = resolve_path(&entered, working_directory);
    if !candidate.is_dir() {
        return Err(AppError::runtime(format!(
            "{} is not a readable directory",
            candidate.display()
        )));
    }
    candidate.canonicalize().map(Some).map_err(|error| {
        AppError::runtime(format!(
            "cannot open working directory {}: {error}",
            candidate.display()
        ))
    })
}

fn select_image(
    theme: &ColorfulTheme,
    working_directory: &Path,
    prompt: &str,
) -> AppResult<Option<PathBuf>> {
    let report = scan_working_directory(working_directory)?;
    let mut paths: Vec<PathBuf> = report
        .items
        .iter()
        .filter(|item| item.state != AssetState::Unreadable)
        .map(|item| PathBuf::from(&item.path))
        .collect();
    let mut labels: Vec<String> = report
        .items
        .iter()
        .filter(|item| item.state != AssetState::Unreadable)
        .map(|item| {
            format!(
                "{:<15} {}",
                short_state_label(item.state),
                menu_path(Path::new(&item.path), working_directory)
            )
        })
        .collect();
    labels.push("Enter another path".to_string());
    labels.push("Back".to_string());

    let Some(selection) = Select::with_theme(theme)
        .with_prompt(prompt)
        .items(&labels)
        .default(0)
        .interact_opt()
        .map_err(prompt_error)?
    else {
        return Ok(None);
    };

    if selection < paths.len() {
        return Ok(Some(paths.swap_remove(selection)));
    }
    if selection == paths.len() {
        let entered = Input::<String>::with_theme(theme)
            .with_prompt("Image path")
            .allow_empty(false)
            .interact_text()
            .map_err(prompt_error)?;
        return Ok(Some(resolve_path(&entered, working_directory)));
    }
    Ok(None)
}

const fn short_state_label(state: AssetState) -> &'static str {
    match state {
        AssetState::Unsigned => "Unsigned",
        AssetState::SignedExternal => "Foreign signed",
        AssetState::SignedLocal => "Local signed",
        AssetState::Covered => "Covered",
        AssetState::Invalid => "Invalid",
        AssetState::Unreadable => "Unreadable",
    }
}

fn resolve_path(entered: &str, working_directory: &Path) -> PathBuf {
    let trimmed = entered.trim();
    let expanded = if trimmed == "~" {
        std::env::var_os("HOME").map(PathBuf::from)
    } else if let Some(rest) = trimmed.strip_prefix("~/") {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(rest))
    } else {
        None
    };
    let path = expanded.unwrap_or_else(|| PathBuf::from(trimmed));
    if path.is_absolute() {
        path
    } else {
        working_directory.join(path)
    }
}

fn advanced_menu(theme: &ColorfulTheme, working_directory: &Path) -> AppResult<()> {
    loop {
        let actions = [
            "Initialize or repair local identity",
            "Show local identity",
            "Attest one image",
            "Create a signed derivative",
            "Rotate leaf signer",
            "Back",
        ];
        let Some(selection) = Select::with_theme(theme)
            .with_prompt("Advanced actions")
            .items(actions)
            .default(0)
            .interact_opt()
            .map_err(prompt_error)?
        else {
            return Ok(());
        };
        let action = AdvancedAction::from_index(selection)
            .ok_or_else(|| AppError::runtime("invalid advanced menu selection"))?;
        let result = match action {
            AdvancedAction::Initialize => run_simple(Command::Init {
                name: None,
                organization: None,
                domain: None,
                uri: None,
                vendor: None,
                rotate_signer: false,
            }),
            AdvancedAction::Identity => run_simple(Command::Identity),
            AdvancedAction::Attest => attest_one(theme, working_directory),
            AdvancedAction::Derivative => derivative(theme, working_directory),
            AdvancedAction::RotateSigner => rotate_signer(theme),
            AdvancedAction::Back => return Ok(()),
        };
        if let Err(error) = result {
            eprintln!("\nERROR: {error}\n");
        }
    }
}

fn run_simple(command: Command) -> AppResult<()> {
    crate::run(Cli {
        json: false,
        command,
    })?;
    println!();
    Ok(())
}

fn attest_one(theme: &ColorfulTheme, working_directory: &Path) -> AppResult<()> {
    if !ensure_identity(theme)? {
        return Ok(());
    }
    let Some(input) = select_image(theme, working_directory, "Choose an image to attest")? else {
        return Ok(());
    };
    let published = confirm_publication(theme)?;
    let description = optional_description(theme, DEFAULT_ATTEST_DESCRIPTION)?;
    let output = default_output_path(&input);
    let Some(force) = confirm_overwrite(theme, &output)? else {
        println!("Attestation cancelled.\n");
        return Ok(());
    };
    run_simple(Command::Attest {
        input,
        output: Some(output),
        published,
        description,
        force,
    })
}

fn derivative(theme: &ColorfulTheme, working_directory: &Path) -> AppResult<()> {
    if !ensure_identity(theme)? {
        return Ok(());
    }
    let Some(parent) = select_image(theme, working_directory, "Choose the parent image")? else {
        return Ok(());
    };
    let Some(input) = select_image(theme, working_directory, "Choose the edited image")? else {
        return Ok(());
    };
    let published = confirm_publication(theme)?;
    let description = optional_description(theme, DEFAULT_DERIVATIVE_DESCRIPTION)?;
    let output = default_output_path(&input);
    let Some(force) = confirm_overwrite(theme, &output)? else {
        println!("Derivative signing cancelled.\n");
        return Ok(());
    };
    run_simple(Command::Derivative {
        parent,
        input,
        output: Some(output),
        published,
        description,
        force,
    })
}

fn confirm_publication(theme: &ColorfulTheme) -> AppResult<bool> {
    Confirm::with_theme(theme)
        .with_prompt("Record a c2pa.published action?")
        .default(true)
        .interact_opt()
        .map(|answer| answer.unwrap_or(false))
        .map_err(prompt_error)
}

fn optional_description(theme: &ColorfulTheme, default: &str) -> AppResult<Option<String>> {
    let description = Input::<String>::with_theme(theme)
        .with_prompt("Description")
        .default(default.to_string())
        .allow_empty(true)
        .interact_text()
        .map_err(prompt_error)?;
    let trimmed = description.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
}

fn confirm_overwrite(theme: &ColorfulTheme, output: &Path) -> AppResult<Option<bool>> {
    if !output.exists() {
        return Ok(Some(false));
    }
    Confirm::with_theme(theme)
        .with_prompt(format!(
            "{} already exists. Replace it after validating the new file?",
            output.display()
        ))
        .default(false)
        .interact_opt()
        .map(|answer| answer.filter(|confirmed| *confirmed))
        .map_err(prompt_error)
}

fn rotate_signer(theme: &ColorfulTheme) -> AppResult<()> {
    if !ensure_identity(theme)? {
        return Ok(());
    }
    let confirmed = Confirm::with_theme(theme)
        .with_prompt("Rotate the active leaf signer? This requires macOS authentication")
        .default(false)
        .interact_opt()
        .map_err(prompt_error)?
        .unwrap_or(false);
    if confirmed {
        run_simple(Command::Init {
            name: None,
            organization: None,
            domain: None,
            uri: None,
            vendor: None,
            rotate_signer: true,
        })?;
    }
    Ok(())
}

fn prompt_error(error: dialoguer::Error) -> AppError {
    AppError::runtime(format!("terminal prompt failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_indices_have_stable_meaning() {
        assert_eq!(MainAction::from_index(0), Some(MainAction::Status));
        assert_eq!(MainAction::from_index(1), Some(MainAction::Sign));
        assert_eq!(
            MainAction::from_index(MAIN_ACTIONS - 1),
            Some(MainAction::Quit)
        );
        assert_eq!(MainAction::from_index(MAIN_ACTIONS), None);
    }

    #[test]
    fn status_labels_distinguish_foreign_and_local_signatures() {
        assert_eq!(
            state_label(AssetState::SignedExternal),
            "Foreign signed — needs local signature"
        );
        assert_eq!(
            state_label(AssetState::SignedLocal),
            "Local signed — already signed locally"
        );
    }

    #[test]
    fn simple_signing_is_recursive_published_and_never_forced() {
        let cli = pending_sign_command(Path::new("/tmp/images"));
        let Command::Sign {
            paths,
            recursive,
            published,
            description,
            force,
        } = cli.command
        else {
            panic!("expected sign command");
        };
        assert_eq!(paths, vec![PathBuf::from("/tmp/images")]);
        assert!(recursive);
        assert!(published);
        assert_eq!(description, None);
        assert!(!force);
    }

    #[test]
    fn relative_and_home_paths_resolve_from_the_working_folder() {
        let working = Path::new("/tmp/images");
        assert_eq!(
            resolve_path("nested/a.png", working),
            working.join("nested/a.png")
        );
        assert!(resolve_path("~/a.png", working).is_absolute());
    }

    #[test]
    fn menu_path_removes_the_working_directory_prefix() {
        let working = Path::new("/tmp/images");
        assert_eq!(
            menu_path(Path::new("/tmp/images/nested/a.png"), working),
            "nested/a.png"
        );
    }
}
