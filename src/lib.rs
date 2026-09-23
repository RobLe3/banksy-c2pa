#![deny(unsafe_op_in_unsafe_fn)]

pub mod audit;
pub mod batch;
pub mod bundle;
pub mod cli;
pub mod config;
pub mod container;
pub mod error;
pub mod image_info;
pub mod keychain;
pub mod menu;
pub mod pki;
pub mod provenance;
pub mod scan;
pub mod setup;
pub mod signing;

use std::path::Path;

use cli::{Cli, Command};
use config::AppPaths;
use error::{AppError, AppResult};

pub fn run(cli: Cli) -> AppResult<u8> {
    let paths = AppPaths::discover()?;

    match cli.command {
        Command::Init {
            name,
            organization,
            domain,
            uri,
            vendor,
            rotate_signer,
        } => {
            let identity = setup::identity_for_init(
                &paths,
                setup::IdentityOptions {
                    name,
                    organization,
                    domain,
                    uri,
                    vendor,
                },
                rotate_signer,
                cli.json,
            )?;
            let report = pki::initialize(&paths, rotate_signer, identity)?;
            print_value(&report, cli.json)?;
            Ok(0)
        }
        Command::Identity => {
            let profile = config::Profile::load(&paths)?;
            let report = pki::identity_report(&paths, &profile)?;
            print_value(&report, cli.json)?;
            Ok(0)
        }
        Command::Inspect { image } => {
            let report = provenance::inspect_asset(&image, None)?;
            print_value(&report, cli.json)?;
            Ok(0)
        }
        Command::Status {
            paths: roots,
            recursive,
            check,
        } => {
            let root = scan::load_local_root(&paths)?;
            let report = scan::scan_paths(&roots, recursive, root.as_deref())?;
            let exit_code = if report.summary.has_runtime_issues() {
                1
            } else if check && report.summary.has_policy_issues() {
                3
            } else {
                0
            };
            print_value(&report, cli.json)?;
            Ok(exit_code)
        }
        Command::Sign {
            paths: roots,
            recursive,
            published,
            description,
            force,
        } => {
            let profile = config::Profile::load(&paths)?;
            let report = batch::sign_paths(
                &paths,
                &profile,
                &roots,
                recursive,
                description.as_deref(),
                published,
                force,
            )?;
            let exit_code = report.exit_code();
            print_value(&report, cli.json)?;
            Ok(exit_code)
        }
        Command::Attest {
            input,
            output,
            published,
            description,
            force,
        } => {
            let profile = config::Profile::load(&paths)?;
            let output = output.unwrap_or_else(|| signing::default_output_path(&input));
            let report = signing::attest(
                &paths,
                &profile,
                &input,
                &output,
                description.as_deref(),
                published,
                force,
            )?;
            print_value(&report, cli.json)?;
            Ok(0)
        }
        Command::Derivative {
            parent,
            input,
            output,
            published,
            description,
            force,
        } => {
            let profile = config::Profile::load(&paths)?;
            let output = output.unwrap_or_else(|| signing::default_output_path(&input));
            let report = signing::derivative(
                &paths,
                &profile,
                &parent,
                &input,
                &output,
                description.as_deref(),
                published,
                force,
            )?;
            print_value(&report, cli.json)?;
            Ok(0)
        }
        Command::Verify {
            image,
            trust_local_root,
        } => {
            let root = if trust_local_root {
                let profile = config::Profile::load(&paths)?;
                Some(
                    std::fs::read_to_string(paths.root_certificate(&profile)).map_err(|e| {
                        AppError::runtime(format!("cannot read the local root certificate: {e}"))
                    })?,
                )
            } else {
                None
            };
            let report = provenance::verify_asset(&image, root.as_deref(), trust_local_root)?;
            print_value(&report, cli.json)?;
            if !report.signature_valid {
                return Ok(3);
            }
            Ok(0)
        }
        Command::Audit {
            paths: roots,
            recursive,
            expect_sha256,
        } => {
            let report = audit::audit_paths(&paths, &roots, recursive, expect_sha256.as_deref())?;
            let exit_code = report.exit_code();
            print_value(&report, cli.json)?;
            Ok(exit_code)
        }
        Command::Package {
            paths: roots,
            recursive,
            output,
            force,
        } => {
            let output = match output {
                Some(output) => output,
                None => bundle::default_bundle_path(Path::new("."))?,
            };
            let report = bundle::create_bundle(&paths, &roots, recursive, &output, force)?;
            print_value(&report, cli.json)?;
            Ok(0)
        }
    }
}

fn print_value<T>(value: &T, json: bool) -> AppResult<()>
where
    T: serde::Serialize + std::fmt::Display,
{
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(value)
                .map_err(|e| AppError::runtime(format!("cannot serialize report: {e}")))?
        );
    } else {
        println!("{value}");
    }
    Ok(())
}

pub(crate) fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
