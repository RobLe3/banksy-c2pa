use std::process::Command;

use image::{ImageBuffer, Rgba};
use predicates::prelude::*;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_banksy-c2pa"))
}

#[test]
fn help_lists_the_semantically_distinct_signing_commands() {
    let output = binary().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(predicate::str::contains("attest").eval(&stdout));
    assert!(predicate::str::contains("derivative").eval(&stdout));
    assert!(predicate::str::contains("verify").eval(&stdout));
    assert!(predicate::str::contains("status").eval(&stdout));
    assert!(predicate::str::contains("sign").eval(&stdout));
    assert!(predicate::str::contains("audit").eval(&stdout));
    assert!(predicate::str::contains("package").eval(&stdout));
}

#[test]
fn no_arguments_on_non_terminal_input_prints_usage_instead_of_waiting() {
    let output = binary().output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(predicate::str::contains("Usage: banksy-c2pa [OPTIONS] <COMMAND>").eval(&stderr));
}

#[test]
fn sign_without_paths_defaults_to_the_current_directory() {
    let directory = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let output = binary()
        .current_dir(directory.path())
        .env("BANKSY_C2PA_CONFIG_DIR", config.path())
        .arg("sign")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(predicate::str::contains("run `banksy-c2pa init` first").eval(&stderr));
    assert!(!predicate::str::contains("required arguments").eval(&stderr));
}

#[test]
fn status_classifies_unsigned_images_and_check_uses_exit_three() {
    let directory = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let image = directory.path().join("plain image.PNG");
    ImageBuffer::from_pixel(2, 2, Rgba([1_u8, 2, 3, 255]))
        .save(&image)
        .unwrap();

    let output = binary()
        .env("BANKSY_C2PA_CONFIG_DIR", config.path())
        .arg("status")
        .arg(directory.path())
        .args(["--check", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["needs_signing"], 1);
    assert_eq!(report["items"][0]["state"], "unsigned");
    assert_eq!(report["items"][0]["needs_signing"], true);
}

#[test]
fn status_reports_missing_explicit_path_as_runtime_failure() {
    let config = tempfile::tempdir().unwrap();
    let output = binary()
        .env("BANKSY_C2PA_CONFIG_DIR", config.path())
        .args(["status", "missing.png", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["items"][0]["state"], "unreadable");
}

#[test]
fn unsigned_image_fails_verification_with_exit_three() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("unsigned.png");
    ImageBuffer::from_pixel(2, 2, Rgba([1_u8, 2, 3, 255]))
        .save(&image)
        .unwrap();

    let output = binary().arg("verify").arg(&image).output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(predicate::str::contains("Claim signature and asset binding\n  invalid").eval(&stdout));
}

#[test]
fn clap_usage_errors_use_exit_two() {
    let output = binary().arg("derivative").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn noninteractive_init_requires_a_signer_name() {
    let config = tempfile::tempdir().unwrap();
    let output = binary()
        .env("BANKSY_C2PA_CONFIG_DIR", config.path())
        .args(["init", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(report["exit_code"], 2);
    assert!(report["error"].as_str().unwrap().contains("--name"));
}

#[test]
fn rotation_rejects_identity_options_before_key_access() {
    let config = tempfile::tempdir().unwrap();
    let output = binary()
        .env("BANKSY_C2PA_CONFIG_DIR", config.path())
        .args(["init", "--rotate-signer", "--name", "Replacement signer"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("cannot be combined")
    );
}

#[test]
fn existing_profile_rejects_identity_replacement() {
    let config = tempfile::tempdir().unwrap();
    std::fs::write(config.path().join("profile.toml"), "existing = true\n").unwrap();
    let output = binary()
        .env("BANKSY_C2PA_CONFIG_DIR", config.path())
        .args(["init", "--name", "Replacement signer"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("existing identities are never rewritten")
    );
}

#[test]
fn inspect_json_is_machine_readable() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("plain.png");
    ImageBuffer::from_pixel(2, 2, Rgba([1_u8, 2, 3, 255]))
        .save(&image)
        .unwrap();

    let output = binary()
        .args(["inspect", "--json"])
        .arg(&image)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "ok");
    assert_eq!(report["c2pa"]["present"], false);
    assert_eq!(report["file"]["format"], "image/png");
}

#[test]
fn audit_reports_a_stripped_managed_file_with_exit_three() {
    let directory = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let image = directory.path().join("plain.banksy-signed.png");
    ImageBuffer::from_pixel(2, 2, Rgba([1_u8, 2, 3, 255]))
        .save(&image)
        .unwrap();

    let output = binary()
        .env("BANKSY_C2PA_CONFIG_DIR", config.path())
        .args(["audit", "--json"])
        .arg(&image)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["targets"][0]["state"], "missing-credential");
    assert_eq!(report["targets"][0]["container"]["embedded"], false);
}

#[test]
fn audit_enforces_an_expected_sha256() {
    let directory = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let image = directory.path().join("plain.png");
    ImageBuffer::from_pixel(2, 2, Rgba([1_u8, 2, 3, 255]))
        .save(&image)
        .unwrap();

    let output = binary()
        .env("BANKSY_C2PA_CONFIG_DIR", config.path())
        .args(["audit", "--expect-sha256", &"0".repeat(64), "--json"])
        .arg(&image)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["targets"][0]["state"], "hash-mismatch");
}
