use std::io::IsTerminal;

use dialoguer::{Confirm, Input, theme::ColorfulTheme};

use crate::{
    config::{AppPaths, Identity},
    error::{AppError, AppResult},
};

#[derive(Debug, Default)]
pub struct IdentityOptions {
    pub name: Option<String>,
    pub organization: Option<String>,
    pub domain: Option<String>,
    pub uri: Option<String>,
    pub vendor: Option<String>,
}

impl IdentityOptions {
    fn has_any(&self) -> bool {
        self.name.is_some()
            || self.organization.is_some()
            || self.domain.is_some()
            || self.uri.is_some()
            || self.vendor.is_some()
    }
}

pub fn identity_for_init(
    paths: &AppPaths,
    options: IdentityOptions,
    rotate_signer: bool,
    json: bool,
) -> AppResult<Option<Identity>> {
    if rotate_signer && options.has_any() {
        return Err(AppError::usage(
            "identity options cannot be combined with --rotate-signer",
        ));
    }

    if paths.profile_file.exists() {
        if options.has_any() {
            return Err(AppError::usage(
                "identity options are only accepted when creating a new profile; existing identities are never rewritten automatically",
            ));
        }
        return Ok(None);
    }

    if rotate_signer {
        return Err(AppError::usage(
            "cannot rotate a signer before an identity exists; run `banksy-c2pa init --name <NAME>` first",
        ));
    }

    let interactive = !json
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal();
    if interactive {
        interactive_identity(options).map(Some)
    } else {
        identity_from_options(options).map(Some)
    }
}

fn identity_from_options(options: IdentityOptions) -> AppResult<Identity> {
    let signer_name = required("--name", options.name)?;
    Ok(Identity {
        signer_name,
        organization: optional("--organization", options.organization)?,
        domain: optional("--domain", options.domain)?,
        uri: optional("--uri", options.uri)?,
        vendor: optional("--vendor", options.vendor)?,
    })
}

fn interactive_identity(options: IdentityOptions) -> AppResult<Identity> {
    let theme = ColorfulTheme::default();
    println!("\nConfigure the public identity recorded in your local certificate.");
    println!("Optional fields can be left blank. They do not establish public C2PA trust.\n");

    let signer_name = match options.name {
        Some(value) => required("--name", Some(value))?,
        None => Input::<String>::with_theme(&theme)
            .with_prompt("Signer name")
            .default("banksy-c2pa local signer".to_string())
            .validate_with(|value: &String| {
                if value.trim().is_empty() {
                    Err("signer name must not be empty")
                } else {
                    Ok(())
                }
            })
            .interact_text()
            .map_err(prompt_error)?
            .trim()
            .to_string(),
    };
    let organization = prompt_optional(&theme, "Organization", options.organization)?;
    let domain = prompt_optional(&theme, "Domain", options.domain)?;
    let uri = prompt_optional(&theme, "Identity URI", options.uri)?;
    let vendor = prompt_optional(&theme, "Manifest vendor", options.vendor)?;

    println!("\nIdentity summary");
    println!("  Signer name:  {signer_name}");
    println!("  Organization: {}", shown(&organization));
    println!("  Domain:       {}", shown(&domain));
    println!("  URI:          {}", shown(&uri));
    println!("  Vendor:       {}", shown(&vendor));
    let confirmed = Confirm::with_theme(&theme)
        .with_prompt("Create this local identity?")
        .default(true)
        .interact_opt()
        .map_err(prompt_error)?
        .unwrap_or(false);
    if !confirmed {
        return Err(AppError::runtime("identity setup cancelled"));
    }

    Ok(Identity {
        signer_name,
        organization,
        domain,
        uri,
        vendor,
    })
}

fn prompt_optional(
    theme: &ColorfulTheme,
    prompt: &str,
    supplied: Option<String>,
) -> AppResult<Option<String>> {
    if supplied.is_some() {
        return optional(prompt, supplied);
    }
    let value = Input::<String>::with_theme(theme)
        .with_prompt(format!("{prompt} (optional)"))
        .allow_empty(true)
        .interact_text()
        .map_err(prompt_error)?;
    Ok(trimmed(value))
}

fn required(flag: &str, value: Option<String>) -> AppResult<String> {
    let value = value.ok_or_else(|| {
        AppError::usage(format!(
            "{flag} is required when creating an identity without an interactive terminal"
        ))
    })?;
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::usage(format!("{flag} must not be empty")));
    }
    Ok(value.to_string())
}

fn optional(flag: &str, value: Option<String>) -> AppResult<Option<String>> {
    match value {
        Some(value) if value.trim().is_empty() => Err(AppError::usage(format!(
            "{flag} must not be empty; omit the option instead"
        ))),
        Some(value) => Ok(Some(value.trim().to_string())),
        None => Ok(None),
    }
}

fn trimmed(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn shown(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("not configured")
}

fn prompt_error(error: dialoguer::Error) -> AppError {
    AppError::runtime(format!("terminal prompt failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noninteractive_setup_requires_a_name() {
        let error = identity_from_options(IdentityOptions::default()).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert!(error.to_string().contains("--name is required"));
    }

    #[test]
    fn optional_identity_fields_are_really_optional() {
        let identity = identity_from_options(IdentityOptions {
            name: Some("Example signer".into()),
            ..IdentityOptions::default()
        })
        .unwrap();
        assert_eq!(identity.signer_name, "Example signer");
        assert_eq!(identity.organization, None);
        assert_eq!(identity.domain, None);
        assert_eq!(identity.uri, None);
        assert_eq!(identity.vendor, None);
    }

    #[test]
    fn explicit_empty_optional_value_is_a_usage_error() {
        let error = identity_from_options(IdentityOptions {
            name: Some("Example signer".into()),
            organization: Some("  ".into()),
            ..IdentityOptions::default()
        })
        .unwrap_err();
        assert_eq!(error.exit_code(), 2);
    }
}
