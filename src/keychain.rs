use zeroize::Zeroizing;

use crate::{
    config::KeychainBackend,
    error::{AppError, AppResult},
};

/// Stores a PKCS#8 private key in the user's local login Keychain.
///
/// A conventional Cargo-built CLI has no provisioned application identifier,
/// so macOS rejects Data Protection Keychain items with biometric ACLs. This
/// backend remains usable for a normal command-line installation and pairs
/// every read with an explicit LocalAuthentication check.
#[cfg(target_os = "macos")]
pub fn store_secret(
    backend: KeychainBackend,
    service: &str,
    account: &str,
    secret: &[u8],
    label: &str,
) -> AppResult<()> {
    use security_framework::passwords::{PasswordOptions, set_generic_password_options};

    match backend {
        KeychainBackend::LoginKeychainLocalAuthentication => {}
    }
    let mut options = PasswordOptions::new_generic_password(service, account);
    options.set_label(label);
    options.set_description("C2PA ES256 private key; authentication required by banksy-c2pa");
    options.set_comment("Managed by banksy-c2pa. Stored in the local login Keychain.");

    set_generic_password_options(secret, options).map_err(|e| {
        AppError::runtime(format!(
            "cannot store private key in the macOS login Keychain: {e}"
        ))
    })
}

/// Authenticates the user, then retrieves a secret exactly once for the
/// caller's operation. The two steps are adjacent but not an atomic Keychain
/// access-control operation; see SECURITY.md for the distinction.
#[cfg(target_os = "macos")]
pub fn retrieve_secret(
    backend: KeychainBackend,
    service: &str,
    account: &str,
) -> AppResult<Zeroizing<Vec<u8>>> {
    use security_framework::passwords::{PasswordOptions, generic_password};

    match backend {
        KeychainBackend::LoginKeychainLocalAuthentication => {
            require_user_authentication("use the C2PA signing key")?;
        }
    }

    let options = PasswordOptions::new_generic_password(service, account);

    generic_password(options)
        .map(Zeroizing::new)
        .map_err(|e| {
            AppError::runtime(format!(
                "cannot retrieve `{account}` from the macOS Keychain: {e}. Authentication was denied, cancelled, or the item is missing"
            ))
        })
}

/// Runs Apple's LocalAuthentication policy and waits for its asynchronous
/// reply. The policy lets macOS offer Touch ID first on a configured Mac while
/// retaining the account-password fallback.
#[cfg(target_os = "macos")]
fn require_user_authentication(reason: &str) -> AppResult<()> {
    use std::sync::mpsc;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    let policy = LAPolicy::DeviceOwnerAuthentication;

    // SAFETY: LAContext is an Apple framework class and `new` returns an owned,
    // initialized instance. The generated binding marks Objective-C messaging
    // unsafe because Rust cannot prove the runtime class contract.
    let context = unsafe { LAContext::new() };
    // SAFETY: `context` is initialized and `policy` is a documented LAPolicy.
    unsafe { context.canEvaluatePolicy_error(policy) }.map_err(|error| {
        AppError::runtime(format!(
            "macOS user authentication is unavailable: {}",
            error.localizedDescription()
        ))
    })?;

    let localized_reason = NSString::from_str(reason);
    let (sender, receiver) = mpsc::sync_channel::<Result<(), String>>(1);
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let result = if success.as_bool() {
            Ok(())
        } else if error.is_null() {
            Err("authentication failed without an error description".to_string())
        } else {
            // SAFETY: LocalAuthentication supplies a valid NSError for the
            // duration of this reply block when `success` is false. Convert it
            // to an owned Rust String before the block returns.
            let description = unsafe { (&*error).localizedDescription().to_string() };
            Err(description)
        };
        let _ = sender.send(result);
    });

    // SAFETY: The context and reason are valid for this call. `reply` is owned,
    // sendable, and stays alive while we wait for the asynchronous result.
    unsafe { context.evaluatePolicy_localizedReason_reply(policy, &localized_reason, &reply) };

    receiver
        .recv()
        .map_err(|_| AppError::runtime("macOS authentication ended without a result"))?
        .map_err(|message| {
            AppError::runtime(format!("authentication was not completed: {message}"))
        })
}

#[cfg(not(target_os = "macos"))]
pub fn store_secret(
    _backend: KeychainBackend,
    _service: &str,
    _account: &str,
    _secret: &[u8],
    _label: &str,
) -> AppResult<()> {
    Err(AppError::runtime(
        "version 1 supports private-key storage only on macOS",
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn retrieve_secret(
    _backend: KeychainBackend,
    _service: &str,
    _account: &str,
) -> AppResult<Zeroizing<Vec<u8>>> {
    Err(AppError::runtime(
        "version 1 supports private-key retrieval only on macOS",
    ))
}

#[cfg(all(test, target_os = "macos"))]
mod integration_tests {
    /// Deliberately ignored because it opens a system authentication dialog.
    /// Run manually with `cargo test keychain_user_presence -- --ignored`.
    #[test]
    #[ignore = "requires interactive macOS user-presence authentication"]
    fn keychain_user_presence() {
        use security_framework::passwords::delete_generic_password;

        let account = format!("integration-test-{}", std::process::id());
        let service = "com.roblemumin.banksy-c2pa.tests";
        let backend = crate::config::KeychainBackend::default();
        super::store_secret(
            backend,
            service,
            &account,
            b"test-only-secret",
            "banksy-c2pa test",
        )
        .unwrap();
        let found = super::retrieve_secret(backend, service, &account).unwrap();
        assert_eq!(&*found, b"test-only-secret");
        delete_generic_password(service, &account).unwrap();
    }
}
