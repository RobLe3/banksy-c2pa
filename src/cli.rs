use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "banksy-c2pa",
    version,
    about = "Local C2PA editorial provenance signer",
    long_about = "Sign PNG and JPEG images with truthful C2PA editorial provenance. Private keys remain in the local macOS login Keychain, and LocalAuthentication requires user presence immediately before retrieval."
)]
pub struct Cli {
    /// Emit a machine-readable JSON report.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the local identity, certificates, and profile.
    Init {
        /// Public name for the local signer certificate.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,

        /// Optional organization for the certificate subject.
        #[arg(long, value_name = "ORGANIZATION")]
        organization: Option<String>,

        /// Optional DNS name for the certificate SAN and manifest metadata.
        #[arg(long, value_name = "DOMAIN")]
        domain: Option<String>,

        /// Optional URI for the certificate SAN and manifest metadata.
        #[arg(long, value_name = "URI")]
        uri: Option<String>,

        /// Optional C2PA manifest vendor value.
        #[arg(long, value_name = "VENDOR")]
        vendor: Option<String>,

        /// Issue a new leaf signer using the existing protected root key.
        #[arg(long)]
        rotate_signer: bool,
    },

    /// Show configured project and public signer identity without opening Keychain secrets.
    Identity,

    /// Inspect an image and any embedded Content Credentials.
    Inspect {
        /// PNG or JPEG image to inspect.
        image: PathBuf,
    },

    /// List images that need the configured local signature.
    Status {
        /// Files or directories to scan; defaults to the current directory.
        paths: Vec<PathBuf>,

        /// Include supported images in nested directories.
        #[arg(short, long)]
        recursive: bool,

        /// Exit with status 3 when pending or invalid images are found.
        #[arg(long)]
        check: bool,
    },

    /// Attest every pending image with one authentication prompt.
    Sign {
        /// PNG/JPEG files or directories; defaults to the current directory.
        paths: Vec<PathBuf>,

        /// Include supported images in nested directories.
        #[arg(short, long)]
        recursive: bool,

        /// Add an explicit c2pa.published action to every new claim.
        #[arg(long)]
        published: bool,

        /// Human-readable description used for every new attestation.
        #[arg(long)]
        description: Option<String>,

        /// Atomically replace colliding signed-copy destinations after validation.
        #[arg(long)]
        force: bool,
    },

    /// Sign an image without claiming that its pixels were edited.
    Attest {
        /// Existing PNG or JPEG image.
        input: PathBuf,

        /// Destination; defaults to NAME.banksy-signed.EXT.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Add an explicit c2pa.published action.
        #[arg(long)]
        published: bool,

        /// Human-readable description of the metadata/publication attestation.
        #[arg(long)]
        description: Option<String>,

        /// Atomically replace an existing destination after the new file validates.
        #[arg(long)]
        force: bool,
    },

    /// Sign a real edited image as a derivative of a parent image.
    Derivative {
        /// Parent asset from which the edited result was made.
        #[arg(long)]
        parent: PathBuf,

        /// Edited PNG or JPEG result to sign.
        #[arg(long)]
        input: PathBuf,

        /// Destination; defaults to NAME.banksy-signed.EXT.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Add an explicit c2pa.published action.
        #[arg(long)]
        published: bool,

        /// Human-readable description of the editorial work.
        #[arg(long)]
        description: Option<String>,

        /// Atomically replace an existing destination after the new file validates.
        #[arg(long)]
        force: bool,
    },

    /// Validate an image's C2PA manifest and report trust separately.
    Verify {
        /// Signed PNG or JPEG image.
        image: PathBuf,

        /// Add this profile's root only as a local trust anchor.
        #[arg(long)]
        trust_local_root: bool,
    },

    /// Audit embedded credentials, checksums, or an evidence ZIP.
    Audit {
        /// PNG, JPEG, evidence ZIP, or directories; defaults to the current directory.
        paths: Vec<PathBuf>,

        /// Include supported files in nested directories.
        #[arg(short, long)]
        recursive: bool,

        /// Require one target to have this exact SHA-256.
        #[arg(long, value_name = "HASH")]
        expect_sha256: Option<String>,
    },

    /// Package locally signed images in a byte-preserving evidence ZIP.
    Package {
        /// Locally signed PNG/JPEG files or directories; defaults to the current directory.
        paths: Vec<PathBuf>,

        /// Include locally signed files in nested directories.
        #[arg(short, long)]
        recursive: bool,

        /// ZIP destination; defaults to a timestamped file in the current directory.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Atomically replace an existing evidence ZIP.
        #[arg(long)]
        force: bool,
    },
}
