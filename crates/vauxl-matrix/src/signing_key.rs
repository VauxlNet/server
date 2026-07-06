//! Homeserver Ed25519 signing key.
//!
//! Generated on first start, persisted to disk, loaded on every subsequent start.
//! Every Matrix event the homeserver creates is signed with this key.
//! The public key is published at /_matrix/key/v2/server for federation.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::path::Path;

/// The homeserver's Ed25519 signing keypair.
pub struct HomeserverSigningKey {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    /// Key ID used in Matrix signatures, e.g. "ed25519:a"
    pub key_id: String,
}

impl HomeserverSigningKey {
    /// Load the signing key from disk, or generate and save a new one.
    pub fn load_or_generate(path: &str) -> Result<Self> {
        let path = Path::new(path);

        let signing_key = if path.exists() {
            load_key(path).context("Failed to load signing key")?
        } else {
            let key = generate_key();
            save_key(path, &key).context("Failed to save signing key")?;
            tracing::info!("Generated new homeserver signing key at {}", path.display());
            key
        };

        let verifying_key = signing_key.verifying_key();
        let key_id = "ed25519:a".to_string();

        tracing::info!(
            key_id = %key_id,
            public_key = %BASE64.encode(verifying_key.as_bytes()),
            "Loaded homeserver signing key"
        );

        Ok(Self {
            signing_key,
            verifying_key,
            key_id,
        })
    }

    /// Returns the public key as an unpadded base64 string (Matrix wire format).
    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.verifying_key.as_bytes())
    }
}

fn generate_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn save_key(path: &Path, key: &SigningKey) -> Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create signing key directory")?;
    }
    // Store as hex — simple, human-inspectable
    let hex = hex::encode(key.to_bytes());
    // Private key material: create with owner-only permissions from the start
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("Failed to create signing key file")?;
    file.write_all(hex.as_bytes())
        .context("Failed to write signing key")?;
    Ok(())
}

fn load_key(path: &Path) -> Result<SigningKey> {
    let hex = std::fs::read_to_string(path).context("Failed to read signing key file")?;
    let bytes = hex::decode(hex.trim()).context("Signing key file contains invalid hex")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}
