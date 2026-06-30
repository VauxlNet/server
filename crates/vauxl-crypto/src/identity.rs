//! Ed25519 Identitätsschlüssel für Matrix-Geräte.

use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::ZeroizeOnDrop;

/// Ein Ed25519-Schlüsselpaar für die Geräteidentität.
/// Der private Schlüssel wird beim Drop sicher aus dem Speicher gelöscht.
#[derive(ZeroizeOnDrop)]
pub struct IdentityKeypair {
    #[zeroize(skip)]
    pub verifying_key: VerifyingKey,
    signing_key: SigningKey,
}

impl IdentityKeypair {
    /// Generiert ein neues zufälliges Ed25519-Schlüsselpaar.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    /// Gibt den öffentlichen Schlüssel als Base64-String zurück (Matrix-Format).
    pub fn public_key_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .encode(self.verifying_key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = IdentityKeypair::generate();
        let b64 = kp.public_key_base64();
        // Ed25519 public key = 32 bytes = 44 base64 chars (mit padding)
        assert_eq!(b64.len(), 44);
    }
}
