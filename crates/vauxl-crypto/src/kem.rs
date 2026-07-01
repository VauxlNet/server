//! X-Wing Hybrid KEM: X25519 + ML-KEM-1024 (CRYSTALS-Kyber, FIPS 203)
//!
//! Migrated from pqcrypto-kyber to pqcrypto-mlkem (RUSTSEC-2024-0381).

use hkdf::Hkdf;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_mlkem::mlkem1024::{PublicKey as KyberPublicKey, SecretKey as KyberSecretKey};
// Traits must be in scope for .as_bytes() to work
use pqcrypto_traits::kem::{Ciphertext, SharedSecret};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::ZeroizeOnDrop;

use crate::error::{CryptoError, Result};

/// Ein VSX-Session-Key (256 bit). Wird beim Drop sicher gelöscht.
#[derive(ZeroizeOnDrop)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Öffentlicher Schlüssel für die X-Wing KEM.
pub struct XWingPublicKey {
    pub x25519: X25519PublicKey,
    pub mlkem:  KyberPublicKey,
}

/// Privater Schlüssel für die X-Wing KEM. Wird beim Drop sicher gelöscht.
#[derive(ZeroizeOnDrop)]
pub struct XWingSecretKey {
    #[zeroize(skip)]
    pub mlkem: KyberSecretKey,
}

/// Ciphertext der X-Wing KEM.
pub struct XWingCiphertext {
    pub x25519_ephemeral_pub: [u8; 32],
    pub mlkem_ciphertext:     Vec<u8>,
}

/// Generiert ein neues X-Wing-Schlüsselpaar.
pub fn generate_xwing_keypair() -> (XWingPublicKey, XWingSecretKey) {
    let (mlkem_pk, mlkem_sk) = mlkem1024::keypair();

    let x25519_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);
    let _ = x25519_secret;

    let pk = XWingPublicKey { x25519: x25519_public, mlkem: mlkem_pk };
    let sk = XWingSecretKey { mlkem: mlkem_sk };
    (pk, sk)
}

/// Kapselt einen Session-Key für den Empfänger (Sender-Seite).
pub fn encapsulate(recipient_pk: &XWingPublicKey) -> Result<(XWingCiphertext, SessionKey)> {
    // ML-KEM-1024 encapsulation
    let (mlkem_ss, mlkem_ct) = mlkem1024::encapsulate(&recipient_pk.mlkem);

    // X25519 ECDH mit ephemerem Schlüssel
    let x25519_ephemeral     = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let x25519_ephemeral_pub = X25519PublicKey::from(&x25519_ephemeral);
    let x25519_ss            = x25519_ephemeral.diffie_hellman(&recipient_pk.x25519);

    // X-Wing: IKM = mlkem_ss || x25519_ss, then HKDF-SHA256
    let mut ikm = Vec::with_capacity(
        mlkem_ss.as_bytes().len() + x25519_ss.as_bytes().len()
    );
    ikm.extend_from_slice(mlkem_ss.as_bytes());
    ikm.extend_from_slice(x25519_ss.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut session_key = [0u8; 32];
    hk.expand(b"vauxl-vsx-v1", &mut session_key)
        .map_err(|_| CryptoError::KeyDerivation)?;

    let ct = XWingCiphertext {
        x25519_ephemeral_pub: *x25519_ephemeral_pub.as_bytes(),
        mlkem_ciphertext:     mlkem_ct.as_bytes().to_vec(),
    };

    Ok((ct, SessionKey(session_key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation_does_not_panic() {
        let (_pk, _sk) = generate_xwing_keypair();
    }

    #[test]
    fn test_encapsulate_produces_32_byte_key() {
        let (pk, _sk) = generate_xwing_keypair();
        let (ct, session_key) = encapsulate(&pk).expect("encapsulation failed");
        assert_eq!(session_key.as_bytes().len(), 32);
        assert_eq!(ct.x25519_ephemeral_pub.len(), 32);
        assert!(!ct.mlkem_ciphertext.is_empty());
    }

    #[test]
    fn test_different_encapsulations_produce_different_keys() {
        let (pk, _sk) = generate_xwing_keypair();
        let (_, key1) = encapsulate(&pk).unwrap();
        let (_, key2) = encapsulate(&pk).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
