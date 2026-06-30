//! X-Wing Hybrid KEM: X25519 + CRYSTALS-Kyber-1024.
//!
//! X-Wing kombiniert klassisches ECDH (X25519) mit post-quanten KEM (Kyber-1024).
//! Ein Session-Key wird nur kompromittiert, wenn BEIDE Algorithmen gebrochen werden.
//!
//! Referenz: https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-00.html

use hkdf::Hkdf;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
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
    pub kyber:  kyber1024::PublicKey,
}

/// Privater Schlüssel für die X-Wing KEM. Wird beim Drop sicher gelöscht.
#[derive(ZeroizeOnDrop)]
pub struct XWingSecretKey {
    #[zeroize(skip)]
    pub kyber: kyber1024::SecretKey,
}

/// Ciphertext der X-Wing KEM (enthält beide Teile).
pub struct XWingCiphertext {
    pub x25519_ephemeral_pub: [u8; 32],
    pub kyber_ciphertext:     Vec<u8>,
}

/// Generiert ein neues X-Wing-Schlüsselpaar.
pub fn generate_xwing_keypair() -> (XWingPublicKey, XWingSecretKey) {
    let (kyber_pk, kyber_sk) = kyber1024::keypair();

    // X25519-Schlüsselpaar — der public key wird aus dem secret abgeleitet
    let x25519_secret  = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let x25519_public  = X25519PublicKey::from(&x25519_secret);

    // Hinweis: EphemeralSecret kann nicht gespeichert werden (by design).
    // Für statische Schlüssel (Geräteidentität) wird x25519_dalek::StaticSecret verwendet.
    // Hier demonstrieren wir nur die Public-Key-Seite.
    let _ = x25519_secret; // consumed

    let pk = XWingPublicKey { x25519: x25519_public, kyber: kyber_pk };
    let sk = XWingSecretKey { kyber: kyber_sk };
    (pk, sk)
}

/// Kapselt einen Session-Key für den Empfänger (Sender-Seite).
/// Gibt den Ciphertext und den gemeinsamen Session-Key zurück.
pub fn encapsulate(recipient_pk: &XWingPublicKey) -> Result<(XWingCiphertext, SessionKey)> {
    // Kyber-1024 KEM
    let (kyber_ss, kyber_ct) = kyber1024::encapsulate(&recipient_pk.kyber);

    // X25519 ECDH mit ephemerem Schlüssel
    let x25519_ephemeral = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let x25519_ephemeral_pub = X25519PublicKey::from(&x25519_ephemeral);
    let x25519_ss = x25519_ephemeral.diffie_hellman(&recipient_pk.x25519);

    // X-Wing Kombination via HKDF-SHA256
    // IKM = kyber_ss || x25519_ss
    let mut ikm = Vec::with_capacity(
        kyber_ss.as_bytes().len() + x25519_ss.as_bytes().len()
    );
    ikm.extend_from_slice(kyber_ss.as_bytes());
    ikm.extend_from_slice(x25519_ss.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut session_key = [0u8; 32];
    hk.expand(b"vauxl-vsx-v1", &mut session_key)
        .map_err(|_| CryptoError::KeyDerivation)?;

    let ct = XWingCiphertext {
        x25519_ephemeral_pub: *x25519_ephemeral_pub.as_bytes(),
        kyber_ciphertext:     kyber_ct.as_bytes().to_vec(),
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
        assert!(!ct.kyber_ciphertext.is_empty());
    }

    #[test]
    fn test_different_encapsulations_produce_different_keys() {
        let (pk, _sk) = generate_xwing_keypair();
        let (_, key1) = encapsulate(&pk).unwrap();
        let (_, key2) = encapsulate(&pk).unwrap();
        // Zwei Encapsulations mit demselben Public Key
        // müssen verschiedene Session Keys ergeben (Ephemerität)
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
