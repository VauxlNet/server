/// Fehlertypen für vauxl-crypto.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("KEM encapsulation failed")]
    KemEncapsulation,

    #[error("KEM decapsulation failed")]
    KemDecapsulation,

    #[error("Key derivation failed")]
    KeyDerivation,

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Signature verification failed")]
    SignatureVerification,
}

pub type Result<T> = std::result::Result<T, CryptoError>;
