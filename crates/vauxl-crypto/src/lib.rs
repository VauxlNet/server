//! vauxl-crypto — Audit-Grenze für alle kryptographischen Operationen.
//!
//! Regeln für diesen Crate:
//! - Keine anderen vauxl-* Crates als Abhängigkeit
//! - Kein `unwrap()` oder `expect()` außerhalb von Tests
//! - Alle Secrets implementieren `Zeroize` und werden beim Drop gelöscht
//! - Kein unsafe code (durch workspace `unsafe_code = "forbid"` erzwungen)

pub mod kem;
pub mod identity;
pub mod error;
