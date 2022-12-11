//! Digital signatures: ECDSA (P-256/P-384), Ed25519

pub mod ecdsa;
pub mod ed25519;

pub use ::signature::{Error, Signature, Signer, Verifier};
