//! Digital signature support

pub mod ecdsa;
pub mod ed25519;

pub use ::ecdsa::signature::{Error, Signature, Signer, Verifier};
