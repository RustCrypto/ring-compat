//! Compatibility crate for using [RustCrypto traits] with the cryptographic
//! algorithm implementations from [*ring*].
//!
//! Supported algorithms:
//!
//! - [`aead`]: AES-GCM, ChaCha20Poly1305
//! - [`digest`]: SHA-2 family
//! - [`signature`]: ECDSA, Ed25519
//!
//! [RustCrypto traits]: https://github.com/RustCrypto/traits
//! [*ring*]: https://github.com/briansmith/ring

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "aead")]
#[cfg_attr(docsrs, doc(cfg(feature = "aead")))]
pub mod aead;

#[cfg(feature = "digest")]
#[cfg_attr(docsrs, doc(cfg(feature = "digest")))]
pub mod digest;

#[cfg(feature = "signature")]
#[cfg_attr(docsrs, doc(cfg(feature = "signature")))]
pub mod signature;

pub use generic_array;
