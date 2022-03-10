#![doc = include_str!("../README.md")]

//! # Features
//!
//! Functionality in this crate is gated under the following features:
//!
//! - `aead`: Authenticated Encryption with Associated Data algorithms: AES-GCM, ChaCha20Poly1305
//! - `digest`: Cryptographic Hash Functions: SHA-1, SHA-256, SHA-384, SHA-512, SHA-512/256
//! - `signature`: Digital Signature Algorithms, gated under the following features:
//!   - `ecdsa`: Elliptic Curve Digital Signature Algorithm
//!   - `ed25519`: Edwards Digital Signature Algorithm instantiated over Curve25519
//!   - `p256`: ECDSA/NIST P-256
//!   - `p384`: ECDSA/NIST P-384

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/7f79a5e/img/ring-compat/logo-sq.png"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

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
pub use ring;
