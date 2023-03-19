#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/7f79a5e/img/ring-compat/logo-sq.png"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

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

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "aead")]
pub mod aead;

#[cfg(feature = "digest")]
pub mod digest;

#[cfg(feature = "signature")]
pub mod signature;

pub use generic_array;

#[cfg(feature = "signature")]
pub use pkcs8;

pub use ring;
