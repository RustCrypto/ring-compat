//! Compatibility crate for using RustCrypto's traits with the cryptographic
//! algorithm implementations from *ring*

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

pub use generic_array;
