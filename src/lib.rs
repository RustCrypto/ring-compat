//! Compatibility crate for using RustCrypto's traits with the cryptographic
//! algorithm implementations from *ring*

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![warn(missing_docs, rust_2018_idioms)]

pub mod aead;
pub mod digest;

pub use generic_array;
