//! ring-compat test suite

#[cfg(all(feature = "aead", feature = "alloc"))]
mod aead;

#[cfg(feature = "digest")]
mod digest;

#[cfg(feature = "signature")]
mod signature;
