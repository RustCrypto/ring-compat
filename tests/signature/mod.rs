//! Digital signature tests

mod ecdsa;
mod ed25519;

/// Signature test vector
#[derive(Copy, Clone, Debug)]
struct TestVector {
    /// Secret key (ECDSA: secret scalar, Ed25519: unexpanded "seed")
    sk: &'static [u8],

    /// Public key (ECDSA: SEC1-encoded, Ed25519: compressed Edwards-y)
    pk: &'static [u8],

    /// Message to be signed
    msg: &'static [u8],

    /// Expected signature
    sig: &'static [u8],
}
