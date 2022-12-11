//! Ed25519 digital signature algorithm
//!
//! <https://en.wikipedia.org/wiki/EdDSA>

pub use ed25519::Signature;

use super::{Error, Signer, Verifier};
use core::convert::TryInto;
use ring::{
    self,
    signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};

/// Ed25519 signing key.
pub struct SigningKey(Ed25519KeyPair);

impl SigningKey {
    /// Size of a raw [`SigningKey`] (a.k.a. seed) in bytes.
    pub const SIZE: usize = 32;

    /// Create a new [`SigningKey`] from an unexpanded seed value (32-bytes).
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        Ed25519KeyPair::from_seed_unchecked(seed)
            .map(SigningKey)
            .map_err(|_| Error::new())
    }

    /// Create a new [`SigningKey`] from a PKCS#8 encoded key.
    pub fn from_pkcs8(pkcs8_key: &[u8]) -> Result<Self, Error> {
        Ed25519KeyPair::from_pkcs8(pkcs8_key)
            .map(SigningKey)
            .map_err(|_| Error::new())
    }

    /// Get the [`VerifyingKey`] for this [`SigningKey`].
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.public_key().as_ref().try_into().unwrap())
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(Signature::from_bytes(self.0.sign(msg).as_ref()).unwrap())
    }
}

/// Ed25519 verifying key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyingKey([u8; Self::SIZE]);

impl VerifyingKey {
    /// Size of a [`VerifyingKey`] in bytes.
    pub const SIZE: usize = 32;

    /// Parse a verify key (encoded in compressed Edwards-y form) from bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        bytes.try_into().map(VerifyingKey).map_err(|_| Error::new())
    }
}

impl AsRef<[u8]> for VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&SigningKey> for VerifyingKey {
    fn from(signing_key: &SigningKey) -> Self {
        signing_key.verifying_key()
    }
}

impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        UnparsedPublicKey::new(&ring::signature::ED25519, self.0.as_ref())
            .verify(msg, signature.as_ref())
            .map_err(|_| Error::new())
    }
}
