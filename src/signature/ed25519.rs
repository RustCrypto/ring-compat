//! Ed25519 digital signature algorithm
//!
//! <https://en.wikipedia.org/wiki/EdDSA>

pub use ed25519::{Signature, SIGNATURE_LENGTH};

use super::{Error, Signature as _, Signer, Verifier};
use core::convert::TryInto;
use ring::{
    self,
    signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};

/// Size of a raw [`SigningKey`] (a.k.a. seed) in bytes
pub const SIGNING_KEY_LENGTH: usize = 32;

/// Size of a [`VerifyKey`] in bytes
pub const VERIFY_KEY_LENGTH: usize = 32;

/// Ed25519 signing key
pub struct SigningKey(Ed25519KeyPair);

impl SigningKey {
    /// Create a new [`SigningKey`] from an unexpanded seed value (32-bytes)
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        Ed25519KeyPair::from_seed_unchecked(seed)
            .map(SigningKey)
            .map_err(|_| Error::new())
    }

    /// Create a new [`SigningKey`] from a PKCS#8 encoded  key
    pub fn from_pkcs8(pkcs8_key: &[u8]) -> Result<Self, Error> {
        Ed25519KeyPair::from_pkcs8(pkcs8_key)
            .map(SigningKey)
            .map_err(|_| Error::new())
    }

    /// Get the [`VerifyKey`] for this [`SigningKey`]
    pub fn verify_key(&self) -> VerifyKey {
        VerifyKey(self.0.public_key().as_ref().try_into().unwrap())
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(Signature::from_bytes(self.0.sign(msg).as_ref()).unwrap())
    }
}

/// Ed25519 verify key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyKey([u8; VERIFY_KEY_LENGTH]);

impl VerifyKey {
    /// Parse a verify key (encoded in compressed Edwards-y form) from bytes
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        bytes.try_into().map(VerifyKey).map_err(|_| Error::new())
    }
}

impl AsRef<[u8]> for VerifyKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&SigningKey> for VerifyKey {
    fn from(signing_key: &SigningKey) -> Self {
        signing_key.verify_key()
    }
}

impl Verifier<Signature> for VerifyKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        UnparsedPublicKey::new(&ring::signature::ED25519, self.0.as_ref())
            .verify(msg, signature.as_ref())
            .map_err(|_| Error::new())
    }
}
