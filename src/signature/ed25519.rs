//! Ed25519 digital signature algorithm
//!
//! <https://en.wikipedia.org/wiki/EdDSA>

pub use ed25519::Signature;

use super::{Error, Signer, Verifier};
use core::convert::TryInto;
use pkcs8::DecodePrivateKey;
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
    pub fn from_bytes(seed: &[u8; Self::SIZE]) -> signature::Result<Self> {
        Ed25519KeyPair::from_seed_unchecked(seed)
            .map(SigningKey)
            .map_err(|_| Error::new())
    }

    /// Create a new [`SigningKey`] from a byte slice containing a seed value.
    pub fn from_slice(seed: &[u8]) -> signature::Result<Self> {
        seed.try_into()
            .map_err(|_| Error::new())
            .and_then(Self::from_bytes)
    }

    /// Alias for `from_slice`.
    #[deprecated(since = "0.7.0", note = "use `from_slice` instead")]
    pub fn from_seed(seed: &[u8]) -> signature::Result<Self> {
        Self::from_slice(seed)
    }

    /// Get the [`VerifyingKey`] for this [`SigningKey`].
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.public_key().as_ref().try_into().unwrap())
    }
}

impl DecodePrivateKey for SigningKey {
    fn from_pkcs8_der(pkcs8_bytes: &[u8]) -> pkcs8::Result<Self> {
        Ed25519KeyPair::from_pkcs8(pkcs8_bytes)
            .map(SigningKey)
            .map_err(|_| pkcs8::Error::KeyMalformed)
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        Ok(Signature::try_from(self.0.sign(msg).as_ref()).unwrap())
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> signature::Result<Self> {
        Self::from_slice(slice)
    }
}

/// Ed25519 verifying key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyingKey(pub [u8; Self::SIZE]);

impl VerifyingKey {
    /// Size of a [`VerifyingKey`] in bytes.
    pub const SIZE: usize = 32;

    /// Parse a verify key (encoded in compressed Edwards-y form) from a byte slice.
    pub fn from_slice(slice: &[u8]) -> signature::Result<Self> {
        slice.try_into().map(Self).map_err(|_| Error::new())
    }

    /// Alias for `from_slice`.
    #[deprecated(since = "0.7.0", note = "use `from_slice` instead")]
    pub fn new(bytes: &[u8]) -> signature::Result<Self> {
        Self::from_slice(bytes)
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
            .verify(msg, &signature.to_bytes())
            .map_err(|_| Error::new())
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> signature::Result<Self> {
        Self::from_slice(slice)
    }
}
