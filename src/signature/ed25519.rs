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

#[cfg(feature = "pkcs8")]
use ed25519::pkcs8;

#[cfg(feature = "rand_core")]
use rand_core::CryptoRngCore;

/// Ed25519 signing key.
pub struct SigningKey {
    keypair: Ed25519KeyPair,
    seed: [u8; Self::SIZE],
}

impl SigningKey {
    /// Size of a raw [`SigningKey`] (a.k.a. seed) in bytes.
    pub const SIZE: usize = 32;

    /// Generate a random Ed25519 key using the provided RNG.
    #[cfg(feature = "rand_core")]
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; Self::SIZE];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(&bytes)
    }

    /// Create a new [`SigningKey`] from an unexpanded seed value (32-bytes).
    pub fn from_bytes(seed: &[u8; Self::SIZE]) -> Self {
        let keypair = Ed25519KeyPair::from_seed_unchecked(seed)
            .expect("all 32-byte values should be valied Ed25519 signing keys");

        Self {
            keypair,
            seed: *seed,
        }
    }

    /// Create a new [`SigningKey`] from a byte slice containing a seed value.
    pub fn from_slice(seed: &[u8]) -> signature::Result<Self> {
        seed.try_into()
            .map(Self::from_bytes)
            .map_err(|_| Error::new())
    }

    /// Alias for `from_slice`.
    #[deprecated(since = "0.7.0", note = "use `from_slice` instead")]
    pub fn from_seed(seed: &[u8]) -> signature::Result<Self> {
        Self::from_slice(seed)
    }

    /// Serialize this [`SigningKey`] as a 32-byte "seed".
    #[inline]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.seed
    }

    /// Get the [`VerifyingKey`] for this [`SigningKey`].
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.keypair.public_key().as_ref().try_into().unwrap())
    }
}

impl Clone for SigningKey {
    fn clone(&self) -> Self {
        Self::from_bytes(&self.seed)
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        Ok(Signature::try_from(self.keypair.sign(msg).as_ref()).unwrap())
    }
}

impl TryFrom<&[u8]> for SigningKey {
    type Error = Error;

    fn try_from(slice: &[u8]) -> signature::Result<Self> {
        Self::from_slice(slice)
    }
}

#[cfg(all(feature = "alloc", feature = "pkcs8"))]
impl pkcs8::EncodePrivateKey for SigningKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<pkcs8::SecretDocument> {
        pkcs8::KeypairBytes::from(self).to_pkcs8_der()
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<pkcs8::KeypairBytes> for SigningKey {
    type Error = pkcs8::Error;

    fn try_from(pkcs8_key: pkcs8::KeypairBytes) -> pkcs8::Result<Self> {
        SigningKey::try_from(&pkcs8_key)
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<&pkcs8::KeypairBytes> for SigningKey {
    type Error = pkcs8::Error;

    fn try_from(pkcs8_key: &pkcs8::KeypairBytes) -> pkcs8::Result<Self> {
        let signing_key = SigningKey::from_bytes(&pkcs8_key.secret_key);

        // Validate the public key in the PKCS#8 document if present
        if let Some(expected_public_bytes) = &pkcs8_key.public_key {
            if signing_key.verifying_key().as_ref() != expected_public_bytes.as_ref() {
                return Err(pkcs8::Error::KeyMalformed);
            }
        }

        Ok(signing_key)
    }
}

#[cfg(feature = "pkcs8")]
impl From<SigningKey> for pkcs8::KeypairBytes {
    fn from(signing_key: SigningKey) -> pkcs8::KeypairBytes {
        pkcs8::KeypairBytes::from(&signing_key)
    }
}

#[cfg(feature = "pkcs8")]
impl From<&SigningKey> for pkcs8::KeypairBytes {
    fn from(signing_key: &SigningKey) -> pkcs8::KeypairBytes {
        pkcs8::KeypairBytes {
            secret_key: signing_key.to_bytes(),
            public_key: Some(pkcs8::PublicKeyBytes(signing_key.verifying_key().0)),
        }
    }
}

#[cfg(feature = "pkcs8")]
impl TryFrom<pkcs8::PrivateKeyInfo<'_>> for SigningKey {
    type Error = pkcs8::Error;

    fn try_from(private_key: pkcs8::PrivateKeyInfo<'_>) -> pkcs8::Result<Self> {
        pkcs8::KeypairBytes::try_from(private_key)?.try_into()
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
