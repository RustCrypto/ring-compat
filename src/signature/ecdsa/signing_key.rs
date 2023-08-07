//! ECDSA signing key

use super::{CurveAlg, Signature, VerifyingKey};
use crate::signature::{Error, Keypair, Signer};
use ::ecdsa::{
    elliptic_curve::{sec1, FieldBytesSize},
    SignatureSize,
};
use core::marker::PhantomData;
use generic_array::ArrayLength;
use pkcs8::DecodePrivateKey;
use ring::{
    self,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair as _},
};

/// ECDSA signing key. Generic over elliptic curves.
pub struct SigningKey<C>
where
    C: CurveAlg,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// *ring* ECDSA keypair
    keypair: EcdsaKeyPair,

    /// Cryptographically secure random number generator
    csrng: SystemRandom,

    /// Elliptic curve type
    curve: PhantomData<C>,
}

impl<C> SigningKey<C>
where
    C: CurveAlg,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Initialize a [`SigningKey`] from a raw keypair
    pub fn from_keypair_bytes(signing_key: &[u8], verifying_key: &[u8]) -> Result<Self, Error> {
        EcdsaKeyPair::from_private_key_and_public_key(C::signing_alg(), signing_key, verifying_key)
            .map(|keypair| Self {
                keypair,
                csrng: SystemRandom::new(),
                curve: PhantomData,
            })
            .map_err(|_| Error::new())
    }

    /// Get the [`VerifyingKey`] for this [`SigningKey`]
    pub fn verifying_key(&self) -> VerifyingKey<C>
    where
        FieldBytesSize<C>: sec1::ModulusSize,
    {
        VerifyingKey::new(self.keypair.public_key().as_ref()).unwrap()
    }
}

impl<C> DecodePrivateKey for SigningKey<C>
where
    C: CurveAlg,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn from_pkcs8_der(pkcs8_bytes: &[u8]) -> Result<Self, pkcs8::Error> {
        EcdsaKeyPair::from_pkcs8(C::signing_alg(), pkcs8_bytes)
            .map(|keypair| Self {
                keypair,
                csrng: SystemRandom::new(),
                curve: PhantomData,
            })
            .map_err(|_| pkcs8::Error::KeyMalformed)
    }
}

impl<C> Keypair for SigningKey<C>
where
    C: CurveAlg,
    FieldBytesSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
{
    type VerifyingKey = VerifyingKey<C>;

    fn verifying_key(&self) -> VerifyingKey<C> {
        self.verifying_key()
    }
}

impl<C> Signer<Signature<C>> for SigningKey<C>
where
    C: CurveAlg,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<C>, Error> {
        self.keypair
            .sign(&self.csrng, msg)
            .map_err(|_| Error::new())
            .and_then(|sig| Signature::try_from(sig.as_ref()))
    }
}
