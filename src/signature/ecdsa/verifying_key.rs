//! ECDSA verifying key

use super::{CurveAlg, PrimeCurve, Signature};
use crate::signature::{Error, Verifier};
use ::ecdsa::{
    elliptic_curve::{bigint::Encoding as _, sec1, FieldSize},
    SignatureSize,
};
use core::convert::TryInto;
use generic_array::ArrayLength;
use ring::signature::UnparsedPublicKey;

/// ECDSA verifying key. Generic over elliptic curves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyingKey<C>(sec1::EncodedPoint<C>)
where
    C: PrimeCurve + CurveAlg,
    FieldSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>;

impl<C> VerifyingKey<C>
where
    C: PrimeCurve + CurveAlg,
    FieldSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
{
    /// Initialize [`VerifyingKey`] from a SEC1-encoded public key
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        let point_result = if bytes.len() == C::UInt::BYTE_SIZE * 2 {
            Ok(sec1::EncodedPoint::<C>::from_untagged_bytes(
                bytes.try_into().map_err(|_| Error::new())?,
            ))
        } else {
            sec1::EncodedPoint::<C>::from_bytes(bytes)
        };

        point_result.map(VerifyingKey).map_err(|_| Error::new())
    }

    /// Get byte slice of inner encoded point
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<C: PrimeCurve> Verifier<Signature<C>> for VerifyingKey<C>
where
    C: PrimeCurve + CurveAlg,
    FieldSize<C>: sec1::ModulusSize,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn verify(&self, msg: &[u8], sig: &Signature<C>) -> Result<(), Error> {
        UnparsedPublicKey::new(C::verify_alg(), self.0.as_ref())
            .verify(msg, sig.as_ref())
            .map_err(|_| Error::new())
    }
}
