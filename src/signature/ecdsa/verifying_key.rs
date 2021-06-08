//! ECDSA verifying key

use super::{Curve, CurveAlg, Signature};
use crate::signature::{Error, Verifier};
use ::ecdsa::{
    elliptic_curve::{
        bigint::Encoding as _,
        sec1::{self, UncompressedPointSize, UntaggedPointSize},
    },
    SignatureSize,
};
use core::{convert::TryInto, ops::Add};
use generic_array::{typenum::U1, ArrayLength};
use ring::signature::UnparsedPublicKey;

/// ECDSA verifying key. Generic over elliptic curves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyingKey<C>(sec1::EncodedPoint<C>)
where
    C: Curve + CurveAlg,
    SignatureSize<C>: ArrayLength<u8>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>;

impl<C> VerifyingKey<C>
where
    C: Curve + CurveAlg,
    SignatureSize<C>: ArrayLength<u8>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Initialize [`VerifyingKey`] from a SEC1-encoded public key
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        let point_result = if bytes.len() == C::UInt::BYTE_SIZE * 2 {
            Ok(sec1::EncodedPoint::from_untagged_bytes(
                bytes.try_into().unwrap(),
            ))
        } else {
            sec1::EncodedPoint::from_bytes(bytes)
        };

        point_result.map(VerifyingKey).map_err(|_| Error::new())
    }

    /// Get byte slice of inner encoded point
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<C: Curve> Verifier<Signature<C>> for VerifyingKey<C>
where
    C: Curve + CurveAlg,
    SignatureSize<C>: ArrayLength<u8>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    fn verify(&self, msg: &[u8], sig: &Signature<C>) -> Result<(), Error> {
        UnparsedPublicKey::new(C::verify_alg(), self.0.as_ref())
            .verify(msg, sig.as_ref())
            .map_err(|_| Error::new())
    }
}
