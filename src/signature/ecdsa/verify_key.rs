//! ECDSA verify key

use super::{Curve, CurveAlg, Signature};
use crate::signature::{Error, Verifier};
use ::ecdsa::{
    elliptic_curve::sec1::{self, UncompressedPointSize, UntaggedPointSize},
    generic_array::{
        typenum::{Unsigned, U1},
        ArrayLength,
    },
    CheckSignatureBytes, SignatureSize,
};
use core::{convert::TryInto, ops::Add};
use ring::signature::UnparsedPublicKey;

/// ECDSA verify key. Generic over elliptic curves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyKey<C>(sec1::EncodedPoint<C>)
where
    C: Curve + CurveAlg + CheckSignatureBytes,
    SignatureSize<C>: ArrayLength<u8>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>;

impl<C> VerifyKey<C>
where
    C: Curve + CurveAlg + CheckSignatureBytes,
    SignatureSize<C>: ArrayLength<u8>,
    UntaggedPointSize<C>: Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
{
    /// Initialize [`VerifyKey`] from a SEC1-encoded public key
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        let point_result = if bytes.len() == C::FieldSize::to_usize() * 2 {
            Ok(sec1::EncodedPoint::from_untagged_bytes(
                bytes.try_into().unwrap(),
            ))
        } else {
            sec1::EncodedPoint::from_bytes(bytes)
        };

        point_result.map(VerifyKey).map_err(|_| Error::new())
    }

    /// Get byte slice of inner encoded point
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<C: Curve> Verifier<Signature<C>> for VerifyKey<C>
where
    C: Curve + CurveAlg + CheckSignatureBytes,
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
