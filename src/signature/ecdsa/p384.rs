//! ECDSA support for the NIST P-384 elliptic curve

pub use p384::NistP384;

use super::CurveAlg;
use ring::signature::{
    EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm, ECDSA_P384_SHA384_FIXED,
    ECDSA_P384_SHA384_FIXED_SIGNING,
};

/// ECDSA/P-384 signature
pub type Signature = super::Signature<NistP384>;

/// ECDSA/P-384 signing key
pub type SigningKey = super::SigningKey<NistP384>;

/// ECDSA/P-384 verify key
pub type VerifyKey = super::VerifyKey<NistP384>;

impl CurveAlg for NistP384 {
    fn signing_alg() -> &'static EcdsaSigningAlgorithm {
        &ECDSA_P384_SHA384_FIXED_SIGNING
    }

    fn verify_alg() -> &'static EcdsaVerificationAlgorithm {
        &ECDSA_P384_SHA384_FIXED
    }
}
