//! ECDSA support for the NIST P-256 elliptic curve

pub use p256::NistP256;

use super::CurveAlg;
use ring::signature::{
    EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING,
};

/// ECDSA/P-256 signature
pub type Signature = super::Signature<NistP256>;

/// ECDSA/P-256 signing key
pub type SigningKey = super::SigningKey<NistP256>;

/// ECDSA/P-256 verify key
pub type VerifyKey = super::VerifyKey<NistP256>;

impl CurveAlg for NistP256 {
    fn signing_alg() -> &'static EcdsaSigningAlgorithm {
        &ECDSA_P256_SHA256_FIXED_SIGNING
    }

    fn verify_alg() -> &'static EcdsaVerificationAlgorithm {
        &ECDSA_P256_SHA256_FIXED
    }
}
