//! Elliptic Curve Digital Signature Algorithm
//!
//! <https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>

pub mod p256;
pub mod p384;

mod signing_key;
mod verifying_key;

pub use self::{signing_key::SigningKey, verifying_key::VerifyingKey};
pub use ::ecdsa::{der, elliptic_curve::weierstrass::Curve, Signature};

use ring::signature::{EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm};

/// Trait for associating a *ring* [`EcdsaSigningAlgorithm`] with an
/// elliptic curve
pub trait CurveAlg: Curve {
    /// *ring* signing algorithm
    fn signing_alg() -> &'static EcdsaSigningAlgorithm;

    /// *ring* verify algorithm
    fn verify_alg() -> &'static EcdsaVerificationAlgorithm;
}
