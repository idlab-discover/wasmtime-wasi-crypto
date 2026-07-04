mod ecdsa;
mod eddsa;
pub mod keypair;
pub mod publickey;
mod rsa;
pub mod secretkey;
pub mod signature;

use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno;
use crate::error::{CryptoError, CryptoResult};
use crate::options::OptionsLike;
pub use crate::signatures::signature::Signature;
use std::any::Any;
use std::convert::TryFrom;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    ECDSA_P256_SHA256,
    ECDSA_K256_SHA256,
    ECDSA_P384_SHA384,
    Ed25519,
    RSA_PKCS1_2048_SHA256,
    RSA_PKCS1_2048_SHA384,
    RSA_PKCS1_2048_SHA512,
    RSA_PKCS1_3072_SHA384,
    RSA_PKCS1_3072_SHA512,
    RSA_PKCS1_4096_SHA512,
    RSA_PSS_2048_SHA256,
    RSA_PSS_2048_SHA384,
    RSA_PSS_2048_SHA512,
    RSA_PSS_3072_SHA384,
    RSA_PSS_3072_SHA512,
    RSA_PSS_4096_SHA512,
}

pub enum SignatureAlgorithmFamily {
    ECDSA,
    EdDSA,
    RSA,
}

impl SignatureAlgorithm {
    pub fn family(&self) -> SignatureAlgorithmFamily {
        match self {
            SignatureAlgorithm::ECDSA_P256_SHA256
            | SignatureAlgorithm::ECDSA_K256_SHA256
            | SignatureAlgorithm::ECDSA_P384_SHA384 => SignatureAlgorithmFamily::ECDSA,
            SignatureAlgorithm::Ed25519 => SignatureAlgorithmFamily::EdDSA,
            SignatureAlgorithm::RSA_PKCS1_2048_SHA256
            | SignatureAlgorithm::RSA_PKCS1_2048_SHA384
            | SignatureAlgorithm::RSA_PKCS1_2048_SHA512
            | SignatureAlgorithm::RSA_PKCS1_3072_SHA384
            | SignatureAlgorithm::RSA_PKCS1_3072_SHA512
            | SignatureAlgorithm::RSA_PKCS1_4096_SHA512
            | SignatureAlgorithm::RSA_PSS_2048_SHA256
            | SignatureAlgorithm::RSA_PSS_2048_SHA384
            | SignatureAlgorithm::RSA_PSS_2048_SHA512
            | SignatureAlgorithm::RSA_PSS_3072_SHA384
            | SignatureAlgorithm::RSA_PSS_3072_SHA512
            | SignatureAlgorithm::RSA_PSS_4096_SHA512 => SignatureAlgorithmFamily::RSA,
        }
    }
}

impl TryFrom<&str> for SignatureAlgorithm {
    type Error = CryptoError;

    fn try_from(alg_str: &str) -> CryptoResult<Self> {
        match alg_str.to_uppercase().as_str() {
            "ECDSA_P256_SHA256" => Ok(SignatureAlgorithm::ECDSA_P256_SHA256),
            "ECDSA_K256_SHA256" => Ok(SignatureAlgorithm::ECDSA_K256_SHA256),
            "ECDSA_P384_SHA384" => Ok(SignatureAlgorithm::ECDSA_P384_SHA384),

            "ED25519" => Ok(SignatureAlgorithm::Ed25519),

            "RSA_PKCS1_2048_SHA256" => Ok(SignatureAlgorithm::RSA_PKCS1_2048_SHA256),
            "RSA_PKCS1_2048_SHA384" => Ok(SignatureAlgorithm::RSA_PKCS1_2048_SHA384),
            "RSA_PKCS1_2048_SHA512" => Ok(SignatureAlgorithm::RSA_PKCS1_2048_SHA512),
            "RSA_PKCS1_3072_SHA384" => Ok(SignatureAlgorithm::RSA_PKCS1_3072_SHA384),
            "RSA_PKCS1_3072_SHA512" => Ok(SignatureAlgorithm::RSA_PKCS1_3072_SHA512),
            "RSA_PKCS1_4096_SHA512" => Ok(SignatureAlgorithm::RSA_PKCS1_4096_SHA512),

            "RSA_PSS_2048_SHA256" => Ok(SignatureAlgorithm::RSA_PSS_2048_SHA256),
            "RSA_PSS_2048_SHA384" => Ok(SignatureAlgorithm::RSA_PSS_2048_SHA384),
            "RSA_PSS_2048_SHA512" => Ok(SignatureAlgorithm::RSA_PSS_2048_SHA512),
            "RSA_PSS_3072_SHA384" => Ok(SignatureAlgorithm::RSA_PSS_3072_SHA384),
            "RSA_PSS_3072_SHA512" => Ok(SignatureAlgorithm::RSA_PSS_3072_SHA512),
            "RSA_PSS_4096_SHA512" => Ok(SignatureAlgorithm::RSA_PSS_4096_SHA512),

            _ => Err(CryptoErrno::UnsupportedAlgorithm.into()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SignatureOptions {}

impl OptionsLike for SignatureOptions {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn set(&mut self, _name: &str, _value: &[u8]) -> CryptoResult<()> {
        Err(CryptoErrno::UnsupportedOption.into())
    }

    fn set_u64(&mut self, _name: &str, _value: u64) -> CryptoResult<()> {
        Err(CryptoErrno::UnsupportedOption.into())
    }
}
