mod dh;
mod kem;
pub mod keypair;
pub mod publickey;
pub mod secretkey;

pub use dh::{X25519PublicKeyBuilder, X25519SecretKeyBuilder};
#[cfg(feature = "pqcrypto")]
pub use kem::{
    MlKemPublicKeyBuilder, MlKemSecretKeyBuilder, XWingPublicKeyBuilder, XWingSecretKeyBuilder,
};

use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno;
use crate::error::{CryptoError, CryptoResult};
use crate::options::OptionsLike;
use std::any::Any;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct KxOptionsInner {
    context: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
pub struct KxOptions {
    inner: Arc<Mutex<KxOptionsInner>>,
}

impl OptionsLike for KxOptions {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KxAlgorithm {
    X25519,
    MlKem512,
    MlKem768,
    MlKem1024,
    XWing,
}

impl TryFrom<&str> for KxAlgorithm {
    type Error = CryptoError;

    fn try_from(alg_str: &str) -> CryptoResult<Self> {
        match alg_str.to_uppercase().as_str() {
            "X25519" => Ok(KxAlgorithm::X25519),
            "ML-KEM-512" => Ok(KxAlgorithm::MlKem512),
            "ML-KEM-768" => Ok(KxAlgorithm::MlKem768),
            "ML-KEM-1024" => Ok(KxAlgorithm::MlKem1024),
            "X-WING" => Ok(KxAlgorithm::XWing),
            _ => Err(CryptoErrno::UnsupportedAlgorithm.into()),
        }
    }
}
