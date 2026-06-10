use crate::{
    crypto::bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno, options::OptionsLike,
};
use std::any::Any;

#[derive(Clone, Debug, Default)]
pub struct SignatureOptions {}

impl OptionsLike for SignatureOptions {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn set(&mut self, _name: &str, _value: &[u8]) -> Result<(), CryptoErrno> {
        Err(CryptoErrno::UnsupportedOption)
    }

    fn set_u64(&mut self, _name: &str, _value: u64) -> Result<(), CryptoErrno> {
        Err(CryptoErrno::UnsupportedOption)
    }
}
