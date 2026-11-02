use crate::{bindings::wasi::crypto::common::CryptoErrno, error::CryptoResult};
use std::any::Any;

pub trait OptionsLike: Send + Sized {
    fn as_any(&self) -> &dyn Any;

    fn set(&mut self, _name: &str, _value: &[u8]) -> CryptoResult<()> {
        Err(CryptoErrno::UnsupportedOption.into())
    }

    fn set_guest_buffer(&mut self, _name: &str, _buffer: &'static mut [u8]) -> CryptoResult<()> {
        Err(CryptoErrno::UnsupportedOption.into())
    }

    fn get(&self, _name: &str) -> CryptoResult<Vec<u8>> {
        Err(CryptoErrno::UnsupportedOption.into())
    }

    fn set_u64(&mut self, _name: &str, _value: u64) -> CryptoResult<()> {
        Err(CryptoErrno::UnsupportedOption.into())
    }

    fn get_u64(&self, _name: &str) -> CryptoResult<u64> {
        Err(CryptoErrno::UnsupportedOption.into())
    }
}
