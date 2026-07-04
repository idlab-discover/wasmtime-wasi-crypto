use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno, error::CryptoResult,
    key_exchange::KxOptions, signatures::SignatureOptions, symmetric::SymmetricOptions,
};
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

#[derive(Clone, Debug)]
pub enum Options {
    Signatures(SignatureOptions),
    Symmetric(SymmetricOptions),
    KeyExchange(KxOptions),
}

impl Options {
    pub fn into_signatures(self) -> CryptoResult<SignatureOptions> {
        match self {
            Options::Signatures(options) => Ok(options),
            _ => Err(CryptoErrno::InvalidHandle.into()),
        }
    }

    pub fn into_symmetric(self) -> CryptoResult<SymmetricOptions> {
        match self {
            Options::Symmetric(options) => Ok(options),
            _ => Err(CryptoErrno::InvalidHandle.into()),
        }
    }

    pub fn into_key_exchange(self) -> CryptoResult<KxOptions> {
        match self {
            Options::KeyExchange(options) => Ok(options),
            _ => Err(CryptoErrno::InvalidHandle.into()),
        }
    }

    pub fn set(&mut self, name: &str, value: &[u8]) -> CryptoResult<()> {
        match self {
            Options::Signatures(options) => options.set(name, value),
            Options::Symmetric(options) => options.set(name, value),
            Options::KeyExchange(options) => options.set(name, value),
        }
    }

    pub fn set_guest_buffer(&mut self, name: &str, buffer: &'static mut [u8]) -> CryptoResult<()> {
        match self {
            Options::Signatures(options) => options.set_guest_buffer(name, buffer),
            Options::Symmetric(options) => options.set_guest_buffer(name, buffer),
            Options::KeyExchange(options) => options.set_guest_buffer(name, buffer),
        }
    }

    pub fn get(&mut self, name: &str) -> CryptoResult<Vec<u8>> {
        match self {
            Options::Signatures(options) => options.get(name),
            Options::Symmetric(options) => options.get(name),
            Options::KeyExchange(options) => options.get(name),
        }
    }

    pub fn set_u64(&mut self, name: &str, value: u64) -> CryptoResult<()> {
        match self {
            Options::Signatures(options) => options.set_u64(name, value),
            Options::Symmetric(options) => options.set_u64(name, value),
            Options::KeyExchange(options) => options.set_u64(name, value),
        }
    }

    pub fn get_u64(&mut self, name: &str) -> CryptoResult<u64> {
        match self {
            Options::Signatures(options) => options.get_u64(name),
            Options::Symmetric(options) => options.get_u64(name),
            Options::KeyExchange(options) => options.get_u64(name),
        }
    }
}
