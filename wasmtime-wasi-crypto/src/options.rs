use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno, key_exchange::KxOptions,
    signatures::SignatureOptions, symmetric::SymmetricOptions,
};
use std::any::Any;

pub trait OptionsLike: Send + Sized {
    fn as_any(&self) -> &dyn Any;

    fn set(&mut self, _name: &str, _value: &[u8]) -> Result<(), CryptoErrno> {
        Err(CryptoErrno::UnsupportedOption)
    }

    fn set_guest_buffer(
        &mut self,
        _name: &str,
        _buffer: &'static mut [u8],
    ) -> Result<(), CryptoErrno> {
        Err(CryptoErrno::UnsupportedOption)
    }

    fn get(&self, _name: &str) -> Result<Vec<u8>, CryptoErrno> {
        Err(CryptoErrno::UnsupportedOption)
    }

    fn set_u64(&mut self, _name: &str, _value: u64) -> Result<(), CryptoErrno> {
        Err(CryptoErrno::UnsupportedOption)
    }

    fn get_u64(&self, _name: &str) -> Result<u64, CryptoErrno> {
        Err(CryptoErrno::UnsupportedOption)
    }
}

#[derive(Clone, Debug)]
pub enum Options {
    Signatures(SignatureOptions),
    Symmetric(SymmetricOptions),
    KeyExchange(KxOptions),
}

impl Options {
    pub fn into_signatures(self) -> Result<SignatureOptions, CryptoErrno> {
        match self {
            Options::Signatures(options) => Ok(options),
            _ => Err(CryptoErrno::InvalidHandle),
        }
    }

    pub fn into_symmetric(self) -> Result<SymmetricOptions, CryptoErrno> {
        match self {
            Options::Symmetric(options) => Ok(options),
            _ => Err(CryptoErrno::InvalidHandle),
        }
    }

    pub fn into_key_exchange(self) -> Result<KxOptions, CryptoErrno> {
        match self {
            Options::KeyExchange(options) => Ok(options),
            _ => Err(CryptoErrno::InvalidHandle),
        }
    }

    pub fn set(&mut self, name: &str, value: &[u8]) -> Result<(), CryptoErrno> {
        match self {
            Options::Signatures(options) => options.set(name, value),
            Options::Symmetric(options) => options.set(name, value),
            Options::KeyExchange(options) => options.set(name, value),
        }
    }

    pub fn set_guest_buffer(
        &mut self,
        name: &str,
        buffer: &'static mut [u8],
    ) -> Result<(), CryptoErrno> {
        match self {
            Options::Signatures(options) => options.set_guest_buffer(name, buffer),
            Options::Symmetric(options) => options.set_guest_buffer(name, buffer),
            Options::KeyExchange(options) => options.set_guest_buffer(name, buffer),
        }
    }

    pub fn get(&mut self, name: &str) -> Result<Vec<u8>, CryptoErrno> {
        match self {
            Options::Signatures(options) => options.get(name),
            Options::Symmetric(options) => options.get(name),
            Options::KeyExchange(options) => options.get(name),
        }
    }

    pub fn set_u64(&mut self, name: &str, value: u64) -> Result<(), CryptoErrno> {
        match self {
            Options::Signatures(options) => options.set_u64(name, value),
            Options::Symmetric(options) => options.set_u64(name, value),
            Options::KeyExchange(options) => options.set_u64(name, value),
        }
    }

    pub fn get_u64(&mut self, name: &str) -> Result<u64, CryptoErrno> {
        match self {
            Options::Signatures(options) => options.get_u64(name),
            Options::Symmetric(options) => options.get_u64(name),
            Options::KeyExchange(options) => options.get_u64(name),
        }
    }
}
