mod aes_gcm;
mod chacha_poly;
mod hkdf;
mod hmac_sha2;
mod key;
mod sha2;
mod state;
mod tag;
#[cfg(test)]
mod tests;
mod xoodyak;

pub use self::key::SymmetricKey;
pub use self::state::SymmetricState;
pub use self::tag::SymmetricTag;
use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno,
    error::{CryptoError, CryptoResult},
    options::OptionsLike,
};
use std::{
    any::Any,
    sync::{Arc, Mutex, MutexGuard},
};

#[derive(Debug, Default)]
pub struct SymmetricOptionsInner {
    context: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    memory_limit: Option<u64>,
    ops_limit: Option<u64>,
    parallelism: Option<u64>,
    guest_buffer: Option<&'static mut [u8]>,
}

#[derive(Clone, Debug, Default)]
pub struct SymmetricOptions {
    inner: Arc<Mutex<SymmetricOptionsInner>>,
}

impl SymmetricOptions {
    fn inner(&self) -> MutexGuard<'_, SymmetricOptionsInner> {
        self.inner.lock().unwrap()
    }

    fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<'_, SymmetricOptionsInner>) -> U,
    {
        f(self.inner())
    }
}

impl OptionsLike for SymmetricOptions {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn set_guest_buffer(
        &mut self,
        name: &str,
        guest_buffer: &'static mut [u8],
    ) -> CryptoResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let option = match name.to_lowercase().as_str() {
            "buffer" => &mut inner.guest_buffer,
            _ => return Err(CryptoErrno::UnsupportedOption.into()),
        };
        *option = Some(guest_buffer);
        Ok(())
    }

    fn set(&mut self, name: &str, value: &[u8]) -> CryptoResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let option = match name.to_lowercase().as_str() {
            "context" => &mut inner.context,
            "salt" => &mut inner.salt,
            "nonce" => &mut inner.nonce,
            _ => return Err(CryptoErrno::UnsupportedOption.into()),
        };
        *option = Some(value.to_vec());
        Ok(())
    }

    fn get(&self, name: &str) -> CryptoResult<Vec<u8>> {
        let inner = self.inner.lock().unwrap();
        let value = match name.to_lowercase().as_str() {
            "context" => &inner.context,
            "salt" => &inner.salt,
            "nonce" => &inner.nonce,
            _ => return Err(CryptoErrno::UnsupportedOption.into()),
        };
        value
            .as_ref()
            .cloned()
            .ok_or(CryptoErrno::OptionNotSet.into())
    }

    fn set_u64(&mut self, name: &str, value: u64) -> CryptoResult<()> {
        let mut inner = self.inner.lock().unwrap();
        let option = match name.to_lowercase().as_str() {
            "memory_limit" => &mut inner.memory_limit,
            "ops_limit" => &mut inner.ops_limit,
            "parallelism" => &mut inner.parallelism,
            _ => return Err(CryptoErrno::UnsupportedOption.into()),
        };
        *option = Some(value);
        Ok(())
    }

    fn get_u64(&self, name: &str) -> CryptoResult<u64> {
        let inner = self.inner.lock().unwrap();
        let value = match name.to_lowercase().as_str() {
            "memory_limit" => &inner.memory_limit,
            "ops_limit" => &inner.ops_limit,
            "parallelism" => &inner.parallelism,
            _ => return Err(CryptoErrno::UnsupportedOption.into()),
        };
        value.ok_or(CryptoErrno::OptionNotSet.into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymmetricAlgorithm {
    None,
    HmacSha256,
    HmacSha512,
    HkdfSha256Extract,
    HkdfSha512Extract,
    HkdfSha256Expand,
    HkdfSha512Expand,
    Sha256,
    Sha384,
    Sha512,
    Sha512_256,
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    Xoodyak128,
    Xoodyak160,
}

impl TryFrom<&str> for SymmetricAlgorithm {
    type Error = CryptoError;

    fn try_from(alg_str: &str) -> CryptoResult<Self> {
        match alg_str.to_uppercase().as_str() {
            "HKDF-EXTRACT/SHA-256" => Ok(SymmetricAlgorithm::HkdfSha256Extract),
            "HKDF-EXTRACT/SHA-512" => Ok(SymmetricAlgorithm::HkdfSha512Extract),
            "HKDF-EXPAND/SHA-256" => Ok(SymmetricAlgorithm::HkdfSha256Expand),
            "HKDF-EXPAND/SHA-512" => Ok(SymmetricAlgorithm::HkdfSha512Expand),
            "HMAC/SHA-256" => Ok(SymmetricAlgorithm::HmacSha256),
            "HMAC/SHA-512" => Ok(SymmetricAlgorithm::HmacSha512),
            "SHA-256" => Ok(SymmetricAlgorithm::Sha256),
            "SHA-384" => Ok(SymmetricAlgorithm::Sha384),
            "SHA-512" => Ok(SymmetricAlgorithm::Sha512),
            "SHA-512/256" => Ok(SymmetricAlgorithm::Sha512_256),
            "AES-128-GCM" => Ok(SymmetricAlgorithm::Aes128Gcm),
            "AES-256-GCM" => Ok(SymmetricAlgorithm::Aes256Gcm),
            "CHACHA20-POLY1305" => Ok(SymmetricAlgorithm::ChaCha20Poly1305),
            "XCHACHA20-POLY1305" => Ok(SymmetricAlgorithm::XChaCha20Poly1305),
            "XOODYAK-128" => Ok(SymmetricAlgorithm::Xoodyak128),
            "XOODYAK-160" => Ok(SymmetricAlgorithm::Xoodyak160),
            _ => Err(CryptoErrno::UnsupportedAlgorithm.into()),
        }
    }
}
