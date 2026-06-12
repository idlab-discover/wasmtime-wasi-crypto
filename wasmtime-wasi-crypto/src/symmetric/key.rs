use crate::{
    crypto::bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno,
    symmetric::{SymmetricAlgorithm, SymmetricOptions},
};
use std::{
    any::Any,
    sync::{Arc, Mutex, MutexGuard},
};

#[derive(Clone)]
pub struct SymmetricKey {
    inner: Arc<Mutex<Box<dyn SymmetricKeyLike>>>,
}

pub trait SymmetricKeyBuilder {
    fn generate(&self, options: Option<SymmetricOptions>) -> Result<SymmetricKey, CryptoErrno>;

    fn import(&self, raw: &[u8]) -> Result<SymmetricKey, CryptoErrno>;

    fn key_len(&self) -> Result<usize, CryptoErrno>;
}

impl SymmetricKey {
    pub fn new(symmetric_key_like: Box<dyn SymmetricKeyLike>) -> Self {
        SymmetricKey {
            inner: Arc::new(Mutex::new(symmetric_key_like)),
        }
    }

    pub fn inner(&self) -> MutexGuard<'_, Box<dyn SymmetricKeyLike>> {
        self.inner.lock().unwrap()
    }

    pub fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<'_, Box<dyn SymmetricKeyLike>>) -> U,
    {
        f(self.inner())
    }

    pub fn alg(&self) -> SymmetricAlgorithm {
        self.inner().alg()
    }

    pub fn builder(alg_str: &str) -> Result<Box<dyn SymmetricKeyBuilder>, CryptoErrno> {
        let alg = SymmetricAlgorithm::try_from(alg_str)?;
        let builder = match alg {
            // SymmetricAlgorithm::HmacSha256 | SymmetricAlgorithm::HmacSha512 => {
            //     HmacSha2SymmetricKeyBuilder::new(alg)
            // }
            // SymmetricAlgorithm::HkdfSha256Expand
            // | SymmetricAlgorithm::HkdfSha256Extract
            // | SymmetricAlgorithm::HkdfSha512Expand
            // | SymmetricAlgorithm::HkdfSha512Extract => HkdfSymmetricKeyBuilder::new(alg),
            // SymmetricAlgorithm::Aes128Gcm | SymmetricAlgorithm::Aes256Gcm => {
            //     AesGcmSymmetricKeyBuilder::new(alg)
            // }
            // SymmetricAlgorithm::Xoodyak128 | SymmetricAlgorithm::Xoodyak160 => {
            //     XoodyakSymmetricKeyBuilder::new(alg)
            // }
            // SymmetricAlgorithm::ChaCha20Poly1305 | SymmetricAlgorithm::XChaCha20Poly1305 => {
            //     ChaChaPolySymmetricKeyBuilder::new(alg)
            // }
            _ => return Err(CryptoErrno::InvalidOperation),
        };
        Ok(builder)
    }

    pub fn generate(
        alg_str: &str,
        options: Option<SymmetricOptions>,
    ) -> Result<SymmetricKey, CryptoErrno> {
        let builder = Self::builder(alg_str)?;
        builder.generate(options)
    }

    pub fn import(alg_str: &str, raw: &[u8]) -> Result<SymmetricKey, CryptoErrno> {
        let builder = Self::builder(alg_str)?;
        builder.import(raw)
    }
}

pub trait SymmetricKeyLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn alg(&self) -> SymmetricAlgorithm;
    fn as_raw(&self) -> Result<&[u8], CryptoErrno>;
}
