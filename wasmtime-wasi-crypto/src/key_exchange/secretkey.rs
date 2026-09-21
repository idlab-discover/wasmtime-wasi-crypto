#[cfg(feature = "pqcrypto")]
use crate::key_exchange::kem::{MlKemSecretKeyBuilder, XWingSecretKeyBuilder};
use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{CryptoErrno, SecretkeyEncoding},
    error::CryptoResult,
    key_exchange::{KxAlgorithm, dh::X25519SecretKeyBuilder, publickey::KxPublicKey},
};
use std::{
    any::Any,
    sync::{Arc, Mutex, MutexGuard},
};

pub trait KxSecretKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> CryptoResult<KxSecretKey>;
}

#[derive(Clone)]
pub struct KxSecretKey {
    inner: Arc<Mutex<Box<dyn KxSecretKeyLike>>>,
}

impl KxSecretKey {
    pub fn new(kx_secretkey_like: Box<dyn KxSecretKeyLike>) -> Self {
        KxSecretKey {
            inner: Arc::new(Mutex::new(kx_secretkey_like)),
        }
    }

    pub fn inner(&self) -> MutexGuard<'_, Box<dyn KxSecretKeyLike>> {
        self.inner.lock().unwrap()
    }

    pub fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<'_, Box<dyn KxSecretKeyLike>>) -> U,
    {
        f(self.inner())
    }

    pub fn alg(&self) -> KxAlgorithm {
        self.inner().alg()
    }

    pub fn builder(alg: KxAlgorithm) -> CryptoResult<Box<dyn KxSecretKeyBuilder>> {
        let builder = match alg {
            KxAlgorithm::X25519 => X25519SecretKeyBuilder::new(alg),
            #[cfg(feature = "pqcrypto")]
            KxAlgorithm::MlKem512 | KxAlgorithm::MlKem768 | KxAlgorithm::MlKem1024 => {
                MlKemSecretKeyBuilder::new(alg)
            }
            #[cfg(not(feature = "pqcrypto"))]
            KxAlgorithm::MlKem512 | KxAlgorithm::MlKem768 | KxAlgorithm::MlKem1024 => {
                return Err(CryptoErrno::NotImplemented.into());
            }
            #[cfg(feature = "pqcrypto")]
            KxAlgorithm::XWing => XWingSecretKeyBuilder::new(alg),
            #[cfg(not(feature = "pqcrypto"))]
            KxAlgorithm::XWing => return Err(CryptoErrno::NotImplemented.into()),
        };
        Ok(builder)
    }

    pub fn from_raw(alg: KxAlgorithm, raw: &[u8]) -> CryptoResult<KxSecretKey> {
        Self::builder(alg)?.from_raw(raw)
    }

    pub(crate) fn import(
        alg: KxAlgorithm,
        encoded: &[u8],
        encoding: SecretkeyEncoding,
    ) -> CryptoResult<KxSecretKey> {
        match encoding {
            SecretkeyEncoding::Raw => Self::from_raw(alg, encoded),
            _ => Err(CryptoErrno::UnsupportedEncoding.into()),
        }
    }

    pub(crate) fn as_raw(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.inner().as_raw()?.to_vec())
    }

    pub(crate) fn export(&self, encoding: SecretkeyEncoding) -> CryptoResult<Vec<u8>> {
        match encoding {
            SecretkeyEncoding::Raw => Ok(self.inner().as_raw()?.to_vec()),
            _ => Err(CryptoErrno::UnsupportedEncoding.into()),
        }
    }

    pub(crate) fn publickey(&self) -> CryptoResult<KxPublicKey> {
        self.inner().publickey()
    }

    pub fn dh(&self, pk: &KxPublicKey) -> CryptoResult<Vec<u8>> {
        if pk.alg() != self.alg() {
            return Err(CryptoErrno::IncompatibleKeys.into());
        };
        self.inner().dh(pk)
    }

    pub(crate) fn decapsulate(&self, encapsulated_secret: &[u8]) -> CryptoResult<Vec<u8>> {
        self.inner().decapsulate(encapsulated_secret)
    }
}

pub trait KxSecretKeyLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn alg(&self) -> KxAlgorithm;
    fn len(&self) -> CryptoResult<usize>;
    fn as_raw(&self) -> CryptoResult<&[u8]>;
    fn publickey(&self) -> CryptoResult<KxPublicKey>;

    fn dh(&self, _pk: &KxPublicKey) -> CryptoResult<Vec<u8>> {
        Err(CryptoErrno::InvalidOperation.into())
    }

    fn decapsulate(&self, _encapsulated_secret: &[u8]) -> CryptoResult<Vec<u8>> {
        Err(CryptoErrno::InvalidOperation.into())
    }
}
