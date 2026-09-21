#[cfg(feature = "pqcrypto")]
use crate::key_exchange::kem::{MlKemPublicKeyBuilder, XWingPublicKeyBuilder};
use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{CryptoErrno, PublickeyEncoding},
    error::CryptoResult,
    key_exchange::{KxAlgorithm, dh::X25519PublicKeyBuilder, kem::EncapsulatedSecret},
};
use std::{
    any::Any,
    sync::{Arc, Mutex, MutexGuard},
};

pub trait KxPublicKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> CryptoResult<KxPublicKey>;
}

#[derive(Clone)]
pub struct KxPublicKey {
    inner: Arc<Mutex<Box<dyn KxPublicKeyLike>>>,
}

impl KxPublicKey {
    pub fn new(kx_publickey_like: Box<dyn KxPublicKeyLike>) -> Self {
        KxPublicKey {
            inner: Arc::new(Mutex::new(kx_publickey_like)),
        }
    }

    pub fn inner(&self) -> MutexGuard<'_, Box<dyn KxPublicKeyLike>> {
        self.inner.lock().unwrap()
    }

    pub fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<'_, Box<dyn KxPublicKeyLike>>) -> U,
    {
        f(self.inner())
    }

    pub fn alg(&self) -> KxAlgorithm {
        self.inner().alg()
    }

    pub fn builder(alg: KxAlgorithm) -> CryptoResult<Box<dyn KxPublicKeyBuilder>> {
        let builder = match alg {
            KxAlgorithm::X25519 => X25519PublicKeyBuilder::new(alg),
            #[cfg(feature = "pqcrypto")]
            KxAlgorithm::MlKem512 | KxAlgorithm::MlKem768 | KxAlgorithm::MlKem1024 => {
                MlKemPublicKeyBuilder::new(alg)
            }
            #[cfg(not(feature = "pqcrypto"))]
            KxAlgorithm::MlKem512 | KxAlgorithm::MlKem768 | KxAlgorithm::MlKem1024 => {
                return Err(CryptoErrno::NotImplemented.into());
            }
            #[cfg(feature = "pqcrypto")]
            KxAlgorithm::XWing => XWingPublicKeyBuilder::new(alg),
            #[cfg(not(feature = "pqcrypto"))]
            KxAlgorithm::XWing => return Err(CryptoErrno::NotImplemented.into()),
        };
        Ok(builder)
    }

    pub fn from_raw(alg: KxAlgorithm, raw: &[u8]) -> CryptoResult<KxPublicKey> {
        Self::builder(alg)?.from_raw(raw)
    }

    pub(crate) fn import(
        alg: KxAlgorithm,
        encoded: &[u8],
        encoding: PublickeyEncoding,
    ) -> CryptoResult<KxPublicKey> {
        match encoding {
            PublickeyEncoding::Raw => Self::from_raw(alg, encoded),
            _ => Err(CryptoErrno::UnsupportedEncoding.into()),
        }
    }

    pub(crate) fn as_raw(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.inner().as_raw()?.to_vec())
    }

    pub(crate) fn export(&self, encoding: PublickeyEncoding) -> CryptoResult<Vec<u8>> {
        match encoding {
            PublickeyEncoding::Raw => Ok(self.inner().as_raw()?.to_vec()),
            _ => Err(CryptoErrno::UnsupportedEncoding.into()),
        }
    }

    pub(crate) fn verify(&self) -> CryptoResult<()> {
        self.inner().verify()
    }

    pub(crate) fn encapsulate(&self) -> CryptoResult<EncapsulatedSecret> {
        self.inner().encapsulate()
    }
}

pub trait KxPublicKeyLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn alg(&self) -> KxAlgorithm;
    fn len(&self) -> CryptoResult<usize>;
    fn as_raw(&self) -> CryptoResult<&[u8]>;

    fn verify(&self) -> CryptoResult<()> {
        Ok(())
    }

    fn encapsulate(&self) -> CryptoResult<EncapsulatedSecret> {
        Err(CryptoErrno::InvalidOperation.into())
    }
}
