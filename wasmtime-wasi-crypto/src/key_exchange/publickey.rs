use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{CryptoErrno, PublickeyEncoding},
    key_exchange::{KxAlgorithm, kem::EncapsulatedSecret},
};
use std::{
    any::Any,
    sync::{Arc, Mutex, MutexGuard},
};

pub trait KxPublicKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> Result<KxPublicKey, CryptoErrno>;
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

    pub(crate) fn as_raw(&self) -> Result<Vec<u8>, CryptoErrno> {
        Ok(self.inner().as_raw()?.to_vec())
    }

    pub(crate) fn export(&self, encoding: PublickeyEncoding) -> Result<Vec<u8>, CryptoErrno> {
        match encoding {
            PublickeyEncoding::Raw => Ok(self.inner().as_raw()?.to_vec()),
            _ => return Err(CryptoErrno::UnsupportedEncoding),
        }
    }

    pub(crate) fn verify(&self) -> Result<(), CryptoErrno> {
        self.inner().verify()
    }

    pub(crate) fn encapsulate(&self) -> Result<EncapsulatedSecret, CryptoErrno> {
        self.inner().encapsulate()
    }
}

pub trait KxPublicKeyLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn alg(&self) -> KxAlgorithm;
    fn len(&self) -> Result<usize, CryptoErrno>;
    fn as_raw(&self) -> Result<&[u8], CryptoErrno>;

    fn verify(&self) -> Result<(), CryptoErrno> {
        Ok(())
    }

    fn encapsulate(&self) -> Result<EncapsulatedSecret, CryptoErrno> {
        return Err(CryptoErrno::InvalidOperation);
    }
}
