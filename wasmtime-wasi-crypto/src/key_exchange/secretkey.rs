use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{CryptoErrno, SecretkeyEncoding},
    key_exchange::{KxAlgorithm, publickey::KxPublicKey},
};
use std::{
    any::Any,
    sync::{Arc, Mutex, MutexGuard},
};

pub trait KxSecretKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> Result<KxSecretKey, CryptoErrno>;
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

    pub(crate) fn as_raw(&self) -> Result<Vec<u8>, CryptoErrno> {
        Ok(self.inner().as_raw()?.to_vec())
    }

    pub(crate) fn export(&self, encoding: SecretkeyEncoding) -> Result<Vec<u8>, CryptoErrno> {
        match encoding {
            SecretkeyEncoding::Raw => Ok(self.inner().as_raw()?.to_vec()),
            _ => return Err(CryptoErrno::UnsupportedEncoding),
        }
    }

    pub(crate) fn publickey(&self) -> Result<KxPublicKey, CryptoErrno> {
        self.inner().publickey()
    }

    pub fn dh(&self, pk: &KxPublicKey) -> Result<Vec<u8>, CryptoErrno> {
        if pk.alg() != self.alg() {
            return Err(CryptoErrno::IncompatibleKeys);
        };
        self.inner().dh(pk)
    }

    pub(crate) fn decapsulate(&self, encapsulated_secret: &[u8]) -> Result<Vec<u8>, CryptoErrno> {
        self.inner().decapsulate(encapsulated_secret)
    }
}

pub trait KxSecretKeyLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn alg(&self) -> KxAlgorithm;
    fn len(&self) -> Result<usize, CryptoErrno>;
    fn as_raw(&self) -> Result<&[u8], CryptoErrno>;
    fn publickey(&self) -> Result<KxPublicKey, CryptoErrno>;

    fn dh(&self, _pk: &KxPublicKey) -> Result<Vec<u8>, CryptoErrno> {
        return Err(CryptoErrno::InvalidOperation);
    }

    fn decapsulate(&self, _encapsulated_secret: &[u8]) -> Result<Vec<u8>, CryptoErrno> {
        return Err(CryptoErrno::InvalidOperation);
    }
}
