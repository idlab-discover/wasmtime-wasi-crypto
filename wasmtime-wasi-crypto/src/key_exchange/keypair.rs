#[cfg(feature = "pqcrypto")]
use crate::key_exchange::kem::{Kyber768KeyPairBuilder, Kyber1024KeyPairBuilder};
use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno,
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::KeypairEncoding,
    key_exchange::{
        KxAlgorithm, KxOptions, dh::X25519KeyPairBuilder, publickey::KxPublicKey,
        secretkey::KxSecretKey,
    },
};
use std::{
    any::Any,
    sync::{Arc, Mutex, MutexGuard},
};

#[derive(Clone)]
pub struct KxKeyPair {
    inner: Arc<Mutex<Box<dyn KxKeyPairLike>>>,
}

pub trait KxKeyPairBuilder {
    fn generate(&self, options: Option<KxOptions>) -> Result<KxKeyPair, CryptoErrno>;
}

impl KxKeyPair {
    pub fn new(kx_keypair_like: Box<dyn KxKeyPairLike>) -> Self {
        KxKeyPair {
            inner: Arc::new(Mutex::new(kx_keypair_like)),
        }
    }

    pub fn inner(&self) -> MutexGuard<'_, Box<dyn KxKeyPairLike>> {
        self.inner.lock().unwrap()
    }

    pub fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<'_, Box<dyn KxKeyPairLike>>) -> U,
    {
        f(self.inner())
    }

    pub fn alg(&self) -> KxAlgorithm {
        self.inner().alg()
    }

    pub fn builder(alg: KxAlgorithm) -> Result<Box<dyn KxKeyPairBuilder>, CryptoErrno> {
        let builder = match alg {
            KxAlgorithm::X25519 => X25519KeyPairBuilder::new(alg),
            #[cfg(feature = "pqcrypto")]
            KxAlgorithm::Kyber768 => Kyber768KeyPairBuilder::new(alg),
            #[cfg(not(feature = "pqcrypto"))]
            KxAlgorithm::Kyber768 => return Err(CryptoErrno::NotImplemented),
            #[cfg(feature = "pqcrypto")]
            KxAlgorithm::Kyber1024 => Kyber1024KeyPairBuilder::new(alg),
            #[cfg(not(feature = "pqcrypto"))]
            KxAlgorithm::Kyber1024 => return Err(CryptoErrno::NotImplemented),
        };
        Ok(builder)
    }

    pub fn generate(
        alg: KxAlgorithm,
        options: Option<KxOptions>,
    ) -> Result<KxKeyPair, CryptoErrno> {
        let builder = Self::builder(alg)?;
        builder.generate(options)
    }

    pub(crate) fn export(&self, encoding: KeypairEncoding) -> Result<Vec<u8>, CryptoErrno> {
        match encoding {
            KeypairEncoding::Raw => self.inner().as_raw(),
            _ => return Err(CryptoErrno::UnsupportedEncoding),
        }
    }

    pub(crate) fn public_key(&self) -> Result<KxPublicKey, CryptoErrno> {
        self.inner().publickey()
    }

    pub(crate) fn secret_key(&self) -> Result<KxSecretKey, CryptoErrno> {
        self.inner().secretkey()
    }
}

pub trait KxKeyPairLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn alg(&self) -> KxAlgorithm;
    fn as_raw(&self) -> Result<Vec<u8>, CryptoErrno> {
        let pk_raw = self.publickey()?.as_raw()?;
        let sk_raw = self.secretkey()?.as_raw()?;
        let mut combined_raw = pk_raw;
        combined_raw.extend_from_slice(&sk_raw);
        Ok(combined_raw)
    }
    fn publickey(&self) -> Result<KxPublicKey, CryptoErrno>;
    fn secretkey(&self) -> Result<KxSecretKey, CryptoErrno>;
}
