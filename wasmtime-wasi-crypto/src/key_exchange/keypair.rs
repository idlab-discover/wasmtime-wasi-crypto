#[cfg(feature = "pqcrypto")]
use crate::key_exchange::kem::{MlKemKeyPairBuilder, XWingKeyPairBuilder};
use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{CryptoErrno, KeypairEncoding},
    error::CryptoResult,
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
    fn generate(&self, options: Option<KxOptions>) -> CryptoResult<KxKeyPair>;
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

    pub fn builder(alg: KxAlgorithm) -> CryptoResult<Box<dyn KxKeyPairBuilder>> {
        let builder = match alg {
            KxAlgorithm::X25519 => X25519KeyPairBuilder::new(alg),
            #[cfg(feature = "pqcrypto")]
            KxAlgorithm::MlKem512 | KxAlgorithm::MlKem768 | KxAlgorithm::MlKem1024 => {
                MlKemKeyPairBuilder::new(alg)
            }
            #[cfg(not(feature = "pqcrypto"))]
            KxAlgorithm::MlKem512 | KxAlgorithm::MlKem768 | KxAlgorithm::MlKem1024 => {
                return Err(CryptoErrno::NotImplemented);
            }
            #[cfg(feature = "pqcrypto")]
            KxAlgorithm::XWing => XWingKeyPairBuilder::new(alg),
            #[cfg(not(feature = "pqcrypto"))]
            KxAlgorithm::XWing => return Err(CryptoErrno::NotImplemented),
        };
        Ok(builder)
    }

    pub fn generate(alg: KxAlgorithm, options: Option<KxOptions>) -> CryptoResult<KxKeyPair> {
        let builder = Self::builder(alg)?;
        builder.generate(options)
    }

    pub(crate) fn export(&self, encoding: KeypairEncoding) -> CryptoResult<Vec<u8>> {
        match encoding {
            KeypairEncoding::Raw => self.inner().as_raw(),
            _ => Err(CryptoErrno::UnsupportedEncoding.into()),
        }
    }

    pub(crate) fn public_key(&self) -> CryptoResult<KxPublicKey> {
        self.inner().publickey()
    }

    pub(crate) fn secret_key(&self) -> CryptoResult<KxSecretKey> {
        self.inner().secretkey()
    }
}

pub trait KxKeyPairLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn alg(&self) -> KxAlgorithm;
    fn as_raw(&self) -> CryptoResult<Vec<u8>> {
        let pk_raw = self.publickey()?.as_raw()?;
        let sk_raw = self.secretkey()?.as_raw()?;
        let mut combined_raw = pk_raw;
        combined_raw.extend_from_slice(&sk_raw);
        Ok(combined_raw)
    }
    fn publickey(&self) -> CryptoResult<KxPublicKey>;
    fn secretkey(&self) -> CryptoResult<KxSecretKey>;
}
