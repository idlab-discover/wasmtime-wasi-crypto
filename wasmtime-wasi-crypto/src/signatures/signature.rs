use std::{
    any::Any,
    sync::{Arc, Mutex, MutexGuard},
};

use subtle::ConstantTimeEq;

use crate::{
    bindings::wasi::crypto::{
        wasi_ephemeral_crypto_common::CryptoErrno,
        wasi_ephemeral_crypto_signatures::{SignatureKeypair, SignaturePublickey},
    },
    signatures::{
        SignatureAlgorithm, SignatureAlgorithmFamily,
        ecdsa::{EcdsaSignature, EcdsaSignatureState, EcdsaSignatureVerificationState},
        eddsa::{EddsaSignature, EddsaSignatureState, EddsaSignatureVerificationState},
        keypair::SignatureKeyPair,
        publickey::SignaturePublicKey,
        rsa::{RsaSignature, RsaSignatureState, RsaSignatureVerificationState},
    },
};
use wasmtime::component::Resource;
use wasmtime_wasi::ResourceTable;

#[derive(Clone)]
pub struct Signature {
    inner: Arc<Mutex<Box<dyn SignatureLike>>>,
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        let v1 = self.inner();
        let v1 = v1.as_ref();
        let v2 = other.inner();
        let v2 = v2.as_ref();
        v1.as_ref().ct_eq(v2.as_ref()).unwrap_u8() == 1
    }
}

impl Eq for Signature {}

impl Signature {
    pub fn new(signature_like: Box<dyn SignatureLike>) -> Self {
        Signature {
            inner: Arc::new(Mutex::new(signature_like)),
        }
    }

    pub fn from_raw(alg: SignatureAlgorithm, encoded: &[u8]) -> Result<Self, CryptoErrno> {
        let signature = match alg.family() {
            SignatureAlgorithmFamily::ECDSA => {
                Signature::new(Box::new(EcdsaSignature::from_raw(alg, encoded)?))
            }
            SignatureAlgorithmFamily::EdDSA => {
                Signature::new(Box::new(EddsaSignature::from_raw(alg, encoded)?))
            }
            SignatureAlgorithmFamily::RSA => {
                Signature::new(Box::new(RsaSignature::from_raw(alg, encoded)?))
            }
        };
        Ok(signature)
    }

    pub fn inner(&self) -> MutexGuard<'_, Box<dyn SignatureLike>> {
        self.inner.lock().unwrap()
    }

    pub fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<'_, Box<dyn SignatureLike>>) -> U,
    {
        f(self.inner())
    }
}

pub trait SignatureLike: Sync + Send {
    fn as_any(&self) -> &dyn Any;
    fn as_ref(&self) -> &[u8];
}

#[derive(Clone)]
pub struct SignatureState {
    inner: Arc<Mutex<Box<dyn SignatureStateLike>>>,
}

impl SignatureState {
    fn new(signature_state_like: Box<dyn SignatureStateLike>) -> Self {
        SignatureState {
            inner: Arc::new(Mutex::new(signature_state_like)),
        }
    }

    fn inner(&self) -> MutexGuard<'_, Box<dyn SignatureStateLike>> {
        self.inner.lock().unwrap()
    }

    pub(crate) fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<'_, Box<dyn SignatureStateLike>>) -> U,
    {
        f(self.inner())
    }

    pub(crate) fn open(
        table: &mut ResourceTable,
        kp: Resource<SignatureKeypair>,
    ) -> Result<Resource<SignatureState>, CryptoErrno> {
        let kp = table.get(&kp)?.clone().into_signature_keypair()?;
        let signature_state = match kp {
            SignatureKeyPair::Ecdsa(kp) => {
                SignatureState::new(Box::new(EcdsaSignatureState::new(kp)))
            }
            SignatureKeyPair::Eddsa(kp) => {
                SignatureState::new(Box::new(EddsaSignatureState::new(kp)))
            }
            SignatureKeyPair::Rsa(kp) => SignatureState::new(Box::new(RsaSignatureState::new(kp))),
        };
        let handle = table.push(signature_state)?;
        Ok(handle)
    }
}

pub trait SignatureStateLike: Sync + Send {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoErrno>;
    fn sign(&mut self) -> Result<Signature, CryptoErrno>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureEncoding {
    Raw,
    Der,
}

#[derive(Clone)]
pub struct SignatureVerificationState {
    inner: Arc<Mutex<Box<dyn SignatureVerificationStateLike>>>,
}

impl SignatureVerificationState {
    fn new(signature_verification_state_like: Box<dyn SignatureVerificationStateLike>) -> Self {
        SignatureVerificationState {
            inner: Arc::new(Mutex::new(signature_verification_state_like)),
        }
    }

    fn inner(&self) -> MutexGuard<'_, Box<dyn SignatureVerificationStateLike>> {
        self.inner.lock().unwrap()
    }

    pub(crate) fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<'_, Box<dyn SignatureVerificationStateLike>>) -> U,
    {
        f(self.inner())
    }

    pub(crate) fn open(
        table: &mut ResourceTable,
        pk: Resource<SignaturePublickey>,
    ) -> Result<Resource<SignatureVerificationState>, CryptoErrno> {
        let pk = table.get(&pk)?.clone().into_signature_public_key()?;
        let signature_verification_state = match pk {
            SignaturePublicKey::Ecdsa(pk) => {
                SignatureVerificationState::new(Box::new(EcdsaSignatureVerificationState::new(pk)))
            }
            SignaturePublicKey::Eddsa(pk) => {
                SignatureVerificationState::new(Box::new(EddsaSignatureVerificationState::new(pk)))
            }
            SignaturePublicKey::Rsa(pk) => {
                SignatureVerificationState::new(Box::new(RsaSignatureVerificationState::new(pk)))
            }
        };
        let handle = table.push(signature_verification_state)?;
        Ok(handle)
    }
}

pub trait SignatureVerificationStateLike: Sync + Send {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoErrno>;
    fn verify(&self, signature: &Signature) -> Result<(), CryptoErrno>;
}
