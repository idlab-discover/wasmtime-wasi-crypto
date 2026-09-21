use x_wing::{
    Decapsulate, DecapsulationKey, Decapsulator, Encapsulate, EncapsulationKey, Kem, KeyExport,
    KeyInit, TryKeyInit, XWingKem,
};

use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno,
    error::CryptoResult,
    key_exchange::{
        KxAlgorithm, KxOptions,
        kem::EncapsulatedSecret,
        keypair::{KxKeyPair, KxKeyPairBuilder, KxKeyPairLike},
        publickey::{KxPublicKey, KxPublicKeyBuilder, KxPublicKeyLike},
        secretkey::{KxSecretKey, KxSecretKeyBuilder, KxSecretKeyLike},
    },
};
use derivative::Derivative;
use std::any::Any;

/// Encapsulation key: an ML-KEM-768 encapsulation key (1184) followed by an
/// X25519 public key (32).
const PK_LEN: usize = 1216;

/// Decapsulation keys are stored and exchanged in their 32-byte seed form,
/// which is what `DecapsulationKey::as_bytes` returns.
const SK_LEN: usize = 32;

fn generate() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = XWingKem::generate_keypair();
    (ek.to_bytes().to_vec(), dk.as_bytes().to_vec())
}

fn encapsulate(pk_raw: &[u8]) -> CryptoResult<EncapsulatedSecret> {
    let ek = EncapsulationKey::new_from_slice(pk_raw).map_err(|_| CryptoErrno::InvalidKey)?;
    let (ciphertext, secret) = ek.encapsulate();
    Ok(EncapsulatedSecret {
        secret: secret.to_vec(),
        encapsulated_secret: ciphertext.to_vec(),
    })
}

fn decapsulate(sk_raw: &[u8], encapsulated_secret: &[u8]) -> CryptoResult<Vec<u8>> {
    let dk = DecapsulationKey::new_from_slice(sk_raw).map_err(|_| CryptoErrno::InvalidKey)?;
    Ok(dk
        .decapsulate_slice(encapsulated_secret)
        .map_err(|_| CryptoErrno::VerificationFailed)?
        .to_vec())
}

fn derive_publickey(sk_raw: &[u8]) -> CryptoResult<Vec<u8>> {
    let dk = DecapsulationKey::new_from_slice(sk_raw).map_err(|_| CryptoErrno::InvalidKey)?;
    Ok(dk.encapsulation_key().to_bytes().to_vec())
}

#[derive(Clone, Debug)]
pub struct XWingPublicKey {
    raw: Vec<u8>,
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct XWingSecretKey {
    #[derivative(Debug = "ignore")]
    raw: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct XWingKeyPair {
    pk: XWingPublicKey,
    sk: XWingSecretKey,
}

pub struct XWingKeyPairBuilder;

impl XWingKeyPairBuilder {
    pub fn new(_alg: KxAlgorithm) -> Box<dyn KxKeyPairBuilder> {
        Box::new(Self)
    }
}

impl KxKeyPairBuilder for XWingKeyPairBuilder {
    fn generate(&self, _options: Option<KxOptions>) -> CryptoResult<KxKeyPair> {
        let (pk_raw, sk_raw) = generate();
        let kp = XWingKeyPair {
            pk: XWingPublicKey { raw: pk_raw },
            sk: XWingSecretKey { raw: sk_raw },
        };
        Ok(KxKeyPair::new(Box::new(kp)))
    }
}

pub struct XWingSecretKeyBuilder;

impl XWingSecretKeyBuilder {
    pub fn new(_alg: KxAlgorithm) -> Box<dyn KxSecretKeyBuilder> {
        Box::new(Self)
    }
}

impl KxSecretKeyBuilder for XWingSecretKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> CryptoResult<KxSecretKey> {
        if raw.len() != SK_LEN {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let sk = XWingSecretKey { raw: raw.to_vec() };
        Ok(KxSecretKey::new(Box::new(sk)))
    }
}

pub struct XWingPublicKeyBuilder;

impl XWingPublicKeyBuilder {
    pub fn new(_alg: KxAlgorithm) -> Box<dyn KxPublicKeyBuilder> {
        Box::new(Self)
    }
}

impl KxPublicKeyBuilder for XWingPublicKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> CryptoResult<KxPublicKey> {
        if raw.len() != PK_LEN {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let pk = XWingPublicKey { raw: raw.to_vec() };
        Ok(KxPublicKey::new(Box::new(pk)))
    }
}

impl KxKeyPairLike for XWingKeyPair {
    fn alg(&self) -> KxAlgorithm {
        KxAlgorithm::XWing
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn publickey(&self) -> CryptoResult<KxPublicKey> {
        Ok(KxPublicKey::new(Box::new(self.pk.clone())))
    }

    fn secretkey(&self) -> CryptoResult<KxSecretKey> {
        Ok(KxSecretKey::new(Box::new(self.sk.clone())))
    }
}

impl KxPublicKeyLike for XWingPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        KxAlgorithm::XWing
    }

    fn len(&self) -> CryptoResult<usize> {
        Ok(self.raw.len())
    }

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(&self.raw)
    }

    fn encapsulate(&self) -> CryptoResult<EncapsulatedSecret> {
        encapsulate(&self.raw)
    }
}

impl KxSecretKeyLike for XWingSecretKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        KxAlgorithm::XWing
    }

    fn len(&self) -> CryptoResult<usize> {
        Ok(self.raw.len())
    }

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(&self.raw)
    }

    fn publickey(&self) -> CryptoResult<KxPublicKey> {
        let raw = derive_publickey(&self.raw)?;
        Ok(KxPublicKey::new(Box::new(XWingPublicKey { raw })))
    }

    fn decapsulate(&self, encapsulated_secret: &[u8]) -> CryptoResult<Vec<u8>> {
        decapsulate(&self.raw, encapsulated_secret)
    }
}
