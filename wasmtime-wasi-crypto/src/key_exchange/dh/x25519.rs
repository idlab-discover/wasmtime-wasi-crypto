use ed25519_compact::x25519;

use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno,
    error::CryptoResult,
    key_exchange::{
        KxAlgorithm, KxOptions,
        keypair::{KxKeyPair, KxKeyPairBuilder, KxKeyPairLike},
        publickey::{KxPublicKey, KxPublicKeyBuilder, KxPublicKeyLike},
        secretkey::{KxSecretKey, KxSecretKeyBuilder, KxSecretKeyLike},
    },
    rand::SecureRandom,
};
use std::any::Any;

const PK_LEN: usize = 32;
const SK_LEN: usize = 32;

#[derive(Clone, Debug)]
pub struct X25519PublicKey {
    alg: KxAlgorithm,
    group_element: x25519::PublicKey,
}

impl X25519PublicKey {
    fn new(alg: KxAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
        let group_element =
            x25519::PublicKey::from_slice(raw).map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(X25519PublicKey { alg, group_element })
    }
}

#[derive(Clone, Debug)]
pub struct X25519SecretKey {
    alg: KxAlgorithm,
    raw: Vec<u8>,
    scalar: x25519::SecretKey,
}

impl X25519SecretKey {
    fn new(alg: KxAlgorithm, raw: Vec<u8>) -> CryptoResult<Self> {
        let scalar = x25519::SecretKey::from_slice(&raw).map_err(|_| CryptoErrno::InvalidKey)?;
        let sk = X25519SecretKey { alg, raw, scalar };
        Ok(sk)
    }
}

#[derive(Clone, Debug)]
pub struct X25519KeyPair {
    alg: KxAlgorithm,
    pk: X25519PublicKey,
    sk: X25519SecretKey,
}

pub struct X25519KeyPairBuilder {
    alg: KxAlgorithm,
}

impl X25519KeyPairBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxKeyPairBuilder> {
        Box::new(Self { alg })
    }
}

impl KxKeyPairBuilder for X25519KeyPairBuilder {
    fn generate(&self, _options: Option<KxOptions>) -> CryptoResult<KxKeyPair> {
        let mut rng = SecureRandom::new();
        let mut sk_raw = vec![0u8; SK_LEN];
        rng.fill(&mut sk_raw)?;
        let sk = X25519SecretKey::new(self.alg, sk_raw)?;
        let pk = sk.x25519_publickey()?;
        let kp = X25519KeyPair {
            alg: self.alg,
            pk,
            sk,
        };
        Ok(KxKeyPair::new(Box::new(kp)))
    }
}

pub struct X25519SecretKeyBuilder {
    alg: KxAlgorithm,
}

impl KxSecretKeyBuilder for X25519SecretKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> CryptoResult<KxSecretKey> {
        if raw.len() != SK_LEN {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let sk = X25519SecretKey::new(self.alg, raw.to_vec())?;
        Ok(KxSecretKey::new(Box::new(sk)))
    }
}

impl X25519SecretKeyBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxSecretKeyBuilder> {
        Box::new(Self { alg })
    }
}

pub struct X25519PublicKeyBuilder {
    alg: KxAlgorithm,
}

impl KxPublicKeyBuilder for X25519PublicKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> CryptoResult<KxPublicKey> {
        if raw.len() != PK_LEN {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let pk = X25519PublicKey::new(self.alg, raw)?;
        Ok(KxPublicKey::new(Box::new(pk)))
    }
}

impl X25519PublicKeyBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxPublicKeyBuilder> {
        Box::new(Self { alg })
    }
}

impl KxKeyPairLike for X25519KeyPair {
    fn alg(&self) -> KxAlgorithm {
        self.alg
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

impl KxPublicKeyLike for X25519PublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        self.alg
    }

    fn len(&self) -> CryptoResult<usize> {
        Ok(PK_LEN)
    }

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(&*self.group_element)
    }

    fn verify(&self) -> CryptoResult<()> {
        self.group_element
            .clear_cofactor()
            .map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(())
    }
}

impl X25519SecretKey {
    fn x25519_publickey(&self) -> CryptoResult<X25519PublicKey> {
        let group_element = self
            .scalar
            .recover_public_key()
            .map_err(|_| CryptoErrno::InvalidKey)?;
        let pk = X25519PublicKey {
            alg: self.alg,
            group_element,
        };
        Ok(pk)
    }
}

impl KxSecretKeyLike for X25519SecretKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        self.alg
    }

    fn len(&self) -> CryptoResult<usize> {
        Ok(SK_LEN)
    }

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(&self.raw)
    }

    fn publickey(&self) -> CryptoResult<KxPublicKey> {
        Ok(KxPublicKey::new(Box::new(self.x25519_publickey()?)))
    }

    fn dh(&self, pk: &KxPublicKey) -> CryptoResult<Vec<u8>> {
        let pk = pk.inner();
        let pk = pk
            .as_any()
            .downcast_ref::<X25519PublicKey>()
            .ok_or(CryptoErrno::InvalidKey)?;
        let shared_secret = pk
            .group_element
            .dh(&self.scalar)
            .map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(shared_secret.to_vec())
    }
}
