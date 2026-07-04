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
use pqcrypto_kyber::{kyber768, kyber1024};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use std::any::Any;

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct Kyber768PublicKey {
    alg: KxAlgorithm,
    #[derivative(Debug = "ignore")]
    pq_pk: kyber768::PublicKey,
}

impl Kyber768PublicKey {
    fn new(alg: KxAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
        if raw.len() != kyber768::public_key_bytes() {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let mut raw_ = [0u8; kyber768::public_key_bytes()];
        raw_.copy_from_slice(raw);
        let pq_pk = kyber768::PublicKey::from_bytes(raw).map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(Kyber768PublicKey { alg, pq_pk })
    }
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct Kyber768SecretKey {
    alg: KxAlgorithm,
    #[derivative(Debug = "ignore")]
    pq_sk: kyber768::SecretKey,
}

impl Kyber768SecretKey {
    fn new(alg: KxAlgorithm, raw: Vec<u8>) -> CryptoResult<Self> {
        if raw.len() != kyber768::secret_key_bytes() {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let mut raw_ = [0u8; kyber768::secret_key_bytes()];
        raw_.copy_from_slice(&raw);
        let pq_sk = kyber768::SecretKey::from_bytes(&raw).map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(Kyber768SecretKey { alg, pq_sk })
    }
}

#[derive(Clone, Debug)]
pub struct Kyber768KeyPair {
    alg: KxAlgorithm,
    pk: Kyber768PublicKey,
    sk: Kyber768SecretKey,
}

pub struct Kyber768KeyPairBuilder {
    alg: KxAlgorithm,
}

impl Kyber768KeyPairBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxKeyPairBuilder> {
        Box::new(Self { alg })
    }
}

impl KxKeyPairBuilder for Kyber768KeyPairBuilder {
    fn generate(&self, _options: Option<KxOptions>) -> CryptoResult<KxKeyPair> {
        let (pq_pk, pq_sk) = kyber768::keypair();
        let pk = Kyber768PublicKey {
            alg: self.alg,
            pq_pk,
        };
        let sk = Kyber768SecretKey {
            alg: self.alg,
            pq_sk,
        };
        let kp = Kyber768KeyPair {
            alg: self.alg,
            pk,
            sk,
        };
        Ok(KxKeyPair::new(Box::new(kp)))
    }
}

//

pub struct Kyber768SecretKeyBuilder {
    alg: KxAlgorithm,
}

impl KxSecretKeyBuilder for Kyber768SecretKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> CryptoResult<KxSecretKey> {
        if raw.len() != kyber768::secret_key_bytes() {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let sk = Kyber768SecretKey::new(self.alg, raw.to_vec())?;
        Ok(KxSecretKey::new(Box::new(sk)))
    }
}

impl Kyber768SecretKeyBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxSecretKeyBuilder> {
        Box::new(Self { alg })
    }
}

pub struct Kyber768PublicKeyBuilder {
    alg: KxAlgorithm,
}

impl KxPublicKeyBuilder for Kyber768PublicKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> CryptoResult<KxPublicKey> {
        if raw.len() != kyber768::public_key_bytes() {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let pk = Kyber768PublicKey::new(self.alg, raw)?;
        Ok(KxPublicKey::new(Box::new(pk)))
    }
}

impl Kyber768PublicKeyBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxPublicKeyBuilder> {
        Box::new(Self { alg })
    }
}

impl KxKeyPairLike for Kyber768KeyPair {
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

impl KxPublicKeyLike for Kyber768PublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        self.alg
    }

    fn len(&self) -> CryptoResult<usize> {
        Ok(kyber768::public_key_bytes())
    }

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(self.pq_pk.as_bytes())
    }

    fn verify(&self) -> CryptoResult<()> {
        Ok(())
    }

    fn encapsulate(&self) -> CryptoResult<EncapsulatedSecret> {
        let (secret, encapsulated_secret) = kyber768::encapsulate(&self.pq_pk);
        Ok(EncapsulatedSecret {
            secret: secret.as_bytes().to_vec(),
            encapsulated_secret: encapsulated_secret.as_bytes().to_vec(),
        })
    }
}

impl Kyber768SecretKey {
    fn kyber768_publickey(&self) -> CryptoResult<Kyber768PublicKey> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }
}

impl KxSecretKeyLike for Kyber768SecretKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        self.alg
    }

    fn len(&self) -> CryptoResult<usize> {
        Ok(kyber768::secret_key_bytes())
    }

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(self.pq_sk.as_bytes())
    }

    fn publickey(&self) -> CryptoResult<KxPublicKey> {
        Ok(KxPublicKey::new(Box::new(self.kyber768_publickey()?)))
    }

    fn decapsulate(&self, encapsulated_secret: &[u8]) -> CryptoResult<Vec<u8>> {
        let pq_encapsulated_secret = kyber768::Ciphertext::from_bytes(encapsulated_secret)
            .map_err(|_| CryptoErrno::VerificationFailed)?;
        Ok(kyber768::decapsulate(&pq_encapsulated_secret, &self.pq_sk)
            .as_bytes()
            .to_vec())
    }
}

//

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct Kyber1024PublicKey {
    alg: KxAlgorithm,
    #[derivative(Debug = "ignore")]
    pq_pk: kyber1024::PublicKey,
}

impl Kyber1024PublicKey {
    fn new(alg: KxAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
        if raw.len() != kyber1024::public_key_bytes() {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let mut raw_ = [0u8; kyber1024::public_key_bytes()];
        raw_.copy_from_slice(raw);
        let pq_pk = kyber1024::PublicKey::from_bytes(raw).map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(Kyber1024PublicKey { alg, pq_pk })
    }
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct Kyber1024SecretKey {
    alg: KxAlgorithm,
    #[derivative(Debug = "ignore")]
    pq_sk: kyber1024::SecretKey,
}

impl Kyber1024SecretKey {
    fn new(alg: KxAlgorithm, raw: Vec<u8>) -> CryptoResult<Self> {
        if raw.len() != kyber1024::secret_key_bytes() {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let mut raw_ = [0u8; kyber1024::secret_key_bytes()];
        raw_.copy_from_slice(&raw);
        let pq_sk = kyber1024::SecretKey::from_bytes(&raw).map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(Kyber1024SecretKey { alg, pq_sk })
    }
}

#[derive(Clone, Debug)]
pub struct Kyber1024KeyPair {
    alg: KxAlgorithm,
    pk: Kyber1024PublicKey,
    sk: Kyber1024SecretKey,
}

pub struct Kyber1024KeyPairBuilder {
    alg: KxAlgorithm,
}

impl Kyber1024KeyPairBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxKeyPairBuilder> {
        Box::new(Self { alg })
    }
}

impl KxKeyPairBuilder for Kyber1024KeyPairBuilder {
    fn generate(&self, _options: Option<KxOptions>) -> CryptoResult<KxKeyPair> {
        let (pq_pk, pq_sk) = kyber1024::keypair();
        let pk = Kyber1024PublicKey {
            alg: self.alg,
            pq_pk,
        };
        let sk = Kyber1024SecretKey {
            alg: self.alg,
            pq_sk,
        };
        let kp = Kyber1024KeyPair {
            alg: self.alg,
            pk,
            sk,
        };
        Ok(KxKeyPair::new(Box::new(kp)))
    }
}

// Kyber-1024

pub struct Kyber1024SecretKeyBuilder {
    alg: KxAlgorithm,
}

impl KxSecretKeyBuilder for Kyber1024SecretKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> CryptoResult<KxSecretKey> {
        if raw.len() != kyber1024::secret_key_bytes() {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let sk = Kyber1024SecretKey::new(self.alg, raw.to_vec())?;
        Ok(KxSecretKey::new(Box::new(sk)))
    }
}

impl Kyber1024SecretKeyBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxSecretKeyBuilder> {
        Box::new(Self { alg })
    }
}

pub struct Kyber1024PublicKeyBuilder {
    alg: KxAlgorithm,
}

impl KxPublicKeyBuilder for Kyber1024PublicKeyBuilder {
    fn from_raw(&self, raw: &[u8]) -> CryptoResult<KxPublicKey> {
        if raw.len() != kyber1024::public_key_bytes() {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let pk = Kyber1024PublicKey::new(self.alg, raw)?;
        Ok(KxPublicKey::new(Box::new(pk)))
    }
}

impl Kyber1024PublicKeyBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxPublicKeyBuilder> {
        Box::new(Self { alg })
    }
}

impl KxKeyPairLike for Kyber1024KeyPair {
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

impl KxPublicKeyLike for Kyber1024PublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        self.alg
    }

    fn len(&self) -> CryptoResult<usize> {
        Ok(kyber1024::public_key_bytes())
    }

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(self.pq_pk.as_bytes())
    }

    fn verify(&self) -> CryptoResult<()> {
        Ok(())
    }

    fn encapsulate(&self) -> CryptoResult<EncapsulatedSecret> {
        let (secret, encapsulated_secret) = kyber1024::encapsulate(&self.pq_pk);
        Ok(EncapsulatedSecret {
            secret: secret.as_bytes().to_vec(),
            encapsulated_secret: encapsulated_secret.as_bytes().to_vec(),
        })
    }
}

impl Kyber1024SecretKey {
    fn kyber1024_publickey(&self) -> CryptoResult<Kyber1024PublicKey> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }
}

impl KxSecretKeyLike for Kyber1024SecretKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        self.alg
    }

    fn len(&self) -> CryptoResult<usize> {
        Ok(kyber1024::secret_key_bytes())
    }

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(self.pq_sk.as_bytes())
    }

    fn publickey(&self) -> CryptoResult<KxPublicKey> {
        Ok(KxPublicKey::new(Box::new(self.kyber1024_publickey()?)))
    }

    fn decapsulate(&self, encapsulated_secret: &[u8]) -> CryptoResult<Vec<u8>> {
        let pq_encapsulated_secret = kyber1024::Ciphertext::from_bytes(encapsulated_secret)
            .map_err(|_| CryptoErrno::VerificationFailed)?;
        Ok(kyber1024::decapsulate(&pq_encapsulated_secret, &self.pq_sk)
            .as_bytes()
            .to_vec())
    }
}
