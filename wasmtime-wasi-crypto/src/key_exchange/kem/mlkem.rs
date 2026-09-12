use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno,
    error::CryptoResult,
    key_exchange::{
        KxAlgorithm, KxOptions,
        kem::EncapsulatedSecret,
        keypair::{KxKeyPair, KxKeyPairBuilder, KxKeyPairLike},
        publickey::{KxPublicKey, KxPublicKeyLike},
        secretkey::{KxSecretKey, KxSecretKeyLike},
    },
};
use derivative::Derivative;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, KeyInit, TryKeyInit};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem512, MlKem768, MlKem1024};
use std::any::Any;

const SK_LEN: usize = 64;

macro_rules! mlkem_dispatch {
    ($alg:expr, $p:ident => $body:block) => {
        match $alg {
            KxAlgorithm::MlKem512 => {
                type $p = MlKem512;
                $body
            }
            KxAlgorithm::MlKem768 => {
                type $p = MlKem768;
                $body
            }
            KxAlgorithm::MlKem1024 => {
                type $p = MlKem1024;
                $body
            }
            _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
        }
    };
}

fn generate(alg: KxAlgorithm) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    Ok(mlkem_dispatch!(alg, P => {
        let (dk, ek) = P::generate_keypair();
        (ek.to_bytes().to_vec(), dk.to_bytes().to_vec())
    }))
}

fn encapsulate(alg: KxAlgorithm, pk_raw: &[u8]) -> CryptoResult<EncapsulatedSecret> {
    let (secret, encapsulated_secret) = mlkem_dispatch!(alg, P => {
        let ek = EncapsulationKey::<P>::new_from_slice(pk_raw).map_err(|_| CryptoErrno::InvalidKey)?;
        let (ciphertext, secret) = ek.encapsulate();
        (secret.to_vec(), ciphertext.to_vec())
    });
    Ok(EncapsulatedSecret {
        secret,
        encapsulated_secret,
    })
}

fn decapsulate(
    alg: KxAlgorithm,
    sk_raw: &[u8],
    encapsulated_secret: &[u8],
) -> CryptoResult<Vec<u8>> {
    Ok(mlkem_dispatch!(alg, P => {
        let dk = DecapsulationKey::<P>::new_from_slice(sk_raw).map_err(|_| CryptoErrno::InvalidKey)?;
        dk.decapsulate_slice(encapsulated_secret)
            .map_err(|_| CryptoErrno::VerificationFailed)?
            .to_vec()
    }))
}

fn derive_publickey(alg: KxAlgorithm, sk_raw: &[u8]) -> CryptoResult<Vec<u8>> {
    Ok(mlkem_dispatch!(alg, P => {
        let dk = DecapsulationKey::<P>::new_from_slice(sk_raw).map_err(|_| CryptoErrno::InvalidKey)?;
        dk.encapsulation_key().to_bytes().to_vec()
    }))
}

#[derive(Clone, Debug)]
pub struct MlKemPublicKey {
    alg: KxAlgorithm,
    raw: Vec<u8>,
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct MlKemSecretKey {
    alg: KxAlgorithm,
    #[derivative(Debug = "ignore")]
    raw: Vec<u8>,
}

impl MlKemPublicKey {
    fn new(alg: KxAlgorithm, raw: Vec<u8>) -> Self {
        MlKemPublicKey { alg, raw }
    }
}

impl MlKemSecretKey {
    fn new(alg: KxAlgorithm, raw: Vec<u8>) -> Self {
        MlKemSecretKey { alg, raw }
    }
}

#[derive(Clone, Debug)]
pub struct MlKemKeyPair {
    alg: KxAlgorithm,
    pk: MlKemPublicKey,
    sk: MlKemSecretKey,
}

pub struct MlKemKeyPairBuilder {
    alg: KxAlgorithm,
}

impl MlKemKeyPairBuilder {
    pub fn new(alg: KxAlgorithm) -> Box<dyn KxKeyPairBuilder> {
        Box::new(Self { alg })
    }
}

impl KxKeyPairBuilder for MlKemKeyPairBuilder {
    fn generate(&self, _options: Option<KxOptions>) -> CryptoResult<KxKeyPair> {
        let (pk_raw, sk_raw) = generate(self.alg)?;
        let pk = MlKemPublicKey {
            alg: self.alg,
            raw: pk_raw,
        };
        let sk = MlKemSecretKey {
            alg: self.alg,
            raw: sk_raw,
        };
        let kp = MlKemKeyPair {
            alg: self.alg,
            pk,
            sk,
        };
        Ok(KxKeyPair::new(Box::new(kp)))
    }
}

impl KxKeyPairLike for MlKemKeyPair {
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

impl KxPublicKeyLike for MlKemPublicKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        self.alg
    }

    fn len(&self) -> CryptoResult<usize> {
        Ok(self.raw.len())
    }

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(&self.raw)
    }

    fn encapsulate(&self) -> CryptoResult<EncapsulatedSecret> {
        encapsulate(self.alg, &self.raw)
    }
}

impl KxSecretKeyLike for MlKemSecretKey {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn alg(&self) -> KxAlgorithm {
        self.alg
    }

    fn len(&self) -> CryptoResult<usize> {
        Ok(self.raw.len())
    }

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(&self.raw)
    }

    fn publickey(&self) -> CryptoResult<KxPublicKey> {
        let raw = derive_publickey(self.alg, &self.raw)?;
        Ok(KxPublicKey::new(Box::new(MlKemPublicKey {
            alg: self.alg,
            raw,
        })))
    }

    fn decapsulate(&self, encapsulated_secret: &[u8]) -> CryptoResult<Vec<u8>> {
        decapsulate(self.alg, &self.raw, encapsulated_secret)
    }
}
