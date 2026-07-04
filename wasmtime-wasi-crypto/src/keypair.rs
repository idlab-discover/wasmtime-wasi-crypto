use crate::{
    asymmetric_common::{publickey::PublicKey, secretkey::SecretKey},
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
        AlgorithmType, CryptoErrno, KeypairEncoding,
    },
    error::CryptoResult,
    key_exchange::{KxAlgorithm, keypair::KxKeyPair},
    options::Options,
    signatures::{SignatureAlgorithm, keypair::SignatureKeyPair},
};

#[derive(Clone)]
pub enum KeyPair {
    Signature(SignatureKeyPair),
    KeyExchange(KxKeyPair),
}

impl KeyPair {
    pub(crate) fn into_signature_keypair(self) -> CryptoResult<SignatureKeyPair> {
        match self {
            KeyPair::Signature(kp) => Ok(kp),
            _ => Err(CryptoErrno::InvalidHandle.into()),
        }
    }

    pub(crate) fn into_kx_keypair(self) -> CryptoResult<KxKeyPair> {
        match self {
            KeyPair::KeyExchange(kp) => Ok(kp),
            _ => Err(CryptoErrno::InvalidHandle.into()),
        }
    }

    pub fn export(&self, encoding: KeypairEncoding) -> CryptoResult<Vec<u8>> {
        match self {
            KeyPair::Signature(key_pair) => key_pair.export(encoding),
            KeyPair::KeyExchange(key_pair) => key_pair.export(encoding),
        }
    }

    pub fn generate(
        alg_type: AlgorithmType,
        alg_str: &str,
        options: Option<Options>,
    ) -> CryptoResult<KeyPair> {
        match alg_type {
            AlgorithmType::Signatures => {
                let options = match options {
                    None => None,
                    Some(options) => Some(options.into_signatures()?),
                };
                Ok(KeyPair::Signature(SignatureKeyPair::generate(
                    SignatureAlgorithm::try_from(alg_str)?,
                    options,
                )?))
            }
            AlgorithmType::KeyExchange => {
                let options = match options {
                    None => None,
                    Some(options) => Some(options.into_key_exchange()?),
                };
                Ok(KeyPair::KeyExchange(KxKeyPair::generate(
                    KxAlgorithm::try_from(alg_str)?,
                    options,
                )?))
            }
            _ => Err(CryptoErrno::InvalidOperation.into()),
        }
    }

    pub fn import(
        alg_type: AlgorithmType,
        alg_str: &str,
        encoded: &[u8],
        encoding: KeypairEncoding,
    ) -> CryptoResult<KeyPair> {
        match alg_type {
            AlgorithmType::Signatures => Ok(KeyPair::Signature(SignatureKeyPair::import(
                SignatureAlgorithm::try_from(alg_str)?,
                encoded,
                encoding,
            )?)),
            _ => Err(CryptoErrno::InvalidOperation.into()),
        }
    }

    pub fn from_pk_and_sk(_pk: PublicKey, _sk: SecretKey) -> CryptoResult<KeyPair> {
        match (_pk, _sk) {
            (PublicKey::Signature(pk), SecretKey::Signature(sk)) => {
                if !(pk.alg() == sk.alg()) {
                    return Err(CryptoErrno::IncompatibleKeys.into());
                };
            }
            (PublicKey::KeyExchange(pk), SecretKey::KeyExchange(sk)) => {
                if !(pk.alg() == sk.alg()) {
                    return Err(CryptoErrno::IncompatibleKeys.into());
                };
            }
            _ => return Err(CryptoErrno::IncompatibleKeys.into()),
        }
        Err(CryptoErrno::NotImplemented.into())
    }

    pub fn public_key(&self) -> CryptoResult<PublicKey> {
        match self {
            KeyPair::Signature(key_pair) => Ok(PublicKey::Signature(key_pair.public_key()?)),
            KeyPair::KeyExchange(key_pair) => Ok(PublicKey::KeyExchange(key_pair.public_key()?)),
        }
    }

    pub fn secret_key(&self) -> CryptoResult<SecretKey> {
        match self {
            KeyPair::Signature(key_pair) => Ok(SecretKey::Signature(key_pair.secret_key()?)),
            KeyPair::KeyExchange(key_pair) => Ok(SecretKey::KeyExchange(key_pair.secret_key()?)),
        }
    }
}
