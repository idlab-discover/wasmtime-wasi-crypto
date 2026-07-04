use crate::{
    asymmetric_common::publickey::PublicKey,
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
        AlgorithmType, CryptoErrno, SecretkeyEncoding,
    },
    error::CryptoResult,
    key_exchange::{KxAlgorithm, X25519SecretKeyBuilder, secretkey::KxSecretKey},
    signatures::secretkey::SignatureSecretKey,
};

#[derive(Clone)]
pub enum SecretKey {
    Signature(SignatureSecretKey),
    KeyExchange(KxSecretKey),
}

impl SecretKey {
    pub(crate) fn into_signature_secret_key(self) -> CryptoResult<SignatureSecretKey> {
        match self {
            SecretKey::Signature(sk) => Ok(sk),
            _ => Err(CryptoErrno::InvalidHandle.into()),
        }
    }

    pub(crate) fn into_kx_secret_key(self) -> CryptoResult<KxSecretKey> {
        match self {
            SecretKey::KeyExchange(sk) => Ok(sk),
            _ => Err(CryptoErrno::InvalidHandle.into()),
        }
    }

    pub(crate) fn import(
        alg_type: AlgorithmType,
        alg_str: &str,
        encoded: &[u8],
        _encoding: SecretkeyEncoding,
    ) -> CryptoResult<SecretKey> {
        match alg_type {
            AlgorithmType::KeyExchange => {
                let alg = KxAlgorithm::try_from(alg_str)?;
                let builder = match alg {
                    KxAlgorithm::X25519 => X25519SecretKeyBuilder::new(alg),
                    _ => return Err(CryptoErrno::NotImplemented.into()),
                };
                Ok(SecretKey::KeyExchange(builder.from_raw(encoded)?))
            }
            _ => Err(CryptoErrno::NotImplemented.into()),
        }
    }

    pub(crate) fn export(&self, encoding: SecretkeyEncoding) -> CryptoResult<Vec<u8>> {
        match self {
            SecretKey::Signature(sk) => Ok(sk.export(encoding)?),
            SecretKey::KeyExchange(sk) => Ok(sk.export(encoding)?),
        }
    }

    pub fn publickey(&self) -> CryptoResult<PublicKey> {
        match self {
            SecretKey::Signature(sk) => Ok(PublicKey::Signature(sk.publickey()?)),
            SecretKey::KeyExchange(sk) => Ok(PublicKey::KeyExchange(sk.publickey()?)),
        }
    }
}
