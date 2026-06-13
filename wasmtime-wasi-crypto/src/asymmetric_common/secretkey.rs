use crate::{
    asymmetric_common::publickey::PublicKey,
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
        AlgorithmType, CryptoErrno, SecretkeyEncoding,
    },
    key_exchange::secretkey::KxSecretKey,
    signatures::secretkey::SignatureSecretKey,
};

#[derive(Clone)]
pub enum SecretKey {
    Signature(SignatureSecretKey),
    KeyExchange(KxSecretKey),
}

impl SecretKey {
    pub(crate) fn into_signature_secret_key(self) -> Result<SignatureSecretKey, CryptoErrno> {
        match self {
            SecretKey::Signature(sk) => Ok(sk),
            _ => return Err(CryptoErrno::InvalidHandle),
        }
    }

    pub(crate) fn into_kx_secret_key(self) -> Result<KxSecretKey, CryptoErrno> {
        match self {
            SecretKey::KeyExchange(sk) => Ok(sk),
            _ => return Err(CryptoErrno::InvalidHandle),
        }
    }

    pub(crate) fn import(
        _alg_type: AlgorithmType,
        _alg_str: &str,
        _encoded: &[u8],
        _encoding: SecretkeyEncoding,
    ) -> Result<SecretKey, CryptoErrno> {
        return Err(CryptoErrno::NotImplemented);
    }

    pub(crate) fn export(&self, encoding: SecretkeyEncoding) -> Result<Vec<u8>, CryptoErrno> {
        match self {
            SecretKey::Signature(sk) => Ok(sk.export(encoding)?),
            SecretKey::KeyExchange(sk) => Ok(sk.export(encoding)?),
        }
    }

    pub fn publickey(&self) -> Result<PublicKey, CryptoErrno> {
        match self {
            SecretKey::Signature(sk) => Ok(PublicKey::Signature(sk.publickey()?)),
            SecretKey::KeyExchange(sk) => Ok(PublicKey::KeyExchange(sk.publickey()?)),
        }
    }
}
