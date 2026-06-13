use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
        AlgorithmType, CryptoErrno, PublickeyEncoding,
    },
    key_exchange::publickey::KxPublicKey,
    signatures::{SignatureAlgorithm, publickey::SignaturePublicKey},
};
use wasmtime::component::Resource;
use wasmtime_wasi::ResourceTable;

#[derive(Clone)]
pub enum PublicKey {
    Signature(SignaturePublicKey),
    KeyExchange(KxPublicKey),
}

impl PublicKey {
    pub(crate) fn into_signature_public_key(self) -> Result<SignaturePublicKey, CryptoErrno> {
        match self {
            PublicKey::Signature(pk) => Ok(pk),
            _ => return Err(CryptoErrno::InvalidHandle),
        }
    }

    pub(crate) fn into_kx_public_key(self) -> Result<KxPublicKey, CryptoErrno> {
        match self {
            PublicKey::KeyExchange(pk) => Ok(pk),
            _ => return Err(CryptoErrno::InvalidHandle),
        }
    }

    pub(crate) fn import(
        alg_type: AlgorithmType,
        alg_str: &str,
        encoded: &[u8],
        encoding: PublickeyEncoding,
    ) -> Result<PublicKey, CryptoErrno> {
        match alg_type {
            AlgorithmType::Signatures => Ok(PublicKey::Signature(SignaturePublicKey::import(
                SignatureAlgorithm::try_from(alg_str)?,
                encoded,
                encoding,
            )?)),
            AlgorithmType::KeyExchange => return Err(CryptoErrno::NotImplemented),
            _ => return Err(CryptoErrno::InvalidOperation),
        }
    }

    pub(crate) fn export(&self, encoding: PublickeyEncoding) -> Result<Vec<u8>, CryptoErrno> {
        match self {
            PublicKey::Signature(pk) => pk.export(encoding),
            PublicKey::KeyExchange(pk) => pk.export(encoding),
        }
    }

    pub(crate) fn verify(
        table: &mut ResourceTable,
        pk: Resource<PublicKey>,
    ) -> Result<(), CryptoErrno> {
        match table.get(&pk)? {
            PublicKey::Signature(pk) => SignaturePublicKey::verify(pk),
            PublicKey::KeyExchange(pk) => pk.verify(),
        }
    }
}
