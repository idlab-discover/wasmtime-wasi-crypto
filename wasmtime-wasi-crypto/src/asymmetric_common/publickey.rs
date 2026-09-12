use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
        AlgorithmType, CryptoErrno, PublickeyEncoding,
    },
    error::CryptoResult,
    key_exchange::{KxAlgorithm, X25519PublicKeyBuilder, publickey::KxPublicKey},
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
    pub(crate) fn into_signature_public_key(self) -> CryptoResult<SignaturePublicKey> {
        match self {
            PublicKey::Signature(pk) => Ok(pk),
            _ => Err(CryptoErrno::InvalidHandle.into()),
        }
    }

    pub(crate) fn into_kx_public_key(self) -> CryptoResult<KxPublicKey> {
        match self {
            PublicKey::KeyExchange(pk) => Ok(pk),
            _ => Err(CryptoErrno::InvalidHandle.into()),
        }
    }

    pub(crate) fn import(
        alg_type: AlgorithmType,
        alg_str: &str,
        encoded: &[u8],
        encoding: PublickeyEncoding,
    ) -> CryptoResult<PublicKey> {
        match alg_type {
            AlgorithmType::Signatures => Ok(PublicKey::Signature(SignaturePublicKey::import(
                SignatureAlgorithm::try_from(alg_str)?,
                encoded,
                encoding,
            )?)),
            AlgorithmType::KeyExchange => {
                let alg = KxAlgorithm::try_from(alg_str)?;
                let builder = match alg {
                    KxAlgorithm::X25519 => X25519PublicKeyBuilder::new(alg),
                    KxAlgorithm::MlKem512 | KxAlgorithm::MlKem768 | KxAlgorithm::MlKem1024 => {
                        return Err(CryptoErrno::NotImplemented.into());
                    }
                    KxAlgorithm::XWing => return Err(CryptoErrno::NotImplemented.into()),
                };
                Ok(PublicKey::KeyExchange(builder.from_raw(encoded)?))
            }
            _ => Err(CryptoErrno::InvalidOperation.into()),
        }
    }

    pub(crate) fn export(&self, encoding: PublickeyEncoding) -> CryptoResult<Vec<u8>> {
        match self {
            PublicKey::Signature(pk) => pk.export(encoding),
            PublicKey::KeyExchange(pk) => pk.export(encoding),
        }
    }

    pub(crate) fn verify(table: &mut ResourceTable, pk: Resource<PublicKey>) -> CryptoResult<()> {
        match table.get(&pk)? {
            PublicKey::Signature(pk) => SignaturePublicKey::verify(pk),
            PublicKey::KeyExchange(pk) => pk.verify(),
        }
    }
}
