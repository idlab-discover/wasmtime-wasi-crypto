use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{CryptoErrno, SecretkeyEncoding},
    error::CryptoResult,
    signatures::{
        SignatureAlgorithm, ecdsa::EcdsaSignatureSecretKey, eddsa::EddsaSignatureSecretKey,
        publickey::SignaturePublicKey, rsa::RsaSignatureSecretKey,
    },
};

#[derive(Clone, Debug)]
pub enum SignatureSecretKey {
    Ecdsa(EcdsaSignatureSecretKey),
    Eddsa(EddsaSignatureSecretKey),
    Rsa(RsaSignatureSecretKey),
}

impl SignatureSecretKey {
    pub fn alg(&self) -> SignatureAlgorithm {
        match self {
            SignatureSecretKey::Ecdsa(x) => x.alg,
            SignatureSecretKey::Eddsa(x) => x.alg,
            SignatureSecretKey::Rsa(x) => x.alg,
        }
    }

    pub(crate) fn export(&self, _encoding: SecretkeyEncoding) -> CryptoResult<Vec<u8>> {
        Err(CryptoErrno::NotImplemented.into())
    }

    pub(crate) fn publickey(&self) -> CryptoResult<SignaturePublicKey> {
        Err(CryptoErrno::NotImplemented.into())
    }
}
