use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{CryptoErrno, SecretkeyEncoding},
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

    pub(crate) fn export(&self, _encoding: SecretkeyEncoding) -> Result<Vec<u8>, CryptoErrno> {
        return Err(CryptoErrno::NotImplemented);
    }

    pub(crate) fn publickey(&self) -> Result<SignaturePublicKey, CryptoErrno> {
        return Err(CryptoErrno::NotImplemented);
    }
}
