use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{CryptoErrno, PublickeyEncoding},
    signatures::{
        SignatureAlgorithm, SignatureAlgorithmFamily, ecdsa::EcdsaSignaturePublicKey,
        eddsa::EddsaSignaturePublicKey, rsa::RsaSignaturePublicKey,
    },
};

#[derive(Clone, Debug)]
pub enum SignaturePublicKey {
    Ecdsa(EcdsaSignaturePublicKey),
    Eddsa(EddsaSignaturePublicKey),
    Rsa(RsaSignaturePublicKey),
}

impl SignaturePublicKey {
    pub fn alg(&self) -> SignatureAlgorithm {
        match self {
            SignaturePublicKey::Ecdsa(x) => x.alg,
            SignaturePublicKey::Eddsa(x) => x.alg,
            SignaturePublicKey::Rsa(x) => x.alg,
        }
    }

    pub(crate) fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: PublickeyEncoding,
    ) -> Result<SignaturePublicKey, CryptoErrno> {
        let pk = match alg.family() {
            SignatureAlgorithmFamily::ECDSA => {
                SignaturePublicKey::Ecdsa(EcdsaSignaturePublicKey::import(alg, encoded, encoding)?)
            }
            SignatureAlgorithmFamily::EdDSA => {
                SignaturePublicKey::Eddsa(EddsaSignaturePublicKey::import(alg, encoded, encoding)?)
            }
            SignatureAlgorithmFamily::RSA => {
                SignaturePublicKey::Rsa(RsaSignaturePublicKey::import(alg, encoded, encoding)?)
            }
        };
        Ok(pk)
    }

    pub(crate) fn export(&self, encoding: PublickeyEncoding) -> Result<Vec<u8>, CryptoErrno> {
        let raw_pk = match self {
            SignaturePublicKey::Ecdsa(pk) => pk.export(encoding)?,
            SignaturePublicKey::Eddsa(pk) => pk.export(encoding)?,
            SignaturePublicKey::Rsa(pk) => pk.export(encoding)?,
        };
        Ok(raw_pk)
    }

    pub(crate) fn verify(pk: &SignaturePublicKey) -> Result<(), CryptoErrno> {
        match pk {
            SignaturePublicKey::Ecdsa(pk) => pk.verify(),
            SignaturePublicKey::Eddsa(pk) => pk.verify(),
            SignaturePublicKey::Rsa(pk) => pk.verify(),
        }
    }
}
