use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno,
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::KeypairEncoding,
    signatures::{
        SignatureAlgorithm, SignatureAlgorithmFamily, SignatureOptions,
        ecdsa::EcdsaSignatureKeyPair, eddsa::EddsaSignatureKeyPair, publickey::SignaturePublicKey,
        rsa::RsaSignatureKeyPair, secretkey::SignatureSecretKey,
    },
};

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum SignatureKeyPair {
    Ecdsa(EcdsaSignatureKeyPair),
    Eddsa(EddsaSignatureKeyPair),
    Rsa(RsaSignatureKeyPair),
}

impl SignatureKeyPair {
    pub(crate) fn export(&self, encoding: KeypairEncoding) -> Result<Vec<u8>, CryptoErrno> {
        let encoded = match self {
            SignatureKeyPair::Ecdsa(kp) => kp.export(encoding)?,
            SignatureKeyPair::Eddsa(kp) => kp.export(encoding)?,
            SignatureKeyPair::Rsa(kp) => kp.export(encoding)?,
        };
        Ok(encoded)
    }

    pub(crate) fn generate(
        alg: SignatureAlgorithm,
        options: Option<SignatureOptions>,
    ) -> Result<SignatureKeyPair, CryptoErrno> {
        let kp = match alg.family() {
            SignatureAlgorithmFamily::ECDSA => {
                SignatureKeyPair::Ecdsa(EcdsaSignatureKeyPair::generate(alg, options)?)
            }
            SignatureAlgorithmFamily::EdDSA => {
                SignatureKeyPair::Eddsa(EddsaSignatureKeyPair::generate(alg, options)?)
            }
            SignatureAlgorithmFamily::RSA => {
                SignatureKeyPair::Rsa(RsaSignatureKeyPair::generate(alg, options)?)
            }
        };
        Ok(kp)
    }

    pub(crate) fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: KeypairEncoding,
    ) -> Result<SignatureKeyPair, CryptoErrno> {
        let kp = match alg.family() {
            SignatureAlgorithmFamily::ECDSA => {
                SignatureKeyPair::Ecdsa(EcdsaSignatureKeyPair::import(alg, encoded, encoding)?)
            }
            SignatureAlgorithmFamily::EdDSA => {
                SignatureKeyPair::Eddsa(EddsaSignatureKeyPair::import(alg, encoded, encoding)?)
            }
            SignatureAlgorithmFamily::RSA => {
                SignatureKeyPair::Rsa(RsaSignatureKeyPair::import(alg, encoded, encoding)?)
            }
        };
        Ok(kp)
    }

    pub(crate) fn public_key(&self) -> Result<SignaturePublicKey, CryptoErrno> {
        let pk = match self {
            SignatureKeyPair::Ecdsa(kp) => SignaturePublicKey::Ecdsa(kp.public_key()?),
            SignatureKeyPair::Eddsa(kp) => SignaturePublicKey::Eddsa(kp.public_key()?),
            SignatureKeyPair::Rsa(kp) => SignaturePublicKey::Rsa(kp.public_key()?),
        };
        Ok(pk)
    }

    pub(crate) fn secret_key(&self) -> Result<SignatureSecretKey, CryptoErrno> {
        Err(CryptoErrno::NotImplemented)
    }
}
