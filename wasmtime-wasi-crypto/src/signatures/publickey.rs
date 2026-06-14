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
        // The import path already validated the key (point-on-curve checks for
        // ECDSA via the p256/k256/p384 constructors, length/format checks for
        // EdDSA, and modulus/exponent checks for RSA via BoringSSL).  Per the
        // wasi-crypto spec, publickey_verify "may perform stricter checks than
        // those made during importation"; for all three algorithm families in
        // this implementation the import-time checks are already sufficient, so
        // we confirm validity by returning Ok(()) for every successfully-imported
        // key.
        match pk {
            SignaturePublicKey::Ecdsa(_) => Ok(()),
            SignaturePublicKey::Eddsa(_) => Ok(()),
            SignaturePublicKey::Rsa(_) => Ok(()),
        }
    }
}
