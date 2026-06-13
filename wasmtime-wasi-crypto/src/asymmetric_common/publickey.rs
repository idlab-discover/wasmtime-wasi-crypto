use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{AlgorithmType, CryptoErrno},
    signatures::{SignatureAlgorithm, publickey::SignaturePublicKey},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicKeyEncoding {
    Raw,
    Pkcs8,
    Pem,
    Sec,
    Local,
}

#[derive(Clone)]
pub enum PublicKey {
    Signature(SignaturePublicKey),
    // KeyExchange(KxPublicKey),
}

impl PublicKey {
    pub(crate) fn into_signature_public_key(self) -> Result<SignaturePublicKey, CryptoErrno> {
        match self {
            PublicKey::Signature(pk) => Ok(pk),
            _ => return Err(CryptoErrno::InvalidHandle),
        }
    }

    // pub(crate) fn into_kx_public_key(self) -> Result<KxPublicKey, CryptoErrno> {
    //     match self {
    //         PublicKey::KeyExchange(pk) => Ok(pk),
    //         _ => return Err(CryptoErrno::InvalidHandle),
    //     }
    // }

    fn import(
        alg_type: AlgorithmType,
        alg_str: &str,
        encoded: &[u8],
        encoding: PublicKeyEncoding,
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

    fn export(&self, encoding: PublicKeyEncoding) -> Result<Vec<u8>, CryptoErrno> {
        match self {
            PublicKey::Signature(pk) => pk.export(encoding),
            // PublicKey::KeyExchange(pk) => pk.export(encoding),
        }
    }

    // fn verify(handles: &HandleManagers, pk_handle: Handle) -> Result<(), CryptoErrno> {
    //     match handles.publickey.get(pk_handle)? {
    //         PublicKey::Signature(pk) => SignaturePublicKey::verify(pk),
    //         PublicKey::KeyExchange(pk) => pk.verify(),
    //     }
    // }
}
