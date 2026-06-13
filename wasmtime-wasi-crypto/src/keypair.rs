use crate::{
    asymmetric_common::{publickey::PublicKey, secretkey::SecretKey},
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{AlgorithmType, CryptoErrno},
    options::Options,
    signatures::{SignatureAlgorithm, keypair::SignatureKeyPair},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPairEncoding {
    Raw,
    Pkcs8,
    Pem,
    Local,
}

#[derive(Clone)]
pub enum KeyPair {
    Signature(SignatureKeyPair),
    // KeyExchange(KxKeyPair),
}

impl KeyPair {
    pub(crate) fn into_signature_keypair(self) -> Result<SignatureKeyPair, CryptoErrno> {
        match self {
            KeyPair::Signature(kp) => Ok(kp),
            _ => return Err(CryptoErrno::InvalidHandle),
        }
    }

    // pub(crate) fn into_kx_keypair(self) -> Result<KxKeyPair, CryptoErrno> {
    //     match self {
    //         KeyPair::KeyExchange(kp) => Ok(kp),
    //         _ => return Err(CryptoErrno::InvalidHandle),
    //     }
    // }

    pub fn export(&self, encoding: KeyPairEncoding) -> Result<Vec<u8>, CryptoErrno> {
        match self {
            KeyPair::Signature(key_pair) => key_pair.export(encoding),
            // KeyPair::KeyExchange(key_pair) => key_pair.export(encoding),
        }
    }

    pub fn generate(
        alg_type: AlgorithmType,
        alg_str: &str,
        options: Option<Options>,
    ) -> Result<KeyPair, CryptoErrno> {
        match alg_type {
            AlgorithmType::Signatures => {
                let options = match options {
                    None => None,
                    Some(options) => Some(options.into_signatures()?),
                };
                Ok(KeyPair::Signature(SignatureKeyPair::generate(
                    SignatureAlgorithm::try_from(alg_str)?,
                    options,
                )?))
            }
            // AlgorithmType::KeyExchange => {
            //     let options = match options {
            //         None => None,
            //         Some(options) => Some(options.into_key_exchange()?),
            //     };
            //     Ok(KeyPair::KeyExchange(KxKeyPair::generate(
            //         KxAlgorithm::try_from(alg_str)?,
            //         options,
            //     )?))
            // }
            _ => return Err(CryptoErrno::InvalidOperation),
        }
    }

    pub fn import(
        alg_type: AlgorithmType,
        alg_str: &str,
        encoded: &[u8],
        encoding: KeyPairEncoding,
    ) -> Result<KeyPair, CryptoErrno> {
        match alg_type {
            AlgorithmType::Signatures => Ok(KeyPair::Signature(SignatureKeyPair::import(
                SignatureAlgorithm::try_from(alg_str)?,
                encoded,
                encoding,
            )?)),
            _ => return Err(CryptoErrno::InvalidOperation),
        }
    }

    pub fn from_pk_and_sk(_pk: PublicKey, _sk: SecretKey) -> Result<KeyPair, CryptoErrno> {
        match (_pk, _sk) {
            (PublicKey::Signature(pk), SecretKey::Signature(sk)) => {
                if !(pk.alg() == sk.alg()) {
                    return Err(CryptoErrno::IncompatibleKeys);
                };
            }
            // (PublicKey::KeyExchange(pk), SecretKey::KeyExchange(sk)) => {
            //     if !(pk.alg() == sk.alg()) {
            //         return Err(CryptoErrno::IncompatibleKeys);
            //     };
            // }
            _ => return Err(CryptoErrno::IncompatibleKeys),
        }
        return Err(CryptoErrno::NotImplemented);
    }

    pub fn public_key(&self) -> Result<PublicKey, CryptoErrno> {
        match self {
            KeyPair::Signature(key_pair) => Ok(PublicKey::Signature(key_pair.public_key()?)),
            // KeyPair::KeyExchange(key_pair) => Ok(PublicKey::KeyExchange(key_pair.public_key()?)),
        }
    }

    pub fn secret_key(&self) -> Result<SecretKey, CryptoErrno> {
        match self {
            KeyPair::Signature(key_pair) => Ok(SecretKey::Signature(key_pair.secret_key()?)),
            // KeyPair::KeyExchange(key_pair) => Ok(SecretKey::KeyExchange(key_pair.secret_key()?)),
        }
    }
}
