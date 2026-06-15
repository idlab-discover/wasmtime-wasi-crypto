use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    CryptoErrno, PublickeyEncoding, Signature,
};
use crate::signatures::{SignatureAlgorithm, SignatureOptions};
use derivative::Derivative;
use std::sync::Arc;

use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::KeypairEncoding;
use crate::rand::SecureRandom;
use crate::signatures::signature::{
    SignatureLike, SignatureStateLike, SignatureVerificationStateLike,
};
use ::sha2::{Digest, Sha256, Sha384};
use k256::ecdsa::{
    self as ecdsa_k256, signature::DigestVerifier as _, signature::RandomizedDigestSigner as _,
};
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use k256::pkcs8::{
    DecodePrivateKey as _, DecodePublicKey as _,
};
use p256::ecdsa::{
    self as ecdsa_p256, signature::DigestVerifier as _, signature::RandomizedDigestSigner as _,
};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::pkcs8::{
    DecodePrivateKey as _, DecodePublicKey as _,
};
use p384::ecdsa::{
    self as ecdsa_p384, signature::DigestVerifier as _, signature::RandomizedDigestSigner as _,
};
use p384::elliptic_curve::sec1::ToEncodedPoint as _;
use p384::pkcs8::{
    DecodePrivateKey as _, DecodePublicKey as _,
};
use std::any::Any;

#[derive(Debug, Clone)]
pub struct EcdsaSignatureSecretKey {
    pub alg: SignatureAlgorithm,
}

enum EcdsaSigningKeyVariant {
    P256(ecdsa_p256::SigningKey),
    K256(ecdsa_k256::SigningKey),
    P384(ecdsa_p384::SigningKey),
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct EcdsaSignatureKeyPair {
    pub alg: SignatureAlgorithm,
    #[derivative(Debug = "ignore")]
    ctx: Arc<EcdsaSigningKeyVariant>,
}

impl EcdsaSignatureKeyPair {
    fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> Result<Self, CryptoErrno> {
        let ctx = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => {
                let ecdsa_sk = ecdsa_p256::SigningKey::from_bytes(raw.into())
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::P256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_K256_SHA256 => {
                let ecdsa_sk = ecdsa_k256::SigningKey::from_bytes(raw.into())
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::K256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_P384_SHA384 => {
                let ecdsa_sk = ecdsa_p384::SigningKey::from_bytes(raw.into())
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::P384(ecdsa_sk)
            }
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        };
        Ok(EcdsaSignatureKeyPair {
            alg,
            ctx: Arc::new(ctx),
        })
    }

    fn from_pkcs8(alg: SignatureAlgorithm, pkcs8: &[u8]) -> Result<Self, CryptoErrno> {
        let ctx = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => {
                let ecdsa_sk = ecdsa_p256::SigningKey::from_pkcs8_der(pkcs8)
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::P256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_K256_SHA256 => {
                let ecdsa_sk = ecdsa_k256::SigningKey::from_pkcs8_der(pkcs8)
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::K256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_P384_SHA384 => {
                let ecdsa_sk = ecdsa_p384::SigningKey::from_pkcs8_der(pkcs8)
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::P384(ecdsa_sk)
            }
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        };
        Ok(EcdsaSignatureKeyPair {
            alg,
            ctx: Arc::new(ctx),
        })
    }

    fn from_pem(alg: SignatureAlgorithm, pem: &[u8]) -> Result<Self, CryptoErrno> {
        let ctx = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => {
                let ecdsa_sk = ecdsa_p256::SigningKey::from_pkcs8_pem(
                    std::str::from_utf8(pem).map_err(|_| CryptoErrno::InvalidKey)?,
                )
                .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::P256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_K256_SHA256 => {
                let ecdsa_sk = ecdsa_k256::SigningKey::from_pkcs8_pem(
                    std::str::from_utf8(pem).map_err(|_| CryptoErrno::InvalidKey)?,
                )
                .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::K256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_P384_SHA384 => {
                let ecdsa_sk = ecdsa_p384::SigningKey::from_pkcs8_pem(
                    std::str::from_utf8(pem).map_err(|_| CryptoErrno::InvalidKey)?,
                )
                .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::P384(ecdsa_sk)
            }
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        };
        Ok(EcdsaSignatureKeyPair {
            alg,
            ctx: Arc::new(ctx),
        })
    }

    fn as_raw(&self) -> Result<Vec<u8>, CryptoErrno> {
        let raw = match self.ctx.as_ref() {
            EcdsaSigningKeyVariant::P256(x) => x.to_bytes().to_vec(),
            EcdsaSigningKeyVariant::K256(x) => x.to_bytes().to_vec(),
            EcdsaSigningKeyVariant::P384(x) => x.to_bytes().to_vec(),
        };
        Ok(raw)
    }

    pub fn generate(
        alg: SignatureAlgorithm,
        _options: Option<SignatureOptions>,
    ) -> Result<Self, CryptoErrno> {
        let mut rng = SecureRandom::new();
        match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => {
                let ecdsa_sk = ecdsa_p256::SigningKey::random(&mut rng);
                Self::from_raw(alg, ecdsa_sk.to_bytes().as_slice())
            }
            SignatureAlgorithm::ECDSA_K256_SHA256 => {
                let ecdsa_sk = ecdsa_k256::SigningKey::random(&mut rng);
                Self::from_raw(alg, ecdsa_sk.to_bytes().as_slice())
            }
            SignatureAlgorithm::ECDSA_P384_SHA384 => {
                let ecdsa_sk = ecdsa_p384::SigningKey::random(&mut rng);
                Self::from_raw(alg, ecdsa_sk.to_bytes().as_slice())
            }
            _ => Err(CryptoErrno::UnsupportedAlgorithm),
        }
    }

    pub fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: KeypairEncoding,
    ) -> Result<Self, CryptoErrno> {
        if !(alg == SignatureAlgorithm::ECDSA_P256_SHA256
            || alg == SignatureAlgorithm::ECDSA_K256_SHA256
            || alg == SignatureAlgorithm::ECDSA_P384_SHA384)
        {
            return Err(CryptoErrno::UnsupportedAlgorithm);
        };
        let kp = match encoding {
            KeypairEncoding::Raw => EcdsaSignatureKeyPair::from_raw(alg, encoded)?,
            KeypairEncoding::Pkcs8 => EcdsaSignatureKeyPair::from_pkcs8(alg, encoded)?,
            KeypairEncoding::Pem => EcdsaSignatureKeyPair::from_pem(alg, encoded)?,
            _ => return Err(CryptoErrno::UnsupportedEncoding),
        };
        Ok(kp)
    }

    pub fn export(&self, encoding: KeypairEncoding) -> Result<Vec<u8>, CryptoErrno> {
        match encoding {
            KeypairEncoding::Raw => self.as_raw(),
            _ => Err(CryptoErrno::UnsupportedEncoding),
        }
    }

    pub fn public_key(&self) -> Result<EcdsaSignaturePublicKey, CryptoErrno> {
        let ctx = match self.ctx.as_ref() {
            EcdsaSigningKeyVariant::P256(x) => EcdsaVerifyingKeyVariant::P256(*x.verifying_key()),
            EcdsaSigningKeyVariant::K256(x) => EcdsaVerifyingKeyVariant::K256(*x.verifying_key()),
            EcdsaSigningKeyVariant::P384(x) => EcdsaVerifyingKeyVariant::P384(*x.verifying_key()),
        };
        Ok(EcdsaSignaturePublicKey {
            alg: self.alg,
            ctx: Arc::new(ctx),
        })
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum HashVariant {
    Sha256(Sha256),
    Sha384(Sha384),
}

#[derive(Debug)]
pub struct EcdsaSignatureState {
    pub kp: EcdsaSignatureKeyPair,
    h: HashVariant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcdsaSignature {
    pub raw: Vec<u8>,
}

impl EcdsaSignature {
    pub fn new(raw: Vec<u8>) -> Self {
        EcdsaSignature { raw }
    }

    pub fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> Result<Self, CryptoErrno> {
        let expected_len = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 | SignatureAlgorithm::ECDSA_K256_SHA256 => 64,
            SignatureAlgorithm::ECDSA_P384_SHA384 => 96,
            _ => return Err(CryptoErrno::InvalidSignature),
        };
        if raw.len() != expected_len {
            return Err(CryptoErrno::InvalidSignature);
        };
        Ok(Self::new(raw.to_vec()))
    }
}

impl SignatureLike for EcdsaSignature {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl EcdsaSignatureState {
    pub fn new(kp: EcdsaSignatureKeyPair) -> Self {
        let h = match kp.alg {
            SignatureAlgorithm::ECDSA_P384_SHA384 => HashVariant::Sha384(Sha384::new()),
            _ => HashVariant::Sha256(Sha256::new()),
        };
        EcdsaSignatureState { kp, h }
    }
}

impl SignatureStateLike for EcdsaSignatureState {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoErrno> {
        match &mut self.h {
            HashVariant::Sha256(x) => x.update(input),
            HashVariant::Sha384(x) => x.update(input),
        };
        Ok(())
    }

    fn sign(&mut self) -> Result<Signature, CryptoErrno> {
        let mut rng = SecureRandom::new();
        let encoded_signature = match self.kp.ctx.as_ref() {
            EcdsaSigningKeyVariant::P256(x) => {
                let digest = match &self.h {
                    HashVariant::Sha256(x) => x.clone(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm),
                };
                let encoded_signature: ecdsa_p256::Signature =
                    x.sign_digest_with_rng(&mut rng, digest);
                encoded_signature.to_vec()
            }
            EcdsaSigningKeyVariant::K256(x) => {
                let digest = match &self.h {
                    HashVariant::Sha256(x) => x.clone(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm),
                };
                let encoded_signature: ecdsa_k256::Signature =
                    x.sign_digest_with_rng(&mut rng, digest);
                encoded_signature.to_vec()
            }
            EcdsaSigningKeyVariant::P384(x) => {
                let digest = match &self.h {
                    HashVariant::Sha384(x) => x.clone(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm),
                };
                let encoded_signature: ecdsa_p384::Signature =
                    x.sign_digest_with_rng(&mut rng, digest);
                encoded_signature.to_vec()
            }
        };
        let signature = EcdsaSignature::new(encoded_signature);
        Ok(Signature::new(Box::new(signature)))
    }
}

#[derive(Debug)]
pub struct EcdsaSignatureVerificationState {
    pub pk: EcdsaSignaturePublicKey,
    h: HashVariant,
}

impl EcdsaSignatureVerificationState {
    pub fn new(pk: EcdsaSignaturePublicKey) -> Self {
        let h = match pk.alg {
            SignatureAlgorithm::ECDSA_P384_SHA384 => HashVariant::Sha384(Sha384::new()),
            SignatureAlgorithm::ECDSA_P256_SHA256 | SignatureAlgorithm::ECDSA_K256_SHA256 => {
                HashVariant::Sha256(Sha256::new())
            }
            _ => unreachable!(),
        };
        EcdsaSignatureVerificationState { pk, h }
    }
}

impl SignatureVerificationStateLike for EcdsaSignatureVerificationState {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoErrno> {
        match &mut self.h {
            HashVariant::Sha256(x) => x.update(input),
            HashVariant::Sha384(x) => x.update(input),
        };
        Ok(())
    }

    fn verify(&self, signature: &Signature) -> Result<(), CryptoErrno> {
        let signature = signature.inner();
        let signature = signature
            .as_any()
            .downcast_ref::<EcdsaSignature>()
            .ok_or(CryptoErrno::InvalidSignature)?;

        match self.pk.ctx.as_ref() {
            EcdsaVerifyingKeyVariant::P256(x) => {
                let ecdsa_signature = ecdsa_p256::Signature::try_from(signature.as_ref())
                    .map_err(|_| CryptoErrno::InvalidSignature)?;
                let digest = match &self.h {
                    HashVariant::Sha256(x) => x.clone(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm),
                };
                x.verify_digest(digest, &ecdsa_signature)
            }
            EcdsaVerifyingKeyVariant::K256(x) => {
                let ecdsa_signature = ecdsa_k256::Signature::try_from(signature.as_ref())
                    .map_err(|_| CryptoErrno::InvalidSignature)?;
                let digest = match &self.h {
                    HashVariant::Sha256(x) => x.clone(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm),
                };
                x.verify_digest(digest, &ecdsa_signature)
            }
            EcdsaVerifyingKeyVariant::P384(x) => {
                let ecdsa_signature = ecdsa_p384::Signature::try_from(signature.as_ref())
                    .map_err(|_| CryptoErrno::InvalidSignature)?;
                let digest = match &self.h {
                    HashVariant::Sha384(x) => x.clone(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm),
                };
                x.verify_digest(digest, &ecdsa_signature)
            }
        }
        .map_err(|_| CryptoErrno::InvalidSignature)?;
        Ok(())
    }
}

enum EcdsaVerifyingKeyVariant {
    P256(ecdsa_p256::VerifyingKey),
    K256(ecdsa_k256::VerifyingKey),
    P384(ecdsa_p384::VerifyingKey),
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct EcdsaSignaturePublicKey {
    pub alg: SignatureAlgorithm,
    #[derivative(Debug = "ignore")]
    ctx: Arc<EcdsaVerifyingKeyVariant>,
}

impl EcdsaSignaturePublicKey {
    fn from_sec(alg: SignatureAlgorithm, sec: &[u8]) -> Result<Self, CryptoErrno> {
        let ctx = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => {
                let ecdsa_sk = ecdsa_p256::VerifyingKey::from_sec1_bytes(sec)
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaVerifyingKeyVariant::P256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_K256_SHA256 => {
                let ecdsa_sk = ecdsa_k256::VerifyingKey::from_sec1_bytes(sec)
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaVerifyingKeyVariant::K256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_P384_SHA384 => {
                let ecdsa_sk = ecdsa_p384::VerifyingKey::from_sec1_bytes(sec)
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaVerifyingKeyVariant::P384(ecdsa_sk)
            }
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        };
        let pk = EcdsaSignaturePublicKey {
            alg,
            ctx: Arc::new(ctx),
        };
        Ok(pk)
    }

    fn from_pkcs8(alg: SignatureAlgorithm, pkcs8: &[u8]) -> Result<Self, CryptoErrno> {
        let ctx = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => {
                let ecdsa_sk = ecdsa_p256::VerifyingKey::from_public_key_der(pkcs8)
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaVerifyingKeyVariant::P256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_K256_SHA256 => {
                let ecdsa_sk = ecdsa_k256::VerifyingKey::from_public_key_der(pkcs8)
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaVerifyingKeyVariant::K256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_P384_SHA384 => {
                let ecdsa_sk = ecdsa_p384::VerifyingKey::from_public_key_der(pkcs8)
                    .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaVerifyingKeyVariant::P384(ecdsa_sk)
            }
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        };
        let pk = EcdsaSignaturePublicKey {
            alg,
            ctx: Arc::new(ctx),
        };
        Ok(pk)
    }

    fn from_pem(alg: SignatureAlgorithm, pem: &[u8]) -> Result<Self, CryptoErrno> {
        let ctx = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => {
                let ecdsa_sk = ecdsa_p256::VerifyingKey::from_public_key_pem(
                    std::str::from_utf8(pem).map_err(|_| CryptoErrno::InvalidKey)?,
                )
                .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaVerifyingKeyVariant::P256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_K256_SHA256 => {
                let ecdsa_sk = ecdsa_k256::VerifyingKey::from_public_key_pem(
                    std::str::from_utf8(pem).map_err(|_| CryptoErrno::InvalidKey)?,
                )
                .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaVerifyingKeyVariant::K256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_P384_SHA384 => {
                let ecdsa_sk = ecdsa_p384::VerifyingKey::from_public_key_pem(
                    std::str::from_utf8(pem).map_err(|_| CryptoErrno::InvalidKey)?,
                )
                .map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaVerifyingKeyVariant::P384(ecdsa_sk)
            }
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        };
        let pk = EcdsaSignaturePublicKey {
            alg,
            ctx: Arc::new(ctx),
        };
        Ok(pk)
    }

    fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> Result<Self, CryptoErrno> {
        Self::from_sec(alg, raw)
    }

    fn as_sec(&self, compress: bool) -> Result<Vec<u8>, CryptoErrno> {
        let raw = match self.ctx.as_ref() {
            EcdsaVerifyingKeyVariant::P256(x) => x.to_encoded_point(compress).to_bytes().to_vec(),
            EcdsaVerifyingKeyVariant::K256(x) => x.to_encoded_point(compress).to_bytes().to_vec(),
            EcdsaVerifyingKeyVariant::P384(x) => x.to_encoded_point(compress).to_bytes().to_vec(),
        };
        Ok(raw)
    }

    fn as_raw(&self) -> Result<Vec<u8>, CryptoErrno> {
        self.as_sec(true)
    }

    pub fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: PublickeyEncoding,
    ) -> Result<Self, CryptoErrno> {
        match encoding {
            PublickeyEncoding::Raw => Self::from_raw(alg, encoded),
            PublickeyEncoding::Sec => Self::from_sec(alg, encoded),
            PublickeyEncoding::Pkcs8 => Self::from_pkcs8(alg, encoded),
            PublickeyEncoding::Pem => Self::from_pem(alg, encoded),
            _ => Err(CryptoErrno::UnsupportedEncoding),
        }
    }

    pub fn export(&self, encoding: PublickeyEncoding) -> Result<Vec<u8>, CryptoErrno> {
        match encoding {
            PublickeyEncoding::Raw => self.as_raw(),
            PublickeyEncoding::Sec => self.as_sec(false),
            _ => Err(CryptoErrno::UnsupportedEncoding),
        }
    }

    pub(crate) fn verify(&self) -> Result<(), CryptoErrno> {
        // Import validates point-on-curve and non-identity via from_sec1_bytes;
        // no stricter check is available through the p256/k256/p384 public API.
        Ok(())
    }
}
