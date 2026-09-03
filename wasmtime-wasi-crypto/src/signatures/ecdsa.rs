use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    CryptoErrno, PublickeyEncoding, Signature,
};
use crate::signatures::{SignatureAlgorithm, SignatureOptions};
use derivative::Derivative;
use std::sync::Arc;

use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::KeypairEncoding;
use crate::error::CryptoResult;
use crate::rand::SecureRandom;
use crate::signatures::signature::{
    SignatureLike, SignatureStateLike, SignatureVerificationStateLike,
};
use ::sha2::{Digest, Sha256, Sha384};
use k256::ecdsa::{
    self as ecdsa_k256,
    // The WIT streaming interface retains only the SHA-2 state, so ECDSA must sign
    // and verify its finalized digest rather than the original message.
    // SAFETY: This hazmat API is safe here because guests cannot provide a digest:
    // each fully specified algorithm selects its hash, and this host computes that
    // hash from guest input.
    signature::hazmat::{PrehashVerifier as _, RandomizedPrehashSigner as _},
};
use k256::elliptic_curve::Generate as _;
use k256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use p256::ecdsa::{self as ecdsa_p256};
use p384::ecdsa::{self as ecdsa_p384};
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
    fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
        let ctx = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => {
                let ecdsa_sk =
                    ecdsa_p256::SigningKey::try_from(raw).map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::P256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_K256_SHA256 => {
                let ecdsa_sk =
                    ecdsa_k256::SigningKey::try_from(raw).map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::K256(ecdsa_sk)
            }
            SignatureAlgorithm::ECDSA_P384_SHA384 => {
                let ecdsa_sk =
                    ecdsa_p384::SigningKey::try_from(raw).map_err(|_| CryptoErrno::InvalidKey)?;
                EcdsaSigningKeyVariant::P384(ecdsa_sk)
            }
            _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
        };
        Ok(EcdsaSignatureKeyPair {
            alg,
            ctx: Arc::new(ctx),
        })
    }

    fn from_pkcs8(alg: SignatureAlgorithm, pkcs8: &[u8]) -> CryptoResult<Self> {
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
            _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
        };
        Ok(EcdsaSignatureKeyPair {
            alg,
            ctx: Arc::new(ctx),
        })
    }

    fn from_pem(alg: SignatureAlgorithm, pem: &[u8]) -> CryptoResult<Self> {
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
            _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
        };
        Ok(EcdsaSignatureKeyPair {
            alg,
            ctx: Arc::new(ctx),
        })
    }

    fn as_raw(&self) -> CryptoResult<Vec<u8>> {
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
    ) -> CryptoResult<Self> {
        let mut rng = SecureRandom::new();
        match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 => {
                let ecdsa_sk = ecdsa_p256::SigningKey::generate_from_rng(&mut rng);
                Self::from_raw(alg, ecdsa_sk.to_bytes().as_slice())
            }
            SignatureAlgorithm::ECDSA_K256_SHA256 => {
                let ecdsa_sk = ecdsa_k256::SigningKey::generate_from_rng(&mut rng);
                Self::from_raw(alg, ecdsa_sk.to_bytes().as_slice())
            }
            SignatureAlgorithm::ECDSA_P384_SHA384 => {
                let ecdsa_sk = ecdsa_p384::SigningKey::generate_from_rng(&mut rng);
                Self::from_raw(alg, ecdsa_sk.to_bytes().as_slice())
            }
            _ => Err(CryptoErrno::UnsupportedAlgorithm.into()),
        }
    }

    pub fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: KeypairEncoding,
    ) -> CryptoResult<Self> {
        if !(alg == SignatureAlgorithm::ECDSA_P256_SHA256
            || alg == SignatureAlgorithm::ECDSA_K256_SHA256
            || alg == SignatureAlgorithm::ECDSA_P384_SHA384)
        {
            return Err(CryptoErrno::UnsupportedAlgorithm.into());
        };
        let kp = match encoding {
            KeypairEncoding::Raw => EcdsaSignatureKeyPair::from_raw(alg, encoded)?,
            KeypairEncoding::Pkcs8 => EcdsaSignatureKeyPair::from_pkcs8(alg, encoded)?,
            KeypairEncoding::Pem => EcdsaSignatureKeyPair::from_pem(alg, encoded)?,
            _ => return Err(CryptoErrno::UnsupportedEncoding.into()),
        };
        Ok(kp)
    }

    pub fn export(&self, encoding: KeypairEncoding) -> CryptoResult<Vec<u8>> {
        match encoding {
            KeypairEncoding::Raw => self.as_raw(),
            _ => Err(CryptoErrno::UnsupportedEncoding.into()),
        }
    }

    pub fn public_key(&self) -> CryptoResult<EcdsaSignaturePublicKey> {
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

    pub fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
        let expected_len = match alg {
            SignatureAlgorithm::ECDSA_P256_SHA256 | SignatureAlgorithm::ECDSA_K256_SHA256 => 64,
            SignatureAlgorithm::ECDSA_P384_SHA384 => 96,
            _ => return Err(CryptoErrno::InvalidSignature.into()),
        };
        if raw.len() != expected_len {
            return Err(CryptoErrno::InvalidSignature.into());
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
    fn update(&mut self, input: &[u8]) -> CryptoResult<()> {
        match &mut self.h {
            HashVariant::Sha256(x) => x.update(input),
            HashVariant::Sha384(x) => x.update(input),
        };
        Ok(())
    }

    fn sign(&mut self) -> CryptoResult<Signature> {
        let mut rng = SecureRandom::new();
        let encoded_signature = match self.kp.ctx.as_ref() {
            EcdsaSigningKeyVariant::P256(x) => {
                let prehash = match &self.h {
                    HashVariant::Sha256(d) => d.clone().finalize(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
                };
                let sig: ecdsa_p256::Signature = x
                    .sign_prehash_with_rng(&mut rng, &prehash)
                    .map_err(|_| CryptoErrno::AlgorithmFailure)?;
                sig.to_vec()
            }
            EcdsaSigningKeyVariant::K256(x) => {
                let prehash = match &self.h {
                    HashVariant::Sha256(d) => d.clone().finalize(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
                };
                let sig: ecdsa_k256::Signature = x
                    .sign_prehash_with_rng(&mut rng, &prehash)
                    .map_err(|_| CryptoErrno::AlgorithmFailure)?;
                sig.to_vec()
            }
            EcdsaSigningKeyVariant::P384(x) => {
                let prehash = match &self.h {
                    HashVariant::Sha384(d) => d.clone().finalize(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
                };
                let sig: ecdsa_p384::Signature = x
                    .sign_prehash_with_rng(&mut rng, &prehash)
                    .map_err(|_| CryptoErrno::AlgorithmFailure)?;
                sig.to_vec()
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
    fn update(&mut self, input: &[u8]) -> CryptoResult<()> {
        match &mut self.h {
            HashVariant::Sha256(x) => x.update(input),
            HashVariant::Sha384(x) => x.update(input),
        };
        Ok(())
    }

    fn verify(&self, signature: &Signature) -> CryptoResult<()> {
        let signature = signature.inner();
        let signature = signature
            .as_any()
            .downcast_ref::<EcdsaSignature>()
            .ok_or(CryptoErrno::InvalidSignature)?;

        match self.pk.ctx.as_ref() {
            EcdsaVerifyingKeyVariant::P256(x) => {
                let ecdsa_signature = ecdsa_p256::Signature::try_from(signature.as_ref())
                    .map_err(|_| CryptoErrno::InvalidSignature)?;
                let prehash = match &self.h {
                    HashVariant::Sha256(d) => d.clone().finalize().to_vec(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
                };
                x.verify_prehash(&prehash, &ecdsa_signature)
            }
            EcdsaVerifyingKeyVariant::K256(x) => {
                let ecdsa_signature = ecdsa_k256::Signature::try_from(signature.as_ref())
                    .map_err(|_| CryptoErrno::InvalidSignature)?;
                let prehash = match &self.h {
                    HashVariant::Sha256(d) => d.clone().finalize().to_vec(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
                };
                x.verify_prehash(&prehash, &ecdsa_signature)
            }
            EcdsaVerifyingKeyVariant::P384(x) => {
                let ecdsa_signature = ecdsa_p384::Signature::try_from(signature.as_ref())
                    .map_err(|_| CryptoErrno::InvalidSignature)?;
                let prehash = match &self.h {
                    HashVariant::Sha384(d) => d.clone().finalize().to_vec(),
                    _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
                };
                x.verify_prehash(&prehash, &ecdsa_signature)
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
    fn from_sec(alg: SignatureAlgorithm, sec: &[u8]) -> CryptoResult<Self> {
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
            _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
        };
        let pk = EcdsaSignaturePublicKey {
            alg,
            ctx: Arc::new(ctx),
        };
        Ok(pk)
    }

    fn from_pkcs8(alg: SignatureAlgorithm, pkcs8: &[u8]) -> CryptoResult<Self> {
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
            _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
        };
        let pk = EcdsaSignaturePublicKey {
            alg,
            ctx: Arc::new(ctx),
        };
        Ok(pk)
    }

    fn from_pem(alg: SignatureAlgorithm, pem: &[u8]) -> CryptoResult<Self> {
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
            _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
        };
        let pk = EcdsaSignaturePublicKey {
            alg,
            ctx: Arc::new(ctx),
        };
        Ok(pk)
    }

    fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
        Self::from_sec(alg, raw)
    }

    fn as_sec(&self, compress: bool) -> CryptoResult<Vec<u8>> {
        let raw = match self.ctx.as_ref() {
            EcdsaVerifyingKeyVariant::P256(x) => x.to_sec1_point(compress).as_bytes().to_vec(),
            EcdsaVerifyingKeyVariant::K256(x) => x.to_sec1_point(compress).as_bytes().to_vec(),
            EcdsaVerifyingKeyVariant::P384(x) => x.to_sec1_point(compress).as_bytes().to_vec(),
        };
        Ok(raw)
    }

    fn as_raw(&self) -> CryptoResult<Vec<u8>> {
        self.as_sec(true)
    }

    pub fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: PublickeyEncoding,
    ) -> CryptoResult<Self> {
        match encoding {
            PublickeyEncoding::Raw => Self::from_raw(alg, encoded),
            PublickeyEncoding::Sec => Self::from_sec(alg, encoded),
            PublickeyEncoding::Pkcs8 => Self::from_pkcs8(alg, encoded),
            PublickeyEncoding::Pem => Self::from_pem(alg, encoded),
            _ => Err(CryptoErrno::UnsupportedEncoding.into()),
        }
    }

    pub fn export(&self, encoding: PublickeyEncoding) -> CryptoResult<Vec<u8>> {
        match encoding {
            PublickeyEncoding::Raw => self.as_raw(),
            PublickeyEncoding::Sec => self.as_sec(false),
            _ => Err(CryptoErrno::UnsupportedEncoding.into()),
        }
    }

    pub(crate) fn verify(&self) -> CryptoResult<()> {
        // Import validates point-on-curve and non-identity via from_sec1_bytes;
        // no stricter check is available through the p256/k256/p384 public API.
        Ok(())
    }
}
