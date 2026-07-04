use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
        CryptoErrno, KeypairEncoding, PublickeyEncoding,
    },
    error::CryptoResult,
    signatures::{
        SignatureAlgorithm, SignatureOptions,
        signature::{Signature, SignatureLike, SignatureStateLike, SignatureVerificationStateLike},
    },
};
use std::{any::Any, sync::Arc};

const KP_LEN: usize = ed25519_compact::KeyPair::BYTES;
const PK_LEN: usize = ed25519_compact::PublicKey::BYTES;

#[derive(Debug, Clone)]
pub struct EddsaSignatureSecretKey {
    pub alg: SignatureAlgorithm,
}

#[derive(Debug, Clone)]
pub struct EddsaSignatureKeyPair {
    pub alg: SignatureAlgorithm,
    pub ctx: Arc<ed25519_compact::KeyPair>,
}

impl EddsaSignatureKeyPair {
    fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
        if raw.len() != KP_LEN {
            return Err(CryptoErrno::InvalidKey.into());
        };
        let ctx = ed25519_compact::KeyPair::from_slice(raw).map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(EddsaSignatureKeyPair {
            alg,
            ctx: Arc::new(ctx),
        })
    }

    fn as_raw(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.ctx.to_vec())
    }

    pub fn generate(
        alg: SignatureAlgorithm,
        _options: Option<SignatureOptions>,
    ) -> CryptoResult<Self> {
        let ctx = ed25519_compact::KeyPair::generate();
        Ok(EddsaSignatureKeyPair {
            alg,
            ctx: Arc::new(ctx),
        })
    }

    pub fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: KeypairEncoding,
    ) -> CryptoResult<Self> {
        if !(alg == SignatureAlgorithm::Ed25519) {
            return Err(CryptoErrno::UnsupportedAlgorithm.into());
        };
        let kp = match encoding {
            KeypairEncoding::Raw => EddsaSignatureKeyPair::from_raw(alg, encoded)?,
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

    pub fn public_key(&self) -> CryptoResult<EddsaSignaturePublicKey> {
        let ctx = self.ctx.pk;
        Ok(EddsaSignaturePublicKey { alg: self.alg, ctx })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EddsaSignature {
    pub raw: Vec<u8>,
}

impl EddsaSignature {
    pub fn new(raw: Vec<u8>) -> Self {
        EddsaSignature { raw }
    }

    pub fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
        let expected_len = match alg {
            SignatureAlgorithm::Ed25519 => 64,
            _ => return Err(CryptoErrno::InvalidSignature.into()),
        };
        if raw.len() != expected_len {
            return Err(CryptoErrno::InvalidSignature.into());
        };
        Ok(Self::new(raw.to_vec()))
    }
}

impl SignatureLike for EddsaSignature {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

pub struct EddsaSignatureState {
    pub kp: EddsaSignatureKeyPair,
    pub st: ed25519_compact::SigningState,
    pub signed: bool,
}

impl EddsaSignatureState {
    pub fn new(kp: EddsaSignatureKeyPair) -> Self {
        let st = kp.ctx.sk.sign_incremental(Default::default());
        EddsaSignatureState {
            kp,
            st,
            signed: false,
        }
    }
}

impl SignatureStateLike for EddsaSignatureState {
    fn update(&mut self, input: &[u8]) -> CryptoResult<()> {
        if self.signed {
            return Err(CryptoErrno::UnsupportedFeature.into());
        }
        self.st.absorb(input);
        Ok(())
    }

    fn sign(&mut self) -> CryptoResult<Signature> {
        let signature_u8 = self.st.sign().to_vec();
        self.signed = true;
        let signature = EddsaSignature::new(signature_u8);
        Ok(Signature::new(Box::new(signature)))
    }
}

#[derive(Debug)]
pub struct EddsaSignatureVerificationState {
    pub pk: EddsaSignaturePublicKey,
    pub input: Vec<u8>,
}

impl EddsaSignatureVerificationState {
    pub fn new(pk: EddsaSignaturePublicKey) -> Self {
        EddsaSignatureVerificationState { pk, input: vec![] }
    }
}

impl SignatureVerificationStateLike for EddsaSignatureVerificationState {
    fn update(&mut self, input: &[u8]) -> CryptoResult<()> {
        self.input.extend_from_slice(input);
        Ok(())
    }

    fn verify(&self, signature: &Signature) -> CryptoResult<()> {
        let signature = signature.inner();
        let signature = signature
            .as_any()
            .downcast_ref::<EddsaSignature>()
            .ok_or(CryptoErrno::InvalidSignature)?;
        let mut signature_u8 = [0u8; KP_LEN];
        if signature.as_ref().len() != signature_u8.len() {
            return Err(CryptoErrno::InvalidSignature.into());
        };
        signature_u8.copy_from_slice(signature.as_ref());
        self.pk
            .ctx
            .verify(
                &self.input,
                &ed25519_compact::Signature::from_slice(&signature_u8)
                    .map_err(|_| CryptoErrno::InvalidSignature)?,
            )
            .map_err(|_| CryptoErrno::InvalidSignature)?;
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct EddsaSignaturePublicKey {
    pub alg: SignatureAlgorithm,
    pub ctx: ed25519_compact::PublicKey,
}

impl EddsaSignaturePublicKey {
    fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
        let ctx =
            ed25519_compact::PublicKey::from_slice(raw).map_err(|_| CryptoErrno::InvalidKey)?;
        let pk = EddsaSignaturePublicKey { alg, ctx };
        Ok(pk)
    }

    fn as_raw(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.ctx.to_vec())
    }

    pub fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: PublickeyEncoding,
    ) -> CryptoResult<Self> {
        match encoding {
            PublickeyEncoding::Raw => Self::from_raw(alg, encoded),
            _ => Err(CryptoErrno::UnsupportedEncoding.into()),
        }
    }

    pub fn export(&self, encoding: PublickeyEncoding) -> CryptoResult<Vec<u8>> {
        match encoding {
            PublickeyEncoding::Raw => self.as_raw(),
            _ => Err(CryptoErrno::UnsupportedEncoding.into()),
        }
    }

    pub(crate) fn verify(&self) -> CryptoResult<()> {
        // import (from_slice) only checks the length.  Re-encode to DER and
        // re-import to trigger the full point decompression and curve check
        // performed by from_der.
        let der = self.ctx.to_der();
        ed25519_compact::PublicKey::from_der(&der).map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(())
    }
}
