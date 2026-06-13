use std::{any::Any, pin::Pin};

use boring::{bn, pkey, rsa};
use rkyv::rancor;
use zeroize::Zeroize;

use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
        CryptoErrno, KeypairEncoding, PublickeyEncoding, Signature,
    },
    signatures::{
        SignatureAlgorithm, SignatureAlgorithmFamily, SignatureOptions,
        signature::{SignatureLike, SignatureStateLike, SignatureVerificationStateLike},
    },
};

const RAW_ENCODING_VERSION: u16 = 2;
const RAW_ENCODING_ALG_ID: u16 = 1;
const MIN_MODULUS_SIZE: u32 = 2048;
const MAX_MODULUS_SIZE: u32 = 4096;

#[derive(Debug, Clone)]
pub struct RsaSignatureSecretKey {
    pub alg: SignatureAlgorithm,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Zeroize)]
struct RsaSignatureKeyPairParts {
    version: u16,
    alg_id: u16,
    n: Vec<u8>,
    e: Vec<u8>,
    d: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    dmp1: Vec<u8>,
    dmq1: Vec<u8>,
    iqmp: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RsaSignatureKeyPair {
    pub alg: SignatureAlgorithm,
    ctx: rsa::Rsa<pkey::Private>,
}

fn modulus_bits(alg: SignatureAlgorithm) -> Result<u32, CryptoErrno> {
    let modulus_bits = match alg {
        SignatureAlgorithm::RSA_PKCS1_2048_SHA256
        | SignatureAlgorithm::RSA_PKCS1_2048_SHA384
        | SignatureAlgorithm::RSA_PKCS1_2048_SHA512
        | SignatureAlgorithm::RSA_PSS_2048_SHA256
        | SignatureAlgorithm::RSA_PSS_2048_SHA384
        | SignatureAlgorithm::RSA_PSS_2048_SHA512 => 2048,
        SignatureAlgorithm::RSA_PKCS1_3072_SHA384
        | SignatureAlgorithm::RSA_PKCS1_3072_SHA512
        | SignatureAlgorithm::RSA_PSS_3072_SHA384
        | SignatureAlgorithm::RSA_PSS_3072_SHA512 => 3072,
        SignatureAlgorithm::RSA_PKCS1_4096_SHA512 | SignatureAlgorithm::RSA_PSS_4096_SHA512 => 4096,
        _ => return Err(CryptoErrno::UnsupportedAlgorithm),
    };
    Ok(modulus_bits)
}

impl RsaSignatureKeyPair {
    fn from_pkcs8(alg: SignatureAlgorithm, der: &[u8]) -> Result<Self, CryptoErrno> {
        if !(der.len() < 4096) {
            return Err(CryptoErrno::InvalidKey);
        };
        let ctx: rsa::Rsa<pkey::Private> =
            rsa::Rsa::private_key_from_der(der).map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(RsaSignatureKeyPair { alg, ctx })
    }

    fn from_pem(alg: SignatureAlgorithm, pem: &[u8]) -> Result<Self, CryptoErrno> {
        if !(pem.len() < 4096) {
            return Err(CryptoErrno::InvalidKey);
        };
        let ctx: rsa::Rsa<pkey::Private> =
            rsa::Rsa::private_key_from_pem(pem).map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(RsaSignatureKeyPair { alg, ctx })
    }

    fn from_local(alg: SignatureAlgorithm, local: &[u8]) -> Result<Self, CryptoErrno> {
        if !(local.len() < 2048) {
            return Err(CryptoErrno::InvalidKey);
        };
        let parts: RsaSignatureKeyPairParts =
            rkyv::from_bytes::<RsaSignatureKeyPairParts, rancor::Error>(local)
                .map_err(|_| CryptoErrno::InvalidKey)?;
        if !(parts.version == RAW_ENCODING_VERSION && parts.alg_id == RAW_ENCODING_ALG_ID) {
            return Err(CryptoErrno::InvalidKey);
        };
        let n = bn::BigNum::from_slice(&parts.n).map_err(|_| CryptoErrno::InvalidKey)?;
        let e = bn::BigNum::from_slice(&parts.e).map_err(|_| CryptoErrno::InvalidKey)?;
        let d = bn::BigNum::from_slice(&parts.d).map_err(|_| CryptoErrno::InvalidKey)?;
        let p = bn::BigNum::from_slice(&parts.p).map_err(|_| CryptoErrno::InvalidKey)?;
        let q = bn::BigNum::from_slice(&parts.q).map_err(|_| CryptoErrno::InvalidKey)?;
        let dmp1 = bn::BigNum::from_slice(&parts.dmp1).map_err(|_| CryptoErrno::InvalidKey)?;
        let dmq1 = bn::BigNum::from_slice(&parts.dmq1).map_err(|_| CryptoErrno::InvalidKey)?;
        let iqmp = bn::BigNum::from_slice(&parts.iqmp).map_err(|_| CryptoErrno::InvalidKey)?;
        let ctx: rsa::Rsa<pkey::Private> =
            rsa::Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp)
                .map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(RsaSignatureKeyPair { alg, ctx })
    }

    fn to_pkcs8(&self) -> Result<Vec<u8>, CryptoErrno> {
        self.ctx
            .private_key_to_der()
            .map_err(|_| CryptoErrno::InternalError)
    }

    fn to_pem(&self) -> Result<Vec<u8>, CryptoErrno> {
        self.ctx
            .private_key_to_pem()
            .map_err(|_| CryptoErrno::InternalError)
    }

    fn to_local(&self) -> Result<Vec<u8>, CryptoErrno> {
        let parts = RsaSignatureKeyPairParts {
            version: RAW_ENCODING_VERSION,
            alg_id: RAW_ENCODING_ALG_ID,
            n: self.ctx.n().to_vec(),
            e: self.ctx.e().to_vec(),
            d: self.ctx.d().to_vec(),
            p: self.ctx.p().ok_or(CryptoErrno::InternalError)?.to_vec(),
            q: self.ctx.q().ok_or(CryptoErrno::InternalError)?.to_vec(),
            dmp1: self.ctx.dmp1().ok_or(CryptoErrno::InternalError)?.to_vec(),
            dmq1: self.ctx.dmq1().ok_or(CryptoErrno::InternalError)?.to_vec(),
            iqmp: self.ctx.iqmp().ok_or(CryptoErrno::InternalError)?.to_vec(),
        };
        let local = rkyv::to_bytes::<rancor::Error>(&parts)
            .map_err(|_| CryptoErrno::InternalError)?
            .to_vec();
        Ok(local)
    }

    pub fn generate(
        alg: SignatureAlgorithm,
        _options: Option<SignatureOptions>,
    ) -> Result<Self, CryptoErrno> {
        let modulus_bits = modulus_bits(alg)?;
        let ctx: rsa::Rsa<pkey::Private> =
            rsa::Rsa::generate(modulus_bits).map_err(|_| CryptoErrno::UnsupportedAlgorithm)?;
        Ok(RsaSignatureKeyPair { alg, ctx })
    }

    pub fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: KeypairEncoding,
    ) -> Result<Self, CryptoErrno> {
        match alg.family() {
            SignatureAlgorithmFamily::RSA => {}
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        };
        let kp = match encoding {
            KeypairEncoding::Pkcs8 => Self::from_pkcs8(alg, encoded)?,
            KeypairEncoding::Pem => Self::from_pem(alg, encoded)?,
            KeypairEncoding::Local => Self::from_local(alg, encoded)?,
            _ => return Err(CryptoErrno::UnsupportedEncoding),
        };
        let modulus_size = kp.ctx.size();
        let min_modulus_bits = modulus_bits(alg)?;
        if !((min_modulus_bits / 8..=MAX_MODULUS_SIZE / 8).contains(&modulus_size)) {
            return Err(CryptoErrno::InvalidKey);
        }
        kp.ctx.check_key().map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(kp)
    }

    pub fn export(&self, encoding: KeypairEncoding) -> Result<Vec<u8>, CryptoErrno> {
        match encoding {
            KeypairEncoding::Pkcs8 => self.to_pkcs8(),
            KeypairEncoding::Pem => self.to_pem(),
            KeypairEncoding::Local => self.to_local(),
            _ => return Err(CryptoErrno::UnsupportedEncoding),
        }
    }

    pub fn public_key(&self) -> Result<RsaSignaturePublicKey, CryptoErrno> {
        let ctx = rsa::Rsa::from_public_components(
            self.ctx
                .n()
                .to_owned()
                .map_err(|_| CryptoErrno::InternalError)?,
            self.ctx
                .e()
                .to_owned()
                .map_err(|_| CryptoErrno::InternalError)?,
        )
        .map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(RsaSignaturePublicKey { alg: self.alg, ctx })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RsaSignature {
    pub raw: Vec<u8>,
}

impl RsaSignature {
    pub fn new(raw: Vec<u8>) -> Self {
        RsaSignature { raw }
    }

    pub fn from_raw(alg: SignatureAlgorithm, raw: &[u8]) -> Result<Self, CryptoErrno> {
        let expected_len = (modulus_bits(alg)? / 8) as usize;
        if !(raw.len() == expected_len) {
            return Err(CryptoErrno::InvalidSignature);
        };
        Ok(Self::new(raw.to_vec()))
    }
}

impl SignatureLike for RsaSignature {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

fn padding_scheme(alg: SignatureAlgorithm) -> (rsa::Padding, boring::hash::MessageDigest) {
    match alg {
        SignatureAlgorithm::RSA_PKCS1_2048_SHA256 => {
            (rsa::Padding::PKCS1, boring::hash::MessageDigest::sha256())
        }
        SignatureAlgorithm::RSA_PKCS1_2048_SHA384 | SignatureAlgorithm::RSA_PKCS1_3072_SHA384 => {
            (rsa::Padding::PKCS1, boring::hash::MessageDigest::sha384())
        }
        SignatureAlgorithm::RSA_PKCS1_2048_SHA512
        | SignatureAlgorithm::RSA_PKCS1_3072_SHA512
        | SignatureAlgorithm::RSA_PKCS1_4096_SHA512 => {
            (rsa::Padding::PKCS1, boring::hash::MessageDigest::sha512())
        }

        SignatureAlgorithm::RSA_PSS_2048_SHA256 => (
            rsa::Padding::PKCS1_PSS,
            boring::hash::MessageDigest::sha256(),
        ),
        SignatureAlgorithm::RSA_PSS_2048_SHA384 | SignatureAlgorithm::RSA_PSS_3072_SHA384 => (
            rsa::Padding::PKCS1_PSS,
            boring::hash::MessageDigest::sha384(),
        ),
        SignatureAlgorithm::RSA_PSS_2048_SHA512
        | SignatureAlgorithm::RSA_PSS_3072_SHA512
        | SignatureAlgorithm::RSA_PSS_4096_SHA512 => (
            rsa::Padding::PKCS1_PSS,
            boring::hash::MessageDigest::sha512(),
        ),
        _ => unreachable!(),
    }
}

pub struct RsaSignatureState<'z> {
    ctx: Pin<Box<pkey::PKey<pkey::Private>>>,
    signer: boring::sign::Signer<'z>,
}

impl RsaSignatureState<'_> {
    pub fn new(kp: RsaSignatureKeyPair) -> Self {
        let ctx = Box::pin(pkey::PKey::from_rsa(kp.ctx).unwrap());
        let (padding_alg, padding_hash) = padding_scheme(kp.alg);
        let pkr: *const pkey::PKey<pkey::Private> = ctx.as_ref().get_ref();
        let mut signer = boring::sign::Signer::new(padding_hash, unsafe { &*pkr }).unwrap();
        signer
            .set_rsa_padding(padding_alg)
            .expect("Unexpected padding");
        RsaSignatureState { ctx, signer }
    }
}

impl SignatureStateLike for RsaSignatureState<'_> {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoErrno> {
        self.signer
            .update(input)
            .map_err(|_| CryptoErrno::InternalError)?;
        Ok(())
    }

    fn sign(&mut self) -> Result<Signature, CryptoErrno> {
        let signature = self
            .signer
            .sign_to_vec()
            .map_err(|_| CryptoErrno::InternalError)?;
        let signature = RsaSignature::new(signature);
        Ok(Signature::new(Box::new(signature)))
    }
}

pub struct RsaSignatureVerificationState<'z> {
    ctx: Pin<Box<pkey::PKey<pkey::Public>>>,
    verifier: boring::sign::Verifier<'z>,
}

impl RsaSignatureVerificationState<'_> {
    pub fn new(pk: RsaSignaturePublicKey) -> Self {
        let ctx = Box::pin(pkey::PKey::from_rsa(pk.ctx).unwrap());
        let (padding_alg, padding_hash) = padding_scheme(pk.alg);
        let pkr: *const pkey::PKey<pkey::Public> = ctx.as_ref().get_ref();
        let mut verifier = boring::sign::Verifier::new(padding_hash, unsafe { &*pkr }).unwrap();
        verifier
            .set_rsa_padding(padding_alg)
            .expect("Unexpected padding");

        RsaSignatureVerificationState { ctx, verifier }
    }
}

impl SignatureVerificationStateLike for RsaSignatureVerificationState<'_> {
    fn update(&mut self, input: &[u8]) -> Result<(), CryptoErrno> {
        self.verifier
            .update(input)
            .map_err(|_| CryptoErrno::InternalError)?;
        Ok(())
    }

    fn verify(&self, signature: &Signature) -> Result<(), CryptoErrno> {
        let signature = signature.inner();
        let signature = signature
            .as_any()
            .downcast_ref::<RsaSignature>()
            .ok_or(CryptoErrno::InvalidSignature)?;
        if !self
            .verifier
            .verify(signature.as_ref())
            .map_err(|_| CryptoErrno::InvalidSignature)?
        {
            return Err(CryptoErrno::InvalidSignature);
        }
        Ok(())
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Zeroize)]
struct RsaSignaturePublicKeyParts {
    version: u16,
    alg_id: u16,
    n: Vec<u8>,
    e: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RsaSignaturePublicKey {
    pub alg: SignatureAlgorithm,
    ctx: rsa::Rsa<pkey::Public>,
}

impl RsaSignaturePublicKey {
    fn from_pkcs8(alg: SignatureAlgorithm, der: &[u8]) -> Result<Self, CryptoErrno> {
        if !(der.len() < 4096) {
            return Err(CryptoErrno::InvalidKey);
        };
        let ctx = rsa::Rsa::public_key_from_der(der).map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(RsaSignaturePublicKey { alg, ctx })
    }

    fn from_pem(alg: SignatureAlgorithm, pem: &[u8]) -> Result<Self, CryptoErrno> {
        if !(pem.len() < 4096) {
            return Err(CryptoErrno::InvalidKey);
        };
        let ctx = rsa::Rsa::public_key_from_pem(pem)
            .or_else(|_| rsa::Rsa::public_key_from_pem_pkcs1(pem))
            .map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(RsaSignaturePublicKey { alg, ctx })
    }

    fn from_local(alg: SignatureAlgorithm, local: &[u8]) -> Result<Self, CryptoErrno> {
        if !(local.len() < 1024) {
            return Err(CryptoErrno::InvalidKey);
        };
        let parts: RsaSignaturePublicKeyParts =
            rkyv::from_bytes::<RsaSignaturePublicKeyParts, rancor::Error>(local)
                .map_err(|_| CryptoErrno::InvalidKey)?;
        if !(parts.version == RAW_ENCODING_VERSION && parts.alg_id == RAW_ENCODING_ALG_ID) {
            return Err(CryptoErrno::InvalidKey);
        };
        let n = bn::BigNum::from_slice(&parts.n).map_err(|_| CryptoErrno::InvalidKey)?;
        let e = bn::BigNum::from_slice(&parts.e).map_err(|_| CryptoErrno::InvalidKey)?;
        let ctx: rsa::Rsa<pkey::Public> =
            rsa::Rsa::from_public_components(n, e).map_err(|_| CryptoErrno::InvalidKey)?;
        Ok(RsaSignaturePublicKey { alg, ctx })
    }

    fn to_pkcs8(&self) -> Result<Vec<u8>, CryptoErrno> {
        self.ctx
            .public_key_to_der()
            .map_err(|_| CryptoErrno::InternalError)
    }

    fn to_pem(&self) -> Result<Vec<u8>, CryptoErrno> {
        self.ctx
            .public_key_to_pem()
            .map_err(|_| CryptoErrno::InternalError)
    }

    fn to_local(&self) -> Result<Vec<u8>, CryptoErrno> {
        let parts = RsaSignaturePublicKeyParts {
            version: RAW_ENCODING_VERSION,
            alg_id: RAW_ENCODING_ALG_ID,
            n: self.ctx.n().to_vec(),
            e: self.ctx.e().to_vec(),
        };
        let local = rkyv::to_bytes::<rancor::Error>(&parts)
            .map_err(|_| CryptoErrno::InternalError)?
            .to_vec();
        Ok(local)
    }

    pub fn import(
        alg: SignatureAlgorithm,
        encoded: &[u8],
        encoding: PublickeyEncoding,
    ) -> Result<Self, CryptoErrno> {
        let pk = match encoding {
            PublickeyEncoding::Pkcs8 => Self::from_pkcs8(alg, encoded)?,
            PublickeyEncoding::Pem => Self::from_pem(alg, encoded)?,
            PublickeyEncoding::Local => Self::from_local(alg, encoded)?,
            _ => return Err(CryptoErrno::UnsupportedEncoding),
        };
        let modulus_size = pk.ctx.size();
        let min_modulus_bits = modulus_bits(alg)?;
        if !(modulus_size >= min_modulus_bits / 8 && modulus_size <= MAX_MODULUS_SIZE / 8) {
            return Err(CryptoErrno::InvalidKey);
        };
        Ok(pk)
    }

    pub fn export(&self, encoding: PublickeyEncoding) -> Result<Vec<u8>, CryptoErrno> {
        match encoding {
            PublickeyEncoding::Pkcs8 => self.to_pkcs8(),
            PublickeyEncoding::Pem => self.to_pem(),
            PublickeyEncoding::Local => self.to_local(),
            _ => return Err(CryptoErrno::UnsupportedEncoding),
        }
    }
}
