use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    bindings::wasi::crypto::{
        wasi_ephemeral_crypto_common::CryptoErrno,
        wasi_ephemeral_crypto_symmetric::{SymmetricKey, SymmetricTag},
    },
    error::CryptoResult,
    options::OptionsLike,
    rand::SecureRandom,
    symmetric::{
        SymmetricAlgorithm, SymmetricOptions,
        key::{SymmetricKeyBuilder, SymmetricKeyLike},
        state::SymmetricStateLike,
    },
};
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, KeyInit};
use derivative::Derivative;
use sha2::digest::generic_array::GenericArray;
use std::any::Any;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum AesGcmVariant {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub struct AesGcmSymmetricState {
    pub alg: SymmetricAlgorithm,
    options: SymmetricOptions,
    size_limit: Option<usize>,
    #[derivative(Debug = "ignore")]
    ctx: AesGcmVariant,
    ad: Vec<u8>,
    nonce: Option<[u8; NONCE_LEN]>,
}

#[derive(Clone, Debug, Eq)]
pub struct AesGcmSymmetricKey {
    alg: SymmetricAlgorithm,
    raw: Vec<u8>,
}

impl PartialEq for AesGcmSymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg && self.raw.ct_eq(&other.raw).unwrap_u8() == 1
    }
}

impl Drop for AesGcmSymmetricKey {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl SymmetricKeyLike for AesGcmSymmetricKey {
    fn alg(&self) -> SymmetricAlgorithm {
        self.alg
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(&self.raw)
    }
}

impl AesGcmSymmetricKey {
    fn new(alg: SymmetricAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
        Ok(AesGcmSymmetricKey {
            alg,
            raw: raw.to_vec(),
        })
    }
}

pub struct AesGcmSymmetricKeyBuilder {
    alg: SymmetricAlgorithm,
}

impl AesGcmSymmetricKeyBuilder {
    pub fn new(alg: SymmetricAlgorithm) -> Box<dyn SymmetricKeyBuilder> {
        Box::new(Self { alg })
    }
}

impl SymmetricKeyBuilder for AesGcmSymmetricKeyBuilder {
    fn generate(&self, _options: Option<SymmetricOptions>) -> CryptoResult<SymmetricKey> {
        let mut rng = SecureRandom::new();
        let mut raw = vec![0u8; self.key_len()?];
        rng.fill(&mut raw)?;
        self.import(&raw)
    }

    fn import(&self, raw: &[u8]) -> CryptoResult<SymmetricKey> {
        let key = AesGcmSymmetricKey::new(self.alg, raw)?;
        Ok(SymmetricKey::new(Box::new(key)))
    }

    fn key_len(&self) -> CryptoResult<usize> {
        match self.alg {
            SymmetricAlgorithm::Aes128Gcm => Ok(16),
            SymmetricAlgorithm::Aes256Gcm => Ok(32),
            _ => Err(CryptoErrno::UnsupportedAlgorithm.into()),
        }
    }
}

impl AesGcmSymmetricState {
    pub fn new(
        alg: SymmetricAlgorithm,
        key: Option<SymmetricKey>,
        options: Option<SymmetricOptions>,
        size_limit: Option<usize>,
    ) -> CryptoResult<Self> {
        let key = key.ok_or(CryptoErrno::KeyRequired)?;
        let key = key.inner();
        let key = key
            .as_any()
            .downcast_ref::<AesGcmSymmetricKey>()
            .ok_or(CryptoErrno::InvalidKey)?;
        let options = options.as_ref().ok_or(CryptoErrno::NonceRequired)?;
        let inner = options.inner.lock().unwrap();
        let nonce_vec = inner.nonce.as_ref().ok_or(CryptoErrno::NonceRequired)?;
        if nonce_vec.len() != NONCE_LEN {
            return Err(CryptoErrno::InvalidNonce.into());
        };
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_vec);
        let aes_gcm_impl = match alg {
            SymmetricAlgorithm::Aes128Gcm => {
                AesGcmVariant::Aes128(Aes128Gcm::new(GenericArray::from_slice(key.as_raw()?)))
            }
            SymmetricAlgorithm::Aes256Gcm => {
                AesGcmVariant::Aes256(Aes256Gcm::new(GenericArray::from_slice(key.as_raw()?)))
            }
            _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
        };
        let state = AesGcmSymmetricState {
            alg,
            options: options.clone(),
            size_limit,
            ctx: aes_gcm_impl,
            ad: vec![],
            nonce: Some(nonce),
        };
        Ok(state)
    }
}

impl SymmetricStateLike for AesGcmSymmetricState {
    fn alg(&self) -> SymmetricAlgorithm {
        self.alg
    }

    fn options_get(&self, name: &str) -> CryptoResult<Vec<u8>> {
        self.options.get(name)
    }

    fn options_get_u64(&self, name: &str) -> CryptoResult<u64> {
        self.options.get_u64(name)
    }

    fn size_limit(&self) -> Option<usize> {
        self.size_limit
    }

    fn absorb_unchecked(&mut self, data: &[u8]) -> CryptoResult<()> {
        self.ad.extend_from_slice(data);
        Ok(())
    }

    fn max_tag_len(&mut self) -> CryptoResult<usize> {
        Ok(TAG_LEN)
    }

    fn encrypt_unchecked(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let (mut out, tag) = self.encrypt_detached_unchecked(data)?;
        out.extend_from_slice(tag.as_ref());
        Ok(out)
    }

    fn encrypt_detached_unchecked(&mut self, data: &[u8]) -> CryptoResult<(Vec<u8>, SymmetricTag)> {
        let nonce = self.nonce.as_ref().ok_or(CryptoErrno::NonceRequired)?;
        // if out.as_ptr() != data.as_ptr() {
        //     out.copy_from_slice(data);
        // }
        let mut out = data.to_vec();
        let raw_tag = match &self.ctx {
            AesGcmVariant::Aes128(x) => {
                x.encrypt_in_place_detached(GenericArray::from_slice(nonce), &self.ad, &mut out)
            }
            AesGcmVariant::Aes256(x) => {
                x.encrypt_in_place_detached(GenericArray::from_slice(nonce), &self.ad, &mut out)
            }
        }
        .map_err(|_| CryptoErrno::InternalError)?
        .to_vec();

        self.nonce = None;
        Ok((out, SymmetricTag::new(self.alg, raw_tag)))
    }

    fn decrypt_unchecked(&mut self, data: &[u8], raw_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        self.decrypt_detached_unchecked(data, raw_tag)
    }

    fn decrypt_detached_unchecked(&mut self, data: &[u8], raw_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce = self.nonce.as_ref().ok_or(CryptoErrno::NonceRequired)?;
        // if out.as_ptr() != data.as_ptr() {
        //     out[..data.len()].copy_from_slice(data);
        // }
        let mut out = data.to_vec();
        match &self.ctx {
            AesGcmVariant::Aes128(x) => x.decrypt_in_place_detached(
                GenericArray::from_slice(nonce),
                &self.ad,
                &mut out,
                GenericArray::from_slice(raw_tag),
            ),
            AesGcmVariant::Aes256(x) => x.decrypt_in_place_detached(
                GenericArray::from_slice(nonce),
                &self.ad,
                &mut out,
                GenericArray::from_slice(raw_tag),
            ),
        }
        .map_err(|_| CryptoErrno::InvalidTag)?;
        Ok(out)
    }
}
