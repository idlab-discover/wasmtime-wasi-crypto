use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    bindings::wasi::crypto::{
        wasi_ephemeral_crypto_common::CryptoErrno,
        wasi_ephemeral_crypto_symmetric::{SymmetricKey, SymmetricTag},
    },
    options::OptionsLike,
    rand::SecureRandom,
    symmetric::{
        SymmetricAlgorithm, SymmetricOptions,
        key::{SymmetricKeyBuilder, SymmetricKeyLike},
        state::SymmetricStateLike,
    },
};
use aes_gcm::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use derivative::Derivative;
use sha2::digest::generic_array::GenericArray;
use std::any::Any;

pub const TAG_LEN: usize = 16;

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum ChaChaPolyVariant {
    ChaCha(ChaCha20Poly1305),
    XChaCha(XChaCha20Poly1305),
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub struct ChaChaPolySymmetricState {
    pub alg: SymmetricAlgorithm,
    options: SymmetricOptions,
    size_limit: Option<usize>,
    #[derivative(Debug = "ignore")]
    ctx: ChaChaPolyVariant,
    ad: Vec<u8>,
    nonce: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq)]
pub struct ChaChaPolySymmetricKey {
    alg: SymmetricAlgorithm,
    raw: Vec<u8>,
}

impl PartialEq for ChaChaPolySymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg && self.raw.ct_eq(&other.raw).unwrap_u8() == 1
    }
}

impl Drop for ChaChaPolySymmetricKey {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl SymmetricKeyLike for ChaChaPolySymmetricKey {
    fn alg(&self) -> SymmetricAlgorithm {
        self.alg
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_raw(&self) -> Result<&[u8], CryptoErrno> {
        Ok(&self.raw)
    }
}

impl ChaChaPolySymmetricKey {
    fn new(alg: SymmetricAlgorithm, raw: &[u8]) -> Result<Self, CryptoErrno> {
        Ok(ChaChaPolySymmetricKey {
            alg,
            raw: raw.to_vec(),
        })
    }
}

pub struct ChaChaPolySymmetricKeyBuilder {
    alg: SymmetricAlgorithm,
}

impl ChaChaPolySymmetricKeyBuilder {
    pub fn new(alg: SymmetricAlgorithm) -> Box<dyn SymmetricKeyBuilder> {
        Box::new(Self { alg })
    }
}

impl SymmetricKeyBuilder for ChaChaPolySymmetricKeyBuilder {
    fn generate(&self, _options: Option<SymmetricOptions>) -> Result<SymmetricKey, CryptoErrno> {
        let mut rng = SecureRandom::new();
        let mut raw = vec![0u8; self.key_len()?];
        rng.fill(&mut raw)?;
        self.import(&raw)
    }

    fn import(&self, raw: &[u8]) -> Result<SymmetricKey, CryptoErrno> {
        let key = ChaChaPolySymmetricKey::new(self.alg, raw)?;
        Ok(SymmetricKey::new(Box::new(key)))
    }

    fn key_len(&self) -> Result<usize, CryptoErrno> {
        match self.alg {
            SymmetricAlgorithm::ChaCha20Poly1305 | SymmetricAlgorithm::XChaCha20Poly1305 => Ok(32),
            _ => Err(CryptoErrno::UnsupportedAlgorithm),
        }
    }
}

impl ChaChaPolySymmetricState {
    pub fn new(
        alg: SymmetricAlgorithm,
        key: Option<SymmetricKey>,
        options: Option<SymmetricOptions>,
        size_limits: Option<usize>,
    ) -> Result<Self, CryptoErrno> {
        let key = key.ok_or(CryptoErrno::KeyRequired)?;
        let key = key.inner();
        let key = key
            .as_any()
            .downcast_ref::<ChaChaPolySymmetricKey>()
            .ok_or(CryptoErrno::InvalidKey)?;
        let expected_nonce_len = match alg {
            SymmetricAlgorithm::ChaCha20Poly1305 => 12,
            SymmetricAlgorithm::XChaCha20Poly1305 => 24,
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        };
        let options = options.as_ref().ok_or(CryptoErrno::NonceRequired)?;
        let nonce = options.locked(|mut options| {
            if options.nonce.is_none() && expected_nonce_len >= 16 {
                options.nonce = Some(vec![0u8; expected_nonce_len]);
                let mut rng = SecureRandom::new();
                rng.fill(options.nonce.as_mut().unwrap())?;
            }
            let nonce_vec = options.nonce.as_ref().ok_or(CryptoErrno::NonceRequired)?;
            if nonce_vec.len() != expected_nonce_len  {
                return Err(CryptoErrno::InvalidNonce);
            };
            Ok(nonce_vec.clone())
        })?;
        let chapoly_impl = match alg {
            SymmetricAlgorithm::ChaCha20Poly1305 => ChaChaPolyVariant::ChaCha(
                ChaCha20Poly1305::new(GenericArray::from_slice(key.as_raw()?)),
            ),
            SymmetricAlgorithm::XChaCha20Poly1305 => ChaChaPolyVariant::XChaCha(
                XChaCha20Poly1305::new(GenericArray::from_slice(key.as_raw()?)),
            ),
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        };
        let state = ChaChaPolySymmetricState {
            alg,
            options: options.clone(),
            size_limit: size_limits,
            ctx: chapoly_impl,
            ad: vec![],
            nonce: Some(nonce),
        };
        Ok(state)
    }
}

impl SymmetricStateLike for ChaChaPolySymmetricState {
    fn alg(&self) -> SymmetricAlgorithm {
        self.alg
    }

    fn options_get(&self, name: &str) -> Result<Vec<u8>, CryptoErrno> {
        self.options.get(name)
    }

    fn options_get_u64(&self, name: &str) -> Result<u64, CryptoErrno> {
        self.options.get_u64(name)
    }

    fn size_limit(&self) -> Option<usize> {
        self.size_limit
    }

    fn absorb_unchecked(&mut self, data: &[u8]) -> Result<(), CryptoErrno> {
        self.ad.extend_from_slice(data);
        Ok(())
    }

    fn max_tag_len(&mut self) -> Result<usize, CryptoErrno> {
        Ok(TAG_LEN)
    }

    fn encrypt_unchecked(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoErrno> {
        let (mut out, tag) = self.encrypt_detached_unchecked(data)?;
        out.extend_from_slice(tag.as_ref());
        Ok(out)
    }

    fn encrypt_detached_unchecked(
        &mut self,
        data: &[u8],
    ) -> Result<(Vec<u8>, SymmetricTag), CryptoErrno> {
        let nonce = self.nonce.as_ref().ok_or(CryptoErrno::NonceRequired)?;
        let data_len = data.len();
        // if out.len() != data_len {
        //     return Err(CryptoErrno::InvalidLength);
        // }
        // if out.as_ptr() != data.as_ptr() {
        //     out.copy_from_slice(data);
        // }
        let mut out = data.to_vec();

        let raw_tag = match &self.ctx {
            ChaChaPolyVariant::ChaCha(x) => {
                x.encrypt_in_place_detached(GenericArray::from_slice(nonce), &self.ad, &mut out)
            }
            ChaChaPolyVariant::XChaCha(x) => {
                x.encrypt_in_place_detached(GenericArray::from_slice(nonce), &self.ad, &mut out)
            }
        }
        .map_err(|_| CryptoErrno::InternalError)?
        .to_vec();

        self.nonce = None;
        Ok((out, SymmetricTag::new(self.alg, raw_tag)))
    }

    fn decrypt_unchecked(&mut self, data: &[u8], raw_tag: &[u8]) -> Result<Vec<u8>, CryptoErrno> {
        self.decrypt_detached_unchecked(data, raw_tag)
    }

    fn decrypt_detached_unchecked(
        &mut self,
        data: &[u8],
        raw_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoErrno> {
        let nonce = self.nonce.as_ref().ok_or(CryptoErrno::NonceRequired)?;
        // if out.as_ptr() != data.as_ptr() {
        //     out[..data.len()].copy_from_slice(data);
        // }
        let mut out = data.to_vec();
        match &self.ctx {
            ChaChaPolyVariant::ChaCha(x) => x.decrypt_in_place_detached(
                GenericArray::from_slice(nonce),
                &self.ad,
                &mut out,
                GenericArray::from_slice(raw_tag),
            ),
            ChaChaPolyVariant::XChaCha(x) => x.decrypt_in_place_detached(
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
