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
use derivative::Derivative;
use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::{Sha256, Sha512};
use std::any::Any;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
enum HmacVariant {
    Sha256(Hmac<Sha256>),
    Sha512(Hmac<Sha512>),
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub struct HmacSha2SymmetricState {
    pub alg: SymmetricAlgorithm,
    options: Option<SymmetricOptions>,
    size_limit: Option<usize>,
    ctx: HmacVariant,
}

#[derive(Clone, Debug, Eq)]
pub struct HmacSha2SymmetricKey {
    alg: SymmetricAlgorithm,
    raw: Vec<u8>,
}

impl PartialEq for HmacSha2SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg && self.raw.ct_eq(&other.raw).unwrap_u8() == 1
    }
}

impl Drop for HmacSha2SymmetricKey {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl SymmetricKeyLike for HmacSha2SymmetricKey {
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

impl HmacSha2SymmetricKey {
    pub fn new(alg: SymmetricAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
        Ok(HmacSha2SymmetricKey {
            alg,
            raw: raw.to_vec(),
        })
    }
}

pub struct HmacSha2SymmetricKeyBuilder {
    alg: SymmetricAlgorithm,
}

impl HmacSha2SymmetricKeyBuilder {
    pub fn new(alg: SymmetricAlgorithm) -> Box<dyn SymmetricKeyBuilder> {
        Box::new(Self { alg })
    }
}

impl SymmetricKeyBuilder for HmacSha2SymmetricKeyBuilder {
    fn generate(&self, _options: Option<SymmetricOptions>) -> CryptoResult<SymmetricKey> {
        let mut rng = SecureRandom::new();
        let mut raw = vec![0u8; self.key_len()?];
        rng.fill(&mut raw)?;
        self.import(&raw)
    }

    fn import(&self, raw: &[u8]) -> CryptoResult<SymmetricKey> {
        let key = HmacSha2SymmetricKey::new(self.alg, raw)?;
        Ok(SymmetricKey::new(Box::new(key)))
    }

    fn key_len(&self) -> CryptoResult<usize> {
        match self.alg {
            SymmetricAlgorithm::HmacSha256 => Ok(32),
            SymmetricAlgorithm::HmacSha512 => Ok(64),
            _ => Err(CryptoErrno::UnsupportedAlgorithm.into()),
        }
    }
}

impl HmacSha2SymmetricState {
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
            .downcast_ref::<HmacSha2SymmetricKey>()
            .ok_or(CryptoErrno::InvalidKey)?;
        let ctx = match alg {
            SymmetricAlgorithm::HmacSha256 => HmacVariant::Sha256(
                Hmac::<Sha256>::new_from_slice(key.as_raw()?)
                    .map_err(|_| CryptoErrno::InvalidKey)?,
            ),
            SymmetricAlgorithm::HmacSha512 => HmacVariant::Sha512(
                Hmac::<Sha512>::new_from_slice(key.as_raw()?)
                    .map_err(|_| CryptoErrno::InvalidKey)?,
            ),
            _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
        };
        Ok(HmacSha2SymmetricState {
            alg,
            options,
            size_limit,
            ctx,
        })
    }
}

impl SymmetricStateLike for HmacSha2SymmetricState {
    fn alg(&self) -> SymmetricAlgorithm {
        self.alg
    }

    fn options_get(&self, name: &str) -> CryptoResult<Vec<u8>> {
        self.options
            .as_ref()
            .ok_or(CryptoErrno::OptionNotSet)?
            .get(name)
    }

    fn options_get_u64(&self, name: &str) -> CryptoResult<u64> {
        self.options
            .as_ref()
            .ok_or(CryptoErrno::OptionNotSet)?
            .get_u64(name)
    }

    fn size_limit(&self) -> Option<usize> {
        self.size_limit
    }

    fn absorb_unchecked(&mut self, data: &[u8]) -> CryptoResult<()> {
        match &mut self.ctx {
            HmacVariant::Sha256(x) => x.update(data),
            HmacVariant::Sha512(x) => x.update(data),
        };
        Ok(())
    }

    fn squeeze_tag(&mut self) -> CryptoResult<SymmetricTag> {
        let raw = match &self.ctx {
            HmacVariant::Sha256(x) => x.clone().finalize().into_bytes().to_vec(),
            HmacVariant::Sha512(x) => x.clone().finalize().into_bytes().to_vec(),
        };
        Ok(SymmetricTag::new(self.alg, raw))
    }
}
