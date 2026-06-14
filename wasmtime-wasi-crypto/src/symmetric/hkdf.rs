use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    bindings::wasi::crypto::{
        wasi_ephemeral_crypto_common::CryptoErrno, wasi_ephemeral_crypto_symmetric::SymmetricKey,
    },
    options::OptionsLike,
    rand::SecureRandom,
    symmetric::{
        SymmetricAlgorithm, SymmetricOptions,
        key::{SymmetricKeyBuilder, SymmetricKeyLike},
        state::SymmetricStateLike,
    },
};
use hkdf::Hkdf;
use sha2::{Sha256, Sha512};
use std::any::Any;

#[derive(Clone, Debug)]
pub struct HkdfSymmetricState {
    pub alg: SymmetricAlgorithm,
    options: Option<SymmetricOptions>,
    size_limit: Option<usize>,
    key: Vec<u8>,
    data: Vec<u8>,
}

impl Drop for HkdfSymmetricState {
    fn drop(&mut self) {
        self.key.zeroize();
        self.data.zeroize();
    }
}

impl SymmetricKeyLike for HkdfSymmetricKey {
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

#[derive(Clone, Debug, Eq)]
pub struct HkdfSymmetricKey {
    alg: SymmetricAlgorithm,
    raw: Vec<u8>,
}

impl Drop for HkdfSymmetricKey {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl PartialEq for HkdfSymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg && self.raw.ct_eq(&other.raw).unwrap_u8() == 1
    }
}

impl HkdfSymmetricKey {
    pub fn new(alg: SymmetricAlgorithm, raw: &[u8]) -> Result<Self, CryptoErrno> {
        Ok(HkdfSymmetricKey {
            alg,
            raw: raw.to_vec(),
        })
    }
}

pub struct HkdfSymmetricKeyBuilder {
    alg: SymmetricAlgorithm,
}

impl HkdfSymmetricKeyBuilder {
    pub fn new(alg: SymmetricAlgorithm) -> Box<dyn SymmetricKeyBuilder> {
        Box::new(Self { alg })
    }
}

impl SymmetricKeyBuilder for HkdfSymmetricKeyBuilder {
    fn generate(&self, _options: Option<SymmetricOptions>) -> Result<SymmetricKey, CryptoErrno> {
        let mut rng = SecureRandom::new();
        let mut raw = vec![0u8; self.key_len()?];
        rng.fill(&mut raw)?;
        self.import(&raw)
    }

    fn import(&self, raw: &[u8]) -> Result<SymmetricKey, CryptoErrno> {
        let key = HkdfSymmetricKey::new(self.alg, raw)?;
        Ok(SymmetricKey::new(Box::new(key)))
    }

    fn key_len(&self) -> Result<usize, CryptoErrno> {
        match self.alg {
            SymmetricAlgorithm::HkdfSha256Expand | SymmetricAlgorithm::HkdfSha256Extract => Ok(32),
            SymmetricAlgorithm::HkdfSha512Expand | SymmetricAlgorithm::HkdfSha512Extract => Ok(64),
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        }
    }
}

impl HkdfSymmetricState {
    pub fn new(
        alg: SymmetricAlgorithm,
        key: Option<SymmetricKey>,
        options: Option<SymmetricOptions>,
        size_limit: Option<usize>,
    ) -> Result<Self, CryptoErrno> {
        let key = key.ok_or(CryptoErrno::KeyRequired)?;
        let key = key.inner();
        let key = key
            .as_any()
            .downcast_ref::<HkdfSymmetricKey>()
            .ok_or(CryptoErrno::InvalidKey)?;
        let key = key.as_raw()?.to_vec();
        Ok(HkdfSymmetricState {
            alg,
            options,
            size_limit,
            key,
            data: vec![],
        })
    }
}

impl SymmetricStateLike for HkdfSymmetricState {
    fn alg(&self) -> SymmetricAlgorithm {
        self.alg
    }

    fn options_get(&self, name: &str) -> Result<Vec<u8>, CryptoErrno> {
        self.options
            .as_ref()
            .ok_or(CryptoErrno::OptionNotSet)?
            .get(name)
    }

    fn options_get_u64(&self, name: &str) -> Result<u64, CryptoErrno> {
        self.options
            .as_ref()
            .ok_or(CryptoErrno::OptionNotSet)?
            .get_u64(name)
    }

    fn size_limit(&self) -> Option<usize> {
        self.size_limit
    }

    fn absorb_unchecked(&mut self, data: &[u8]) -> Result<(), CryptoErrno> {
        self.data.extend_from_slice(data);
        Ok(())
    }

    fn squeeze_key(&mut self, alg_str: &str) -> Result<SymmetricKey, CryptoErrno> {
        let raw_prk = match self.alg {
            SymmetricAlgorithm::HkdfSha256Extract => {
                Hkdf::<Sha256>::extract(Some(&self.data), &self.key)
                    .0
                    .to_vec()
            }
            SymmetricAlgorithm::HkdfSha512Extract => {
                Hkdf::<Sha512>::extract(Some(&self.data), &self.key)
                    .0
                    .to_vec()
            }
            _ => return Err(CryptoErrno::InvalidOperation),
        };
        let builder = SymmetricKey::builder(alg_str)?;
        builder.import(&raw_prk)
    }

    fn squeeze_unchecked(&mut self) -> Result<Vec<u8>, CryptoErrno> {
        let out_len = match self.alg {
            SymmetricAlgorithm::HkdfSha256Expand => 32,
            SymmetricAlgorithm::HkdfSha512Expand => 64,
            _ => return Err(CryptoErrno::InvalidOperation),
        };
        let mut out = vec![0u8; out_len];
        match self.alg {
            SymmetricAlgorithm::HkdfSha256Expand => Hkdf::<Sha256>::from_prk(&self.key)
                .map_err(|_| CryptoErrno::InvalidKey)?
                .expand(&self.data, &mut out),
            SymmetricAlgorithm::HkdfSha512Expand => Hkdf::<Sha512>::from_prk(&self.key)
                .map_err(|_| CryptoErrno::InvalidKey)?
                .expand(&self.data, &mut out),
            _ => return Err(CryptoErrno::InvalidOperation),
        }
        .map_err(|_| CryptoErrno::Overflow)?;
        Ok(out)
    }
}
