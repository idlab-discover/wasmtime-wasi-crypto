use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_symmetric::SymmetricTag;
use crate::options::OptionsLike;
use crate::rand::SecureRandom;
use crate::symmetric::key::SymmetricKeyBuilder;
use crate::{
    bindings::wasi::crypto::{
        wasi_ephemeral_crypto_common::CryptoErrno, wasi_ephemeral_crypto_symmetric::SymmetricKey,
    },
    symmetric::{
        SymmetricAlgorithm, SymmetricOptions, key::SymmetricKeyLike, state::SymmetricStateLike,
    },
};
use std::any::Any;
use xoodyak::{
    XOODYAK_AUTH_TAG_BYTES, XoodyakAny, XoodyakCommon, XoodyakError, XoodyakHash, XoodyakKeyed,
};

#[derive(Clone, Debug)]
pub struct XoodyakSymmetricState {
    pub alg: SymmetricAlgorithm,
    options: Option<SymmetricOptions>,
    size_limit: Option<usize>,
    xoodyak_state: XoodyakAny,
}

#[derive(Clone, Debug, Eq)]
pub struct XoodyakSymmetricKey {
    alg: SymmetricAlgorithm,
    raw: Vec<u8>,
}

impl PartialEq for XoodyakSymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg && self.raw.ct_eq(&other.raw).unwrap_u8() == 1
    }
}

impl Drop for XoodyakSymmetricKey {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl SymmetricKeyLike for XoodyakSymmetricKey {
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

impl XoodyakSymmetricKey {
    fn new(alg: SymmetricAlgorithm, raw: &[u8]) -> Result<Self, CryptoErrno> {
        Ok(XoodyakSymmetricKey {
            alg,
            raw: raw.to_vec(),
        })
    }
}

pub struct XoodyakSymmetricKeyBuilder {
    alg: SymmetricAlgorithm,
}

impl XoodyakSymmetricKeyBuilder {
    pub fn new(alg: SymmetricAlgorithm) -> Box<dyn SymmetricKeyBuilder> {
        Box::new(Self { alg })
    }
}

impl SymmetricKeyBuilder for XoodyakSymmetricKeyBuilder {
    fn generate(&self, _options: Option<SymmetricOptions>) -> Result<SymmetricKey, CryptoErrno> {
        let mut rng = SecureRandom::new();
        let mut raw = vec![0u8; self.key_len()?];
        rng.fill(&mut raw)?;
        self.import(&raw)
    }

    fn import(&self, raw: &[u8]) -> Result<SymmetricKey, CryptoErrno> {
        let key = XoodyakSymmetricKey::new(self.alg, raw)?;
        Ok(SymmetricKey::new(Box::new(key)))
    }

    fn key_len(&self) -> Result<usize, CryptoErrno> {
        match self.alg {
            SymmetricAlgorithm::Xoodyak128 => Ok(16),
            SymmetricAlgorithm::Xoodyak160 => Ok(20),
            _ => Err(CryptoErrno::UnsupportedAlgorithm),
        }
    }
}

impl XoodyakSymmetricState {
    pub fn new(
        alg: SymmetricAlgorithm,
        key: Option<SymmetricKey>,
        options: Option<SymmetricOptions>,
        size_limit: Option<usize>,
    ) -> Result<Self, CryptoErrno> {
        let key = match key {
            None => None,
            Some(key) => {
                let key = key.inner();
                let key = key
                    .as_any()
                    .downcast_ref::<XoodyakSymmetricKey>()
                    .ok_or(CryptoErrno::InvalidKey)?
                    .clone();
                Some(key)
            }
        };
        let nonce = options
            .as_ref()
            .and_then(|options| options.inner.lock().unwrap().nonce.as_ref().cloned());
        let nonce = nonce.as_deref();
        let xoodyak_state = match key {
            None => XoodyakAny::Hash(XoodyakHash::new()),
            Some(key) => XoodyakAny::Keyed(
                XoodyakKeyed::new(key.as_raw()?, nonce, None, None)
                    .map_err(|_| CryptoErrno::InvalidKey)?,
            ),
        };
        Ok(XoodyakSymmetricState {
            alg,
            options,
            size_limit,
            xoodyak_state,
        })
    }
}

impl SymmetricStateLike for XoodyakSymmetricState {
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
        self.xoodyak_state.absorb(data);
        Ok(())
    }

    fn squeeze_unchecked(&mut self) -> Result<Vec<u8>, CryptoErrno> {
        let mut out = vec![0u8; XOODYAK_AUTH_TAG_BYTES];
        self.xoodyak_state.squeeze(&mut out);
        Ok(out)
    }

    fn squeeze_key(&mut self, alg_str: &str) -> Result<SymmetricKey, CryptoErrno> {
        let builder = SymmetricKey::builder(alg_str)?;
        let mut raw = vec![0u8; builder.key_len()?];
        self.xoodyak_state.squeeze_key(&mut raw);
        builder.import(&raw)
    }

    fn squeeze_tag(&mut self) -> Result<SymmetricTag, CryptoErrno> {
        let mut raw_tag = vec![0u8; XOODYAK_AUTH_TAG_BYTES];
        self.xoodyak_state.squeeze(&mut raw_tag);
        let symmetric_tag = SymmetricTag::new(self.alg(), raw_tag);
        Ok(symmetric_tag)
    }

    fn max_tag_len(&mut self) -> Result<usize, CryptoErrno> {
        Ok(XOODYAK_AUTH_TAG_BYTES)
    }

    fn encrypt_unchecked(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoErrno> {
        let ct_len = data
            .len()
            .checked_add(XOODYAK_AUTH_TAG_BYTES)
            .ok_or(CryptoErrno::Overflow)?;
        let mut out = vec![0u8; ct_len];
        match self.xoodyak_state.aead_encrypt(&mut out, Some(data)) {
            Err(XoodyakError::KeyRequired) => Err(CryptoErrno::InvalidOperation),
            Err(_) => Err(CryptoErrno::Overflow),
            Ok(()) => Ok(out),
        }
    }

    fn encrypt_detached_unchecked(
        &mut self,
        data: &[u8],
    ) -> Result<(Vec<u8>, SymmetricTag), CryptoErrno> {
        let mut out = vec![0u8; data.len()];
        match self
            .xoodyak_state
            .aead_encrypt_detached(&mut out, Some(data))
        {
            Err(XoodyakError::KeyRequired) => Err(CryptoErrno::InvalidOperation),
            Err(_) => Err(CryptoErrno::Overflow),
            Ok(xoodyak_tag) => {
                let symmetric_tag = SymmetricTag::new(self.alg(), xoodyak_tag.as_ref().to_vec());
                Ok((out, symmetric_tag))
            }
        }
    }

    fn decrypt_unchecked(&mut self, data: &[u8], raw_tag: &[u8]) -> Result<Vec<u8>, CryptoErrno> {
        self.decrypt_detached_unchecked(data, raw_tag)
    }

    fn decrypt_detached_unchecked(
        &mut self,
        data: &[u8],
        raw_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoErrno> {
        let mut out = vec![0u8; data.len()];
        let msg_len = data.len();
        let mut raw_tag_ = [0u8; XOODYAK_AUTH_TAG_BYTES];
        if raw_tag.len() != raw_tag_.len()  {
            return Err(CryptoErrno::InvalidTag);
        };
        raw_tag_.copy_from_slice(raw_tag);
        match self
            .xoodyak_state
            .aead_decrypt_detached(&mut out, &raw_tag_.into(), Some(data))
        {
            Err(XoodyakError::KeyRequired) => {
                out.zeroize();
                Err(CryptoErrno::InvalidOperation)
            }
            Err(_) => {
                out.zeroize();
                Err(CryptoErrno::InvalidTag)
            }
            Ok(()) => Ok(out),
        }
    }

    fn ratchet(&mut self) -> Result<(), CryptoErrno> {
        self.xoodyak_state
            .ratchet()
            .map_err(|_| CryptoErrno::InvalidOperation)
    }
}
