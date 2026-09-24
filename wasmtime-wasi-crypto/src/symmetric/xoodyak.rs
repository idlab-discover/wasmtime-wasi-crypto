use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_symmetric::SymmetricTag;
use crate::error::CryptoResult;
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

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(&self.raw)
    }
}

impl XoodyakSymmetricKey {
    fn new(alg: SymmetricAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
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
    fn generate(&self, _options: Option<SymmetricOptions>) -> CryptoResult<SymmetricKey> {
        let mut rng = SecureRandom::new();
        let mut raw = vec![0u8; self.key_len()?];
        rng.fill(&mut raw)?;
        self.import(&raw)
    }

    fn import(&self, raw: &[u8]) -> CryptoResult<SymmetricKey> {
        let key = XoodyakSymmetricKey::new(self.alg, raw)?;
        Ok(SymmetricKey::new(Box::new(key)))
    }

    fn key_len(&self) -> CryptoResult<usize> {
        match self.alg {
            SymmetricAlgorithm::Xoodyak128 => Ok(16),
            SymmetricAlgorithm::Xoodyak160 => Ok(20),
            _ => Err(CryptoErrno::UnsupportedAlgorithm.into()),
        }
    }
}

impl XoodyakSymmetricState {
    pub fn new(
        alg: SymmetricAlgorithm,
        key: Option<SymmetricKey>,
        options: Option<SymmetricOptions>,
        size_limit: Option<usize>,
    ) -> CryptoResult<Self> {
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
        self.xoodyak_state.absorb(data);
        Ok(())
    }

    fn squeeze_unchecked(&mut self) -> CryptoResult<Vec<u8>> {
        let mut out = vec![0u8; XOODYAK_AUTH_TAG_BYTES];
        self.xoodyak_state.squeeze(&mut out);
        Ok(out)
    }

    fn squeeze_key(&mut self, alg_str: &str) -> CryptoResult<SymmetricKey> {
        let builder = SymmetricKey::builder(alg_str)?;
        let mut raw = vec![0u8; builder.key_len()?];
        self.xoodyak_state.squeeze_key(&mut raw);
        builder.import(&raw)
    }

    fn squeeze_tag(&mut self) -> CryptoResult<SymmetricTag> {
        let mut raw_tag = vec![0u8; XOODYAK_AUTH_TAG_BYTES];
        self.xoodyak_state.squeeze(&mut raw_tag);
        let symmetric_tag = SymmetricTag::new(self.alg(), raw_tag);
        Ok(symmetric_tag)
    }

    fn max_tag_len(&mut self) -> CryptoResult<usize> {
        Ok(XOODYAK_AUTH_TAG_BYTES)
    }

    // Encryption and decryption happen in place, in the `Vec` the bindings
    // received, which is then returned as the output. The crate's in-place
    // functions perform the same duplex operations as the copying ones, so
    // the output bytes are the same.

    fn encrypt_unchecked(&mut self, data: Vec<u8>) -> CryptoResult<Vec<u8>> {
        // This is what `aead_encrypt_in_place` does too, except that it needs
        // the room for the tag before encrypting. Reserving only after
        // encrypting means that if this reallocates, the buffer it frees
        // holds ciphertext rather than plaintext.
        //
        // Known limitation: Wasmtime lifts the argument into a `Vec` whose
        // capacity equals its length, so this reserve does reallocate once
        // and copies the message. The `bindgen!`-generated bindings offer
        // no way to allocate room for the tag while lifting the list.
        let (mut out, tag) = self.encrypt_detached_unchecked(data)?;
        out.reserve_exact(XOODYAK_AUTH_TAG_BYTES);
        out.extend_from_slice(tag.as_ref());
        Ok(out)
    }

    fn encrypt_detached_unchecked(
        &mut self,
        mut data: Vec<u8>,
    ) -> CryptoResult<(Vec<u8>, SymmetricTag)> {
        // The only failure is an unkeyed (hash) state, which is detected
        // before the buffer is touched, so there is nothing to zeroize.
        match self.xoodyak_state.aead_encrypt_in_place_detached(&mut data) {
            Err(XoodyakError::KeyRequired) => Err(CryptoErrno::InvalidOperation.into()),
            Err(_) => Err(CryptoErrno::Overflow.into()),
            Ok(xoodyak_tag) => {
                let symmetric_tag = SymmetricTag::new(self.alg(), xoodyak_tag.as_ref().to_vec());
                Ok((data, symmetric_tag))
            }
        }
    }

    fn decrypt_unchecked(&mut self, data: Vec<u8>, raw_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        self.decrypt_detached_unchecked(data, raw_tag)
    }

    fn decrypt_detached_unchecked(
        &mut self,
        mut data: Vec<u8>,
        raw_tag: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let mut raw_tag_ = [0u8; XOODYAK_AUTH_TAG_BYTES];
        if raw_tag.len() != raw_tag_.len() {
            return Err(CryptoErrno::InvalidTag.into());
        };
        raw_tag_.copy_from_slice(raw_tag);
        // Unlike the AEADs above, Xoodyak decrypts before it can check the
        // tag, so on a mismatch the buffer briefly holds plaintext. The crate
        // zeroes it itself; zeroize here too, so that doesn't depend on it.
        match self
            .xoodyak_state
            .aead_decrypt_in_place_detached(&mut data, &raw_tag_.into())
        {
            Err(XoodyakError::KeyRequired) => {
                data.zeroize();
                Err(CryptoErrno::InvalidOperation.into())
            }
            Err(_) => {
                data.zeroize();
                Err(CryptoErrno::InvalidTag.into())
            }
            Ok(()) => Ok(data),
        }
    }

    fn ratchet(&mut self) -> CryptoResult<()> {
        self.xoodyak_state
            .ratchet()
            .map_err(|_| CryptoErrno::InvalidOperation.into())
    }
}
