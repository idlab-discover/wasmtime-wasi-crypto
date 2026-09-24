use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    bindings::wasi::crypto::{
        wasi_ephemeral_crypto_common::CryptoErrno,
        wasi_ephemeral_crypto_symmetric::{SymmetricKey, SymmetricTag},
    },
    error::{CryptoError, CryptoResult},
    options::OptionsLike,
    rand::SecureRandom,
    symmetric::{
        SymmetricAlgorithm, SymmetricOptions,
        key::{SymmetricKeyBuilder, SymmetricKeyLike},
        state::SymmetricStateLike,
    },
};
use aes_gcm::{AeadInOut, KeyInit};
use chacha20poly1305::aead::{Nonce, Tag};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use derivative::Derivative;
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

    fn as_raw(&self) -> CryptoResult<&[u8]> {
        Ok(&self.raw)
    }
}

impl ChaChaPolySymmetricKey {
    fn new(alg: SymmetricAlgorithm, raw: &[u8]) -> CryptoResult<Self> {
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
    fn generate(&self, _options: Option<SymmetricOptions>) -> CryptoResult<SymmetricKey> {
        let mut rng = SecureRandom::new();
        let mut raw = vec![0u8; self.key_len()?];
        rng.fill(&mut raw)?;
        self.import(&raw)
    }

    fn import(&self, raw: &[u8]) -> CryptoResult<SymmetricKey> {
        let key = ChaChaPolySymmetricKey::new(self.alg, raw)?;
        Ok(SymmetricKey::new(Box::new(key)))
    }

    fn key_len(&self) -> CryptoResult<usize> {
        match self.alg {
            SymmetricAlgorithm::ChaCha20Poly1305 | SymmetricAlgorithm::XChaCha20Poly1305 => Ok(32),
            _ => Err(CryptoErrno::UnsupportedAlgorithm.into()),
        }
    }
}

impl ChaChaPolySymmetricState {
    pub fn new(
        alg: SymmetricAlgorithm,
        key: Option<SymmetricKey>,
        options: Option<SymmetricOptions>,
        size_limits: Option<usize>,
    ) -> CryptoResult<Self> {
        let key = key.ok_or(CryptoErrno::KeyRequired)?;
        let key = key.inner();
        let key = key
            .as_any()
            .downcast_ref::<ChaChaPolySymmetricKey>()
            .ok_or(CryptoErrno::InvalidKey)?;
        let expected_nonce_len = match alg {
            SymmetricAlgorithm::ChaCha20Poly1305 => 12,
            SymmetricAlgorithm::XChaCha20Poly1305 => 24,
            _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
        };
        let options = options.as_ref().ok_or(CryptoErrno::NonceRequired)?;
        let nonce = options.locked(|mut options| {
            if options.nonce.is_none() && expected_nonce_len >= 16 {
                options.nonce = Some(vec![0u8; expected_nonce_len]);
                let mut rng = SecureRandom::new();
                rng.fill(options.nonce.as_mut().unwrap())?;
            }
            let nonce_vec = options.nonce.as_ref().ok_or(CryptoErrno::NonceRequired)?;
            if nonce_vec.len() != expected_nonce_len {
                return Err(CryptoError::from(CryptoErrno::InvalidNonce));
            };
            Ok(nonce_vec.clone())
        })?;
        let chapoly_impl = match alg {
            SymmetricAlgorithm::ChaCha20Poly1305 => ChaChaPolyVariant::ChaCha(
                ChaCha20Poly1305::new_from_slice(key.as_raw()?)
                    .map_err(|_| CryptoErrno::InvalidKey)?,
            ),
            SymmetricAlgorithm::XChaCha20Poly1305 => ChaChaPolyVariant::XChaCha(
                XChaCha20Poly1305::new_from_slice(key.as_raw()?)
                    .map_err(|_| CryptoErrno::InvalidKey)?,
            ),
            _ => return Err(CryptoErrno::UnsupportedAlgorithm.into()),
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

    // Encryption and decryption happen in place, in the `Vec` the bindings
    // received, which is then returned as the output.

    fn encrypt_unchecked(&mut self, data: Vec<u8>) -> CryptoResult<Vec<u8>> {
        let (mut out, tag) = self.encrypt_detached_unchecked(data)?;
        // Reserve exactly the tag length, rather than letting `extend` grow
        // the capacity by doubling it. Reserving only after encrypting means
        // that if this reallocates, the buffer it frees holds ciphertext
        // rather than plaintext.
        //
        // Known limitation: Wasmtime lifts the argument into a `Vec` whose
        // capacity equals its length, so this reserve does reallocate once
        // and copies the message. The `bindgen!`-generated bindings offer
        // no way to allocate room for the tag while lifting the list.
        out.reserve_exact(TAG_LEN);
        out.extend_from_slice(tag.as_ref());
        Ok(out)
    }

    fn encrypt_detached_unchecked(
        &mut self,
        mut data: Vec<u8>,
    ) -> CryptoResult<(Vec<u8>, SymmetricTag)> {
        let nonce = self.nonce.as_ref().ok_or(CryptoErrno::NonceRequired)?;

        // Nonce length is validated per-algorithm in the constructor, so these cannot fail.
        let result = match &self.ctx {
            ChaChaPolyVariant::ChaCha(x) => {
                let n: Nonce<ChaCha20Poly1305> = nonce[..]
                    .try_into()
                    .expect("ChaCha nonce is 12 bytes; validated in constructor");
                x.encrypt_inout_detached(&n, &self.ad, (&mut data[..]).into())
            }
            ChaChaPolyVariant::XChaCha(x) => {
                let n: Nonce<XChaCha20Poly1305> = nonce[..]
                    .try_into()
                    .expect("XChaCha nonce is 24 bytes; validated in constructor");
                x.encrypt_inout_detached(&n, &self.ad, (&mut data[..]).into())
            }
        };
        let raw_tag = match result {
            Ok(raw_tag) => raw_tag.to_vec(),
            Err(_) => {
                // The buffer may hold a mix of plaintext and ciphertext.
                data.zeroize();
                return Err(CryptoErrno::InternalError.into());
            }
        };

        self.nonce = None;
        Ok((data, SymmetricTag::new(self.alg, raw_tag)))
    }

    fn decrypt_unchecked(&mut self, data: Vec<u8>, raw_tag: &[u8]) -> CryptoResult<Vec<u8>> {
        self.decrypt_detached_unchecked(data, raw_tag)
    }

    fn decrypt_detached_unchecked(
        &mut self,
        mut data: Vec<u8>,
        raw_tag: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let nonce = self.nonce.as_ref().ok_or(CryptoErrno::NonceRequired)?;

        // Nonce length validated in constructor; tag length from caller -- return InvalidTag on mismatch.
        let result = match &self.ctx {
            ChaChaPolyVariant::ChaCha(x) => {
                let n: Nonce<ChaCha20Poly1305> = nonce[..]
                    .try_into()
                    .expect("ChaCha nonce is 12 bytes; validated in constructor");
                let t: Tag<ChaCha20Poly1305> =
                    raw_tag.try_into().map_err(|_| CryptoErrno::InvalidTag)?;
                x.decrypt_inout_detached(&n, &self.ad, (&mut data[..]).into(), &t)
            }
            ChaChaPolyVariant::XChaCha(x) => {
                let n: Nonce<XChaCha20Poly1305> = nonce[..]
                    .try_into()
                    .expect("XChaCha nonce is 24 bytes; validated in constructor");
                let t: Tag<XChaCha20Poly1305> =
                    raw_tag.try_into().map_err(|_| CryptoErrno::InvalidTag)?;
                x.decrypt_inout_detached(&n, &self.ad, (&mut data[..]).into(), &t)
            }
        };
        if result.is_err() {
            // `chacha20poly1305` verifies the tag before decrypting, so the
            // buffer still holds ciphertext. Zeroize it anyway, so that no
            // partial plaintext can be left behind even if that changes.
            data.zeroize();
            return Err(CryptoErrno::InvalidTag.into());
        }
        Ok(data)
    }
}
