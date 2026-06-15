use crate::{
    bindings::wasi::crypto::{
        wasi_ephemeral_crypto_common::{CryptoErrno, SymmetricTag},
        wasi_ephemeral_crypto_symmetric::SymmetricKey,
    },
    limits::Limits,
    symmetric::{
        SymmetricAlgorithm, SymmetricOptions, aes_gcm::AesGcmSymmetricState,
        chacha_poly::ChaChaPolySymmetricState, hkdf::HkdfSymmetricState,
        hmac_sha2::HmacSha2SymmetricState, sha2::Sha2SymmetricState,
        xoodyak::XoodyakSymmetricState,
    },
};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone)]
pub struct SymmetricState {
    inner: Arc<Mutex<Box<dyn SymmetricStateLike>>>,
}

impl SymmetricState {
    fn new(symmetric_state_like: Box<dyn SymmetricStateLike>) -> Self {
        SymmetricState {
            inner: Arc::new(Mutex::new(symmetric_state_like)),
        }
    }

    pub(crate) fn inner(&self) -> MutexGuard<'_, Box<dyn SymmetricStateLike>> {
        self.inner.lock().unwrap()
    }

    pub(crate) fn locked<T, U>(&self, mut f: T) -> U
    where
        T: FnMut(MutexGuard<'_, Box<dyn SymmetricStateLike>>) -> U,
    {
        f(self.inner())
    }

    pub(crate) fn open(
        alg_str: &str,
        key: Option<&SymmetricKey>,
        options: Option<&SymmetricOptions>,
        limits: &Limits,
    ) -> Result<SymmetricState, CryptoErrno> {
        let alg = SymmetricAlgorithm::try_from(alg_str)?;
        if let Some(key) = key
            && key.alg() != alg {
                return Err(CryptoErrno::InvalidKey);
            }
        let (key, options) = (key.cloned(), options.cloned());
        let size_limit = limits.0.get(alg_str).copied();
        let symmetric_state = match alg {
            SymmetricAlgorithm::HmacSha256 | SymmetricAlgorithm::HmacSha512 => SymmetricState::new(
                Box::new(HmacSha2SymmetricState::new(alg, key, options, size_limit)?),
            ),
            SymmetricAlgorithm::Sha256
            | SymmetricAlgorithm::Sha384
            | SymmetricAlgorithm::Sha512
            | SymmetricAlgorithm::Sha512_256 => SymmetricState::new(Box::new(
                Sha2SymmetricState::new(alg, None, options, size_limit)?,
            )),
            SymmetricAlgorithm::HkdfSha256Expand
            | SymmetricAlgorithm::HkdfSha512Expand
            | SymmetricAlgorithm::HkdfSha256Extract
            | SymmetricAlgorithm::HkdfSha512Extract => SymmetricState::new(Box::new(
                HkdfSymmetricState::new(alg, key, options, size_limit)?,
            )),
            SymmetricAlgorithm::Aes128Gcm | SymmetricAlgorithm::Aes256Gcm => SymmetricState::new(
                Box::new(AesGcmSymmetricState::new(alg, key, options, size_limit)?),
            ),
            SymmetricAlgorithm::ChaCha20Poly1305 => SymmetricState::new(Box::new(
                ChaChaPolySymmetricState::new(alg, key, options, size_limit)?,
            )),
            SymmetricAlgorithm::XChaCha20Poly1305 => SymmetricState::new(Box::new(
                ChaChaPolySymmetricState::new(alg, key, options, size_limit)?,
            )),
            SymmetricAlgorithm::Xoodyak128 | SymmetricAlgorithm::Xoodyak160 => SymmetricState::new(
                Box::new(XoodyakSymmetricState::new(alg, key, options, size_limit)?),
            ),
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        };
        Ok(symmetric_state)
    }
}

pub trait SymmetricStateLike: Sync + Send {
    fn alg(&self) -> SymmetricAlgorithm;
    fn options_get(&self, name: &str) -> Result<Vec<u8>, CryptoErrno>;
    fn options_get_u64(&self, name: &str) -> Result<u64, CryptoErrno>;

    fn size_limit(&self) -> Option<usize>;

    fn absorb_unchecked(&mut self, _data: &[u8]) -> Result<(), CryptoErrno> {
        Err(CryptoErrno::InvalidOperation)
    }

    fn absorb(&mut self, data: &[u8]) -> Result<(), CryptoErrno> {
        if self.size_limit().is_some_and(|l| data.len() > l) {
            return Err(CryptoErrno::Overflow);
        }
        self.absorb_unchecked(data)
    }

    fn squeeze_unchecked(&mut self) -> Result<Vec<u8>, CryptoErrno> {
        Err(CryptoErrno::InvalidOperation)
    }

    fn squeeze(&mut self) -> Result<Vec<u8>, CryptoErrno> {
        // if !self.size_limit().is_none_or(|l| out.len() <= l) {
        //     return Err(CryptoErrno::Overflow);
        // }
        self.squeeze_unchecked()
    }

    fn squeeze_key(&mut self, _alg_str: &str) -> Result<SymmetricKey, CryptoErrno> {
        Err(CryptoErrno::InvalidOperation)
    }

    fn squeeze_tag(&mut self) -> Result<SymmetricTag, CryptoErrno> {
        Err(CryptoErrno::InvalidOperation)
    }

    fn max_tag_len(&mut self) -> Result<usize, CryptoErrno> {
        Err(CryptoErrno::InvalidOperation)
    }

    fn encrypt_unchecked(&mut self, _data: &[u8]) -> Result<Vec<u8>, CryptoErrno> {
        Err(CryptoErrno::InvalidOperation)
    }

    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoErrno> {
        // if !(out.len()
        //     == data
        //         .len()
        //         .checked_add(self.max_tag_len()?)
        //         .ok_or(CryptoErrno::Overflow)?)
        // {
        //     return Err(CryptoErrno::InvalidLength);
        // }
        if self.size_limit().is_some_and(|l| data.len() > l) {
            return Err(CryptoErrno::Overflow);
        }
        self.encrypt_unchecked(data)
    }

    fn encrypt_detached_unchecked(
        &mut self,
        _data: &[u8],
    ) -> Result<(Vec<u8>, SymmetricTag), CryptoErrno> {
        Err(CryptoErrno::InvalidOperation)
    }

    fn encrypt_detached(&mut self, data: &[u8]) -> Result<(Vec<u8>, SymmetricTag), CryptoErrno> {
        // if !(out.len() == data.len()) {
        //     return Err(CryptoErrno::InvalidLength);
        // }
        if self.size_limit().is_some_and(|l| data.len() > l) {
            return Err(CryptoErrno::Overflow);
        }

        self.encrypt_detached_unchecked(data)
    }

    fn decrypt_unchecked(&mut self, _data: &[u8], _raw_tag: &[u8]) -> Result<Vec<u8>, CryptoErrno> {
        Err(CryptoErrno::InvalidOperation)
    }

    fn decrypt(&mut self, data: &[u8], out_len: usize) -> Result<Vec<u8>, CryptoErrno> {
        if self.size_limit().is_some_and(|l| data.len() > l) {
            return Err(CryptoErrno::Overflow);
        }
        if out_len > data.len() {
            return Err(CryptoErrno::Overflow);
        }
        let (ciphertext, raw_tag) = data.split_at(out_len);
        match self.decrypt_unchecked(ciphertext, raw_tag) {
            Ok(out) => Ok(out),
            Err(e) => {
                // out.iter_mut().for_each(|x| *x = 0);
                Err(e)
            }
        }
    }

    fn decrypt_detached_unchecked(
        &mut self,
        _data: &[u8],
        _raw_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoErrno> {
        Err(CryptoErrno::InvalidOperation)
    }

    fn decrypt_detached(&mut self, data: &[u8], raw_tag: &[u8]) -> Result<Vec<u8>, CryptoErrno> {
        // if !(out.len() == data.len()) {
        //     return Err(CryptoErrno::InvalidLength);
        // }

        if self.size_limit().is_some_and(|l| data.len() > l) {
            return Err(CryptoErrno::Overflow);
        }
        match self.decrypt_detached_unchecked(data, raw_tag) {
            Ok(out) => Ok(out),
            Err(e) => {
                // out.iter_mut().for_each(|x| *x = 0);
                Err(e)
            }
        }
    }

    fn ratchet(&mut self) -> Result<(), CryptoErrno> {
        Err(CryptoErrno::InvalidOperation)
    }
}
