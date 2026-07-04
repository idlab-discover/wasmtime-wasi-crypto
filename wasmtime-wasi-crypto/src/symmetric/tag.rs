use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno, error::CryptoResult,
    symmetric::SymmetricAlgorithm,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[derive(Debug, Clone, Eq)]
pub struct SymmetricTag {
    alg: SymmetricAlgorithm,
    raw: Vec<u8>,
}

impl PartialEq for SymmetricTag {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg && self.raw.ct_eq(&other.raw).unwrap_u8() == 1
    }
}

impl Drop for SymmetricTag {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl SymmetricTag {
    pub fn new(alg: SymmetricAlgorithm, raw: Vec<u8>) -> Self {
        SymmetricTag { alg, raw }
    }

    pub fn verify(&self, expected_raw: &[u8]) -> CryptoResult<()> {
        if self.raw.ct_eq(expected_raw).unwrap_u8() != 1 {
            return Err(CryptoErrno::InvalidTag.into());
        }
        Ok(())
    }
}

impl AsRef<[u8]> for SymmetricTag {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}
