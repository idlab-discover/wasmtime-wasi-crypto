use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno, error::CryptoResult,
};
use rand_core::{Infallible, TryCryptoRng, TryRng};

pub struct SecureRandom;

impl SecureRandom {
    pub fn new() -> Self {
        SecureRandom
    }

    pub fn fill(&mut self, bytes: &mut [u8]) -> CryptoResult<()> {
        getrandom::fill(bytes).map_err(|_| CryptoErrno::RngError.into())
    }
}

impl TryRng for SecureRandom {
    // Rng is blanket-implemented for TryRng<Error = Infallible>.
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(getrandom::u32().expect("OS random number generator failed"))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(getrandom::u64().expect("OS random number generator failed"))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        getrandom::fill(dst).expect("OS random number generator failed");
        Ok(())
    }
}

// Marker trait, from the docs:
// > Cryptographically unpredictable output is not a requirement of this trait,
// > but is a requirement of TryCryptoRng.
impl TryCryptoRng for SecureRandom {}
