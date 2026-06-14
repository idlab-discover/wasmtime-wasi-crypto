use ::sha2::{Digest, Sha256, Sha384, Sha512, Sha512_256};

use crate::{
    bindings::wasi::crypto::{
        wasi_ephemeral_crypto_common::CryptoErrno, wasi_ephemeral_crypto_symmetric::SymmetricKey,
    },
    options::OptionsLike,
    symmetric::{SymmetricAlgorithm, SymmetricOptions, state::SymmetricStateLike},
};
use derivative::Derivative;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
enum HashVariant {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha512_256(Sha512_256),
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub struct Sha2SymmetricState {
    pub alg: SymmetricAlgorithm,
    options: Option<SymmetricOptions>,
    size_limit: Option<usize>,
    ctx: HashVariant,
}

impl Sha2SymmetricState {
    pub fn new(
        alg: SymmetricAlgorithm,
        key: Option<&SymmetricKey>,
        options: Option<SymmetricOptions>,
        size_limit: Option<usize>,
    ) -> Result<Self, CryptoErrno> {
        if key.is_some() {
            return Err(CryptoErrno::KeyNotSupported);
        }
        let ctx = match alg {
            SymmetricAlgorithm::Sha256 => HashVariant::Sha256(Sha256::new()),
            SymmetricAlgorithm::Sha384 => HashVariant::Sha384(Sha384::new()),
            SymmetricAlgorithm::Sha512 => HashVariant::Sha512(Sha512::new()),
            SymmetricAlgorithm::Sha512_256 => HashVariant::Sha512_256(Sha512_256::new()),
            _ => return Err(CryptoErrno::UnsupportedAlgorithm),
        };
        Ok(Sha2SymmetricState {
            alg,
            options,
            size_limit,
            ctx,
        })
    }
}

impl SymmetricStateLike for Sha2SymmetricState {
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
        match &mut self.ctx {
            HashVariant::Sha256(x) => x.update(data),
            HashVariant::Sha384(x) => x.update(data),
            HashVariant::Sha512(x) => x.update(data),
            HashVariant::Sha512_256(x) => x.update(data),
        };
        Ok(())
    }

    fn squeeze_unchecked(&mut self) -> Result<Vec<u8>, CryptoErrno> {
        let raw = match &self.ctx {
            HashVariant::Sha256(x) => x.clone().finalize().to_vec(),
            HashVariant::Sha384(x) => x.clone().finalize().to_vec(),
            HashVariant::Sha512(x) => x.clone().finalize().to_vec(),
            HashVariant::Sha512_256(x) => x.clone().finalize().to_vec(),
        };
        // if !(raw.len() >= out.len()) {
        //     return Err(CryptoErrno::InvalidLength);
        // };
        // out.copy_from_slice(&raw[..out.len()]);

        Ok(raw)
    }
}
