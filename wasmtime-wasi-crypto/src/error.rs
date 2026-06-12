use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno;
use wasmtime_wasi::ResourceTableError;

impl From<ResourceTableError> for CryptoErrno {
    fn from(value: ResourceTableError) -> Self {
        CryptoErrno::InvalidHandle
    }
}
