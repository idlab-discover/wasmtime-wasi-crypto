use crate::bindings::wasi::crypto::common::{ArrayOutput, CryptoErrno, Timestamp, Version};
use crate::bindings::wasi::crypto::external_secrets::{Host, SecretId};
use crate::bindings::wasi::crypto::secrets_manager::SecretsManager;
use crate::error::CryptoResult;

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    fn store(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret: Vec<u8>,
        expiration: Timestamp,
    ) -> CryptoResult<SecretId> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn replace(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret: Vec<u8>,
        expiration: Timestamp,
    ) -> CryptoResult<(SecretId, Version)> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn from_id(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret_id: SecretId,
        secret_version: Version,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn invalidate(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret_id: SecretId,
        secret_version: Version,
    ) -> CryptoResult<()> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn encapsulate(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret: Vec<u8>,
        expiration: Timestamp,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn decapsulate(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        encrypted_secret: Vec<u8>,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }
}
