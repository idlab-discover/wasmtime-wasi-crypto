use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    ArrayOutput, CryptoErrno, SecretsManager, Timestamp, Version,
};
use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_external_secrets::{Host, SecretId};
use crate::error::CryptoResult;

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    fn external_secret_store(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret: Vec<u8>,
        expiration: Timestamp,
    ) -> CryptoResult<SecretId> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn external_secret_replace(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret: Vec<u8>,
        expiration: Timestamp,
    ) -> CryptoResult<(SecretId, Version)> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn external_secret_from_id(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret_id: SecretId,
        secret_version: Version,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn external_secret_invalidate(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret_id: SecretId,
        secret_version: Version,
    ) -> CryptoResult<()> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn external_secret_encapsulate(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret: Vec<u8>,
        expiration: Timestamp,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn external_secret_decapsulate(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        encrypted_secret: Vec<u8>,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }
}
