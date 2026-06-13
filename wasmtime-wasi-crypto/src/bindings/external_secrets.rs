use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    ArrayOutput, CryptoErrno, SecretsManager, Timestamp, Version,
};
use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_external_secrets::{Host, SecretId};

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    #[doc = "/ Store an external secret into the secrets manager."]
    #[doc = "/ "]
    #[doc = "/ `expiration` is the expiration date of the secret as a UNIX timestamp, in seconds."]
    #[doc = "/ An expiration date is mandatory."]
    #[doc = "/ "]
    #[doc = "/ On success, the secret identifier is returned."]
    #[doc = "/ "]
    #[doc = "/ If this function is not supported by the host the `$unsupported_feature` error is returned."]
    fn external_secret_store(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret: wasmtime::component::__internal::Vec<u8>,
        expiration: Timestamp,
    ) -> Result<SecretId, CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ Replace a managed external secret with a new version."]
    #[doc = "/ "]
    #[doc = "/ `expiration` is the expiration date of the secret as a UNIX timestamp, in seconds."]
    #[doc = "/ An expiration date is mandatory."]
    #[doc = "/ "]
    #[doc = "/ On success, a new version is created and returned."]
    #[doc = "/ "]
    #[doc = "/ If this function is not supported by the host the `$unsupported_feature` error is returned."]
    fn external_secret_replace(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret: wasmtime::component::__internal::Vec<u8>,
        expiration: Timestamp,
    ) -> Result<(SecretId, Version), CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ Get a copy of an external secret given an identifier and version."]
    #[doc = "/ "]
    #[doc = "/ `secret_version` can be set to a version number, or to `version.latest` to retrieve the most recent version of a secret."]
    #[doc = "/ "]
    #[doc = "/ On success, a copy of the secret is returned."]
    #[doc = "/ "]
    #[doc = "/ The function returns `$unsupported_feature` if this operation is not supported by the host, and `not_found` if the identifier and version don\'t match any existing secret."]
    fn external_secret_from_id(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret_id: SecretId,
        secret_version: Version,
    ) -> Result<wasmtime::component::Resource<ArrayOutput>, CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ Invalidate an external secret given an identifier and a version."]
    #[doc = "/ "]
    #[doc = "/ This asks the secrets manager to delete or revoke a stored secret, a specific version of a secret."]
    #[doc = "/ "]
    #[doc = "/ `secret_version` can be set to a version number, or to `version.latest` to invalidate the current version, or to `version.all` to invalidate all versions of a secret."]
    #[doc = "/ "]
    #[doc = "/ The function returns `$unsupported_feature` if this operation is not supported by the host, and `not_found` if the identifier and version don\'t match any existing secret."]
    fn external_secret_invalidate(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret_id: SecretId,
        secret_version: Version,
    ) -> Result<(), CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ Encrypt an external secret."]
    #[doc = "/ "]
    #[doc = "/ Applications don\'t have access to the encryption key, and the secrets manager is free to choose any suitable algorithm."]
    #[doc = "/ "]
    #[doc = "/ However, the returned ciphertext must include and authenticate both the secret and the expiration date."]
    #[doc = "/ "]
    #[doc = "/ On success, the ciphertext is returned."]
    fn external_secret_encapsulate(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        secret: wasmtime::component::__internal::Vec<u8>,
        expiration: Timestamp,
    ) -> Result<wasmtime::component::Resource<ArrayOutput>, CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }

    #[doc = "/ Decrypt an external secret previously encrypted by the secrets manager."]
    #[doc = "/ "]
    #[doc = "/ Returns the original secret if the ciphertext is valid."]
    #[doc = "/ Returns `$expired` if the current date is past the stored expiration date."]
    #[doc = "/ Returns `$verification_failed` if the ciphertext format is invalid or if its authentication tag couldn\'t be verified."]
    fn external_secret_decapsulate(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        encrypted_secret: wasmtime::component::__internal::Vec<u8>,
    ) -> Result<wasmtime::component::Resource<ArrayOutput>, CryptoErrno> {
        Err(CryptoErrno::UnsupportedFeature)
    }
}
