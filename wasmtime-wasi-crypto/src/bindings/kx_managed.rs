use crate::bindings::wasi::crypto::kx_managed::{
    CryptoErrno, Host, KpId, KxKeypair, KxOptions, SecretsManager, Version,
};
use crate::error::CryptoResult;
use wasmtime::component::Resource;

// No secrets manager is implemented (`secrets-manager.open` always fails), so
// every managed-key function returns `UnsupportedFeature`.
impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    fn generate_managed(
        &mut self,
        _secrets_manager: Resource<SecretsManager>,
        _algorithm: String,
        _options: Option<Resource<KxOptions>>,
    ) -> CryptoResult<Resource<KxKeypair>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn store_managed(
        &mut self,
        _secrets_manager: Resource<SecretsManager>,
        _kp: Resource<KxKeypair>,
    ) -> CryptoResult<KpId> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn replace_managed(
        &mut self,
        _secrets_manager: Resource<SecretsManager>,
        _kp_old: Resource<KxKeypair>,
        _kp_new: Resource<KxKeypair>,
    ) -> CryptoResult<Version> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn id(&mut self, _kp: Resource<KxKeypair>) -> CryptoResult<(KpId, Version)> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn from_id(
        &mut self,
        _secrets_manager: Resource<SecretsManager>,
        _kp_id: KpId,
        _kp_version: Version,
    ) -> CryptoResult<Resource<KxKeypair>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }
}
