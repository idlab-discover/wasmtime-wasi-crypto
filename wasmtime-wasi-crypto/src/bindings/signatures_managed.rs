use crate::bindings::wasi::crypto::signatures_managed::{
    CryptoErrno, Host, KpId, SecretsManager, SignatureKeypair, SignatureOptions, Version,
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
        _options: Option<Resource<SignatureOptions>>,
    ) -> CryptoResult<Resource<SignatureKeypair>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn store_managed(
        &mut self,
        _secrets_manager: Resource<SecretsManager>,
        _kp: Resource<SignatureKeypair>,
    ) -> CryptoResult<KpId> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn replace_managed(
        &mut self,
        _secrets_manager: Resource<SecretsManager>,
        kp_old: Resource<SignatureKeypair>,
        _kp_new: Resource<SignatureKeypair>,
    ) -> CryptoResult<Version> {
        // `kp-old` is passed by ownership, so the host must drop it even though
        // the replacement fails; otherwise its table entry would leak.
        self.table.delete(kp_old)?;
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn id(&mut self, _kp: Resource<SignatureKeypair>) -> CryptoResult<(KpId, Version)> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn from_id(
        &mut self,
        _secrets_manager: Resource<SecretsManager>,
        _kp_id: KpId,
        _kp_version: Version,
    ) -> CryptoResult<Resource<SignatureKeypair>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }
}
