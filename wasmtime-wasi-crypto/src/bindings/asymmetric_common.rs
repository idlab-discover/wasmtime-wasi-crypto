use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_asymmetric_common::{Host, KpId};
use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    AlgorithmType, ArrayOutput, CryptoErrno, Keypair, KeypairEncoding, Options, Publickey,
    PublickeyEncoding, Secretkey, SecretkeyEncoding, SecretsManager, Version,
};
use crate::error::CryptoResult;
use crate::keypair::KeyPair;

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    #[doc = "/ Generate a new key pair."]
    #[doc = "/ "]
    #[doc = "/ Internally, a key pair stores the supplied algorithm and optional parameters."]
    #[doc = "/ "]
    #[doc = "/ Trying to use that key pair with different parameters will throw an `invalid_key` error."]
    #[doc = "/ "]
    #[doc = "/ This function may return `$crypto_errno.unsupported_feature` if key generation is not supported by the host for the chosen algorithm."]
    #[doc = "/ "]
    #[doc = "/ The function may also return `unsupported_algorithm` if the algorithm is not supported by the host."]
    #[doc = "/ "]
    #[doc = "/ Finally, if generating that type of key pair is an expensive operation, the function may return `in_progress`."]
    #[doc = "/ In that case, the guest should retry with the same parameters until the function completes."]
    #[doc = "/ "]
    #[doc = "/ Example usage:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let kp_handle = ctx.keypair_generate(AlgorithmType::Signatures, \"RSA_PKCS1_2048_SHA256\", None)?;"]
    #[doc = "/ ```"]
    fn keypair_generate(
        &mut self,
        algorithm_type: AlgorithmType,
        algorithm: wasmtime::component::__internal::String,
        options: Option<wasmtime::component::Resource<Options>>,
    ) -> CryptoResult<wasmtime::component::Resource<Keypair>> {
        let options = match options {
            None => None,
            Some(options_handle) => Some(self.table.get(&options_handle)?),
        };
        let kp = KeyPair::generate(algorithm_type, &algorithm, options.cloned())?;
        let handle = self.table.push(kp)?;
        Ok(handle)
    }

    #[doc = "/ Import a key pair."]
    #[doc = "/ "]
    #[doc = "/ This function creates a `keypair` object from existing material."]
    #[doc = "/ "]
    #[doc = "/ It may return `unsupported_algorithm` if the encoding scheme is not supported, or `invalid_key` if the key cannot be decoded."]
    #[doc = "/ "]
    #[doc = "/ The function may also return `unsupported_algorithm` if the algorithm is not supported by the host."]
    #[doc = "/ "]
    #[doc = "/ Example usage:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let kp_handle = ctx.keypair_import(AlgorithmType::Signatures, \"RSA_PKCS1_2048_SHA256\", KeypairEncoding::PKCS8)?;"]
    #[doc = "/ ```"]
    fn keypair_import(
        &mut self,
        algorithm_type: AlgorithmType,
        algorithm: wasmtime::component::__internal::String,
        encoded: wasmtime::component::__internal::Vec<u8>,
        encoding: KeypairEncoding,
    ) -> CryptoResult<wasmtime::component::Resource<Keypair>> {
        let kp = KeyPair::import(algorithm_type, &algorithm, &encoded, encoding)?;
        let handle = self.table.push(kp)?;
        Ok(handle)
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Generate a new managed key pair."]
    #[doc = "/ "]
    #[doc = "/ The key pair is generated and stored by the secrets management facilities."]
    #[doc = "/ "]
    #[doc = "/ It may be used through its identifier, but the host may not allow it to be exported."]
    #[doc = "/ "]
    #[doc = "/ The function returns the `unsupported_feature` error code if secrets management facilities are not supported by the host,"]
    #[doc = "/ or `unsupported_algorithm` if a key cannot be created for the chosen algorithm."]
    #[doc = "/ "]
    #[doc = "/ The function may also return `unsupported_algorithm` if the algorithm is not supported by the host."]
    #[doc = "/ "]
    #[doc = "/ This is also an optional import, meaning that the function may not even exist."]
    fn keypair_generate_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        algorithm_type: AlgorithmType,
        algorithm: wasmtime::component::__internal::String,
        options: Option<wasmtime::component::Resource<Options>>,
    ) -> CryptoResult<wasmtime::component::Resource<Keypair>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Store a key pair into the secrets manager."]
    #[doc = "/ "]
    #[doc = "/ On success, the function returns the key pair identifier"]
    fn keypair_store_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        kp: wasmtime::component::Resource<Keypair>,
    ) -> CryptoResult<KpId> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Replace a managed key pair."]
    #[doc = "/ "]
    #[doc = "/ This function creates a new version of a managed key pair, by replacing `$kp_old` with `$kp_new`."]
    #[doc = "/ "]
    #[doc = "/ It does several things:"]
    #[doc = "/ "]
    #[doc = "/ - The key identifier for `$kp_new` is set to the one of `$kp_old`."]
    #[doc = "/ - A new, unique version identifier is assigned to `$kp_new`. This version will be equivalent to using `$version_latest` until the key is replaced."]
    #[doc = "/ - The `$kp_old` handle is closed."]
    #[doc = "/ "]
    #[doc = "/ Both keys must share the same algorithm and have compatible parameters. If this is not the case, `incompatible_keys` is returned."]
    #[doc = "/ "]
    #[doc = "/ The function may also return the `unsupported_feature` error code if secrets management facilities are not supported by the host,"]
    #[doc = "/ or if keys cannot be rotated."]
    #[doc = "/ "]
    #[doc = "/ Finally, `prohibited_operation` can be returned if `$kp_new` wasn\'t created by the secrets manager, and the secrets manager prohibits imported keys."]
    #[doc = "/ "]
    #[doc = "/ If the operation succeeded, the new version is returned."]
    #[doc = "/ "]
    #[doc = "/ This is an optional import, meaning that the function may not even exist."]
    fn keypair_replace_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        kp_old: wasmtime::component::Resource<Keypair>,
        kp_new: wasmtime::component::Resource<Keypair>,
    ) -> CryptoResult<Version> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Return the key pair identifier and version of a managed key pair."]
    #[doc = "/ "]
    #[doc = "/ If the key pair is not managed, `unsupported_feature` is returned instead."]
    #[doc = "/ "]
    #[doc = "/ This is an optional import, meaning that the function may not even exist."]
    fn keypair_id(
        &mut self,
        kp: wasmtime::component::Resource<Keypair>,
    ) -> CryptoResult<(KpId, Version)> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    #[doc = "/ __(optional)__"]
    #[doc = "/ Return a managed key pair from a key identifier."]
    #[doc = "/ "]
    #[doc = "/ `kp_version` can be set to `version_latest` to retrieve the most recent version of a key pair."]
    #[doc = "/ "]
    #[doc = "/ If no key pair matching the provided information is found, `not_found` is returned instead."]
    #[doc = "/ "]
    #[doc = "/ This is an optional import, meaning that the function may not even exist."]
    fn keypair_from_id(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        kp_id: KpId,
        kp_version: Version,
    ) -> CryptoResult<wasmtime::component::Resource<Keypair>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    #[doc = "/ Create a key pair from a public key and a secret key."]
    fn keypair_from_pk_and_sk(
        &mut self,
        publickey: wasmtime::component::Resource<Publickey>,
        secretkey: wasmtime::component::Resource<Secretkey>,
    ) -> CryptoResult<wasmtime::component::Resource<Keypair>> {
        let pk = self.table.get(&publickey)?.clone();
        let sk = self.table.get(&secretkey)?.clone();
        let kp = KeyPair::from_pk_and_sk(pk, sk)?;
        let handle = self.table.push(kp)?;
        Ok(handle)
    }

    #[doc = "/ Export a key pair as the given encoding format."]
    #[doc = "/ "]
    #[doc = "/ May return `prohibited_operation` if this operation is denied or `unsupported_encoding` if the encoding is not supported."]
    fn keypair_export(
        &mut self,
        kp: wasmtime::component::Resource<Keypair>,
        encoding: KeypairEncoding,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        let kp = self.table.get(&kp)?;
        let encoded = kp.export(encoding)?;
        let array_output_handle = ArrayOutput::register(self.table, encoded)?;
        Ok(array_output_handle)
    }

    #[doc = "/ Get the public key of a key pair."]
    fn keypair_publickey(
        &mut self,
        kp: wasmtime::component::Resource<Keypair>,
    ) -> CryptoResult<wasmtime::component::Resource<Publickey>> {
        let kp = self.table.get(&kp)?;
        let pk = kp.public_key()?;
        let handle = self.table.push(pk)?;
        Ok(handle)
    }

    #[doc = "/ Get the secret key of a key pair."]
    fn keypair_secretkey(
        &mut self,
        kp: wasmtime::component::Resource<Keypair>,
    ) -> CryptoResult<wasmtime::component::Resource<Secretkey>> {
        let kp = self.table.get(&kp)?;
        let sk = kp.secret_key()?;
        let handle = self.table.push(sk)?;
        Ok(handle)
    }

    #[doc = "/ Import a public key."]
    #[doc = "/ "]
    #[doc = "/ The function may return `unsupported_encoding` if importing from the given format is not implemented or incompatible with the key type."]
    #[doc = "/ "]
    #[doc = "/ It may also return `invalid_key` if the key doesn\'t appear to match the supplied algorithm."]
    #[doc = "/ "]
    #[doc = "/ Finally, the function may return `unsupported_algorithm` if the algorithm is not supported by the host."]
    #[doc = "/ "]
    #[doc = "/ Example usage:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let pk_handle = ctx.publickey_import(AlgorithmType::Signatures, encoded, PublickeyEncoding::Sec)?;"]
    #[doc = "/ ```"]
    fn publickey_import(
        &mut self,
        algorithm_type: AlgorithmType,
        algorithm: wasmtime::component::__internal::String,
        encoded: wasmtime::component::__internal::Vec<u8>,
        encoding: PublickeyEncoding,
    ) -> CryptoResult<wasmtime::component::Resource<Publickey>> {
        let pk = Publickey::import(algorithm_type, &algorithm, &encoded, encoding)?;
        let handle = self.table.push(pk)?;
        Ok(handle)
    }

    #[doc = "/ Export a public key as the given encoding format."]
    #[doc = "/ "]
    #[doc = "/ May return `unsupported_encoding` if the encoding is not supported."]
    fn publickey_export(
        &mut self,
        pk: wasmtime::component::Resource<Publickey>,
        encoding: PublickeyEncoding,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        let pk = self.table.get(&pk)?;
        let encoded = pk.export(encoding)?;
        let array_output_handle = ArrayOutput::register(self.table, encoded)?;
        Ok(array_output_handle)
    }

    #[doc = "/ Check that a public key is valid and in canonical form."]
    #[doc = "/ "]
    #[doc = "/ This function may perform stricter checks than those made during importation at the expense of additional CPU cycles."]
    #[doc = "/ "]
    #[doc = "/ The function returns `invalid_key` if the public key didn\'t pass the checks."]
    fn publickey_verify(
        &mut self,
        pk: wasmtime::component::Resource<Publickey>,
    ) -> CryptoResult<()> {
        Publickey::verify(self.table, pk)?;
        Ok(())
    }

    #[doc = "/ Compute the public key for a secret key."]
    fn publickey_from_secretkey(
        &mut self,
        sk: wasmtime::component::Resource<Secretkey>,
    ) -> CryptoResult<wasmtime::component::Resource<Publickey>> {
        // Also not defined in witx version
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    #[doc = "/ Import a secret key."]
    #[doc = "/ "]
    #[doc = "/ The function may return `unsupported_encoding` if importing from the given format is not implemented or incompatible with the key type."]
    #[doc = "/ "]
    #[doc = "/ It may also return `invalid_key` if the key doesn\'t appear to match the supplied algorithm."]
    #[doc = "/ "]
    #[doc = "/ Finally, the function may return `unsupported_algorithm` if the algorithm is not supported by the host."]
    #[doc = "/ "]
    #[doc = "/ Example usage:"]
    #[doc = "/ "]
    #[doc = "/ ```rust"]
    #[doc = "/ let pk_handle = ctx.secretkey_import(AlgorithmType::KX, encoded, SecretkeyEncoding::Raw)?;"]
    #[doc = "/ ```"]
    fn secretkey_import(
        &mut self,
        algorithm_type: AlgorithmType,
        algorithm: wasmtime::component::__internal::String,
        encoded: wasmtime::component::__internal::Vec<u8>,
        encoding: SecretkeyEncoding,
    ) -> CryptoResult<wasmtime::component::Resource<Secretkey>> {
        let sk = Secretkey::import(algorithm_type, &algorithm, &encoded, encoding)?;
        let handle = self.table.push(sk)?;
        Ok(handle)
    }

    #[doc = "/ Export a secret key as the given encoding format."]
    #[doc = "/ "]
    #[doc = "/ May return `unsupported_encoding` if the encoding is not supported."]
    fn secretkey_export(
        &mut self,
        sk: wasmtime::component::Resource<Secretkey>,
        encoding: SecretkeyEncoding,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        let sk = self.table.get(&sk)?;
        let encoded = sk.export(encoding)?;
        let array_output_handle = ArrayOutput::register(self.table, encoded)?;
        Ok(array_output_handle)
    }
}
