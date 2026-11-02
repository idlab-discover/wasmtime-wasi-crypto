use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_asymmetric_common::{Host, KpId};
use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    AlgorithmType, ArrayOutput, CryptoErrno, Keypair, KeypairEncoding, Options, Publickey,
    PublickeyEncoding, Secretkey, SecretkeyEncoding, SecretsManager, Version,
};
use crate::error::CryptoResult;
use crate::keypair::KeyPair;

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    fn keypair_generate(
        &mut self,
        algorithm_type: AlgorithmType,
        algorithm: String,
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

    fn keypair_import(
        &mut self,
        algorithm_type: AlgorithmType,
        algorithm: String,
        encoded: Vec<u8>,
        encoding: KeypairEncoding,
    ) -> CryptoResult<wasmtime::component::Resource<Keypair>> {
        let kp = KeyPair::import(algorithm_type, &algorithm, &encoded, encoding)?;
        let handle = self.table.push(kp)?;
        Ok(handle)
    }

    fn keypair_generate_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        algorithm_type: AlgorithmType,
        algorithm: String,
        options: Option<wasmtime::component::Resource<Options>>,
    ) -> CryptoResult<wasmtime::component::Resource<Keypair>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn keypair_store_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        kp: wasmtime::component::Resource<Keypair>,
    ) -> CryptoResult<KpId> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn keypair_replace_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        kp_old: wasmtime::component::Resource<Keypair>,
        kp_new: wasmtime::component::Resource<Keypair>,
    ) -> CryptoResult<Version> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn keypair_id(
        &mut self,
        kp: wasmtime::component::Resource<Keypair>,
    ) -> CryptoResult<(KpId, Version)> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn keypair_from_id(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        kp_id: KpId,
        kp_version: Version,
    ) -> CryptoResult<wasmtime::component::Resource<Keypair>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

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

    fn keypair_publickey(
        &mut self,
        kp: wasmtime::component::Resource<Keypair>,
    ) -> CryptoResult<wasmtime::component::Resource<Publickey>> {
        let kp = self.table.get(&kp)?;
        let pk = kp.public_key()?;
        let handle = self.table.push(pk)?;
        Ok(handle)
    }

    fn keypair_secretkey(
        &mut self,
        kp: wasmtime::component::Resource<Keypair>,
    ) -> CryptoResult<wasmtime::component::Resource<Secretkey>> {
        let kp = self.table.get(&kp)?;
        let sk = kp.secret_key()?;
        let handle = self.table.push(sk)?;
        Ok(handle)
    }

    fn publickey_import(
        &mut self,
        algorithm_type: AlgorithmType,
        algorithm: String,
        encoded: Vec<u8>,
        encoding: PublickeyEncoding,
    ) -> CryptoResult<wasmtime::component::Resource<Publickey>> {
        let pk = Publickey::import(algorithm_type, &algorithm, &encoded, encoding)?;
        let handle = self.table.push(pk)?;
        Ok(handle)
    }

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

    fn publickey_verify(
        &mut self,
        pk: wasmtime::component::Resource<Publickey>,
    ) -> CryptoResult<()> {
        Publickey::verify(self.table, pk)?;
        Ok(())
    }

    fn publickey_from_secretkey(
        &mut self,
        sk: wasmtime::component::Resource<Secretkey>,
    ) -> CryptoResult<wasmtime::component::Resource<Publickey>> {
        // Also not defined in witx version
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn secretkey_import(
        &mut self,
        algorithm_type: AlgorithmType,
        algorithm: String,
        encoded: Vec<u8>,
        encoding: SecretkeyEncoding,
    ) -> CryptoResult<wasmtime::component::Resource<Secretkey>> {
        let sk = Secretkey::import(algorithm_type, &algorithm, &encoded, encoding)?;
        let handle = self.table.push(sk)?;
        Ok(handle)
    }

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
