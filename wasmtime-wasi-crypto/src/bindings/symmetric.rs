use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::{
    ArrayOutput, CryptoErrno, Options, SecretsManager, Size, SymmetricKey, SymmetricState,
    SymmetricTag, U64, Version,
};
use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_symmetric::{Host, StoredKeyId};
use crate::error::CryptoResult;

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    fn symmetric_key_generate(
        &mut self,
        algorithm: String,
        options: Option<wasmtime::component::Resource<Options>>,
    ) -> CryptoResult<wasmtime::component::Resource<SymmetricKey>> {
        let options = match options {
            Some(options_handle) => Some(
                self.table
                    .get(&options_handle)?
                    .clone() // TODO: investigate if this is necessary/valid
                    .into_symmetric()?,
            ),
            None => None,
        };

        let symmetric_key = SymmetricKey::generate(&algorithm, options)?;
        let handle = self.table.push(symmetric_key)?;
        Ok(handle)
    }

    fn symmetric_key_import(
        &mut self,
        algorithm: String,
        raw: Vec<u8>,
    ) -> CryptoResult<wasmtime::component::Resource<SymmetricKey>> {
        let symmetric_key = SymmetricKey::import(&algorithm, &raw)?;
        let handle = self.table.push(symmetric_key)?;
        Ok(handle)
    }

    fn symmetric_key_export(
        &mut self,
        symmetric_key: wasmtime::component::Resource<SymmetricKey>,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        let symmetric_key = self.table.get(&symmetric_key)?;

        let raw = symmetric_key.inner().as_raw()?.to_vec();

        let array_output_handle = ArrayOutput::register(self.table, raw)?;
        Ok(array_output_handle)
    }

    fn symmetric_key_generate_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        algorithm: String,
        options: Option<wasmtime::component::Resource<Options>>,
    ) -> CryptoResult<wasmtime::component::Resource<SymmetricKey>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn symmetric_key_store_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        symmetric_key: wasmtime::component::Resource<SymmetricKey>,
    ) -> CryptoResult<StoredKeyId> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn symmetric_key_replace_managed(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        symmetric_key_old: wasmtime::component::Resource<SymmetricKey>,
        symmetric_key_new: wasmtime::component::Resource<SymmetricKey>,
    ) -> CryptoResult<Version> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn symmetric_key_id(
        &mut self,
        symmetric_key: wasmtime::component::Resource<SymmetricKey>,
    ) -> CryptoResult<(StoredKeyId, Version)> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn symmetric_key_from_id(
        &mut self,
        secrets_manager: wasmtime::component::Resource<SecretsManager>,
        symmetric_key_id: StoredKeyId,
        symmetric_key_version: Version,
    ) -> CryptoResult<wasmtime::component::Resource<SymmetricKey>> {
        Err(CryptoErrno::UnsupportedFeature.into())
    }

    fn symmetric_state_open(
        &mut self,
        algorithm: String,
        key: Option<wasmtime::component::Resource<SymmetricKey>>,
        options: Option<wasmtime::component::Resource<Options>>,
    ) -> CryptoResult<wasmtime::component::Resource<SymmetricState>> {
        let key = match key {
            None => None,
            Some(symmetric_key_handle) => Some(self.table.get(&symmetric_key_handle)?),
        };
        let options = match options {
            None => None,
            Some(options_handle) => Some(
                self.table
                    .get(&options_handle)?
                    .clone() // TODO: investigate if this is necessary/valid
                    .into_symmetric()?,
            ),
        };
        let symmetric_state = SymmetricState::open(&algorithm, key, options.as_ref(), self.limits)?;
        let handle = self.table.push(symmetric_state)?;
        Ok(handle)
    }

    fn symmetric_state_options_get(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        name: String,
    ) -> CryptoResult<Vec<u8>> {
        let symmetric_state = self.table.get(&state)?;
        let v = symmetric_state.inner().options_get(&name)?;
        // if v_len > value.len() {
        //     return Err(CryptoErrno::Overflow);
        // }
        Ok(v)
    }

    fn symmetric_state_options_get_u64(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        name: String,
    ) -> CryptoResult<U64> {
        let symmetric_state = self.table.get(&state)?;
        let v = symmetric_state.inner().options_get_u64(&name)?;
        Ok(v)
    }

    fn symmetric_state_clone(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
    ) -> CryptoResult<wasmtime::component::Resource<SymmetricState>> {
        let symmetric_state = self.table.get(&state)?;
        let symmetric_state = symmetric_state.clone();
        let handle = self.table.push(symmetric_state)?;
        Ok(handle)
    }

    fn symmetric_state_absorb(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        data: Vec<u8>,
    ) -> CryptoResult<()> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.absorb(&data))?;
        Ok(())
    }

    fn symmetric_state_squeeze(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
    ) -> CryptoResult<Vec<u8>> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.squeeze_unchecked())
    }

    fn symmetric_state_squeeze_tag(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
    ) -> CryptoResult<wasmtime::component::Resource<SymmetricTag>> {
        let symmetric_state = self.table.get(&state)?;
        let tag = symmetric_state.locked(|mut state| state.squeeze_tag())?;
        let handle = self.table.push(tag)?;
        Ok(handle)
    }

    fn symmetric_state_squeeze_key(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        alg_str: String,
    ) -> CryptoResult<wasmtime::component::Resource<SymmetricKey>> {
        let symmetric_state = self.table.get(&state)?;
        let tag = symmetric_state.locked(|mut state| state.squeeze_key(&alg_str))?;
        let handle = self.table.push(tag)?;
        Ok(handle)
    }

    fn symmetric_state_max_tag_len(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
    ) -> CryptoResult<Size> {
        let symmetric_state = self.table.get(&state)?;
        let max_tag_len = symmetric_state.inner().max_tag_len()?;
        Ok(max_tag_len as u32)
    }

    fn symmetric_state_encrypt(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        data: Vec<u8>,
    ) -> CryptoResult<Vec<u8>> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.encrypt(data))
    }

    fn symmetric_state_encrypt_detached(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        data: Vec<u8>,
    ) -> CryptoResult<(Vec<u8>, wasmtime::component::Resource<SymmetricTag>)> {
        let symmetric_state = self.table.get(&state)?;
        let (out, symmetric_tag) = symmetric_state.inner().encrypt_detached(data)?;
        let handle = self.table.push(symmetric_tag)?;
        Ok((out, handle))
    }

    fn symmetric_state_decrypt(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        data: Vec<u8>,
        out_len: u32,
    ) -> CryptoResult<Vec<u8>> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.decrypt(data, out_len as usize))
    }

    fn symmetric_state_decrypt_detached(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
        data: Vec<u8>,
        raw_tag: Vec<u8>,
    ) -> CryptoResult<Vec<u8>> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.decrypt_detached(data, &raw_tag))
    }

    fn symmetric_state_ratchet(
        &mut self,
        state: wasmtime::component::Resource<SymmetricState>,
    ) -> CryptoResult<()> {
        let symmetric_state = self.table.get(&state)?;
        symmetric_state.locked(|mut state| state.ratchet())?;
        Ok(())
    }

    fn symmetric_tag_len(
        &mut self,
        symmetric_tag: wasmtime::component::Resource<SymmetricTag>,
    ) -> CryptoResult<Size> {
        let symmetric_tag = self.table.get(&symmetric_tag)?;
        Ok(symmetric_tag.as_ref().len() as u32)
    }

    fn symmetric_tag_pull(
        &mut self,
        symmetric_tag: wasmtime::component::Resource<SymmetricTag>,
    ) -> CryptoResult<Vec<u8>> {
        let symmetric_tag: SymmetricTag = self.table.delete(symmetric_tag)?;
        let out = symmetric_tag.as_ref().to_vec();
        Ok(out)
    }

    fn symmetric_tag_verify(
        &mut self,
        symmetric_tag: wasmtime::component::Resource<SymmetricTag>,
        expected_raw_tag: Vec<u8>,
    ) -> CryptoResult<()> {
        let symmetric_tag = self.table.get(&symmetric_tag)?;
        symmetric_tag.verify(&expected_raw_tag)?;
        Ok(())
    }
}
