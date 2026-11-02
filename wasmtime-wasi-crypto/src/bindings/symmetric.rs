use crate::bindings::wasi::crypto::common::{ArrayOutput, Size, U64};
use crate::bindings::wasi::crypto::symmetric::{
    Host, HostSymmetricKey, HostSymmetricOptions, HostSymmetricState, HostSymmetricTag,
    SymmetricKey, SymmetricOptions, SymmetricState, SymmetricTag,
};
use crate::error::CryptoResult;
use crate::options::OptionsLike;
use wasmtime::component::Resource;

impl HostSymmetricOptions for crate::crypto::WasiCryptoCtxView<'_> {
    fn new(&mut self) -> wasmtime::Result<Resource<SymmetricOptions>> {
        Ok(self.table.push(SymmetricOptions::default())?)
    }

    fn set(
        &mut self,
        self_: Resource<SymmetricOptions>,
        name: String,
        value: Vec<u8>,
    ) -> CryptoResult<()> {
        self.table.get_mut(&self_)?.set(&name, &value)
    }

    fn set_u64(
        &mut self,
        self_: Resource<SymmetricOptions>,
        name: String,
        value: u64,
    ) -> CryptoResult<()> {
        self.table.get_mut(&self_)?.set_u64(&name, value)
    }

    fn set_guest_buffer(
        &mut self,
        self_: Resource<SymmetricOptions>,
        name: String,
        buffer: Vec<u8>,
    ) -> CryptoResult<()> {
        // A `list<u8>` is a copy, not a buffer in guest memory, so this can
        // only behave like `set`.
        self.set(self_, name, buffer)
    }

    fn drop(&mut self, rep: Resource<SymmetricOptions>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostSymmetricKey for crate::crypto::WasiCryptoCtxView<'_> {
    fn generate(
        &mut self,
        algorithm: String,
        options: Option<Resource<SymmetricOptions>>,
    ) -> CryptoResult<Resource<SymmetricKey>> {
        let options = match options {
            Some(options_handle) => Some(
                self.table.get(&options_handle)?.clone(), // TODO: investigate if this is necessary/valid
            ),
            None => None,
        };

        let symmetric_key = SymmetricKey::generate(&algorithm, options)?;
        let handle = self.table.push(symmetric_key)?;
        Ok(handle)
    }

    fn import(&mut self, algorithm: String, raw: Vec<u8>) -> CryptoResult<Resource<SymmetricKey>> {
        let symmetric_key = SymmetricKey::import(&algorithm, &raw)?;
        let handle = self.table.push(symmetric_key)?;
        Ok(handle)
    }

    fn export(&mut self, self_: Resource<SymmetricKey>) -> CryptoResult<Resource<ArrayOutput>> {
        let symmetric_key = self.table.get(&self_)?;

        let raw = symmetric_key.inner().as_raw()?.to_vec();

        let array_output_handle = ArrayOutput::register(self.table, raw)?;
        Ok(array_output_handle)
    }

    fn drop(&mut self, rep: Resource<SymmetricKey>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostSymmetricState for crate::crypto::WasiCryptoCtxView<'_> {
    fn open(
        &mut self,
        algorithm: String,
        key: Option<Resource<SymmetricKey>>,
        options: Option<Resource<SymmetricOptions>>,
    ) -> CryptoResult<Resource<SymmetricState>> {
        let key = match key {
            None => None,
            Some(symmetric_key_handle) => Some(self.table.get(&symmetric_key_handle)?),
        };
        let options = match options {
            None => None,
            Some(options_handle) => Some(
                self.table.get(&options_handle)?.clone(), // TODO: investigate if this is necessary/valid
            ),
        };
        let symmetric_state = SymmetricState::open(&algorithm, key, options.as_ref(), self.limits)?;
        let handle = self.table.push(symmetric_state)?;
        Ok(handle)
    }

    fn options_get(
        &mut self,
        self_: Resource<SymmetricState>,
        name: String,
    ) -> CryptoResult<Vec<u8>> {
        let symmetric_state = self.table.get(&self_)?;
        let v = symmetric_state.inner().options_get(&name)?;
        // if v_len > value.len() {
        //     return Err(CryptoErrno::Overflow);
        // }
        Ok(v)
    }

    fn options_get_u64(
        &mut self,
        self_: Resource<SymmetricState>,
        name: String,
    ) -> CryptoResult<U64> {
        let symmetric_state = self.table.get(&self_)?;
        let v = symmetric_state.inner().options_get_u64(&name)?;
        Ok(v)
    }

    fn clone(&mut self, self_: Resource<SymmetricState>) -> CryptoResult<Resource<SymmetricState>> {
        let symmetric_state = self.table.get(&self_)?;
        let symmetric_state = symmetric_state.clone();
        let handle = self.table.push(symmetric_state)?;
        Ok(handle)
    }

    fn absorb(&mut self, self_: Resource<SymmetricState>, data: Vec<u8>) -> CryptoResult<()> {
        let symmetric_state = self.table.get(&self_)?;
        symmetric_state.locked(|mut state| state.absorb(&data))?;
        Ok(())
    }

    fn squeeze(&mut self, self_: Resource<SymmetricState>) -> CryptoResult<Vec<u8>> {
        let symmetric_state = self.table.get(&self_)?;
        symmetric_state.locked(|mut state| state.squeeze_unchecked())
    }

    fn squeeze_tag(
        &mut self,
        self_: Resource<SymmetricState>,
    ) -> CryptoResult<Resource<SymmetricTag>> {
        let symmetric_state = self.table.get(&self_)?;
        let tag = symmetric_state.locked(|mut state| state.squeeze_tag())?;
        let handle = self.table.push(tag)?;
        Ok(handle)
    }

    fn squeeze_key(
        &mut self,
        self_: Resource<SymmetricState>,
        alg_str: String,
    ) -> CryptoResult<Resource<SymmetricKey>> {
        let symmetric_state = self.table.get(&self_)?;
        let tag = symmetric_state.locked(|mut state| state.squeeze_key(&alg_str))?;
        let handle = self.table.push(tag)?;
        Ok(handle)
    }

    fn max_tag_len(&mut self, self_: Resource<SymmetricState>) -> CryptoResult<Size> {
        let symmetric_state = self.table.get(&self_)?;
        let max_tag_len = symmetric_state.inner().max_tag_len()?;
        Ok(max_tag_len as u32)
    }

    fn encrypt(&mut self, self_: Resource<SymmetricState>, data: Vec<u8>) -> CryptoResult<Vec<u8>> {
        let symmetric_state = self.table.get(&self_)?;
        symmetric_state.locked(|mut state| state.encrypt(data))
    }

    fn encrypt_detached(
        &mut self,
        self_: Resource<SymmetricState>,
        data: Vec<u8>,
    ) -> CryptoResult<(Vec<u8>, Resource<SymmetricTag>)> {
        let symmetric_state = self.table.get(&self_)?;
        let (out, symmetric_tag) = symmetric_state.inner().encrypt_detached(data)?;
        let handle = self.table.push(symmetric_tag)?;
        Ok((out, handle))
    }

    fn decrypt(
        &mut self,
        self_: Resource<SymmetricState>,
        data: Vec<u8>,
        out_len: u32,
    ) -> CryptoResult<Vec<u8>> {
        let symmetric_state = self.table.get(&self_)?;
        symmetric_state.locked(|mut state| state.decrypt(data, out_len as usize))
    }

    fn decrypt_detached(
        &mut self,
        self_: Resource<SymmetricState>,
        data: Vec<u8>,
        raw_tag: Vec<u8>,
    ) -> CryptoResult<Vec<u8>> {
        let symmetric_state = self.table.get(&self_)?;
        symmetric_state.locked(|mut state| state.decrypt_detached(data, &raw_tag))
    }

    fn ratchet(&mut self, self_: Resource<SymmetricState>) -> CryptoResult<()> {
        let symmetric_state = self.table.get(&self_)?;
        symmetric_state.locked(|mut state| state.ratchet())?;
        Ok(())
    }

    fn drop(&mut self, rep: Resource<SymmetricState>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl HostSymmetricTag for crate::crypto::WasiCryptoCtxView<'_> {
    fn len(&mut self, self_: Resource<SymmetricTag>) -> CryptoResult<Size> {
        let symmetric_tag = self.table.get(&self_)?;
        Ok(symmetric_tag.as_ref().len() as u32)
    }

    fn pull(&mut self, this: Resource<SymmetricTag>) -> CryptoResult<Vec<u8>> {
        // `pull` takes an owned handle, so it consumes the tag.
        let symmetric_tag: SymmetricTag = self.table.delete(this)?;
        let out = symmetric_tag.as_ref().to_vec();
        Ok(out)
    }

    fn verify(
        &mut self,
        self_: Resource<SymmetricTag>,
        expected_raw_tag: Vec<u8>,
    ) -> CryptoResult<()> {
        let symmetric_tag = self.table.get(&self_)?;
        symmetric_tag.verify(&expected_raw_tag)?;
        Ok(())
    }

    fn drop(&mut self, rep: Resource<SymmetricTag>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl Host for crate::crypto::WasiCryptoCtxView<'_> {}
