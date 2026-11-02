use crate::{
    bindings::wasi::crypto::common::{ArrayOutput, CryptoErrno, Host, HostArrayOutput, Size},
    error::{CryptoError, CryptoResult},
};
use wasmtime::component::Resource;

impl HostArrayOutput for crate::crypto::WasiCryptoCtxView<'_> {
    fn len(&mut self, self_: Resource<ArrayOutput>) -> CryptoResult<Size> {
        let array_output = self.table.get(&self_)?;
        Ok(array_output.len() as u32)
    }

    fn pull(&mut self, this: Resource<ArrayOutput>) -> CryptoResult<Vec<u8>> {
        // `pull` takes an owned handle, so it consumes the array output.
        let array_output_value: ArrayOutput = self.table.delete(this)?;
        let len = array_output_value.len();
        let mut output = vec![0u8; len];
        array_output_value.pull(&mut output)?;
        Ok(output)
    }

    fn drop(&mut self, rep: Resource<ArrayOutput>) -> wasmtime::Result<()> {
        // The ArrayOutput's Drop impl will zeroize the underlying data for security.
        let _: ArrayOutput = self.table.delete(rep)?;
        Ok(())
    }
}

impl Host for crate::crypto::WasiCryptoCtxView<'_> {
    fn convert_crypto_errno(&mut self, err: CryptoError) -> wasmtime::Result<CryptoErrno> {
        err.downcast()
    }
}
