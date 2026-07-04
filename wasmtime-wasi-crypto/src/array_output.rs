use crate::{
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno, error::CryptoResult,
};
use std::io::{Cursor, Read};
use wasmtime_wasi::ResourceTable;
use zeroize::Zeroize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArrayOutput(Cursor<Vec<u8>>);

impl ArrayOutput {
    pub(crate) fn len(&self) -> usize {
        self.0.get_ref().len()
    }

    pub(crate) fn pull(&self, buf: &mut [u8]) -> CryptoResult<usize> {
        let data = self.0.get_ref();
        let data_len = data.len();
        let buf_len = buf.len();
        if buf_len < data_len {
            return Err(CryptoErrno::Overflow.into());
        }
        buf[..data_len].copy_from_slice(data);
        Ok(data_len)
    }

    pub fn new(data: Vec<u8>) -> Self {
        ArrayOutput(Cursor::new(data))
    }

    pub(crate) fn register(
        table: &mut ResourceTable,
        data: Vec<u8>,
    ) -> CryptoResult<wasmtime::component::Resource<ArrayOutput>> {
        let array_output = ArrayOutput::new(data);

        let handle = table
            .push(array_output)
            .map_err(|_| CryptoErrno::InternalError)?;

        Ok(handle)
    }
}

impl Read for ArrayOutput {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.0.read(buf)
    }
}

impl Drop for ArrayOutput {
    fn drop(&mut self) {
        self.0.get_mut().zeroize()
    }
}
