use crate::bindings::wasi::crypto::wasi_ephemeral_crypto_common::CryptoErrno;
use std::io::Cursor;
use wasmtime_wasi::ResourceTable;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArrayOutput(Cursor<Vec<u8>>);

impl ArrayOutput {
    fn len(&self) -> usize {
        self.0.get_ref().len()
    }

    fn pull(&self, buf: &mut [u8]) -> Result<usize, CryptoErrno> {
        let data = self.0.get_ref();
        let data_len = data.len();
        let buf_len = buf.len();
        if buf_len < data_len {
            return Err(CryptoErrno::Overflow);
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
    ) -> Result<wasmtime::component::Resource<ArrayOutput>, CryptoErrno> {
        let array_output = ArrayOutput::new(data);

        let handle = table
            .push(array_output)
            .map_err(|_| CryptoErrno::InternalError)?;

        Ok(handle)
    }
}
