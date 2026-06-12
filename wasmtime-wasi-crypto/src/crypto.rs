mod asymmetric_common;
pub mod bindings;
mod common;
mod external_secrets;
mod key_exchange;
mod signatures;
mod symmetric;
use crate::limits::Limits;
use wasmtime::component::{HasData, Linker};
use wasmtime_wasi::ResourceTable;

#[derive(Debug, Default)]
pub struct WasiCryptoCtx {}

pub struct WasiCryptoCtxView<'a> {
    pub ctx: &'a mut WasiCryptoCtx,
    pub table: &'a mut ResourceTable,
    pub limits: &'a mut Limits,
}

pub trait WasiCryptoView {
    fn crypto(&mut self) -> WasiCryptoCtxView<'_>;
}

struct WasiCrypto;

impl HasData for WasiCrypto {
    type Data<'a> = WasiCryptoCtxView<'a>;
}

pub fn add_to_linker<T: WasiCryptoView + Send + 'static>(
    linker: &mut Linker<T>,
) -> wasmtime::Result<()> {
    bindings::wasi::crypto::wasi_ephemeral_crypto_common::add_to_linker::<T, WasiCrypto>(
        linker,
        T::crypto,
    )?;
    bindings::wasi::crypto::wasi_ephemeral_crypto_asymmetric_common::add_to_linker::<T, WasiCrypto>(
        linker,
        T::crypto,
    )?;
    bindings::wasi::crypto::wasi_ephemeral_crypto_external_secrets::add_to_linker::<T, WasiCrypto>(
        linker,
        T::crypto,
    )?;
    bindings::wasi::crypto::wasi_ephemeral_crypto_kx::add_to_linker::<T, WasiCrypto>(
        linker,
        T::crypto,
    )?;
    bindings::wasi::crypto::wasi_ephemeral_crypto_signatures::add_to_linker::<T, WasiCrypto>(
        linker,
        T::crypto,
    )?;
    bindings::wasi::crypto::wasi_ephemeral_crypto_symmetric::add_to_linker::<T, WasiCrypto>(
        linker,
        T::crypto,
    )?;
    Ok(())
}
