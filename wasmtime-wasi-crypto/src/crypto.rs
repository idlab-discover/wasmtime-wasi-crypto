use crate::{bindings, limits::Limits};
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

/// Register every `wasi:crypto` interface with the linker.
pub fn add_to_linker<T: WasiCryptoView + Send + 'static>(
    linker: &mut Linker<T>,
) -> wasmtime::Result<()> {
    bindings::wasi::crypto::common::add_to_linker::<T, WasiCrypto>(linker, T::crypto)?;
    bindings::wasi::crypto::secrets_manager::add_to_linker::<T, WasiCrypto>(linker, T::crypto)?;
    bindings::wasi::crypto::symmetric::add_to_linker::<T, WasiCrypto>(linker, T::crypto)?;
    bindings::wasi::crypto::symmetric_managed::add_to_linker::<T, WasiCrypto>(linker, T::crypto)?;
    bindings::wasi::crypto::signatures::add_to_linker::<T, WasiCrypto>(linker, T::crypto)?;
    bindings::wasi::crypto::signatures_managed::add_to_linker::<T, WasiCrypto>(linker, T::crypto)?;
    bindings::wasi::crypto::kx::add_to_linker::<T, WasiCrypto>(linker, T::crypto)?;
    bindings::wasi::crypto::kx_managed::add_to_linker::<T, WasiCrypto>(linker, T::crypto)?;
    bindings::wasi::crypto::external_secrets::add_to_linker::<T, WasiCrypto>(linker, T::crypto)?;
    Ok(())
}
