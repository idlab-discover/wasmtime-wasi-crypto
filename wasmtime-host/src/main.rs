use std::error::Error;
use wasmtime::{Engine, Store, component::Component, component::Linker, error::Context};
use wasmtime_wasi::p2::bindings::Command;
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

struct HostState {
    table: ResourceTable,
    wasi_ctx: WasiCtx,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.table,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    // https://docs.wasmtime.dev/api/wasmtime_wasi/p2/bindings/index.html
    let engine = Engine::default();
    let mut linker: Linker<HostState> = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    // https://docs.wasmtime.dev/api/wasmtime_wasi/p2/bindings/struct.Command.html
    let mut wasi_ctx_builder = WasiCtxBuilder::new();
    wasi_ctx_builder
        .inherit_stdio()
        .inherit_env()
        .inherit_args();

    let state = HostState {
        table: ResourceTable::new(),
        wasi_ctx: wasi_ctx_builder.build(),
    };

    let mut store = Store::new(&engine, state);

    let component = "temp";
    let component =
        Component::from_file(&engine, component).context("Failed to load WebAssembly component")?;

    let command = Command::instantiate_async(&mut store, &component, &linker).await?;
    let _ = command.wasi_cli_run().call_run(&mut store).await?;

    Ok(())
}
