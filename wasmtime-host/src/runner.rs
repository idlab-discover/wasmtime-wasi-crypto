use clap::Parser;
use std::{error::Error, path::Path};
use wasmtime::{Engine, component::Component, error::Context};
use wasmtime_wasi::p2::bindings::Command;

use crate::host::HostState;
use wasmtime_wasi::ResourceTable;
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi_crypto::crypto::WasiCryptoCtx;

use libtest_mimic::{Arguments, Failed, Trial};

/// Retrieve the list of test names from a wasm test binary by running it
/// with `-- --list`. Returns one test name per entry.
pub async fn list_tests(
    engine: &Engine,
    linker: &wasmtime::component::Linker<HostState>,
    component: &Component,
) -> Result<Vec<String>, Box<dyn Error>> {
    let stdout = MemoryOutputPipe::new(usize::MAX);

    let wasi_ctx = WasiCtxBuilder::new()
        .inherit_stderr()
        .stdout(stdout.clone())
        .args(&["--", "--list"])
        .build();

    let mut store = wasmtime::Store::new(
        engine,
        HostState {
            table: ResourceTable::new(),
            wasi_ctx,
            crypto_ctx: WasiCryptoCtx::default(),
        },
    );

    let command = Command::instantiate_async(&mut store, component, linker).await?;
    let _ = command.wasi_cli_run().call_run(&mut store).await;

    let output = String::from_utf8(stdout.contents().to_vec())?;
    let tests = output
        .lines()
        .filter(|l| l.ends_with(": test"))
        .map(|l| l.trim_end_matches(": test").trim().to_string())
        .collect();

    Ok(tests)
}

/// Run all discovered tests using the libtest-mimic harness wrapper
pub async fn run_each(component: &Path, test_args: Vec<String>) -> Result<(), Box<dyn Error>> {
    let engine = Engine::default();
    let linker = crate::host::make_linker(&engine)?;
    let component_obj =
        Component::from_file(&engine, component).context("Failed to load WebAssembly component")?;

    let test_names = list_tests(&engine, &linker, &component_obj).await?;
    let rt_handle = tokio::runtime::Handle::current();

    let trials = test_names
        .into_iter()
        .map(|name| {
            let engine_clone = engine.clone();
            let linker_clone = linker.clone();
            let component_clone = component_obj.clone();
            let test_name = name.clone();
            let rt_handle_clone = rt_handle.clone();

            // Each trial gets its own explicit runner logic closure
            Trial::test(name, move || {
                rt_handle_clone.block_on(async move {
                    let stdout = MemoryOutputPipe::new(usize::MAX);
                    let stderr = MemoryOutputPipe::new(usize::MAX);

                    // Isolate execution inside a spawned task to catch host-side `todo!()` panics cleanly
                    let handle = tokio::spawn(async move {
                        let wasi_ctx = WasiCtxBuilder::new()
                            .stdout(stdout.clone())
                            .stderr(stderr.clone())
                            .inherit_env()
                            .args(&["--", "--exact", &test_name, "--nocapture"])
                            .build();

                        let mut store = wasmtime::Store::new(
                            &engine_clone,
                            HostState {
                                table: ResourceTable::new(),
                                wasi_ctx,
                                crypto_ctx: WasiCryptoCtx::default(),
                            },
                        );

                        match Command::instantiate_async(
                            &mut store,
                            &component_clone,
                            &linker_clone,
                        )
                        .await
                        {
                            Ok(command) => command.wasi_cli_run().call_run(&mut store).await,
                            Err(e) => Err(e),
                        }
                    });

                    match handle.await {
                        Ok(Ok(Ok(()))) => Ok(()),
                        Ok(Ok(Err(()))) => {
                            Err(Failed::from("Test failed inside Wasm guest harness"))
                        }
                        Ok(Err(e)) => Err(Failed::from(format!("Wasmtime engine error: {e:#}"))),
                        Err(join_error) => {
                            if join_error.is_panic() {
                                Err(Failed::from(
                                    "Host implementation feature not yet implemented (todo!())",
                                ))
                            } else {
                                Err(Failed::from("Test execution task was aborted or cancelled"))
                            }
                        }
                    }
                })
            })
        })
        .collect::<Vec<_>>();

    // Combine a dummy binary name with the passed CLI arguments
    let mut mimic_args = vec!["wasmtime-test-runner".to_string()];
    mimic_args.extend(test_args);

    let args = Arguments::parse_from(mimic_args);

    libtest_mimic::run(&args, trials).exit();
}
