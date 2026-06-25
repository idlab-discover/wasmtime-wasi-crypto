mod host;
mod runner;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "wasmtime host with wasi-crypto support")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a wasm component directly
    Run {
        /// Path to the .wasm component
        component: std::path::PathBuf,

        /// Arguments forwarded to the component as WASI argv
        #[arg(last = true)]
        args: Vec<String>,
    },

    /// Run all tests in a wasm test binary, each in an isolated instance
    Test {
        /// Path to the .wasm test binary
        component: std::path::PathBuf,

        /// Arguments forwarded to the test runner (e.g., filters, --ignored)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { component, args } => {
            let wasi_args: Vec<&str> = args.iter().map(String::as_str).collect();
            host::run_component(&component, &wasi_args).await?;
        }

        Commands::Test { component, args } => {
            runner::run_each(&component, args).await?;
        }
    }

    Ok(())
}
