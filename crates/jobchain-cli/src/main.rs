mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "jobchain", version, about = "Verifiable employment credential toolchain")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new jobchain identity (keypair + DID document)
    Init(commands::init::InitArgs),
    /// Issue a signed Verifiable Credential from a jobl ExperienceItem
    Issue(commands::issue::IssueArgs),
    /// Amend an existing signed credential with changed fields
    Amend(commands::amend::AmendArgs),
    /// Verify a signed Verifiable Credential
    Verify(commands::verify::VerifyArgs),
    /// Build and manage a static credential wallet site
    Wallet(commands::wallet::WalletArgs),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init(args) => commands::init::run(args),
        Commands::Issue(args) => commands::issue::run(args),
        Commands::Amend(args) => commands::amend::run(args),
        Commands::Verify(args) => commands::verify::run(args),
        Commands::Wallet(args) => commands::wallet::run(args),
    }
}
