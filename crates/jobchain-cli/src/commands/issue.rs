use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use jobchain_core::credential::issue_credential;
use jobchain_core::did::domain_to_did;
use jobchain_core::signing::Keypair;

#[derive(Debug, Args)]
pub struct IssueArgs {
    /// Path to a JSON file containing a jobl ExperienceItem. If omitted, read from stdin.
    #[arg(long)]
    pub input: Option<PathBuf>,

    /// Issuer domain (e.g., "discourse.org")
    #[arg(long)]
    pub domain: String,

    /// Issuance date as ISO 8601 (e.g., "2024-03-15"). Defaults to today.
    #[arg(long)]
    pub date: Option<String>,

    /// Write signed credential JSON to this file instead of stdout
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Override the default key directory (~/.jobchain/)
    #[arg(long)]
    pub key_dir: Option<PathBuf>,
}

pub fn run(args: IssueArgs) -> Result<()> {
    // Read input JSON
    let json_str = match &args.input {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read input file {}", path.display()))?,
        None => {
            if std::io::stdin().is_terminal() {
                eprintln!("Reading experience entry from stdin (paste JSON, then Ctrl+D)...");
            }
            std::io::read_to_string(std::io::stdin()).context("failed to read from stdin")?
        }
    };

    let experience: jobl::ExperienceItem = serde_json::from_str(&json_str).context(
        "Failed to parse experience entry. Expected a JSON object with fields: title, company, start, and optionally end, technologies, highlights.",
    )?;

    // Load keypair
    let base = match &args.key_dir {
        Some(dir) => dir.clone(),
        None => dirs::home_dir()
            .context("could not determine home directory")?
            .join(".jobchain"),
    };
    let secret_key_path = base.join(&args.domain).join("secret.key");
    if !secret_key_path.exists() {
        anyhow::bail!(
            "No keypair found for domain '{}' at {}. Run `jobchain init --domain {}` first.",
            args.domain,
            secret_key_path.display(),
            args.domain,
        );
    }
    let keypair = Keypair::load(&secret_key_path).context("failed to load keypair")?;

    // Determine issuance date
    let issuance_date = args
        .date
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());

    // Build DID and issue credential
    let issuer_did = domain_to_did(&args.domain).context("failed to construct DID URI")?;
    let vc = issue_credential(&issuer_did, experience, &issuance_date, &keypair)
        .context("failed to issue credential")?;

    let json = serde_json::to_string_pretty(&vc).context("failed to serialize credential")?;

    // Output
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json)
            .with_context(|| format!("failed to write credential to {}", output_path.display()))?;
        eprintln!("Credential written to {}", output_path.display());
    } else {
        println!("{json}");
    }

    // Summary to stderr
    eprintln!(
        "Issued credential for {} ({})",
        vc.credential_subject.experience.company, vc.credential_subject.experience.title,
    );
    eprintln!("  Issuer: {issuer_did}");
    eprintln!("  Date: {issuance_date}");

    Ok(())
}
