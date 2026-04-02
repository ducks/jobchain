use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;

use jobchain_core::did::{did_document_to_json, generate_did_document};
use jobchain_core::signing::Keypair;

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Organization name (e.g., "Discourse")
    #[arg(long)]
    pub org: String,

    /// Domain for did:web resolution (e.g., "discourse.org")
    #[arg(long)]
    pub domain: String,

    /// Write DID document to this file instead of stdout
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Overwrite existing keypair for this domain
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Override the default key directory (~/.jobchain/)
    #[arg(long)]
    pub key_dir: Option<PathBuf>,
}

pub fn run(args: InitArgs) -> Result<()> {
    let base = match args.key_dir {
        Some(dir) => dir,
        None => dirs::home_dir()
            .context("could not determine home directory")?
            .join(".jobchain"),
    };

    let domain_dir = base.join(&args.domain);
    let secret_key_path = domain_dir.join("secret.key");
    let public_key_path = domain_dir.join("public.key");

    // Check for existing keys
    if secret_key_path.exists() && !args.force {
        bail!(
            "Keypair already exists for {} at {}. Use --force to overwrite.",
            args.domain,
            domain_dir.display()
        );
    }

    // Create directory
    std::fs::create_dir_all(&domain_dir)
        .with_context(|| format!("failed to create directory {}", domain_dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&domain_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    // Generate keypair
    let keypair = Keypair::generate().context("failed to generate keypair")?;

    // Save keys
    keypair
        .save(&secret_key_path)
        .context("failed to save secret key")?;
    keypair
        .save_public_key(&public_key_path)
        .context("failed to save public key")?;

    eprintln!("Keypair written to {}", domain_dir.display());

    // Generate DID document
    let doc = generate_did_document(&args.domain, &keypair.public_key_bytes())
        .context("failed to generate DID document")?;
    let json = did_document_to_json(&doc).context("failed to serialize DID document")?;

    // Output DID document
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json)
            .with_context(|| format!("failed to write DID document to {}", output_path.display()))?;
        eprintln!("DID document written to {}", output_path.display());
    } else {
        println!("{json}");
    }

    // Summary to stderr
    let did = jobchain_core::did::domain_to_did(&args.domain)
        .context("failed to compute DID URI")?;
    eprintln!("Initialized jobchain identity for {}", args.org);
    eprintln!("  DID: {did}");
    eprintln!("  Keys: {}/", domain_dir.display());
    eprintln!(
        "  Next: host the DID document at https://{}/.well-known/did.json",
        args.domain
    );

    Ok(())
}
