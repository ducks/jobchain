use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;

use jobchain_core::amendment::{
    amend_credential, content_hash, hashable_bytes, verify_chain, Amendment,
};
use jobchain_core::credential::VerifiableCredential;
use jobchain_core::did::domain_to_did;
use jobchain_core::signing::Keypair;

#[derive(Debug, Args)]
pub struct AmendArgs {
    /// Path to the signed credential JSON file being amended
    #[arg(long)]
    pub credential: PathBuf,

    /// Path to a JSON file containing changed fields. If omitted, read from stdin.
    #[arg(long)]
    pub patch: Option<PathBuf>,

    /// Issuer domain (e.g., "example.com")
    #[arg(long)]
    pub domain: String,

    /// ISO 8601 date when the change takes effect (defaults to today)
    #[arg(long)]
    pub effective_date: Option<String>,

    /// Write signed amendment JSON to this file instead of stdout
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Override the default key directory (~/.jobchain/)
    #[arg(long)]
    pub key_dir: Option<PathBuf>,

    /// Prior amendment files in chain order (oldest first) for multi-amendment chains
    #[arg(long)]
    pub chain: Vec<PathBuf>,
}

pub fn run(args: AmendArgs) -> Result<()> {
    // a. Read the base credential
    let cred_str = std::fs::read_to_string(&args.credential).with_context(|| {
        format!(
            "Failed to read credential at {}",
            args.credential.display()
        )
    })?;
    let credential: VerifiableCredential = serde_json::from_str(&cred_str).with_context(|| {
        format!(
            "Failed to parse credential at {}. Expected a signed W3C Verifiable Credential JSON.",
            args.credential.display()
        )
    })?;
    if credential.proof.is_none() {
        bail!(
            "Credential at {} is unsigned. Only signed credentials can be amended (the content hash covers the proof block).",
            args.credential.display()
        );
    }

    // b. Read the patch (changed fields)
    let patch_str = match &args.patch {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read patch file {}", path.display()))?,
        None => {
            if std::io::stdin().is_terminal() {
                eprintln!(
                    "Reading amendment patch from stdin (paste JSON, then Ctrl+D)..."
                );
            }
            std::io::read_to_string(std::io::stdin()).context("failed to read from stdin")?
        }
    };
    let changes: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&patch_str)
        .context(
            "Failed to parse patch. Expected a flat JSON object with changed fields, \
             e.g. {\"title\": \"Senior Engineer\", \"end\": \"2025-12\"}.",
        )?;
    if changes.is_empty() {
        bail!("Patch is empty. An amendment must change at least one field.");
    }

    // c. Load the issuer keypair
    let base = match &args.key_dir {
        Some(dir) => dir.clone(),
        None => dirs::home_dir()
            .context("could not determine home directory")?
            .join(".jobchain"),
    };
    let secret_key_path = base.join(&args.domain).join("secret.key");
    if !secret_key_path.exists() {
        bail!(
            "No keypair found for domain '{}' at {}. Run `jobchain init --domain {}` first.",
            args.domain,
            secret_key_path.display(),
            args.domain,
        );
    }
    let keypair = Keypair::load(&secret_key_path).context("failed to load keypair")?;

    // d. Validate issuer match
    let expected_did = domain_to_did(&args.domain).context("failed to construct DID URI")?;
    if credential.issuer != expected_did {
        bail!(
            "Domain '{}' resolves to issuer '{}' but the credential was issued by '{}'. \
             Amendments must come from the same issuer.",
            args.domain,
            expected_did,
            credential.issuer,
        );
    }

    // e. Determine effective date
    let effective_date = args
        .effective_date
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());

    // f. Build the amendment
    let amendment = if args.chain.is_empty() {
        // Amend directly from the base credential
        amend_credential(&credential, changes, &effective_date, &keypair)
            .context("failed to create amendment")?
    } else {
        // Amend from an existing chain
        let mut amendments = Vec::with_capacity(args.chain.len());
        for path in &args.chain {
            let s = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read amendment file {}", path.display()))?;
            let a: Amendment = serde_json::from_str(&s).with_context(|| {
                format!(
                    "failed to parse amendment at {}",
                    path.display()
                )
            })?;
            if a.proof.is_none() {
                bail!("Amendment at {} is unsigned.", path.display());
            }
            amendments.push(a);
        }

        // Verify chain integrity
        verify_chain(&credential, &amendments).context("Amendment chain is broken")?;

        // Build new amendment from the last in chain
        let last = amendments.last().unwrap();
        let base_bytes =
            hashable_bytes(&credential).context("failed to hash base credential")?;
        let base_hash = content_hash(&base_bytes);

        let mut new_amendment =
            Amendment::from_amendment(last, &base_hash, changes, &effective_date)
                .context("failed to create amendment")?;
        let verification_method = format!("{}#key-1", expected_did);
        new_amendment
            .sign(&keypair, &verification_method)
            .context("failed to sign amendment")?;
        new_amendment
    };

    // g. Serialize to JSON
    let json =
        serde_json::to_string_pretty(&amendment).context("failed to serialize amendment")?;

    // h. Output
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json)
            .with_context(|| format!("failed to write amendment to {}", output_path.display()))?;
        eprintln!("Amendment written to {}", output_path.display());
    } else {
        println!("{json}");
    }

    // Summary to stderr
    let changed_fields: Vec<&String> = amendment.credential_subject.changes.keys().collect();
    let truncated_hash = &amendment.previous_hash[..amendment.previous_hash.len().min(23)];
    eprintln!(
        "Amended credential for {} ({})",
        credential.credential_subject.experience.company,
        credential.credential_subject.experience.title,
    );
    eprintln!("  Issuer:     {expected_did}");
    eprintln!("  Effective:  {effective_date}");
    eprintln!(
        "  Changed:    {}",
        changed_fields
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!("  Linked to:  {truncated_hash}...");

    Ok(())
}
