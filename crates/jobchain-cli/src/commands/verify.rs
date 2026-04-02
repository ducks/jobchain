use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Args;

use jobchain_core::amendment::Amendment;
use jobchain_core::credential::VerifiableCredential;

enum ParsedDocument {
    Credential(VerifiableCredential),
    Amendment(Amendment),
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Path to a signed credential JSON file. If omitted, read from stdin.
    #[arg(long)]
    pub input: Option<PathBuf>,

    /// Path to a raw 32-byte Ed25519 public key file (skip DID resolution)
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Require --key and refuse network access
    #[arg(long, default_value_t = false)]
    pub offline: bool,

    /// Output result as JSON instead of human-readable text
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: VerifyArgs) -> Result<()> {
    // Read credential input
    let json_str = match &args.input {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read input file {}", path.display()))?,
        None => {
            if std::io::stdin().is_terminal() {
                eprintln!("Reading credential from stdin (paste JSON, then Ctrl+D)...");
            }
            std::io::read_to_string(std::io::stdin()).context("failed to read from stdin")?
        }
    };

    // Try parsing as VerifiableCredential first, then as Amendment
    let parsed = if let Ok(credential) = serde_json::from_str::<VerifiableCredential>(&json_str) {
        ParsedDocument::Credential(credential)
    } else if let Ok(amendment) = serde_json::from_str::<Amendment>(&json_str) {
        ParsedDocument::Amendment(amendment)
    } else {
        bail!(
            "Failed to parse input as a VerifiableCredential or Amendment. \
             Expected a signed W3C Verifiable Credential or Amendment JSON."
        );
    };

    let (issuer, proof_ref) = match &parsed {
        ParsedDocument::Credential(vc) => (&vc.issuer, &vc.proof),
        ParsedDocument::Amendment(a) => (&a.issuer, &a.proof),
    };

    let proof = match proof_ref {
        Some(p) => p,
        None => match &parsed {
            ParsedDocument::Credential(vc) => {
                return report_failure(
                    &args,
                    vc,
                    "Credential has no proof block — it is unsigned.",
                );
            }
            ParsedDocument::Amendment(_) => {
                bail!("Amendment has no proof block — it is unsigned.");
            }
        },
    };

    // Obtain public key
    let public_key: [u8; 32] = if let Some(key_path) = &args.key {
        let bytes = std::fs::read(key_path)
            .with_context(|| format!("failed to read public key file {}", key_path.display()))?;
        if bytes.len() != 32 {
            bail!(
                "Public key file must be exactly 32 bytes, got {}.",
                bytes.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        eprintln!("Using local key: {}", key_path.display());
        key
    } else if args.offline {
        bail!("--offline requires --key <path> to supply the public key directly.");
    } else {
        // Online DID resolution
        eprintln!("Resolving issuer DID: {issuer}");
        let verification_method_id = proof.verification_method.clone();
        let doc = jobchain_core::did::resolve_did_web_blocking(issuer).map_err(|e| {
            anyhow::anyhow!(
                "Failed to resolve DID {issuer}: {e}. Use --key to verify with a local public key instead."
            )
        })?;

        // Try by key ID first, fall back to first Ed25519 key
        match jobchain_core::did::extract_verification_key_by_id(&doc, &verification_method_id) {
            Ok(key) => key,
            Err(_) => jobchain_core::did::extract_verification_key(&doc).map_err(|_| {
                anyhow::anyhow!(
                    "No Ed25519 verification key found in DID document for {issuer}."
                )
            })?,
        }
    };

    // Verify
    match &parsed {
        ParsedDocument::Credential(credential) => {
            match jobchain_verify::verify_credential_full(credential, &public_key, issuer) {
                Ok(()) => report_success(&args, credential),
                Err(e) => report_failure(&args, credential, &e.to_string()),
            }
        }
        ParsedDocument::Amendment(amendment) => {
            match jobchain_verify::verify_amendment(amendment, &public_key) {
                Ok(()) => {
                    if args.json {
                        let output = serde_json::json!({
                            "valid": true,
                            "issuer": amendment.issuer,
                            "type": "Amendment",
                            "effectiveDate": amendment.effective_date,
                            "error": null,
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    } else {
                        println!("VALID — amendment signature verified");
                        println!("  Issuer:    {}", amendment.issuer);
                        println!("  Effective: {}", amendment.effective_date);
                    }
                    Ok(())
                }
                Err(e) => {
                    if args.json {
                        let output = serde_json::json!({
                            "valid": false,
                            "issuer": amendment.issuer,
                            "type": "Amendment",
                            "error": e.to_string(),
                        });
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    } else {
                        eprintln!("INVALID — {e}");
                        eprintln!("  Issuer: {}", amendment.issuer);
                    }
                    std::process::exit(1);
                }
            }
        }
    }
}

fn report_success(args: &VerifyArgs, vc: &VerifiableCredential) -> Result<()> {
    let issuer = &vc.issuer;
    let title = &vc.credential_subject.experience.title;
    let company = &vc.credential_subject.experience.company;
    let issuance_date = &vc.issuance_date;
    let proof_created = vc
        .proof
        .as_ref()
        .map(|p| p.created.as_str())
        .unwrap_or("unknown");

    if args.json {
        let output = serde_json::json!({
            "valid": true,
            "issuer": issuer,
            "subject": { "title": title, "company": company },
            "issuanceDate": issuance_date,
            "error": null,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("VALID — credential signature verified");
        println!("  Issuer:  {issuer}");
        println!("  Subject: {title} at {company}");
        println!("  Issued:  {issuance_date}");
        println!("  Signed:  {proof_created}");
    }

    Ok(())
}

fn report_failure(args: &VerifyArgs, vc: &VerifiableCredential, error: &str) -> Result<()> {
    let issuer = &vc.issuer;
    let title = &vc.credential_subject.experience.title;
    let company = &vc.credential_subject.experience.company;
    let issuance_date = &vc.issuance_date;

    if args.json {
        let output = serde_json::json!({
            "valid": false,
            "issuer": issuer,
            "subject": { "title": title, "company": company },
            "issuanceDate": issuance_date,
            "error": error,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        eprintln!("INVALID — {error}");
        eprintln!("  Issuer:  {issuer}");
        eprintln!("  Subject: {title} at {company}");
    }

    std::process::exit(1);
}
