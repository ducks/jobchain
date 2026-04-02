use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn cmd() -> Command {
    Command::cargo_bin("jobchain").unwrap()
}

fn sample_experience_json() -> &'static str {
    r#"{
  "title": "Infrastructure Engineer",
  "company": "Discourse",
  "start": "2024-03",
  "technologies": ["Ruby", "JavaScript", "Docker"],
  "highlights": ["Led migration to containerized deployment"]
}"#
}

fn init_keypair(tmp: &TempDir, domain: &str) {
    cmd()
        .args([
            "init",
            "--org",
            "TestCorp",
            "--domain",
            domain,
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .assert()
        .success();
}

/// Issue a credential and return its JSON string.
fn issue_credential(tmp: &TempDir, domain: &str) -> String {
    let output = cmd()
        .args([
            "issue",
            "--domain",
            domain,
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(sample_experience_json())
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn test_amend_from_credential() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_json = issue_credential(&tmp, "example.com");
    let cred_path = tmp.path().join("cred.json");
    std::fs::write(&cred_path, &cred_json).unwrap();

    let patch_path = tmp.path().join("patch.json");
    std::fs::write(&patch_path, r#"{"title": "Senior Engineer"}"#).unwrap();

    let output = cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--patch",
            patch_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let amendment: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(amendment["type"][1], "AmendmentCredential");
    assert!(amendment["previousHash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(amendment["proof"]["proofValue"]
        .as_str()
        .unwrap()
        .starts_with('z'));
    assert_eq!(amendment["proof"]["type"], "Ed25519Signature2020");
    assert!(amendment["credentialSubject"]["changes"]
        .as_object()
        .unwrap()
        .contains_key("title"));
}

#[test]
fn test_amend_patch_from_stdin() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_json = issue_credential(&tmp, "example.com");
    let cred_path = tmp.path().join("cred.json");
    std::fs::write(&cred_path, &cred_json).unwrap();

    let output = cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(r#"{"end": "2025-12"}"#)
        .output()
        .unwrap();

    assert!(output.status.success());

    let amendment: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap();
    assert!(amendment["credentialSubject"]["changes"]
        .as_object()
        .unwrap()
        .contains_key("end"));
}

#[test]
fn test_amend_custom_effective_date() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_json = issue_credential(&tmp, "example.com");
    let cred_path = tmp.path().join("cred.json");
    std::fs::write(&cred_path, &cred_json).unwrap();

    let patch_path = tmp.path().join("patch.json");
    std::fs::write(&patch_path, r#"{"title": "Senior Engineer"}"#).unwrap();

    let output = cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--patch",
            patch_path.to_str().unwrap(),
            "--effective-date",
            "2025-06-01",
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let amendment: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(amendment["effectiveDate"], "2025-06-01");
}

#[test]
fn test_amend_default_effective_date() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_json = issue_credential(&tmp, "example.com");
    let cred_path = tmp.path().join("cred.json");
    std::fs::write(&cred_path, &cred_json).unwrap();

    let output = cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(r#"{"title": "Senior"}"#)
        .output()
        .unwrap();

    assert!(output.status.success());

    let amendment: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    assert_eq!(amendment["effectiveDate"].as_str().unwrap(), today);
}

#[test]
fn test_amend_output_to_file() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_json = issue_credential(&tmp, "example.com");
    let cred_path = tmp.path().join("cred.json");
    std::fs::write(&cred_path, &cred_json).unwrap();

    let patch_path = tmp.path().join("patch.json");
    std::fs::write(&patch_path, r#"{"title": "Senior Engineer"}"#).unwrap();

    let output_path = tmp.path().join("amendment.json");

    cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--patch",
            patch_path.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Amendment written to"));

    assert!(output_path.exists());

    let content = std::fs::read_to_string(&output_path).unwrap();
    let amendment: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(amendment["proof"].is_object());
}

#[test]
fn test_amend_chain_integrity() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_json = issue_credential(&tmp, "example.com");
    let cred_path = tmp.path().join("cred.json");
    std::fs::write(&cred_path, &cred_json).unwrap();

    // First amendment
    let output1 = cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(r#"{"title": "Senior Engineer"}"#)
        .output()
        .unwrap();
    assert!(output1.status.success());

    let amend1_path = tmp.path().join("amend1.json");
    std::fs::write(&amend1_path, &output1.stdout).unwrap();

    // Second amendment using --chain
    let output2 = cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--chain",
            amend1_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(r#"{"end": "2025-12"}"#)
        .output()
        .unwrap();
    assert!(output2.status.success());

    let amend2: serde_json::Value =
        serde_json::from_slice(&output2.stdout).unwrap();

    // The second amendment should have originalCredential pointing to the base
    let amend1: serde_json::Value =
        serde_json::from_slice(&output1.stdout).unwrap();
    assert_eq!(
        amend2["credentialSubject"]["originalCredential"],
        amend1["credentialSubject"]["originalCredential"]
    );

    // previousHash of amend2 should NOT equal previousHash of amend1 (they link to different predecessors)
    assert_ne!(amend2["previousHash"], amend1["previousHash"]);
}

#[test]
fn test_amend_chain_verification_catches_broken_link() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_json = issue_credential(&tmp, "example.com");
    let cred_path = tmp.path().join("cred.json");
    std::fs::write(&cred_path, &cred_json).unwrap();

    // Create a valid amendment
    let output1 = cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(r#"{"title": "Senior Engineer"}"#)
        .output()
        .unwrap();
    assert!(output1.status.success());

    // Tamper with the amendment's previousHash
    let mut amend1: serde_json::Value =
        serde_json::from_slice(&output1.stdout).unwrap();
    amend1["previousHash"] = serde_json::Value::String("sha256:deadbeef".to_string());
    let amend1_path = tmp.path().join("amend1_tampered.json");
    std::fs::write(
        &amend1_path,
        serde_json::to_string_pretty(&amend1).unwrap(),
    )
    .unwrap();

    // Try to extend the broken chain
    cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--chain",
            amend1_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(r#"{"end": "2025-12"}"#)
        .assert()
        .failure()
        .stderr(predicate::str::contains("chain is broken"));
}

#[test]
fn test_amend_issuer_mismatch() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");
    init_keypair(&tmp, "other.com");

    let cred_json = issue_credential(&tmp, "example.com");
    let cred_path = tmp.path().join("cred.json");
    std::fs::write(&cred_path, &cred_json).unwrap();

    let patch_path = tmp.path().join("patch.json");
    std::fs::write(&patch_path, r#"{"title": "Senior Engineer"}"#).unwrap();

    cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--patch",
            patch_path.to_str().unwrap(),
            "--domain",
            "other.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("issuer"));
}

#[test]
fn test_amend_unsigned_credential() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    // Create an unsigned credential manually
    let unsigned = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "EmploymentCredential"],
        "issuer": "did:web:example.com",
        "issuanceDate": "2025-01-01",
        "credentialSubject": {
            "type": "EmploymentRecord",
            "title": "Engineer",
            "company": "Acme"
        }
    });
    let cred_path = tmp.path().join("unsigned.json");
    std::fs::write(
        &cred_path,
        serde_json::to_string_pretty(&unsigned).unwrap(),
    )
    .unwrap();

    let patch_path = tmp.path().join("patch.json");
    std::fs::write(&patch_path, r#"{"title": "Senior"}"#).unwrap();

    cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--patch",
            patch_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsigned"));
}

#[test]
fn test_amend_empty_patch() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_json = issue_credential(&tmp, "example.com");
    let cred_path = tmp.path().join("cred.json");
    std::fs::write(&cred_path, &cred_json).unwrap();

    cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin("{}")
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty").or(predicate::str::contains("at least one field")));
}

#[test]
fn test_amend_missing_keypair() {
    let tmp = TempDir::new().unwrap();

    // Create a fake credential file
    let cred_path = tmp.path().join("cred.json");
    let fake_cred = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "issuer": "did:web:example.com",
        "issuanceDate": "2025-01-01",
        "credentialSubject": { "type": "EmploymentRecord", "title": "Eng", "company": "X" },
        "proof": { "type": "Ed25519Signature2020", "verificationMethod": "did:web:example.com#key-1", "proofValue": "zFake", "created": "2025-01-01T00:00:00Z" }
    });
    std::fs::write(&cred_path, serde_json::to_string(&fake_cred).unwrap()).unwrap();

    cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(r#"{"title": "Senior"}"#)
        .assert()
        .failure()
        .stderr(predicate::str::contains("No keypair found"))
        .stderr(predicate::str::contains("jobchain init"));
}

#[test]
fn test_amend_roundtrip_verifiable() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_json = issue_credential(&tmp, "example.com");
    let cred_path = tmp.path().join("cred.json");
    std::fs::write(&cred_path, &cred_json).unwrap();

    let output = cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(r#"{"title": "Senior Engineer"}"#)
        .output()
        .unwrap();
    assert!(output.status.success());

    let amendment: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap();

    // Verify the Ed25519 signature manually
    let proof_value = amendment["proof"]["proofValue"].as_str().unwrap();
    let sig_bytes = bs58::decode(&proof_value[1..]).into_vec().unwrap();
    assert_eq!(sig_bytes.len(), 64);

    // Build the signing payload: remove proof, sort keys, compact JSON
    let mut payload_value = amendment.clone();
    payload_value.as_object_mut().unwrap().remove("proof");
    let canonical = canonicalize(&payload_value);
    let payload = serde_json::to_vec(&canonical).unwrap();

    // Load the public key and verify
    let pk_bytes = std::fs::read(tmp.path().join("example.com/public.key")).unwrap();
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap()).unwrap();

    use ed25519_dalek::Verifier;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());
    verifying_key.verify(&payload, &signature).unwrap();

    // Verify chain link: previousHash matches content hash of credential
    let cred: serde_json::Value = serde_json::from_str(&cred_json).unwrap();
    let cred_canonical = canonicalize(&cred);
    let cred_bytes = serde_json::to_vec(&cred_canonical).unwrap();
    let expected_hash = format!(
        "sha256:{}",
        sha2_digest(&cred_bytes)
    );
    assert_eq!(amendment["previousHash"].as_str().unwrap(), expected_hash);
}

#[test]
fn test_amend_then_verify() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let cred_json = issue_credential(&tmp, "example.com");
    let cred_path = tmp.path().join("cred.json");
    std::fs::write(&cred_path, &cred_json).unwrap();

    // Amend the credential
    let amend_output = cmd()
        .args([
            "amend",
            "--credential",
            cred_path.to_str().unwrap(),
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(r#"{"title": "Senior Engineer"}"#)
        .output()
        .unwrap();
    assert!(amend_output.status.success());

    let amend_path = tmp.path().join("amendment.json");
    std::fs::write(&amend_path, &amend_output.stdout).unwrap();

    // Verify the amendment using `jobchain verify`
    let pk_path = tmp.path().join("example.com/public.key");
    cmd()
        .args([
            "verify",
            "--input",
            amend_path.to_str().unwrap(),
            "--key",
            pk_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

/// Recursively sort all object keys.
fn canonicalize(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize(v)))
                .collect();
            serde_json::to_value(sorted).unwrap()
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize).collect())
        }
        other => other.clone(),
    }
}

/// Compute SHA-256 digest as hex string.
fn sha2_digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
