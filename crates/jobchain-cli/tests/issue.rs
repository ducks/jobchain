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

/// Run `jobchain init` in a tempdir and return the tempdir.
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

#[test]
fn test_issue_from_file() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let input_file = tmp.path().join("experience.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    let output = cmd()
        .args([
            "issue",
            "--domain",
            "example.com",
            "--input",
            input_file.to_str().unwrap(),
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let vc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(vc["issuer"], "did:web:example.com");
    assert_eq!(vc["type"][0], "VerifiableCredential");
    assert_eq!(vc["type"][1], "EmploymentCredential");
    assert_eq!(vc["credentialSubject"]["company"], "Discourse");
    assert_eq!(vc["credentialSubject"]["title"], "Infrastructure Engineer");

    let proof = &vc["proof"];
    assert_eq!(proof["type"], "Ed25519Signature2020");
    assert_eq!(proof["verificationMethod"], "did:web:example.com#key-1");
    assert!(proof["proofValue"].as_str().unwrap().starts_with('z'));
}

#[test]
fn test_issue_from_stdin() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let output = cmd()
        .args([
            "issue",
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin(sample_experience_json())
        .output()
        .unwrap();

    assert!(output.status.success());

    let vc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(vc["issuer"], "did:web:example.com");
    assert_eq!(vc["credentialSubject"]["company"], "Discourse");
    assert!(vc["proof"]["proofValue"].as_str().unwrap().starts_with('z'));
}

#[test]
fn test_issue_custom_date() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let input_file = tmp.path().join("exp.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    let output = cmd()
        .args([
            "issue",
            "--domain",
            "example.com",
            "--input",
            input_file.to_str().unwrap(),
            "--date",
            "2024-06-01",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let vc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(vc["issuanceDate"], "2024-06-01");
}

#[test]
fn test_issue_default_date() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let input_file = tmp.path().join("exp.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    let output = cmd()
        .args([
            "issue",
            "--domain",
            "example.com",
            "--input",
            input_file.to_str().unwrap(),
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let vc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    assert_eq!(vc["issuanceDate"].as_str().unwrap(), today);
}

#[test]
fn test_issue_output_to_file() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let input_file = tmp.path().join("exp.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    let output_file = tmp.path().join("cred.json");

    cmd()
        .args([
            "issue",
            "--domain",
            "example.com",
            "--input",
            input_file.to_str().unwrap(),
            "--output",
            output_file.to_str().unwrap(),
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Credential written to"));

    assert!(output_file.exists());

    let content = std::fs::read_to_string(&output_file).unwrap();
    let vc: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(vc["issuer"], "did:web:example.com");
    assert!(vc["proof"].is_object());
}

#[test]
fn test_issue_missing_keypair() {
    let tmp = TempDir::new().unwrap();

    let input_file = tmp.path().join("exp.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    cmd()
        .args([
            "issue",
            "--domain",
            "example.com",
            "--input",
            input_file.to_str().unwrap(),
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("No keypair found"))
        .stderr(predicate::str::contains("jobchain init"));
}

#[test]
fn test_issue_invalid_json() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    cmd()
        .args([
            "issue",
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .write_stdin("not valid json {{{")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to parse"));
}

#[test]
fn test_issue_roundtrip_verifiable() {
    let tmp = TempDir::new().unwrap();
    init_keypair(&tmp, "example.com");

    let input_file = tmp.path().join("exp.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    // Issue a credential
    let output = cmd()
        .args([
            "issue",
            "--domain",
            "example.com",
            "--input",
            input_file.to_str().unwrap(),
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let vc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    // Extract proof and reconstruct signing payload (proof-stripped, canonicalized)
    let proof_value = vc["proof"]["proofValue"].as_str().unwrap();
    let sig_bytes = bs58::decode(&proof_value[1..]).into_vec().unwrap();
    assert_eq!(sig_bytes.len(), 64);

    // Build the signing payload: remove proof, sort keys, compact JSON
    let mut payload_value = vc.clone();
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
}

/// Recursively sort all object keys (same as core's canonicalize).
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
