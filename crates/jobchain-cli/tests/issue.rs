use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn jobchain() -> Command {
    Command::cargo_bin("jobchain").unwrap()
}

fn sample_experience_json() -> &'static str {
    r#"{
        "title": "Software Engineer",
        "company": "Discourse",
        "location": "Remote",
        "start": "2022-01-15",
        "summary": "Infrastructure team",
        "technologies": ["Ruby", "JavaScript"],
        "highlights": ["Built deployment pipeline"]
    }"#
}

/// Initialize a keypair in the given directory, returning the domain dir path.
fn init_identity(tmp: &TempDir, domain: &str) -> std::path::PathBuf {
    let dir = tmp.path().join(domain);
    jobchain()
        .args(["init", "--domain", domain, "--output-dir"])
        .arg(dir.as_os_str())
        .assert()
        .success();
    dir
}

#[test]
fn issue_from_file_input() {
    let tmp = TempDir::new().unwrap();
    let key_dir = init_identity(&tmp, "example.com");

    let input_file = tmp.path().join("experience.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    jobchain()
        .args(["issue", "--domain", "example.com", "--key-dir"])
        .arg(key_dir.as_os_str())
        .arg("--input")
        .arg(input_file.as_os_str())
        .arg("--date")
        .arg("2025-06-01T00:00:00Z")
        .assert()
        .success()
        .stdout(predicate::str::contains("VerifiableCredential"))
        .stdout(predicate::str::contains("did:web:example.com"))
        .stdout(predicate::str::contains("2025-06-01T00:00:00Z"));
}

#[test]
fn issue_from_stdin_pipe() {
    let tmp = TempDir::new().unwrap();
    let key_dir = init_identity(&tmp, "example.com");

    jobchain()
        .args(["issue", "--domain", "example.com", "--key-dir"])
        .arg(key_dir.as_os_str())
        .arg("--date")
        .arg("2025-06-01T00:00:00Z")
        .write_stdin(sample_experience_json())
        .assert()
        .success()
        .stdout(predicate::str::contains("VerifiableCredential"));
}

#[test]
fn issue_with_custom_date() {
    let tmp = TempDir::new().unwrap();
    let key_dir = init_identity(&tmp, "example.com");

    let input_file = tmp.path().join("experience.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    let output = jobchain()
        .args(["issue", "--domain", "example.com", "--key-dir"])
        .arg(key_dir.as_os_str())
        .arg("--input")
        .arg(input_file.as_os_str())
        .arg("--date")
        .arg("2024-12-25T12:00:00Z")
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let vc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(vc["issuanceDate"], "2024-12-25T12:00:00Z");
}

#[test]
fn issue_default_date_is_now() {
    let tmp = TempDir::new().unwrap();
    let key_dir = init_identity(&tmp, "example.com");

    let input_file = tmp.path().join("experience.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    let output = jobchain()
        .args(["issue", "--domain", "example.com", "--key-dir"])
        .arg(key_dir.as_os_str())
        .arg("--input")
        .arg(input_file.as_os_str())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let vc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let date = vc["issuanceDate"].as_str().unwrap();
    // Should be a valid RFC 3339 date from today
    assert!(date.starts_with(&chrono::Utc::now().format("%Y").to_string()));
}

#[test]
fn issue_output_to_file() {
    let tmp = TempDir::new().unwrap();
    let key_dir = init_identity(&tmp, "example.com");

    let input_file = tmp.path().join("experience.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    let output_file = tmp.path().join("credential.json");

    jobchain()
        .args(["issue", "--domain", "example.com", "--key-dir"])
        .arg(key_dir.as_os_str())
        .arg("--input")
        .arg(input_file.as_os_str())
        .arg("--output")
        .arg(output_file.as_os_str())
        .arg("--date")
        .arg("2025-06-01T00:00:00Z")
        .assert()
        .success()
        .stderr(predicate::str::contains("Credential written to"));

    let contents = std::fs::read_to_string(&output_file).unwrap();
    let vc: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(vc["issuer"], "did:web:example.com");
}

#[test]
fn issue_missing_keypair() {
    let tmp = TempDir::new().unwrap();
    let nonexistent = tmp.path().join("nope");

    let input_file = tmp.path().join("experience.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    jobchain()
        .args(["issue", "--domain", "example.com", "--key-dir"])
        .arg(nonexistent.as_os_str())
        .arg("--input")
        .arg(input_file.as_os_str())
        .assert()
        .failure()
        .stderr(predicate::str::contains("keypair not found"));
}

#[test]
fn issue_invalid_json() {
    let tmp = TempDir::new().unwrap();
    let key_dir = init_identity(&tmp, "example.com");

    let input_file = tmp.path().join("bad.json");
    std::fs::write(&input_file, "not json at all").unwrap();

    jobchain()
        .args(["issue", "--domain", "example.com", "--key-dir"])
        .arg(key_dir.as_os_str())
        .arg("--input")
        .arg(input_file.as_os_str())
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to parse ExperienceItem JSON"));
}

#[test]
fn issue_sign_then_verify_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let key_dir = init_identity(&tmp, "example.com");

    let input_file = tmp.path().join("experience.json");
    std::fs::write(&input_file, sample_experience_json()).unwrap();

    let output = jobchain()
        .args(["issue", "--domain", "example.com", "--key-dir"])
        .arg(key_dir.as_os_str())
        .arg("--input")
        .arg(input_file.as_os_str())
        .arg("--date")
        .arg("2025-06-01T00:00:00Z")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let vc: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    // Extract the proof value and verify the signature manually
    let proof_value = vc["proof"]["proofValue"].as_str().unwrap();
    assert!(proof_value.starts_with("z"), "proof value should be multibase z-encoded");

    // Decode the signature from multibase z-base58btc
    let sig_bytes = bs58::decode(&proof_value[1..]).into_vec().unwrap();
    assert_eq!(sig_bytes.len(), 64, "Ed25519 signature should be 64 bytes");

    // Load the public key and verify
    let pub_key_bytes = std::fs::read(key_dir.join("public.key")).unwrap();
    let pub_key = ed25519_dalek::VerifyingKey::from_bytes(
        &pub_key_bytes.try_into().expect("32-byte public key"),
    )
    .unwrap();

    // Reconstruct the signing payload (VC without proof)
    let mut vc_no_proof = vc.clone();
    vc_no_proof.as_object_mut().unwrap().remove("proof");
    let payload = serde_json::to_vec(&vc_no_proof).unwrap();

    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().expect("64-byte sig"));
    pub_key.verify_strict(&payload, &sig).expect("signature should verify");
}
