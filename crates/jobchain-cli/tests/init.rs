use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn cmd() -> Command {
    Command::cargo_bin("jobchain").unwrap()
}

#[test]
fn test_init_creates_keypair() {
    let tmp = TempDir::new().unwrap();
    let key_dir = tmp.path();

    cmd()
        .args([
            "init",
            "--org",
            "TestCorp",
            "--domain",
            "example.com",
            "--key-dir",
            key_dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    let domain_dir = key_dir.join("example.com");
    let secret_key = domain_dir.join("secret.key");
    let public_key = domain_dir.join("public.key");

    assert!(secret_key.exists());
    assert!(public_key.exists());

    // Keys are correct size
    assert_eq!(std::fs::read(&secret_key).unwrap().len(), 32);
    assert_eq!(std::fs::read(&public_key).unwrap().len(), 32);

    // Check permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let dir_perms = std::fs::metadata(&domain_dir).unwrap().permissions();
        assert_eq!(dir_perms.mode() & 0o777, 0o700);

        let key_perms = std::fs::metadata(&secret_key).unwrap().permissions();
        assert_eq!(key_perms.mode() & 0o777, 0o600);
    }
}

#[test]
fn test_init_outputs_did_document() {
    let tmp = TempDir::new().unwrap();

    let output = cmd()
        .args([
            "init",
            "--org",
            "TestCorp",
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap();

    // Has @context array
    assert!(json["@context"].is_array());

    // id matches did:web:{domain}
    assert_eq!(json["id"], "did:web:example.com");

    // verificationMethod has one entry with correct type
    let vm = &json["verificationMethod"];
    assert_eq!(vm.as_array().unwrap().len(), 1);
    assert_eq!(vm[0]["type"], "Ed25519VerificationKey2020");

    // publicKeyMultibase starts with 'z'
    let pkm = vm[0]["publicKeyMultibase"].as_str().unwrap();
    assert!(pkm.starts_with('z'));
}

#[test]
fn test_init_refuses_overwrite() {
    let tmp = TempDir::new().unwrap();
    let key_dir = tmp.path().to_str().unwrap();

    // First run succeeds
    cmd()
        .args(["init", "--org", "A", "--domain", "example.com", "--key-dir", key_dir])
        .assert()
        .success();

    // Second run fails
    cmd()
        .args(["init", "--org", "A", "--domain", "example.com", "--key-dir", key_dir])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn test_init_force_overwrites() {
    let tmp = TempDir::new().unwrap();
    let key_dir = tmp.path();

    // First run
    cmd()
        .args([
            "init",
            "--org",
            "A",
            "--domain",
            "example.com",
            "--key-dir",
            key_dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    let original_pk = std::fs::read(key_dir.join("example.com/public.key")).unwrap();

    // Second run with --force
    cmd()
        .args([
            "init",
            "--org",
            "A",
            "--domain",
            "example.com",
            "--key-dir",
            key_dir.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success();

    let new_pk = std::fs::read(key_dir.join("example.com/public.key")).unwrap();

    // Extremely unlikely to generate the same keypair twice
    assert_ne!(original_pk, new_pk);
}

#[test]
fn test_init_output_to_file() {
    let tmp = TempDir::new().unwrap();
    let output_file = tmp.path().join("did.json");

    cmd()
        .args([
            "init",
            "--org",
            "TestCorp",
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
            "--output",
            output_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(output_file.exists());

    let content = std::fs::read_to_string(&output_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["id"], "did:web:example.com");
}

#[test]
fn test_init_stderr_summary() {
    let tmp = TempDir::new().unwrap();

    cmd()
        .args([
            "init",
            "--org",
            "TestCorp",
            "--domain",
            "example.com",
            "--key-dir",
            tmp.path().to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("did:web:example.com"))
        .stderr(predicate::str::contains("Initialized jobchain identity for TestCorp"))
        .stderr(predicate::str::contains("Next: host the DID document at https://example.com/.well-known/did.json"));
}
