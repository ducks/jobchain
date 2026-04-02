//! Signature and credential verification for jobchain.

pub use jobchain_core::amendment::Amendment;
pub use jobchain_core::credential::{CredentialSubject, Proof, VerifiableCredential};

/// Errors that can occur during credential verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("credential has no proof block")]
    MissingProof,

    #[error("unsupported proof type: {0}")]
    UnsupportedProofType(String),

    #[error("invalid proof value: {0}")]
    InvalidProofValue(String),

    #[error("signature verification failed")]
    InvalidSignature,

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("issuer mismatch: expected {expected}, got {got}")]
    IssuerMismatch { expected: String, got: String },

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
}

/// Verify the Ed25519 signature on a credential against a known public key.
///
/// Extracts the proof block, reconstructs the canonical signing input via
/// `signing_payload()`, decodes the multibase signature, and runs `verify_strict`.
pub fn verify_credential(
    credential: &VerifiableCredential,
    public_key: &[u8; 32],
) -> Result<(), VerificationError> {
    let proof = credential
        .proof
        .as_ref()
        .ok_or(VerificationError::MissingProof)?;

    if proof.r#type != "Ed25519Signature2020" {
        return Err(VerificationError::UnsupportedProofType(
            proof.r#type.clone(),
        ));
    }

    // Decode multibase base58btc signature
    let proof_value = &proof.proof_value;
    if !proof_value.starts_with('z') {
        return Err(VerificationError::InvalidProofValue(
            "missing 'z' multibase prefix".into(),
        ));
    }
    let sig_bytes = bs58::decode(&proof_value[1..])
        .into_vec()
        .map_err(|e| VerificationError::InvalidProofValue(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(VerificationError::InvalidProofValue(format!(
            "expected 64-byte signature, got {} bytes",
            sig_bytes.len()
        )));
    }
    let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    // Construct verifying key
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| VerificationError::InvalidPublicKey(e.to_string()))?;

    // Reconstruct the signing payload
    let payload = credential.signing_payload()?;

    // Verify with strict mode
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|_| VerificationError::InvalidSignature)
}

/// Verify a credential's signature and also check issuer DID metadata.
///
/// Calls `verify_credential()` for the cryptographic check, then asserts that
/// the credential's issuer matches the expected DID and the proof's
/// verification method belongs to that issuer.
pub fn verify_credential_full(
    credential: &VerifiableCredential,
    public_key: &[u8; 32],
    expected_issuer_did: &str,
) -> Result<(), VerificationError> {
    verify_credential(credential, public_key)?;

    if credential.issuer != expected_issuer_did {
        return Err(VerificationError::IssuerMismatch {
            expected: expected_issuer_did.to_string(),
            got: credential.issuer.clone(),
        });
    }

    // The proof is guaranteed to exist if verify_credential succeeded
    let proof = credential.proof.as_ref().unwrap();
    if !proof.verification_method.starts_with(expected_issuer_did) {
        return Err(VerificationError::IssuerMismatch {
            expected: expected_issuer_did.to_string(),
            got: proof.verification_method.clone(),
        });
    }

    Ok(())
}

/// Verify the Ed25519 signature on an amendment against a known public key.
///
/// Same logic as `verify_credential` but operates on an `Amendment` struct.
pub fn verify_amendment(
    amendment: &Amendment,
    public_key: &[u8; 32],
) -> Result<(), VerificationError> {
    let proof = amendment
        .proof
        .as_ref()
        .ok_or(VerificationError::MissingProof)?;

    if proof.r#type != "Ed25519Signature2020" {
        return Err(VerificationError::UnsupportedProofType(
            proof.r#type.clone(),
        ));
    }

    let proof_value = &proof.proof_value;
    if !proof_value.starts_with('z') {
        return Err(VerificationError::InvalidProofValue(
            "missing 'z' multibase prefix".into(),
        ));
    }
    let sig_bytes = bs58::decode(&proof_value[1..])
        .into_vec()
        .map_err(|e| VerificationError::InvalidProofValue(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(VerificationError::InvalidProofValue(format!(
            "expected 64-byte signature, got {} bytes",
            sig_bytes.len()
        )));
    }
    let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| VerificationError::InvalidPublicKey(e.to_string()))?;

    let payload = amendment.signing_payload().map_err(|e| match e {
        jobchain_core::amendment::AmendmentError::Serialization(se) => {
            VerificationError::Serialization(se)
        }
        other => VerificationError::InvalidProofValue(other.to_string()),
    })?;

    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|_| VerificationError::InvalidSignature)
}

/// Decode a multibase base58btc public key (with multicodec Ed25519 header)
/// into a raw 32-byte key.
///
/// This bridges DID document `publicKeyMultibase` format to the raw key
/// that `verify_credential()` accepts.
///
/// Delegates to [`jobchain_core::did::decode_multibase_ed25519_pubkey`].
pub fn decode_multibase_key(multibase: &str) -> Result<[u8; 32], VerificationError> {
    jobchain_core::did::decode_multibase_ed25519_pubkey(multibase)
        .map_err(|e| VerificationError::InvalidPublicKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jobchain_core::credential::issue_credential;
    use jobchain_core::signing::Keypair;

    fn sample_experience() -> jobl::ExperienceItem {
        jobl::ExperienceItem {
            title: "Software Engineer".to_string(),
            company: "Discourse".to_string(),
            location: Some("Remote".to_string()),
            start: Some("2022-01-15".to_string()),
            end: None,
            summary: Some("Infrastructure team".to_string()),
            technologies: vec!["Ruby".to_string(), "JavaScript".to_string()],
            highlights: vec!["Built deployment pipeline".to_string()],
        }
    }

    fn signed_credential(
        issuer: &str,
        kp: &Keypair,
    ) -> VerifiableCredential {
        issue_credential(issuer, sample_experience(), "2025-06-01T00:00:00Z", kp).unwrap()
    }

    #[test]
    fn test_verify_valid_credential() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential("did:web:example.com", &kp);
        let pk = kp.public_key_bytes();
        assert!(verify_credential(&vc, &pk).is_ok());
    }

    #[test]
    fn test_verify_missing_proof() {
        let vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        let pk = [0u8; 32];
        let err = verify_credential(&vc, &pk).unwrap_err();
        assert!(matches!(err, VerificationError::MissingProof));
    }

    #[test]
    fn test_verify_tampered_subject() {
        let kp = Keypair::generate().unwrap();
        let mut vc = signed_credential("did:web:example.com", &kp);
        vc.credential_subject.experience.title = "CEO".to_string();
        let pk = kp.public_key_bytes();
        let err = verify_credential(&vc, &pk).unwrap_err();
        assert!(matches!(err, VerificationError::InvalidSignature));
    }

    #[test]
    fn test_verify_tampered_issuer() {
        let kp = Keypair::generate().unwrap();
        let mut vc = signed_credential("did:web:example.com", &kp);
        vc.issuer = "did:web:evil.com".to_string();
        let pk = kp.public_key_bytes();
        let err = verify_credential(&vc, &pk).unwrap_err();
        assert!(matches!(err, VerificationError::InvalidSignature));
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp_a = Keypair::generate().unwrap();
        let kp_b = Keypair::generate().unwrap();
        let vc = signed_credential("did:web:example.com", &kp_a);
        let pk_b = kp_b.public_key_bytes();
        let err = verify_credential(&vc, &pk_b).unwrap_err();
        assert!(matches!(err, VerificationError::InvalidSignature));
    }

    #[test]
    fn test_verify_invalid_proof_value() {
        let mut vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        vc.proof = Some(Proof {
            r#type: "Ed25519Signature2020".to_string(),
            verification_method: "did:web:example.com#key-1".to_string(),
            proof_value: "not-valid-multibase!!!".to_string(),
            created: "2025-06-01T00:00:00Z".to_string(),
        });
        let pk = [0u8; 32];
        let err = verify_credential(&vc, &pk).unwrap_err();
        assert!(matches!(err, VerificationError::InvalidProofValue(_)));
    }

    #[test]
    fn test_verify_unsupported_proof_type() {
        let mut vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        vc.proof = Some(Proof {
            r#type: "RsaSignature2018".to_string(),
            verification_method: "did:web:example.com#key-1".to_string(),
            proof_value: "zSomeValue".to_string(),
            created: "2025-06-01T00:00:00Z".to_string(),
        });
        let pk = [0u8; 32];
        let err = verify_credential(&vc, &pk).unwrap_err();
        assert!(matches!(err, VerificationError::UnsupportedProofType(_)));
    }

    #[test]
    fn test_verify_full_issuer_mismatch() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential("did:web:a.com", &kp);
        let pk = kp.public_key_bytes();
        let err = verify_credential_full(&vc, &pk, "did:web:b.com").unwrap_err();
        assert!(matches!(err, VerificationError::IssuerMismatch { .. }));
    }

    #[test]
    fn test_verify_full_happy_path() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential("did:web:example.com", &kp);
        let pk = kp.public_key_bytes();
        assert!(verify_credential_full(&vc, &pk, "did:web:example.com").is_ok());
    }

    #[test]
    fn test_decode_multibase_key() {
        let original = [42u8; 32];
        let mut buf = Vec::with_capacity(34);
        buf.push(0xed);
        buf.push(0x01);
        buf.extend_from_slice(&original);
        let encoded = format!("z{}", bs58::encode(&buf).into_string());

        let decoded = decode_multibase_key(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_multibase_key_wrong_prefix() {
        let err = decode_multibase_key("fSomeBase16Value").unwrap_err();
        assert!(matches!(err, VerificationError::InvalidPublicKey(_)));
    }

    #[test]
    fn test_decode_multibase_key_wrong_codec() {
        let mut buf = Vec::with_capacity(34);
        buf.push(0x00);
        buf.push(0x00);
        buf.extend_from_slice(&[0u8; 32]);
        let encoded = format!("z{}", bs58::encode(&buf).into_string());

        let err = decode_multibase_key(&encoded).unwrap_err();
        assert!(matches!(err, VerificationError::InvalidPublicKey(_)));
    }
}
