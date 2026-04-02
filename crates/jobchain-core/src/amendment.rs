use std::collections::BTreeMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::credential::{canonicalize, CredentialError, Proof, VerifiableCredential};
use crate::signing::Keypair;

/// Compute a SHA-256 content hash of arbitrary bytes, returned as `sha256:<hex>`.
pub fn content_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

/// Produce canonical JSON bytes for a `VerifiableCredential` (for hashing).
///
/// Strips the proof, canonicalizes (sorted keys), and serializes to compact JSON bytes.
pub fn hashable_bytes(vc: &VerifiableCredential) -> Result<Vec<u8>, serde_json::Error> {
    let mut value = serde_json::to_value(vc)?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("proof");
    }
    let canonical = canonicalize(&value);
    serde_json::to_vec(&canonical)
}

/// Produce canonical JSON bytes for an `Amendment` (for hashing).
///
/// Strips the proof, canonicalizes (sorted keys), and serializes to compact JSON bytes.
pub fn hashable_amendment_bytes(amendment: &Amendment) -> Result<Vec<u8>, serde_json::Error> {
    let mut value = serde_json::to_value(amendment)?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("proof");
    }
    let canonical = canonicalize(&value);
    serde_json::to_vec(&canonical)
}

/// The subject of an amendment: a partial field overlay referencing the original credential.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AmendmentSubject {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "originalCredential")]
    pub original_credential: String,
    /// Key-value map of fields being changed.
    pub changes: BTreeMap<String, serde_json::Value>,
}

/// A credential amendment: a VC-shaped envelope carrying chain metadata and field changes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Amendment {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "effectiveDate")]
    pub effective_date: String,
    #[serde(rename = "previousHash")]
    pub previous_hash: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: AmendmentSubject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

/// Errors specific to amendment operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AmendmentError {
    #[error("credential error: {0}")]
    Credential(#[from] CredentialError),

    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("unsigned predecessor: the credential or amendment being amended has no proof")]
    UnsignedPredecessor,

    #[error("empty changes: an amendment must contain at least one change")]
    EmptyChanges,

    #[error("chain verification failed: {0}")]
    ChainVerification(String),
}

impl Amendment {
    /// Create an amendment from a signed credential.
    ///
    /// The credential must have a proof (be signed). The `changes` map must be non-empty.
    pub fn from_credential(
        vc: &VerifiableCredential,
        changes: BTreeMap<String, serde_json::Value>,
        effective_date: String,
    ) -> Result<Self, AmendmentError> {
        if vc.proof.is_none() {
            return Err(AmendmentError::UnsignedPredecessor);
        }
        if changes.is_empty() {
            return Err(AmendmentError::EmptyChanges);
        }

        let hash_bytes = hashable_bytes(vc)?;
        let previous_hash = content_hash(&hash_bytes);

        Ok(Self {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://jobchain.dev/v1/amendment".to_string(),
            ],
            r#type: vec![
                "VerifiableCredential".to_string(),
                "EmploymentAmendment".to_string(),
            ],
            issuer: vc.issuer.clone(),
            issuance_date: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            effective_date,
            previous_hash,
            credential_subject: AmendmentSubject {
                r#type: "AmendmentRecord".to_string(),
                original_credential: vc.issuer.clone(),
                changes,
            },
            proof: None,
        })
    }

    /// Create an amendment from a previous amendment (chaining).
    ///
    /// The previous amendment must have a proof (be signed). The `changes` map must be non-empty.
    pub fn from_amendment(
        prev: &Amendment,
        changes: BTreeMap<String, serde_json::Value>,
        effective_date: String,
    ) -> Result<Self, AmendmentError> {
        if prev.proof.is_none() {
            return Err(AmendmentError::UnsignedPredecessor);
        }
        if changes.is_empty() {
            return Err(AmendmentError::EmptyChanges);
        }

        let hash_bytes = hashable_amendment_bytes(prev)?;
        let previous_hash = content_hash(&hash_bytes);

        Ok(Self {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://jobchain.dev/v1/amendment".to_string(),
            ],
            r#type: vec![
                "VerifiableCredential".to_string(),
                "EmploymentAmendment".to_string(),
            ],
            issuer: prev.issuer.clone(),
            issuance_date: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            effective_date,
            previous_hash,
            credential_subject: AmendmentSubject {
                r#type: "AmendmentRecord".to_string(),
                original_credential: prev.credential_subject.original_credential.clone(),
                changes,
            },
            proof: None,
        })
    }

    /// Produce the canonical JSON bytes to be signed (strips proof, sorts keys).
    pub fn signing_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("proof");
        }
        let canonical = canonicalize(&value);
        serde_json::to_vec(&canonical)
    }

    /// Sign this amendment with the given keypair and verification method.
    pub fn sign(
        &mut self,
        keypair: &Keypair,
        verification_method: &str,
    ) -> Result<(), CredentialError> {
        let payload = self.signing_payload()?;
        let signature = keypair.sign(&payload);
        let proof_value = format!("z{}", bs58::encode(&signature).into_string());
        let created = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        self.proof = Some(Proof {
            r#type: "Ed25519Signature2020".to_string(),
            verification_method: verification_method.to_string(),
            proof_value,
            created,
        });

        Ok(())
    }
}

/// Verify that an amendment's `previousHash` matches the hash of the given credential.
pub fn verify_link(
    amendment: &Amendment,
    vc: &VerifiableCredential,
) -> Result<(), AmendmentError> {
    let hash_bytes = hashable_bytes(vc)?;
    let expected = content_hash(&hash_bytes);
    if amendment.previous_hash != expected {
        return Err(AmendmentError::ChainVerification(format!(
            "previousHash mismatch: expected {}, got {}",
            expected, amendment.previous_hash
        )));
    }
    Ok(())
}

/// Verify that an amendment chain links correctly.
///
/// Takes the original credential and a slice of amendments in order.
/// Verifies that:
/// - The first amendment's `previousHash` matches the credential
/// - Each subsequent amendment's `previousHash` matches the previous amendment
pub fn verify_chain(
    vc: &VerifiableCredential,
    amendments: &[Amendment],
) -> Result<(), AmendmentError> {
    if amendments.is_empty() {
        return Ok(());
    }

    // Verify first amendment links to the credential
    verify_link(&amendments[0], vc)?;

    // Verify each subsequent amendment links to the previous one
    for i in 1..amendments.len() {
        let prev_bytes = hashable_amendment_bytes(&amendments[i - 1])?;
        let expected = content_hash(&prev_bytes);
        if amendments[i].previous_hash != expected {
            return Err(AmendmentError::ChainVerification(format!(
                "amendment {} previousHash mismatch: expected {}, got {}",
                i, expected, amendments[i].previous_hash
            )));
        }
    }

    Ok(())
}

/// Convenience function: create an amendment from a credential and sign it in one step.
pub fn amend_credential(
    vc: &VerifiableCredential,
    changes: BTreeMap<String, serde_json::Value>,
    effective_date: String,
    keypair: &Keypair,
    verification_method: &str,
) -> Result<Amendment, AmendmentError> {
    let mut amendment = Amendment::from_credential(vc, changes, effective_date)?;
    amendment.sign(keypair, verification_method)?;
    Ok(amendment)
}

// We need hex encoding for SHA-256 output. Use a minimal inline implementation
// to avoid adding another dependency.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::Keypair;

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

    fn signed_credential() -> (VerifiableCredential, Keypair) {
        let kp = Keypair::generate().unwrap();
        let mut vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        vc.sign(&kp, "did:web:example.com#key-1").unwrap();
        (vc, kp)
    }

    fn sample_changes() -> BTreeMap<String, serde_json::Value> {
        let mut changes = BTreeMap::new();
        changes.insert(
            "title".to_string(),
            serde_json::Value::String("Senior Software Engineer".to_string()),
        );
        changes
    }

    #[test]
    fn test_content_hash_deterministic() {
        let data = b"hello world";
        let h1 = content_hash(data);
        let h2 = content_hash(data);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn test_content_hash_different_inputs() {
        let h1 = content_hash(b"hello");
        let h2 = content_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hashable_bytes_excludes_proof() {
        let (vc, _) = signed_credential();
        assert!(vc.proof.is_some());
        let bytes = hashable_bytes(&vc).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(!value.as_object().unwrap().contains_key("proof"));
    }

    #[test]
    fn test_hashable_bytes_deterministic() {
        let (vc, _) = signed_credential();
        let b1 = hashable_bytes(&vc).unwrap();
        let b2 = hashable_bytes(&vc).unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_amendment_from_credential() {
        let (vc, _) = signed_credential();
        let amendment = Amendment::from_credential(
            &vc,
            sample_changes(),
            "2025-07-01T00:00:00Z".to_string(),
        )
        .unwrap();

        assert_eq!(
            amendment.r#type,
            vec!["VerifiableCredential", "EmploymentAmendment"]
        );
        assert_eq!(amendment.issuer, "did:web:example.com");
        assert_eq!(amendment.effective_date, "2025-07-01T00:00:00Z");
        assert!(amendment.previous_hash.starts_with("sha256:"));
        assert_eq!(
            amendment.credential_subject.r#type,
            "AmendmentRecord"
        );
        assert!(amendment.proof.is_none());
    }

    #[test]
    fn test_amendment_rejects_unsigned_credential() {
        let vc = VerifiableCredential::new(
            "did:web:example.com".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        let result = Amendment::from_credential(
            &vc,
            sample_changes(),
            "2025-07-01T00:00:00Z".to_string(),
        );
        assert!(matches!(result, Err(AmendmentError::UnsignedPredecessor)));
    }

    #[test]
    fn test_amendment_rejects_empty_changes() {
        let (vc, _) = signed_credential();
        let result = Amendment::from_credential(
            &vc,
            BTreeMap::new(),
            "2025-07-01T00:00:00Z".to_string(),
        );
        assert!(matches!(result, Err(AmendmentError::EmptyChanges)));
    }

    #[test]
    fn test_amendment_sign() {
        let (vc, kp) = signed_credential();
        let mut amendment = Amendment::from_credential(
            &vc,
            sample_changes(),
            "2025-07-01T00:00:00Z".to_string(),
        )
        .unwrap();

        amendment.sign(&kp, "did:web:example.com#key-1").unwrap();
        let proof = amendment.proof.as_ref().unwrap();
        assert_eq!(proof.r#type, "Ed25519Signature2020");
        assert!(proof.proof_value.starts_with('z'));
    }

    #[test]
    fn test_amendment_sign_verify_roundtrip() {
        let (vc, kp) = signed_credential();
        let mut amendment = Amendment::from_credential(
            &vc,
            sample_changes(),
            "2025-07-01T00:00:00Z".to_string(),
        )
        .unwrap();

        amendment.sign(&kp, "did:web:example.com#key-1").unwrap();

        // Verify the signature
        let payload = amendment.signing_payload().unwrap();
        let proof = amendment.proof.as_ref().unwrap();
        let sig = bs58::decode(&proof.proof_value[1..]).into_vec().unwrap();
        kp.verify(&payload, &sig).unwrap();
    }

    #[test]
    fn test_verify_link_success() {
        let (vc, kp) = signed_credential();
        let mut amendment = Amendment::from_credential(
            &vc,
            sample_changes(),
            "2025-07-01T00:00:00Z".to_string(),
        )
        .unwrap();
        amendment.sign(&kp, "did:web:example.com#key-1").unwrap();

        verify_link(&amendment, &vc).unwrap();
    }

    #[test]
    fn test_verify_link_failure() {
        let (vc, kp) = signed_credential();
        let mut amendment = Amendment::from_credential(
            &vc,
            sample_changes(),
            "2025-07-01T00:00:00Z".to_string(),
        )
        .unwrap();
        amendment.sign(&kp, "did:web:example.com#key-1").unwrap();

        // Create a different credential to verify against
        let kp2 = Keypair::generate().unwrap();
        let mut vc2 = VerifiableCredential::new(
            "did:web:other.com".to_string(),
            "2025-09-01T00:00:00Z".to_string(),
            sample_experience(),
        );
        vc2.sign(&kp2, "did:web:other.com#key-1").unwrap();
        let result = verify_link(&amendment, &vc2);
        assert!(matches!(result, Err(AmendmentError::ChainVerification(_))));
    }

    #[test]
    fn test_amendment_from_amendment() {
        let (vc, kp) = signed_credential();
        let mut a1 = Amendment::from_credential(
            &vc,
            sample_changes(),
            "2025-07-01T00:00:00Z".to_string(),
        )
        .unwrap();
        a1.sign(&kp, "did:web:example.com#key-1").unwrap();

        let mut changes2 = BTreeMap::new();
        changes2.insert(
            "end".to_string(),
            serde_json::Value::String("2025-08-01".to_string()),
        );

        let a2 = Amendment::from_amendment(
            &a1,
            changes2,
            "2025-08-01T00:00:00Z".to_string(),
        )
        .unwrap();

        assert!(a2.previous_hash.starts_with("sha256:"));
        assert_ne!(a2.previous_hash, a1.previous_hash);
    }

    #[test]
    fn test_amendment_from_amendment_rejects_unsigned() {
        let (vc, _) = signed_credential();
        let a1 = Amendment::from_credential(
            &vc,
            sample_changes(),
            "2025-07-01T00:00:00Z".to_string(),
        )
        .unwrap();
        // a1 is not signed

        let result = Amendment::from_amendment(
            &a1,
            sample_changes(),
            "2025-08-01T00:00:00Z".to_string(),
        );
        assert!(matches!(result, Err(AmendmentError::UnsignedPredecessor)));
    }

    #[test]
    fn test_verify_chain_success() {
        let (vc, kp) = signed_credential();

        let mut a1 = Amendment::from_credential(
            &vc,
            sample_changes(),
            "2025-07-01T00:00:00Z".to_string(),
        )
        .unwrap();
        a1.sign(&kp, "did:web:example.com#key-1").unwrap();

        let mut changes2 = BTreeMap::new();
        changes2.insert(
            "end".to_string(),
            serde_json::Value::String("2025-12-31".to_string()),
        );
        let mut a2 = Amendment::from_amendment(
            &a1,
            changes2,
            "2025-08-01T00:00:00Z".to_string(),
        )
        .unwrap();
        a2.sign(&kp, "did:web:example.com#key-1").unwrap();

        verify_chain(&vc, &[a1, a2]).unwrap();
    }

    #[test]
    fn test_verify_chain_empty() {
        let (vc, _) = signed_credential();
        verify_chain(&vc, &[]).unwrap();
    }

    #[test]
    fn test_amend_credential_convenience() {
        let (vc, kp) = signed_credential();
        let amendment = amend_credential(
            &vc,
            sample_changes(),
            "2025-07-01T00:00:00Z".to_string(),
            &kp,
            "did:web:example.com#key-1",
        )
        .unwrap();

        assert!(amendment.proof.is_some());
        verify_link(&amendment, &vc).unwrap();
    }
}
