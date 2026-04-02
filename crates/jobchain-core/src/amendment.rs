use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::credential::{canonicalize, Proof, VerifiableCredential};
use crate::signing::{Keypair, SigningError};

/// Errors that can occur during amendment operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AmendmentError {
    #[error("predecessor document is unsigned — cannot compute stable content hash")]
    UnsignedPredecessor,

    #[error("broken link: expected {expected}, got {got}")]
    BrokenLink { expected: String, got: String },

    #[error("original credential hash does not match base credential")]
    InvalidOriginalReference,

    #[error("amendment has no changes")]
    EmptyChanges,

    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("signing failed: {0}")]
    Signing(#[from] SigningError),
}

/// Compute the SHA-256 content hash of a signed document's canonical bytes.
///
/// Returns a hex-encoded digest prefixed with `sha256:`.
pub fn content_hash(document: &[u8]) -> String {
    let digest = Sha256::digest(document);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

/// Serialize a `VerifiableCredential` (including its proof) to canonical JSON bytes.
pub fn hashable_bytes(credential: &VerifiableCredential) -> Result<Vec<u8>, AmendmentError> {
    let value = serde_json::to_value(credential)?;
    let canonical = canonicalize(&value);
    Ok(serde_json::to_vec(&canonical)?)
}

/// Serialize an `Amendment` (including its proof) to canonical JSON bytes.
pub fn hashable_amendment_bytes(amendment: &Amendment) -> Result<Vec<u8>, AmendmentError> {
    let value = serde_json::to_value(amendment)?;
    let canonical = canonicalize(&value);
    Ok(serde_json::to_vec(&canonical)?)
}

/// A partial overlay of changed fields in an amendment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AmendmentSubject {
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "originalCredential")]
    pub original_credential: String,
    pub changes: serde_json::Map<String, serde_json::Value>,
}

/// A W3C VC-shaped amendment document that forms a linked list via content hashes.
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

impl Amendment {
    /// Create an amendment from a signed credential (first amendment in the chain).
    pub fn from_credential(
        credential: &VerifiableCredential,
        changes: serde_json::Map<String, serde_json::Value>,
        effective_date: &str,
    ) -> Result<Self, AmendmentError> {
        if changes.is_empty() {
            return Err(AmendmentError::EmptyChanges);
        }
        if credential.proof.is_none() {
            return Err(AmendmentError::UnsignedPredecessor);
        }

        let bytes = hashable_bytes(credential)?;
        let hash = content_hash(&bytes);

        Ok(Self {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            r#type: vec![
                "VerifiableCredential".to_string(),
                "AmendmentCredential".to_string(),
            ],
            issuer: credential.issuer.clone(),
            issuance_date: String::new(),
            effective_date: effective_date.to_string(),
            previous_hash: hash.clone(),
            credential_subject: AmendmentSubject {
                r#type: "AmendmentRecord".to_string(),
                original_credential: hash,
                changes,
            },
            proof: None,
        })
    }

    /// Create an amendment from a previous amendment (continuing the chain).
    pub fn from_amendment(
        previous: &Amendment,
        original_credential_hash: &str,
        changes: serde_json::Map<String, serde_json::Value>,
        effective_date: &str,
    ) -> Result<Self, AmendmentError> {
        if changes.is_empty() {
            return Err(AmendmentError::EmptyChanges);
        }
        if previous.proof.is_none() {
            return Err(AmendmentError::UnsignedPredecessor);
        }

        let bytes = hashable_amendment_bytes(previous)?;
        let hash = content_hash(&bytes);

        Ok(Self {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
            ],
            r#type: vec![
                "VerifiableCredential".to_string(),
                "AmendmentCredential".to_string(),
            ],
            issuer: previous.issuer.clone(),
            issuance_date: String::new(),
            effective_date: effective_date.to_string(),
            previous_hash: hash,
            credential_subject: AmendmentSubject {
                r#type: "AmendmentRecord".to_string(),
                original_credential: original_credential_hash.to_string(),
                changes,
            },
            proof: None,
        })
    }

    /// Produce the canonical JSON bytes to be signed (proof stripped).
    pub fn signing_payload(&self) -> Result<Vec<u8>, AmendmentError> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("proof");
        }
        let canonical = canonicalize(&value);
        Ok(serde_json::to_vec(&canonical)?)
    }

    /// Sign this amendment, attaching an Ed25519Signature2020 proof block.
    pub fn sign(
        &mut self,
        keypair: &Keypair,
        verification_method: &str,
    ) -> Result<(), AmendmentError> {
        let created = chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.issuance_date = created.clone();

        let payload = self.signing_payload()?;
        let signature = keypair.sign(&payload);
        let proof_value = format!("z{}", bs58::encode(&signature).into_string());

        self.proof = Some(Proof {
            r#type: "Ed25519Signature2020".to_string(),
            verification_method: verification_method.to_string(),
            proof_value,
            created,
        });
        Ok(())
    }
}

/// Verify that an amendment's `previous_hash` matches the content hash of its predecessor.
pub fn verify_link(
    amendment: &Amendment,
    predecessor_bytes: &[u8],
) -> Result<(), AmendmentError> {
    let got = content_hash(predecessor_bytes);
    if amendment.previous_hash != got {
        return Err(AmendmentError::BrokenLink {
            expected: amendment.previous_hash.clone(),
            got,
        });
    }
    Ok(())
}

/// Verify the entire amendment chain from base credential through all amendments.
pub fn verify_chain(
    base_credential: &VerifiableCredential,
    amendments: &[Amendment],
) -> Result<(), AmendmentError> {
    if amendments.is_empty() {
        return Ok(());
    }

    let base_bytes = hashable_bytes(base_credential)?;
    let base_hash = content_hash(&base_bytes);

    // Check first amendment links to the base credential
    verify_link(&amendments[0], &base_bytes)?;

    // Check first amendment's original_credential points to the base
    if amendments[0].credential_subject.original_credential != base_hash {
        return Err(AmendmentError::InvalidOriginalReference);
    }

    // Walk the rest of the chain
    for i in 1..amendments.len() {
        let prev_bytes = hashable_amendment_bytes(&amendments[i - 1])?;
        verify_link(&amendments[i], &prev_bytes)?;

        if amendments[i].credential_subject.original_credential != base_hash {
            return Err(AmendmentError::InvalidOriginalReference);
        }
    }

    Ok(())
}

/// Create and sign an amendment from a credential in one step.
pub fn amend_credential(
    credential: &VerifiableCredential,
    changes: serde_json::Map<String, serde_json::Value>,
    effective_date: &str,
    keypair: &Keypair,
) -> Result<Amendment, AmendmentError> {
    let mut amendment = Amendment::from_credential(credential, changes, effective_date)?;
    let verification_method = format!("{}#key-1", credential.issuer);
    amendment.sign(keypair, &verification_method)?;
    Ok(amendment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::issue_credential;
    use crate::signing::Keypair;

    fn signed_credential(kp: &Keypair) -> VerifiableCredential {
        let experience = jobl::ExperienceItem {
            title: "Software Engineer".to_string(),
            company: "Discourse".to_string(),
            location: Some("Remote".to_string()),
            start: Some("2022-01-15".to_string()),
            end: None,
            summary: Some("Infrastructure team".to_string()),
            technologies: vec!["Ruby".to_string(), "JavaScript".to_string()],
            highlights: vec!["Built deployment pipeline".to_string()],
        };
        issue_credential("did:web:discourse.org", experience, "2025-06-01T00:00:00Z", kp)
            .unwrap()
    }

    fn sample_changes() -> serde_json::Map<String, serde_json::Value> {
        let mut changes = serde_json::Map::new();
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
    }

    #[test]
    fn test_content_hash_prefix() {
        let h = content_hash(b"test data");
        assert!(h.starts_with("sha256:"));
    }

    #[test]
    fn test_content_hash_sensitive() {
        let h1 = content_hash(b"hello");
        let h2 = content_hash(b"hello!");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_amendment_from_credential() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential(&kp);
        let amendment =
            Amendment::from_credential(&vc, sample_changes(), "2025-07-01").unwrap();

        let vc_bytes = hashable_bytes(&vc).unwrap();
        let expected_hash = content_hash(&vc_bytes);
        assert_eq!(amendment.previous_hash, expected_hash);
        assert_eq!(
            amendment.credential_subject.original_credential,
            expected_hash
        );
    }

    #[test]
    fn test_amendment_from_unsigned_fails() {
        let vc = VerifiableCredential::new(
            "did:web:discourse.org".to_string(),
            "2025-06-01T00:00:00Z".to_string(),
            jobl::ExperienceItem {
                title: "Engineer".to_string(),
                company: "Acme".to_string(),
                location: None,
                start: None,
                end: None,
                summary: None,
                technologies: vec![],
                highlights: vec![],
            },
        );

        let result = Amendment::from_credential(&vc, sample_changes(), "2025-07-01");
        assert!(matches!(result, Err(AmendmentError::UnsignedPredecessor)));
    }

    #[test]
    fn test_amendment_sign_attaches_proof() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential(&kp);
        let mut amendment =
            Amendment::from_credential(&vc, sample_changes(), "2025-07-01").unwrap();

        amendment
            .sign(&kp, "did:web:discourse.org#key-1")
            .unwrap();

        let proof = amendment.proof.as_ref().unwrap();
        assert_eq!(proof.r#type, "Ed25519Signature2020");
        assert!(proof.proof_value.starts_with('z'));
    }

    #[test]
    fn test_amendment_signing_payload_excludes_proof() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential(&kp);
        let mut amendment =
            Amendment::from_credential(&vc, sample_changes(), "2025-07-01").unwrap();
        amendment
            .sign(&kp, "did:web:discourse.org#key-1")
            .unwrap();

        let payload = amendment.signing_payload().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(!value.as_object().unwrap().contains_key("proof"));
    }

    #[test]
    fn test_verify_link_valid() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential(&kp);
        let amendment =
            Amendment::from_credential(&vc, sample_changes(), "2025-07-01").unwrap();
        let vc_bytes = hashable_bytes(&vc).unwrap();

        verify_link(&amendment, &vc_bytes).unwrap();
    }

    #[test]
    fn test_verify_link_broken() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential(&kp);
        let mut amendment =
            Amendment::from_credential(&vc, sample_changes(), "2025-07-01").unwrap();

        amendment.previous_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let vc_bytes = hashable_bytes(&vc).unwrap();
        let result = verify_link(&amendment, &vc_bytes);
        assert!(matches!(result, Err(AmendmentError::BrokenLink { .. })));
    }

    #[test]
    fn test_verify_chain_two_amendments() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential(&kp);

        // First amendment
        let mut a1 =
            Amendment::from_credential(&vc, sample_changes(), "2025-07-01").unwrap();
        a1.sign(&kp, "did:web:discourse.org#key-1").unwrap();

        // Second amendment
        let original_hash = a1.credential_subject.original_credential.clone();
        let mut changes2 = serde_json::Map::new();
        changes2.insert(
            "end".to_string(),
            serde_json::Value::String("2025-12-31".to_string()),
        );
        let mut a2 =
            Amendment::from_amendment(&a1, &original_hash, changes2, "2025-12-01").unwrap();
        a2.sign(&kp, "did:web:discourse.org#key-1").unwrap();

        verify_chain(&vc, &[a1, a2]).unwrap();
    }

    #[test]
    fn test_verify_chain_broken_middle() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential(&kp);

        let mut a1 =
            Amendment::from_credential(&vc, sample_changes(), "2025-07-01").unwrap();
        a1.sign(&kp, "did:web:discourse.org#key-1").unwrap();

        let original_hash = a1.credential_subject.original_credential.clone();
        let mut changes2 = serde_json::Map::new();
        changes2.insert(
            "end".to_string(),
            serde_json::Value::String("2025-12-31".to_string()),
        );
        let mut a2 =
            Amendment::from_amendment(&a1, &original_hash, changes2, "2025-12-01").unwrap();
        // Tamper with the previous_hash before signing
        a2.previous_hash = "sha256:deadbeef".to_string();
        a2.sign(&kp, "did:web:discourse.org#key-1").unwrap();

        let result = verify_chain(&vc, &[a1, a2]);
        assert!(matches!(result, Err(AmendmentError::BrokenLink { .. })));
    }

    #[test]
    fn test_verify_chain_wrong_original() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential(&kp);

        let mut a1 =
            Amendment::from_credential(&vc, sample_changes(), "2025-07-01").unwrap();
        a1.sign(&kp, "did:web:discourse.org#key-1").unwrap();

        let mut changes2 = serde_json::Map::new();
        changes2.insert(
            "end".to_string(),
            serde_json::Value::String("2025-12-31".to_string()),
        );
        let mut a2 =
            Amendment::from_amendment(&a1, "sha256:wrong", changes2, "2025-12-01").unwrap();
        a2.sign(&kp, "did:web:discourse.org#key-1").unwrap();

        let result = verify_chain(&vc, &[a1, a2]);
        assert!(matches!(
            result,
            Err(AmendmentError::InvalidOriginalReference)
        ));
    }

    #[test]
    fn test_amend_credential_convenience() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential(&kp);

        let amendment =
            amend_credential(&vc, sample_changes(), "2025-07-01", &kp).unwrap();

        assert!(amendment.proof.is_some());
        assert!(!amendment.issuance_date.is_empty());

        // Verify the link
        let vc_bytes = hashable_bytes(&vc).unwrap();
        verify_link(&amendment, &vc_bytes).unwrap();

        // Verify the signature
        let payload = amendment.signing_payload().unwrap();
        let proof = amendment.proof.as_ref().unwrap();
        let sig = bs58::decode(&proof.proof_value[1..]).into_vec().unwrap();
        kp.verify(&payload, &sig).unwrap();
    }

    #[test]
    fn test_amendment_json_shape() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential(&kp);

        let mut amendment =
            Amendment::from_credential(&vc, sample_changes(), "2025-07-01").unwrap();
        amendment
            .sign(&kp, "did:web:discourse.org#key-1")
            .unwrap();

        let value: serde_json::Value = serde_json::to_value(&amendment).unwrap();
        let obj = value.as_object().unwrap();

        assert!(obj.contains_key("@context"));
        assert!(obj.contains_key("type"));
        assert!(obj.contains_key("issuer"));
        assert!(obj.contains_key("issuanceDate"));
        assert!(obj.contains_key("effectiveDate"));
        assert!(obj.contains_key("previousHash"));
        assert!(obj.contains_key("credentialSubject"));
        assert!(obj.contains_key("proof"));

        let types = obj["type"].as_array().unwrap();
        assert!(types.contains(&serde_json::Value::String(
            "AmendmentCredential".to_string()
        )));

        let subject = obj["credentialSubject"].as_object().unwrap();
        assert_eq!(subject["type"], "AmendmentRecord");
        assert!(subject.contains_key("originalCredential"));
        assert!(subject.contains_key("changes"));
    }

    #[test]
    fn test_empty_changes_rejected() {
        let kp = Keypair::generate().unwrap();
        let vc = signed_credential(&kp);

        let empty = serde_json::Map::new();
        let result = Amendment::from_credential(&vc, empty, "2025-07-01");
        assert!(matches!(result, Err(AmendmentError::EmptyChanges)));
    }
}
