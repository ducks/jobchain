//! Adapter trait for mapping external employment data sources into credential-ready types.

use serde_json::{Map, Value};

/// Errors that adapters may surface when extracting data from external sources.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdapterError {
    /// A required field was absent in the source data.
    #[error("missing field: {field}")]
    MissingField { field: String },

    /// The source data was present but malformed.
    #[error("invalid data: {message}")]
    InvalidData { message: String },

    /// The external system could not be reached or read.
    #[error("source unavailable: {message}")]
    SourceUnavailable { message: String },
}

/// Data extracted from a source system for a new hire, ready to become a `VerifiableCredential`.
#[derive(Debug, Clone, PartialEq)]
pub struct HireData {
    /// The employment record to embed in credentialSubject.
    pub experience: jobl::ExperienceItem,
    /// The did:web URI of the issuing organization.
    pub issuer_did: String,
    /// ISO 8601 date string for the credential's issuanceDate field.
    pub issuance_date: String,
}

impl HireData {
    /// Convert into an unsigned `VerifiableCredential`.
    pub fn into_credential(self) -> crate::credential::VerifiableCredential {
        crate::credential::VerifiableCredential::new(
            self.issuer_did,
            self.issuance_date,
            self.experience,
        )
    }
}

/// Data extracted from a source system for a title/role change, ready to become an `Amendment`.
#[derive(Debug, Clone, PartialEq)]
pub struct TitleChangeData {
    /// The amended fields, using the same key names as CredentialSubject.
    pub changes: Map<String, Value>,
    /// ISO 8601 date when the new title takes effect.
    pub effective_date: String,
    /// The did:web URI of the amending organization.
    pub issuer_did: String,
}

impl TitleChangeData {
    /// Extract the changes map and effective date for amendment construction.
    pub fn into_amendment_changes(self) -> (Map<String, Value>, String) {
        (self.changes, self.effective_date)
    }
}

/// Data extracted from a source system for an employee departure,
/// ready to become a final `Amendment`.
#[derive(Debug, Clone, PartialEq)]
pub struct DepartureData {
    /// ISO 8601 date of the employee's last day.
    pub end_date: String,
    /// ISO 8601 date when the departure is recorded.
    pub effective_date: String,
    /// The did:web URI of the departing organization.
    pub issuer_did: String,
    /// Optional extra fields to amend alongside the departure.
    pub additional_changes: Map<String, Value>,
}

impl DepartureData {
    /// Merge the end date into additional changes and return for amendment construction.
    pub fn into_amendment_changes(self) -> (Map<String, Value>, String) {
        let mut changes = self.additional_changes;
        changes.insert(
            "end".to_string(),
            Value::String(self.end_date),
        );
        (changes, self.effective_date)
    }
}

/// Trait for adapting external employment data sources into credential-ready types.
///
/// Implementors map source-system records into the data structs that the
/// credential and amendment pipeline expects. All methods take `&self`
/// because adapters are pure readers.
pub trait EmploymentAdapter {
    /// The opaque source-specific identifier for an employment record.
    type EmploymentId;

    /// Extract hire data from the source system for a new employment record.
    fn on_hire(&self, id: &Self::EmploymentId) -> Result<HireData, AdapterError>;

    /// Extract title-change data from the source system.
    fn on_title_change(&self, id: &Self::EmploymentId) -> Result<TitleChangeData, AdapterError>;

    /// Extract departure data from the source system.
    fn on_departure(&self, id: &Self::EmploymentId) -> Result<DepartureData, AdapterError>;
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_hire_data_into_credential() {
        let hire = HireData {
            experience: sample_experience(),
            issuer_did: "did:web:discourse.org".to_string(),
            issuance_date: "2025-06-01T00:00:00Z".to_string(),
        };

        let vc = hire.into_credential();

        assert_eq!(vc.issuer, "did:web:discourse.org");
        assert_eq!(vc.issuance_date, "2025-06-01T00:00:00Z");
        assert_eq!(
            vc.credential_subject.experience.title,
            "Software Engineer"
        );
        assert_eq!(vc.credential_subject.experience.company, "Discourse");
        assert!(vc.proof.is_none());
    }

    #[test]
    fn test_title_change_data_into_changes() {
        let mut changes = Map::new();
        changes.insert(
            "title".to_string(),
            Value::String("Senior Software Engineer".to_string()),
        );
        changes.insert(
            "highlights".to_string(),
            Value::Array(vec![Value::String("Led platform migration".to_string())]),
        );

        let data = TitleChangeData {
            changes: changes.clone(),
            effective_date: "2025-09-01".to_string(),
            issuer_did: "did:web:discourse.org".to_string(),
        };

        let (result_changes, date) = data.into_amendment_changes();

        assert_eq!(result_changes, changes);
        assert_eq!(date, "2025-09-01");
        assert!(result_changes.contains_key("title"));
        assert!(result_changes.contains_key("highlights"));
    }

    #[test]
    fn test_departure_data_into_changes_includes_end() {
        let data = DepartureData {
            end_date: "2026-03-15".to_string(),
            effective_date: "2026-03-15".to_string(),
            issuer_did: "did:web:discourse.org".to_string(),
            additional_changes: Map::new(),
        };

        let (changes, date) = data.into_amendment_changes();

        assert_eq!(date, "2026-03-15");
        assert_eq!(
            changes.get("end").unwrap(),
            &Value::String("2026-03-15".to_string())
        );
    }

    #[test]
    fn test_departure_data_merges_additional() {
        let mut additional = Map::new();
        additional.insert(
            "highlights".to_string(),
            Value::Array(vec![Value::String(
                "Completed final handoff".to_string(),
            )]),
        );

        let data = DepartureData {
            end_date: "2026-03-15".to_string(),
            effective_date: "2026-03-15".to_string(),
            issuer_did: "did:web:discourse.org".to_string(),
            additional_changes: additional,
        };

        let (changes, _) = data.into_amendment_changes();

        assert!(changes.contains_key("end"));
        assert!(changes.contains_key("highlights"));
        assert_eq!(
            changes.get("end").unwrap(),
            &Value::String("2026-03-15".to_string())
        );
    }

    #[test]
    fn test_adapter_error_display() {
        let missing = AdapterError::MissingField {
            field: "title".to_string(),
        };
        assert_eq!(missing.to_string(), "missing field: title");

        let invalid = AdapterError::InvalidData {
            message: "bad date format".to_string(),
        };
        assert_eq!(invalid.to_string(), "invalid data: bad date format");

        let unavailable = AdapterError::SourceUnavailable {
            message: "connection refused".to_string(),
        };
        assert_eq!(
            unavailable.to_string(),
            "source unavailable: connection refused"
        );
    }
}
