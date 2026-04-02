//! WASM bindings for in-browser credential verification.
//!
//! Gated behind the `wasm` feature flag. Exposes a single entry point
//! that JavaScript can call after loading the WASM module.

use wasm_bindgen::prelude::*;

/// Verify a credential's Ed25519 signature in the browser.
///
/// # Arguments
/// * `credential_json` — the full credential JSON (including proof)
/// * `public_key_hex` — the issuer's Ed25519 public key as a hex string (64 chars)
///
/// # Returns
/// A JSON object: `{ "valid": true/false, "error": null | "message" }`
#[wasm_bindgen]
pub fn verify_credential_json(credential_json: &str, public_key_hex: &str) -> JsValue {
    let result = (|| -> Result<(), String> {
        let credential: crate::VerifiableCredential =
            serde_json::from_str(credential_json).map_err(|e| format!("JSON parse error: {e}"))?;

        let key_bytes = hex_to_bytes(public_key_hex)?;
        if key_bytes.len() != 32 {
            return Err(format!(
                "expected 32-byte public key, got {} bytes",
                key_bytes.len()
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        crate::verify_credential(&credential, &key).map_err(|e| e.to_string())
    })();

    let (valid, error) = match result {
        Ok(()) => (true, serde_json::Value::Null),
        Err(e) => (false, serde_json::Value::String(e)),
    };

    let obj = serde_json::json!({ "valid": valid, "error": error });
    serde_wasm_bindgen::to_value(&obj).unwrap_or(JsValue::NULL)
}

/// Decode a multibase public key to hex, for extracting keys from DID documents.
#[wasm_bindgen]
pub fn decode_multibase_key_hex(multibase: &str) -> JsValue {
    match crate::decode_multibase_key(multibase) {
        Ok(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            let obj = serde_json::json!({ "hex": hex, "error": null });
            serde_wasm_bindgen::to_value(&obj).unwrap_or(JsValue::NULL)
        }
        Err(e) => {
            let obj = serde_json::json!({ "hex": null, "error": e.to_string() });
            serde_wasm_bindgen::to_value(&obj).unwrap_or(JsValue::NULL)
        }
    }
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
