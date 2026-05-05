// Independent verifier for AES-GCM-SIV vectors (RFC 8452 Appendix C).
//
// Reads the parsed AesGcmSivVector records produced by
// `parse::parse_aes_gcm_siv_file` and runs each through RustCrypto's
// `aes-gcm-siv` crate. Compares the computed `ciphertext || tag`
// against the published `result` field.
//
// Different crate, different lineage, same bytes out. RustCrypto's
// aes-gcm-siv is independent of leviathan-crypto's WASM stack; if both
// agree, the corpus transcription is correct.

use aes_gcm_siv::{
    aead::{Aead, Payload},
    Aes128GcmSiv, Aes256GcmSiv, KeyInit, Nonce,
};

use crate::parse::AesGcmSivVector;

pub fn verify_one(v: &AesGcmSivVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!("━━━ {} ━━━", v.description));

    if v.nonce.len() != 12 {
        log.push(format!("  ✗ nonce length {} != 12", v.nonce.len()));
        return (false, log);
    }

    let payload = Payload { msg: &v.plaintext, aad: &v.aad };
    let nonce   = Nonce::from_slice(&v.nonce);

    let computed: Vec<u8> = match v.key.len() {
        16 => {
            let cipher = Aes128GcmSiv::new_from_slice(&v.key).expect("AES-128 key");
            match cipher.encrypt(nonce, payload) {
                Ok(out) => out,
                Err(e)  => {
                    log.push(format!("  ✗ AES-128-GCM-SIV encrypt failed: {e}"));
                    return (false, log);
                }
            }
        }
        32 => {
            let cipher = Aes256GcmSiv::new_from_slice(&v.key).expect("AES-256 key");
            match cipher.encrypt(nonce, payload) {
                Ok(out) => out,
                Err(e)  => {
                    log.push(format!("  ✗ AES-256-GCM-SIV encrypt failed: {e}"));
                    return (false, log);
                }
            }
        }
        n => {
            log.push(format!("  ✗ unsupported key length {n} (expected 16 or 32)"));
            return (false, log);
        }
    };

    log.push(format!(
        "  pt: {} B, aad: {} B, key: {} B, computed result: {} B",
        v.plaintext.len(), v.aad.len(), v.key.len(), computed.len(),
    ));

    // Always log a confirmation peek of the bytes: full result for short
    // (≤ 16 bytes), otherwise the first 8 bytes of computed and expected.
    if computed.len() <= 16 {
        log.push(format!("  computed: {}", hex::encode(&computed)));
        log.push(format!("  expected: {}", hex::encode(&v.result)));
    } else {
        log.push(format!("  computed[0..8]: {}", hex::encode(&computed[..8])));
        log.push(format!("  expected[0..8]: {}", hex::encode(&v.result[..8.min(v.result.len())])));
    }

    if computed != v.result {
        for (i, (a, b)) in computed.iter().zip(v.result.iter()).enumerate() {
            if a != b {
                log.push(format!(
                    "  ✗ first byte mismatch at offset {i}: computed=0x{:02x}, expected=0x{:02x}",
                    a, b,
                ));
                break;
            }
        }
        if computed.len() != v.result.len() {
            log.push(format!(
                "  ✗ length mismatch: computed={} expected={}",
                computed.len(), v.result.len(),
            ));
        }
        log.push("  ✗ FAIL".to_string());
        return (false, log);
    }

    log.push("  ✓ ciphertext+tag matches RFC 8452 published result".to_string());
    (true, log)
}
