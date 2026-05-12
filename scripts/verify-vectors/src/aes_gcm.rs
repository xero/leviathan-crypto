// Verifier for McGrew-Viega Appendix B AES-GCM vectors
// (test/vectors/aes_gcm.ts).
//
// 18 vectors: 6 per keysize (AES-128, AES-192, AES-256). Within each
// keysize the 6 cases cover empty/non-empty plaintext + AAD and
// 96-bit / 64-bit / 480-bit IVs. The 96-bit cases take the IV-prepending
// fast path; the others trigger GHASH-on-IV (`AesGcm::init_ctr` in the
// crate, NIST SP 800-38D §7.2 step 2).
//
// `aes-gcm 0.10.3` exposes `AesGcm<Aes, NonceSize, TagSize>` as fully
// generic, with built-in handling for any `NonceSize: ArrayLength<u8>`.
// We instantiate three nonce sizes (U8, U12, U60) for the three IV
// regimes the McGrew-Viega corpus exercises. AES-192 has no
// `Aes192Gcm` type alias in this crate version, so we name
// `AesGcm<aes::Aes192, _>` explicitly via the crate's re-exported
// internal `aes` module (`aes-gcm 0.10.3` re-exports `aes 0.8`,
// independent of our direct `aes 0.9` dep used by the FIPS-197 / CBC
// / CTR verifiers).

use aes_gcm::aead::Payload;
use aes_gcm::aead::generic_array::typenum::{U8, U12, U60};
use aes_gcm::aes::{Aes128, Aes192, Aes256};
use aes_gcm::AesGcm;

use crate::parse::AesGcmVector;

pub fn verify_one(v: &AesGcmVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!("━━━ {} ━━━", v.description));

    let payload = Payload { msg: &v.pt, aad: &v.aad };
    let mut expected = v.ct.clone();
    expected.extend_from_slice(&v.tag);

    let computed = match (v.key.len(), v.iv.len()) {
        // 96-bit IVs (recommended fast path)
        (16, 12) => encrypt::<AesGcm<Aes128, U12>>(&v.key, &v.iv, payload),
        (24, 12) => encrypt::<AesGcm<Aes192, U12>>(&v.key, &v.iv, payload),
        (32, 12) => encrypt::<AesGcm<Aes256, U12>>(&v.key, &v.iv, payload),
        // 64-bit IVs (test cases 5, 11, 17, exercise GHASH-on-IV)
        (16, 8)  => encrypt::<AesGcm<Aes128, U8>>(&v.key, &v.iv, payload),
        (24, 8)  => encrypt::<AesGcm<Aes192, U8>>(&v.key, &v.iv, payload),
        (32, 8)  => encrypt::<AesGcm<Aes256, U8>>(&v.key, &v.iv, payload),
        // 480-bit IVs (test cases 6, 12, 18, exercise GHASH-on-IV)
        (16, 60) => encrypt::<AesGcm<Aes128, U60>>(&v.key, &v.iv, payload),
        (24, 60) => encrypt::<AesGcm<Aes192, U60>>(&v.key, &v.iv, payload),
        (32, 60) => encrypt::<AesGcm<Aes256, U60>>(&v.key, &v.iv, payload),
        (k, n)   => {
            log.push(format!("  ✗ unsupported (key={k} B, iv={n} B) combination"));
            return (false, log);
        }
    };

    let computed = match computed {
        Ok(c)  => c,
        Err(e) => { log.push(format!("  ✗ encrypt failed: {e}")); return (false, log); }
    };

    log.push(format!(
        "  key: {} B, iv: {} B ({}-bit, {}), aad: {} B, pt: {} B → ct||tag: {} B",
        v.key.len(), v.iv.len(), v.iv.len() * 8,
        if v.iv.len() == 12 { "fast path" } else { "GHASH-on-IV" },
        v.aad.len(), v.pt.len(), computed.len(),
    ));

    let n = computed.len().min(16);
    log.push(format!("  computed[0..{}]: {}", n, hex::encode(&computed[..n])));
    let m = expected.len().min(16);
    log.push(format!("  expected[0..{}]: {}", m, hex::encode(&expected[..m])));

    if computed != expected {
        for (i, (a, b)) in computed.iter().zip(expected.iter()).enumerate() {
            if a != b {
                log.push(format!(
                    "  ✗ first byte mismatch at offset {i}: computed=0x{:02x}, expected=0x{:02x}",
                    a, b,
                ));
                break;
            }
        }
        if computed.len() != expected.len() {
            log.push(format!("  ✗ length mismatch: computed={} expected={}", computed.len(), expected.len()));
        }
        log.push("  ✗ FAIL".to_string());
        return (false, log);
    }

    log.push("  ✓ ct||tag matches McGrew-Viega Appendix B published value".to_string());
    (true, log)
}

fn encrypt<G>(key: &[u8], iv: &[u8], payload: Payload<'_, '_>) -> Result<Vec<u8>, String>
where
    G: aes_gcm::aead::Aead + aes_gcm::aead::AeadCore + aes_gcm::aead::KeyInit,
{
    let cipher = G::new_from_slice(key).map_err(|_| "key length")?;
    let nonce  = aes_gcm::aead::generic_array::GenericArray::from_slice(iv);
    cipher.encrypt(nonce, payload).map_err(|e| format!("aead encrypt: {e}"))
}
