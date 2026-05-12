// Verifier for FIPS 197 AES vectors (test/vectors/aes.ts).
//
// Verified end-to-end:
//   - aes128CipherVectors, aes192CipherVectors, aes256CipherVectors
//     (1 record each = 3 total) via RustCrypto's `aes` crate, exercising
//     both the encrypt and decrypt directions.
//
// Carried (read but not exercised, RustCrypto's `aes` crate does not
// expose round-key schedules, S-box lookups, or per-round state):
//   - aesKeyExpansionVectors (3 records)
//   - aesSboxTable (256-byte Uint8Array)
//   - aesRoundIntermediates128/192/256 (10 / 12 / 14 records)
//
// Same carry pattern as polyval's algebraic vectors: the cipher
// vectors transitively exercise the schedule and round logic; the
// carried entries are unit-test bisection fixtures for Phase 4b's
// WASM AES, not verifier load.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, array::Array};
use aes::{Aes128, Aes192, Aes256};

use crate::parse::{AesBlockVector, AesVectors};

pub fn verify(av: &AesVectors) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    let mut all_ok = true;

    log.push("FIPS 197 cipher vectors (one per keysize), verified end-to-end:".to_string());
    log.push(String::new());

    for v in &av.cipher_128 { let (ok, sub) = verify_block::<Aes128>(v, 16); log.extend(sub); if !ok { all_ok = false; } }
    for v in &av.cipher_192 { let (ok, sub) = verify_block::<Aes192>(v, 24); log.extend(sub); if !ok { all_ok = false; } }
    for v in &av.cipher_256 { let (ok, sub) = verify_block::<Aes256>(v, 32); log.extend(sub); if !ok { all_ok = false; } }

    log.push(String::new());
    log.push("Algebraic / round-trace vectors are unit-test fixtures; verifier carries them but does not exercise them.".to_string());
    for v in &av.key_expansion {
        log.push(format!("  carrying (unit-test only): {}", v.description));
    }
    if let Some(sbox) = &av.sbox {
        if sbox.len() == 256 {
            log.push("  carrying (unit-test only): aesSboxTable (FIPS 197 §5.1.1 Figure 7, 256 bytes)".to_string());
        } else {
            log.push(format!("  ✗ aesSboxTable length {} != 256", sbox.len()));
            all_ok = false;
        }
    } else {
        log.push("  carrying (unit-test only): aesSboxTable (parser skipped Uint8Array literal)".to_string());
    }
    for v in &av.round_inter_128 { log.push(format!("  carrying (unit-test only): {}", v.description)); }
    for v in &av.round_inter_192 { log.push(format!("  carrying (unit-test only): {}", v.description)); }
    for v in &av.round_inter_256 { log.push(format!("  carrying (unit-test only): {}", v.description)); }

    (all_ok, log)
}

fn verify_block<C>(v: &AesBlockVector, expect_key_len: usize) -> (bool, Vec<String>)
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + KeyInit
       + aes::cipher::BlockSizeUser<BlockSize = aes::cipher::consts::U16>,
{
    let mut log = Vec::new();
    log.push(format!("━━━ {} ━━━", v.description));

    if v.key.len() != expect_key_len {
        log.push(format!("  ✗ key length {} != expected {}", v.key.len(), expect_key_len));
        return (false, log);
    }
    if v.pt.len() != 16 || v.ct.len() != 16 {
        log.push(format!("  ✗ pt/ct must be 16 bytes (got pt={}, ct={})", v.pt.len(), v.ct.len()));
        return (false, log);
    }

    let cipher = match C::new_from_slice(&v.key) {
        Ok(c)  => c,
        Err(e) => { log.push(format!("  ✗ key init failed: {e}")); return (false, log); }
    };

    let mut block: Array<u8, aes::cipher::consts::U16> = Array::try_from(v.pt.as_slice())
        .expect("pt is 16 B");
    cipher.encrypt_block(&mut block);
    let got_ct: Vec<u8> = block.to_vec();

    log.push(format!("  pt:        {}", hex::encode(&v.pt)));
    log.push(format!("  computed:  {}", hex::encode(&got_ct)));
    log.push(format!("  expected:  {}", hex::encode(&v.ct)));

    if got_ct != v.ct {
        for (i, (a, b)) in got_ct.iter().zip(v.ct.iter()).enumerate() {
            if a != b {
                log.push(format!(
                    "  ✗ first ciphertext byte mismatch at offset {i}: computed=0x{:02x}, expected=0x{:02x}",
                    a, b,
                ));
                break;
            }
        }
        log.push("  ✗ encrypt FAIL".to_string());
        return (false, log);
    }

    // Round-trip decrypt to confirm symmetry.
    let mut back: Array<u8, aes::cipher::consts::U16> = Array::try_from(got_ct.as_slice())
        .expect("ct is 16 B");
    cipher.decrypt_block(&mut back);
    let got_pt: Vec<u8> = back.to_vec();
    if got_pt != v.pt {
        log.push(format!("  ✗ decrypt did not round-trip: got {}", hex::encode(&got_pt)));
        return (false, log);
    }

    log.push("  ✓ encrypt + decrypt match FIPS 197 cipher example".to_string());
    (true, log)
}
