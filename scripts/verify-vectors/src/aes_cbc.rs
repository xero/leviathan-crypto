// Verifier for SP 800-38A §F.2 AES-CBC vectors (test/vectors/aes_cbc.ts).
//
// Verified end-to-end:
//   - aesCbcEncryptVectors (3 records) via cbc::Encryptor<AesN>
//   - aesCbcDecryptVectors (3 records) via cbc::Decryptor<AesN>
//
// The §F.2 plaintexts are exact 4-block (64-byte) multiples of the AES
// block size, so the matching padding choice is `NoPadding`. Using the
// crate's PKCS#7 default would inject an extra 16-byte all-0x10 padding
// block and corrupt the comparison.

use cbc::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use aes::{Aes128, Aes192, Aes256};

use crate::parse::AesCbcVector;

pub fn verify_encrypt(v: &AesCbcVector) -> (bool, Vec<String>) {
    match v.key.len() {
        16 => verify_enc::<Aes128>(v),
        24 => verify_enc::<Aes192>(v),
        32 => verify_enc::<Aes256>(v),
        n  => (false, vec![format!("━━━ {} ━━━", v.description),
                           format!("  ✗ unsupported key length {n} (expected 16, 24, or 32)")]),
    }
}

pub fn verify_decrypt(v: &AesCbcVector) -> (bool, Vec<String>) {
    match v.key.len() {
        16 => verify_dec::<Aes128>(v),
        24 => verify_dec::<Aes192>(v),
        32 => verify_dec::<Aes256>(v),
        n  => (false, vec![format!("━━━ {} ━━━", v.description),
                           format!("  ✗ unsupported key length {n} (expected 16, 24, or 32)")]),
    }
}

fn verify_enc<C>(v: &AesCbcVector) -> (bool, Vec<String>)
where
    C: cbc::cipher::BlockCipherEncrypt + cbc::cipher::KeyInit
       + cbc::cipher::BlockSizeUser<BlockSize = cbc::cipher::consts::U16>,
{
    let mut log = Vec::new();
    log.push(format!("━━━ encrypt: {} ━━━", v.description));
    if v.iv.len() != 16 || v.pt.len() % 16 != 0 {
        log.push(format!("  ✗ iv must be 16 B, pt must be a multiple of 16 B (got iv={}, pt={})", v.iv.len(), v.pt.len()));
        return (false, log);
    }

    let cipher = Encryptor::<C>::new_from_slices(&v.key, &v.iv)
        .expect("CBC encryptor key/iv");
    let got = cipher.encrypt_padded_vec::<NoPadding>(&v.pt);

    log_pt_ct(&mut log, &v.pt, &got, &v.ct);

    if got != v.ct {
        diff_first_byte(&mut log, &got, &v.ct);
        log.push("  ✗ encrypt FAIL".to_string());
        return (false, log);
    }
    log.push("  ✓ encrypt matches SP 800-38A §F.2 ciphertext".to_string());
    (true, log)
}

fn verify_dec<C>(v: &AesCbcVector) -> (bool, Vec<String>)
where
    C: cbc::cipher::BlockCipherDecrypt + cbc::cipher::KeyInit
       + cbc::cipher::BlockSizeUser<BlockSize = cbc::cipher::consts::U16>,
{
    let mut log = Vec::new();
    log.push(format!("━━━ decrypt: {} ━━━", v.description));
    if v.iv.len() != 16 || v.ct.len() % 16 != 0 {
        log.push(format!("  ✗ iv must be 16 B, ct must be a multiple of 16 B (got iv={}, ct={})", v.iv.len(), v.ct.len()));
        return (false, log);
    }

    let cipher = Decryptor::<C>::new_from_slices(&v.key, &v.iv)
        .expect("CBC decryptor key/iv");
    let got = cipher
        .decrypt_padded_vec::<NoPadding>(&v.ct)
        .expect("NoPadding decrypt of exact-multiple ct");

    log_pt_ct(&mut log, &v.ct, &got, &v.pt);

    if got != v.pt {
        diff_first_byte(&mut log, &got, &v.pt);
        log.push("  ✗ decrypt FAIL".to_string());
        return (false, log);
    }
    log.push("  ✓ decrypt matches SP 800-38A §F.2 plaintext".to_string());
    (true, log)
}

fn log_pt_ct(log: &mut Vec<String>, input: &[u8], got: &[u8], expected: &[u8]) {
    let n = input.len().min(16);
    log.push(format!("  input[0..{}]:    {}", n, hex::encode(&input[..n])));
    let m = got.len().min(16);
    log.push(format!("  computed[0..{}]: {}", m, hex::encode(&got[..m])));
    let p = expected.len().min(16);
    log.push(format!("  expected[0..{}]: {}", p, hex::encode(&expected[..p])));
}

fn diff_first_byte(log: &mut Vec<String>, got: &[u8], expected: &[u8]) {
    for (i, (a, b)) in got.iter().zip(expected.iter()).enumerate() {
        if a != b {
            log.push(format!(
                "  first byte mismatch at offset {i}: computed=0x{:02x}, expected=0x{:02x}",
                a, b,
            ));
            break;
        }
    }
}
