// Verifier for SP 800-38A §F.5 AES-CTR vectors (test/vectors/aes_ctr.ts).
//
// CRITICAL: vectors use the full 128-bit Initial Counter Block,
// incremented as a 128-bit big-endian integer per SP 800-38A
// Appendix B.1. The matching cipher type is `Ctr128BE`. Do NOT use
// `Ctr64BE` (32-bit counter in the last 4 bytes of ICB, which is
// the GCM/SIV convention) or `Ctr32BE` — both will fail these
// vectors immediately on the very first block.

use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use aes::{Aes128, Aes192, Aes256};

use crate::parse::AesCtrVector;

pub fn verify_encrypt(v: &AesCtrVector) -> (bool, Vec<String>) {
    run::<Aes128, Aes192, Aes256>(v, /*encrypt =*/ true)
}

pub fn verify_decrypt(v: &AesCtrVector) -> (bool, Vec<String>) {
    run::<Aes128, Aes192, Aes256>(v, /*encrypt =*/ false)
}

fn run<C128, C192, C256>(v: &AesCtrVector, encrypt: bool) -> (bool, Vec<String>)
where
    C128: ctr::cipher::BlockCipherEncrypt + ctr::cipher::KeyInit
        + ctr::cipher::BlockSizeUser<BlockSize = ctr::cipher::consts::U16>,
    C192: ctr::cipher::BlockCipherEncrypt + ctr::cipher::KeyInit
        + ctr::cipher::BlockSizeUser<BlockSize = ctr::cipher::consts::U16>,
    C256: ctr::cipher::BlockCipherEncrypt + ctr::cipher::KeyInit
        + ctr::cipher::BlockSizeUser<BlockSize = ctr::cipher::consts::U16>,
{
    let mut log = Vec::new();
    let direction = if encrypt { "encrypt" } else { "decrypt" };
    log.push(format!("━━━ {}: {} ━━━", direction, v.description));

    if v.initial_counter.len() != 16 {
        log.push(format!("  ✗ initialCounter must be 16 B (got {})", v.initial_counter.len()));
        return (false, log);
    }

    let (input, expected) = if encrypt { (&v.pt, &v.ct) } else { (&v.ct, &v.pt) };
    let mut buf = input.clone();

    let ok_apply = match v.key.len() {
        16 => apply::<C128>(&v.key, &v.initial_counter, &mut buf),
        24 => apply::<C192>(&v.key, &v.initial_counter, &mut buf),
        32 => apply::<C256>(&v.key, &v.initial_counter, &mut buf),
        n  => { log.push(format!("  ✗ unsupported key length {n}")); return (false, log); }
    };
    if let Err(e) = ok_apply {
        log.push(format!("  ✗ keystream apply failed: {e}"));
        return (false, log);
    }

    let n = input.len().min(16);
    log.push(format!("  input[0..{}]:    {}", n, hex::encode(&input[..n])));
    let m = buf.len().min(16);
    log.push(format!("  computed[0..{}]: {}", m, hex::encode(&buf[..m])));
    let p = expected.len().min(16);
    log.push(format!("  expected[0..{}]: {}", p, hex::encode(&expected[..p])));

    if &buf != expected {
        for (i, (a, b)) in buf.iter().zip(expected.iter()).enumerate() {
            if a != b {
                log.push(format!(
                    "  first byte mismatch at offset {i}: computed=0x{:02x}, expected=0x{:02x}",
                    a, b,
                ));
                break;
            }
        }
        log.push(format!("  ✗ {direction} FAIL"));
        return (false, log);
    }

    log.push(format!("  ✓ {direction} matches SP 800-38A §F.5 (Ctr128BE / 128-bit BE counter)"));
    (true, log)
}

fn apply<C>(key: &[u8], iv: &[u8], buf: &mut [u8]) -> Result<(), &'static str>
where
    C: ctr::cipher::BlockCipherEncrypt + ctr::cipher::KeyInit
       + ctr::cipher::BlockSizeUser<BlockSize = ctr::cipher::consts::U16>,
{
    let mut cipher = Ctr128BE::<C>::new_from_slices(key, iv)
        .map_err(|_| "CTR key/iv init")?;
    cipher.apply_keystream(buf);
    Ok(())
}
