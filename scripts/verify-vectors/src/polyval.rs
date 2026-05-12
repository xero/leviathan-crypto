// Independent verifier for POLYVAL vectors (RFC 8452 Appendix A
// hash trace). Algebraic primitive vectors (§7 fieldOps, mulX
// pairs) are read but not exercised, they are unit-test bisection
// fixtures for 4b-impl, not verifier load. The SIV vectors
// transitively cover POLYVAL multiplication, so the hash trace
// alone is enough to confirm the transcription.

use polyval::{universal_hash::UniversalHash, Polyval};

use crate::parse::{PolyvalFieldOpsVector, PolyvalHashVector, PolyvalMulXVector};

pub fn verify_one_hash(v: &PolyvalHashVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!("━━━ {} ━━━", v.description));

    if v.h.len() != 16 {
        log.push(format!("  ✗ H length {} != 16", v.h.len()));
        return (false, log);
    }

    let key_arr: [u8; 16] = v.h.as_slice().try_into().expect("H is 16 B");
    let key = polyval::Key::from(key_arr);
    let mut p = Polyval::new(&key);

    for (i, blk) in v.blocks.iter().enumerate() {
        if blk.len() != 16 {
            log.push(format!("  ✗ block #{} length {} != 16", i + 1, blk.len()));
            return (false, log);
        }
        let blk_arr: [u8; 16] = blk.as_slice().try_into().expect("block is 16 B");
        let block = polyval::Block::from(blk_arr);
        p.update(&[block]);
    }

    let tag = p.finalize();
    let got: [u8; 16] = tag.as_slice().try_into().expect("polyval tag is 16 B");

    log.push(format!("  H:        {}",  hex::encode(&v.h)));
    for (i, blk) in v.blocks.iter().enumerate() {
        log.push(format!("  X_{}:      {}", i + 1, hex::encode(blk)));
    }
    log.push(format!("  computed: {}", hex::encode(got)));
    log.push(format!("  expected: {}", hex::encode(&v.expected)));

    if got.as_slice() != v.expected.as_slice() {
        for (i, (a, b)) in got.iter().zip(v.expected.iter()).enumerate() {
            if a != b {
                log.push(format!(
                    "  ✗ first byte mismatch at offset {i}: computed=0x{:02x}, expected=0x{:02x}",
                    a, b,
                ));
                break;
            }
        }
        log.push("  ✗ FAIL".to_string());
        return (false, log);
    }

    log.push("  ✓ POLYVAL(H, X_1..n) matches RFC 8452 Appendix A".to_string());
    (true, log)
}

/// Algebraic / mulX vectors are kept for the WASM unit-test gate but the
/// verifier does not exercise them, RustCrypto's `polyval` does not
/// expose `dot()` or `mulX_GHASH` directly, and the SIV corpus already
/// transitively covers POLYVAL multiplication. We still log them so
/// reviewers can see the corpus is being read end-to-end.
pub fn carry_field_ops(v: &PolyvalFieldOpsVector) -> Vec<String> {
    vec![format!("  carrying (unit-test only): {}", v.description)]
}

pub fn carry_mul_x(v: &PolyvalMulXVector) -> Vec<String> {
    vec![format!("  carrying (unit-test only): {}", v.description)]
}
