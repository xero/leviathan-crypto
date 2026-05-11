// Independent verifier for SP 800-185 KMAC and cSHAKE vectors.
//
// Reads `kmac.ts` (parsed by `parse::parse_*_array`) and runs each
// record through tiny-keccak. Twelve exports total:
//
//   cshake{128,256}_appendix_a / _acvp                  → CShake
//   kmac{128,256}_appendix_a / _acvp     (xof = false)  → Kmac
//   kmacxof{128,256}_appendix_a / _acvp  (xof = true)   → Kmac::into_xof
//
// Two of the ACVP exports (kmac256_acvp, kmacxof128_acvp) are
// deliberately empty: no byte-aligned records survived the Phase 1
// filter for those slots. The verifier still calls the appropriate
// parse + iterate path so the wiring exercises both variants.
//
// Oracle: tiny-keccak. tiny-keccak is the only verifier dep outside the
// RustCrypto family and lives here because RustCrypto's `kmac` is a
// 0.0.0 placeholder and the pinned `sha3 = "=0.11.0"` does not expose
// `CShake`. The crate-selection rationale is recorded in the per-dep
// audit comment in `Cargo.toml`. tiny-keccak's Keccak[1600] permutation
// is a separate lineage from RustCrypto's `sha3`, which keeps the
// "independent of leviathan-crypto's WASM stack" claim intact.
//
// Scope: byte-oriented only. leviathan-crypto's KMAC and cSHAKE WASM
// surface consumes Uint8Array; bit-level ACVP cases were dropped at
// Phase 1 to match. Every record pinned in `kmac.ts` is byte-aligned by
// construction; the assertions below enforce that as a parser sanity
// check and would fire if a future corpus edit broke the invariant.
//
// References: SP 800-185 §3 (cSHAKE), §4 (KMAC). The pinned samples
// come from the three NIST CSRC sample PDFs (cSHAKE_samples.pdf,
// KMAC_samples.pdf, KMACXOF_samples.pdf); the ACVP records come from
// vsId=0 in the corresponding ACVP-Server directories. Provenance is
// recorded in the `kmac.ts` doc comment.

use tiny_keccak::{CShake, Hasher, IntoXof, Kmac, Xof};

use crate::byte_diff::log_byte_diff;
use crate::parse::{
    CshakeAcvpVector, CshakeSampleVector, KmacAcvpVector, KmacSampleVector,
};

// ────────────────────────────────────────────────────────────────────────────
// Bit-to-byte helpers + tiny-keccak adapters.
// ────────────────────────────────────────────────────────────────────────────

fn assert_byte_aligned(label: &str, bits: u32, log: &mut Vec<String>) -> Option<usize> {
    if bits % 8 != 0 {
        log.push(format!("  ✗ {label}: {bits} bits is not byte-aligned (Phase 1 filter bug?)"));
        return None;
    }
    Some((bits / 8) as usize)
}

fn truncate_to_bits(hex_bytes: &[u8], byte_len: usize, label: &str, log: &mut Vec<String>) -> Option<Vec<u8>> {
    if hex_bytes.len() < byte_len {
        log.push(format!(
            "  ✗ {label}: hex carries {} bytes but declared length is {} bytes",
            hex_bytes.len(), byte_len,
        ));
        return None;
    }
    Some(hex_bytes[..byte_len].to_vec())
}

fn cshake_compute(security_bits: u32, n: &[u8], s: &[u8], msg: &[u8], out_bytes: usize) -> Vec<u8> {
    let mut h = if security_bits == 128 { CShake::v128(n, s) } else { CShake::v256(n, s) };
    h.update(msg);
    let mut out = vec![0u8; out_bytes];
    h.finalize(&mut out);
    out
}

fn kmac_compute(security_bits: u32, key: &[u8], custom: &[u8], msg: &[u8], out_bytes: usize) -> Vec<u8> {
    let mut h = if security_bits == 128 { Kmac::v128(key, custom) } else { Kmac::v256(key, custom) };
    h.update(msg);
    let mut out = vec![0u8; out_bytes];
    h.finalize(&mut out);
    out
}

fn kmacxof_compute(security_bits: u32, key: &[u8], custom: &[u8], msg: &[u8], out_bytes: usize) -> Vec<u8> {
    let mut h = if security_bits == 128 { Kmac::v128(key, custom) } else { Kmac::v256(key, custom) };
    h.update(msg);
    let mut xof = h.into_xof();
    let mut out = vec![0u8; out_bytes];
    xof.squeeze(&mut out);
    out
}

// ────────────────────────────────────────────────────────────────────────────
// cSHAKE verifiers.
//
// `label` is the export name from the dispatcher (e.g. "cshake128_acvp");
// surfaced in the header line so failure logs identify the export.
// ────────────────────────────────────────────────────────────────────────────

pub fn verify_cshake_sample(label: &str, security_bits: u32, v: &CshakeSampleVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!("━━━ {label}: {} ━━━", v.description));

    let Some(msg_len)  = assert_byte_aligned("msgLenBits", v.msg_len_bits, &mut log) else { return (false, log); };
    let Some(out_len)  = assert_byte_aligned("outLenBits", v.out_len_bits, &mut log) else { return (false, log); };
    let Some(msg)      = truncate_to_bits(&v.msg, msg_len, "msg", &mut log) else { return (false, log); };

    let got = cshake_compute(security_bits, v.n.as_bytes(), v.s.as_bytes(), &msg, out_len);

    log_byte_diff(&mut log, "cSHAKE output", &got, &v.expected);
    if got == v.expected {
        (true, log)
    } else {
        log.push(format!("  computed: {}", hex::encode(&got)));
        log.push(format!("  expected: {}", hex::encode(&v.expected)));
        log.push(format!("  ✗ {label}: cSHAKE{security_bits} sample mismatch"));
        (false, log)
    }
}

pub fn verify_cshake_acvp(label: &str, security_bits: u32, v: &CshakeAcvpVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!("━━━ {label} tcId={} (tgId={}) ━━━", v.tc_id, v.tg_id));

    let Some(msg_len) = assert_byte_aligned("msgLenBits", v.msg_len_bits, &mut log) else { return (false, log); };
    let Some(out_len) = assert_byte_aligned("outLenBits", v.out_len_bits, &mut log) else { return (false, log); };
    let Some(msg)     = truncate_to_bits(&v.msg, msg_len, "msg", &mut log) else { return (false, log); };

    let n_bytes = v.function_name.as_bytes().to_vec();
    let s_bytes = if v.hex_customization {
        match hex::decode(&v.customization) {
            Ok(b)  => b,
            Err(e) => { log.push(format!("  ✗ customization (hex): {e}")); return (false, log); }
        }
    } else {
        v.customization.as_bytes().to_vec()
    };

    let got = cshake_compute(security_bits, &n_bytes, &s_bytes, &msg, out_len);

    log_byte_diff(&mut log, "cSHAKE output", &got, &v.md);
    if got == v.md {
        (true, log)
    } else {
        log.push(format!("  computed: {}", hex::encode(&got)));
        log.push(format!("  expected: {}", hex::encode(&v.md)));
        log.push(format!("  ✗ {label} tcId={}: cSHAKE{security_bits} ACVP mismatch", v.tc_id));
        (false, log)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// KMAC verifiers (KMAC fixed-output and KMACXOF variable-output).
//
// Sample verifier carries an explicit xof flag because KmacSampleVector
// is shared across both KMAC and KMACXOF sample arrays (the variant is
// encoded in the export name, not the record). ACVP verifier reads the
// xof flag from the record itself.
// ────────────────────────────────────────────────────────────────────────────

pub fn verify_kmac_sample(label: &str, security_bits: u32, xof: bool, v: &KmacSampleVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!("━━━ {label}: {} ━━━", v.description));

    let Some(key_len) = assert_byte_aligned("keyLenBits", v.key_len_bits, &mut log) else { return (false, log); };
    let Some(msg_len) = assert_byte_aligned("msgLenBits", v.msg_len_bits, &mut log) else { return (false, log); };
    let Some(out_len) = assert_byte_aligned("outLenBits", v.out_len_bits, &mut log) else { return (false, log); };
    let Some(key)     = truncate_to_bits(&v.key, key_len, "key", &mut log) else { return (false, log); };
    let Some(msg)     = truncate_to_bits(&v.msg, msg_len, "msg", &mut log) else { return (false, log); };

    let got = if xof {
        kmacxof_compute(security_bits, &key, v.s.as_bytes(), &msg, out_len)
    } else {
        kmac_compute(security_bits, &key, v.s.as_bytes(), &msg, out_len)
    };

    let label_short = if xof { format!("KMACXOF{security_bits}") } else { format!("KMAC{security_bits}") };
    log_byte_diff(&mut log, &format!("{label_short} output"), &got, &v.expected);
    if got == v.expected {
        (true, log)
    } else {
        log.push(format!("  computed: {}", hex::encode(&got)));
        log.push(format!("  expected: {}", hex::encode(&v.expected)));
        log.push(format!("  ✗ {label}: {label_short} sample mismatch"));
        (false, log)
    }
}

pub fn verify_kmac_acvp(label: &str, security_bits: u32, v: &KmacAcvpVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    let label_short = if v.xof { format!("KMACXOF{security_bits}") } else { format!("KMAC{security_bits}") };
    log.push(format!(
        "━━━ {label} tcId={} (tgId={}, testType={}, xof={}, hexCust={}) ━━━",
        v.tc_id, v.tg_id, v.test_type, v.xof, v.hex_customization,
    ));

    let Some(key_len) = assert_byte_aligned("keyLenBits", v.key_len_bits, &mut log) else { return (false, log); };
    let Some(msg_len) = assert_byte_aligned("msgLenBits", v.msg_len_bits, &mut log) else { return (false, log); };
    let Some(mac_len) = assert_byte_aligned("macLenBits", v.mac_len_bits, &mut log) else { return (false, log); };
    let Some(key)     = truncate_to_bits(&v.key, key_len, "key", &mut log) else { return (false, log); };
    let Some(msg)     = truncate_to_bits(&v.msg, msg_len, "msg", &mut log) else { return (false, log); };

    let custom_bytes: Vec<u8> = if v.hex_customization {
        v.customization_hex.clone().unwrap_or_default()
    } else {
        v.customization.as_deref().unwrap_or("").as_bytes().to_vec()
    };

    let computed = if v.xof {
        kmacxof_compute(security_bits, &key, &custom_bytes, &msg, mac_len)
    } else {
        kmac_compute(security_bits, &key, &custom_bytes, &msg, mac_len)
    };

    let outcome = match v.test_type.as_str() {
        "AFT" => computed == v.mac,
        "MVT" => {
            let expected = match v.test_passed {
                Some(b) => b,
                None    => { log.push("  ✗ MVT record missing testPassed".into()); return (false, log); }
            };
            (computed == v.mac) == expected
        }
        other => {
            log.push(format!("  ✗ unknown testType '{other}' on tcId={}", v.tc_id));
            return (false, log);
        }
    };

    if outcome {
        (true, log)
    } else {
        log_byte_diff(&mut log, &format!("{label_short} output"), &computed, &v.mac);
        log.push(format!("  computed: {}", hex::encode(&computed)));
        log.push(format!("  supplied mac: {}", hex::encode(&v.mac)));
        if v.test_type == "MVT" {
            log.push(format!("  testPassed expected: {}", v.test_passed.unwrap()));
        }
        log.push(format!("  ✗ {label} tcId={}: {label_short} ACVP {} mismatch",
            v.tc_id, v.test_type));
        (false, log)
    }
}
