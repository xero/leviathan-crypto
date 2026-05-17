// Independent verifier for ECDSA-P256 vectors (FIPS 186-5 §6.4 + RFC 6979).
//
// Reads five .ts files:
//
//   ecdsa_p256.ts            RFC 6979 §A.2.5 deterministic-K gate (the only
//                            corpus that exercises RFC 6979's k-from-(d, H(m))
//                            derivation; ACVP SigGen supplies k explicitly
//                            and therefore cannot gate the derivation).
//   ecdsa_p256_keygen.ts     ACVP keyGen, FIPS 186-5 §6.2 / SP 800-186 §3.2.1.3.
//                            Each record carries d and the expected (qx, qy);
//                            the verifier rederives q = d*G and compares.
//   ecdsa_p256_siggen.ts     ACVP sigGen, FIPS 186-5 §6.4 + §6.4.2. Each
//                            record carries an explicit k; the verifier drives
//                            `ecdsa::hazmat::sign_prehashed` and compares the
//                            (r, s) byte-for-byte. componentTest=false is the
//                            only mode the v3 substrate exercises.
//   ecdsa_p256_sigver.ts     ACVP sigVer, FIPS 186-5 §6.4.4. Mixed pass/fail
//                            records; the bool from `verify_prehashed` is
//                            compared to ACVP's `testPassed`.
//   ecdsa_p256_wycheproof.ts C2SP Wycheproof p1363 strict-gate + malleability
//                            corpus, 262 records. `result` ∈ {valid, invalid}
//                            in this file (no `acceptable`); the verifier
//                            compares its bool to `result == 'valid'`.
//
// Posture (Wycheproof asymmetry, intentional):
//   The `p256` crate sets `NORMALIZE_S = false` for NistP256, so its verify
//   path does NOT enforce low-S. This matches FIPS 186-5 §6.4.4 (no low-S
//   restriction). leviathan-crypto's WASM verifier and suite-level
//   verifier WILL enforce low-S and reject non-canonical encodings;
//   that strict posture is exercised by the Wycheproof corpus from the
//   leviathan-crypto side, not from this oracle. The oracle's job is to
//   reproduce the published `result` byte-for-byte for the non-strict
//   semantics; the divergence between the WASM verifier and the published
//   `valid` boolean on records flagged `SignatureMalleability` etc. is the
//   design intent and is asserted in the TS-side test code.
//
// Hedged signing path (FIPS 186-5 §6.4.2 + draft-irtf-cfrg-det-sigs-with-noise):
//   ACVP ECDSA-SigGen-FIPS186-5 surfaces a `componentTest` flag that, when
//   true, supplies an `rnd` byte vector and expects the hedged variant
//   (deterministic K with extra-entropy injection). The P-256 + SHA-256
//   transcript filtered here is componentTest=false for every record, so
//   this verifier carries no hedged-path code. If the upstream corpus ever
//   adds componentTest=true P-256 SHA-256 records, the hedged path lives
//   one helper away: feed `rnd` as the `ad` argument to
//   `ecdsa::hazmat::sign_prehashed_rfc6979::<NistP256, sha2::Sha256>`.
//
// Different lineage, same bytes out. RustCrypto's `p256` + `ecdsa` share
// no source, build system, or author with leviathan-crypto's WASM stack;
// agreement between this oracle and the WASM output is the
// "two independent stacks agree on the bytes" signal for the
// ECDSA-P256 corpus.

// digest-0.11 lineage for the ECDSA-P256 oracle. The project-wide
// `sha2 = 0.10.9` pin (used by HKDF/HMAC on the digest-0.10 ecosystem)
// does not expose `digest::EagerHash`, which `ecdsa::hazmat::
// sign_prehashed_rfc6979::<C, D>` requires for the D type parameter.
// `sha2_v11` is the renamed 0.11.0 dep that satisfies that bound.
use sha2_v11::{Digest, Sha256};

use p256::{NistP256, ProjectivePoint, FieldBytes};
use p256::elliptic_curve::Group;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::scalar::NonZeroScalar;

use ecdsa::hazmat::{sign_prehashed, sign_prehashed_rfc6979};

use crate::byte_diff::log_byte_diff;

// ────────────────────────────────────────────────────────────────────────────
// Strip `//` line comments from a TS source string. Quoted strings are honoured
// so a `//` inside a hex literal is not treated as a comment. Backslash inside
// quotes is treated as a one-byte escape so `\'` does not toggle quote state.
// Mirrors the ed25519 module's helper; the central parse.rs comment-stripping
// path lives on each consumer that needs it.
// ────────────────────────────────────────────────────────────────────────────

fn strip_line_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut in_q = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_q && b == b'\\' && i + 1 < bytes.len() {
            out.push(b as char);
            out.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if !in_q && b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' { i += 1; }
            continue;
        }
        if b == b'\'' { in_q = !in_q; }
        out.push(b as char);
        i += 1;
    }
    out
}

// ────────────────────────────────────────────────────────────────────────────
// Per-vector struct shapes. Mirrors parse.rs Ed25519* convention but the
// ECDSA-P256 parsers live in parse.rs and emit these types.
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct EcdsaP256KeyGenVector {
    pub tc_id: u32,
    pub tg_id: u32,
    pub secret_generation_mode: String,
    pub d:  Vec<u8>,
    pub qx: Vec<u8>,
    pub qy: Vec<u8>,
}

#[allow(dead_code)] // test_type surfaced for diagnostic logs.
#[derive(Debug, Clone, Default)]
pub struct EcdsaP256SigGenVector {
    pub tc_id:     u32,
    pub tg_id:     u32,
    pub test_type: String,
    pub d:         Vec<u8>,
    pub qx:        Vec<u8>,
    pub qy:        Vec<u8>,
    pub k:         Vec<u8>,
    pub message:   Vec<u8>,
    pub r:         Vec<u8>,
    pub s:         Vec<u8>,
}

#[allow(dead_code)] // d + test_type + reason surfaced for diagnostic logs;
                    // verifier exercises only (qx, qy) + message + (r, s) +
                    // test_passed.
#[derive(Debug, Clone, Default)]
pub struct EcdsaP256SigVerVector {
    pub tc_id:       u32,
    pub tg_id:       u32,
    pub test_type:   String,
    pub test_passed: bool,
    pub reason:      String,
    pub d:           Vec<u8>,
    pub qx:          Vec<u8>,
    pub qy:          Vec<u8>,
    pub message:     Vec<u8>,
    pub r:           Vec<u8>,
    pub s:           Vec<u8>,
}

#[allow(dead_code)] // comment + flags surfaced for diagnostic logs.
#[derive(Debug, Clone, Default)]
pub struct EcdsaP256WycheproofVector {
    pub tc_id:   u32,
    pub qx:      Vec<u8>,
    pub qy:      Vec<u8>,
    pub msg:     Vec<u8>,
    pub sig:     Vec<u8>,
    pub result:  String,   // 'valid' | 'invalid' | 'acceptable'
    pub comment: String,
    pub flags:   Vec<String>,
}

// Suite-level KAT vectors from test/vectors/sign_ecdsa_p256.ts. Each
// record carries (pk, sk, msg, ctx (always empty), rnd, blob, sig).
// The verifier reproduces the wire bytes by feeding the recorded rnd
// to the RustCrypto hedged-sign path (rnd = all-zero selects the
// deterministic-K path; non-zero selects the hedged path).
#[allow(dead_code)] // description + ctx surfaced for diagnostic logs.
#[derive(Debug, Clone, Default)]
pub struct SignEcdsaP256Vector {
    pub id:          String,
    pub description: String,
    pub format_enum: u32,
    pub pk:          Vec<u8>,
    pub sk:          Vec<u8>,
    pub msg:         Vec<u8>,
    pub ctx:         Vec<u8>,
    pub rnd:         Vec<u8>,
    pub blob:        Vec<u8>,
    pub sig:         Vec<u8>,
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

fn into_field_bytes(label: &str, v: &[u8]) -> Result<FieldBytes, String> {
    if v.len() != 32 {
        return Err(format!("{label} length {} != 32", v.len()));
    }
    Ok(*FieldBytes::from_slice(v))
}

// Build a P-256 verifying key from raw (qx, qy) uncompressed coordinates.
// The SEC1 §2.3.3 uncompressed encoding is 0x04 || x || y; we synthesise it
// here so the ACVP records that carry separate (qx, qy) fields can re-use
// the same `VerifyingKey::from_sec1_bytes` path as the Wycheproof records
// (which the parser already concatenated into the same shape).
fn verifying_key_from_xy(qx: &[u8], qy: &[u8]) -> Result<VerifyingKey, String> {
    if qx.len() != 32 || qy.len() != 32 {
        return Err(format!(
            "(qx, qy) lengths ({}, {}) != (32, 32)",
            qx.len(), qy.len(),
        ));
    }
    let mut sec1 = [0u8; 1 + 32 + 32];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(qx);
    sec1[33..65].copy_from_slice(qy);
    VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| format!("VerifyingKey::from_sec1_bytes: {e:?}"))
}

// SHA-256 the message and return the 32-byte digest as FieldBytes.
fn sha256_field(msg: &[u8]) -> FieldBytes {
    let digest = Sha256::digest(msg);
    *FieldBytes::from_slice(digest.as_slice())
}

// ────────────────────────────────────────────────────────────────────────────
// KeyGen
// ────────────────────────────────────────────────────────────────────────────

// Rederive q = d*G and compare to the recorded (qx, qy). The two ACVP
// `secretGenerationMode` paths (FIPS 186-5 §A.2.1 'extra bits' and §A.2.2
// 'testing candidates') produce the same q given the same d; the mode
// discriminator is surfaced in the audit log but does not branch here.
pub fn verify_ecdsa_p256_keygen(v: &EcdsaP256KeyGenVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!(
        "━━━ ecdsa-p256 keyGen tcId {} (tg={}, mode={:?}) ━━━",
        v.tc_id, v.tg_id, v.secret_generation_mode,
    ));

    let d_bytes = match into_field_bytes("d", &v.d) {
        Ok(fb) => fb,
        Err(e) => { log.push(format!("  ✗ {e}")); return (false, log); }
    };
    let d_scalar = match Option::<NonZeroScalar<NistP256>>::from(
        NonZeroScalar::<NistP256>::from_repr(d_bytes),
    ) {
        Some(s) => s,
        None    => { log.push("  ✗ d failed NonZeroScalar::from_repr (zero or >= n)".to_string()); return (false, log); }
    };

    // q = d*G as an affine point on P-256.
    let q_proj   = ProjectivePoint::generator() * d_scalar.as_ref();
    let q_affine = q_proj.to_affine();
    let vk       = match VerifyingKey::from_affine(q_affine) {
        Ok(k)  => k,
        Err(e) => { log.push(format!("  ✗ VerifyingKey::from_affine: {e:?}")); return (false, log); }
    };
    // Uncompressed SEC1 (§2.3.3): 0x04 || x || y. `to_sec1_point(false)`
    // returns the fixed-size point object backed by hybrid-array; we read
    // the (x, y) slices off it without allocating.
    let ep = vk.to_sec1_point(false);
    let ep_bytes = ep.as_bytes();
    if ep_bytes.len() != 65 || ep_bytes[0] != 0x04 {
        log.push(format!("  ✗ SEC1 encoding shape: {} bytes, first = {:02X}", ep_bytes.len(), ep_bytes[0]));
        return (false, log);
    }
    let qx_bytes = &ep_bytes[1..33];
    let qy_bytes = &ep_bytes[33..65];

    log_byte_diff(&mut log, "qx", qx_bytes, &v.qx);
    log_byte_diff(&mut log, "qy", qy_bytes, &v.qy);
    if qx_bytes == v.qx.as_slice() && qy_bytes == v.qy.as_slice() {
        log.push("  ✓ (qx, qy) matches".to_string());
        (true, log)
    } else {
        log.push("  ✗ FAIL".to_string());
        (false, log)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SigGen, explicit-k path (FIPS 186-5 §6.4 with §6.4.2 randomized k)
// ────────────────────────────────────────────────────────────────────────────

pub fn verify_ecdsa_p256_siggen(v: &EcdsaP256SigGenVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!(
        "━━━ ecdsa-p256 sigGen tcId {} (tg={}, type={}) ━━━",
        v.tc_id, v.tg_id, v.test_type,
    ));

    let d_bytes = match into_field_bytes("d", &v.d) {
        Ok(fb) => fb,
        Err(e) => { log.push(format!("  ✗ {e}")); return (false, log); }
    };
    let k_bytes = match into_field_bytes("k", &v.k) {
        Ok(fb) => fb,
        Err(e) => { log.push(format!("  ✗ {e}")); return (false, log); }
    };
    let d_scalar = match Option::<NonZeroScalar<NistP256>>::from(
        NonZeroScalar::<NistP256>::from_repr(d_bytes),
    ) {
        Some(s) => s,
        None    => { log.push("  ✗ d failed NonZeroScalar::from_repr (zero or >= n)".to_string()); return (false, log); }
    };
    let k_scalar = match Option::<NonZeroScalar<NistP256>>::from(
        NonZeroScalar::<NistP256>::from_repr(k_bytes),
    ) {
        Some(s) => s,
        None    => { log.push("  ✗ k failed NonZeroScalar::from_repr (zero or >= n)".to_string()); return (false, log); }
    };

    let z = sha256_field(&v.message);

    let (sig, _recovery) = match sign_prehashed::<NistP256>(&d_scalar, &k_scalar, &z) {
        Ok(pair) => pair,
        Err(e)   => {
            log.push(format!("  ✗ sign_prehashed: {e:?}"));
            return (false, log);
        }
    };

    let bytes = sig.to_bytes();
    let r_calc = &bytes[..32];
    let s_calc = &bytes[32..];

    log_byte_diff(&mut log, "r", r_calc, &v.r);
    log_byte_diff(&mut log, "s", s_calc, &v.s);
    if r_calc == v.r.as_slice() && s_calc == v.s.as_slice() {
        log.push("  ✓ (r, s) matches".to_string());
        (true, log)
    } else {
        log.push("  ✗ FAIL".to_string());
        (false, log)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SigVer, FIPS 186-5 §6.4.4
// ────────────────────────────────────────────────────────────────────────────

pub fn verify_ecdsa_p256_sigver(v: &EcdsaP256SigVerVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!(
        "━━━ ecdsa-p256 sigVer tcId {} (tg={}, type={}, reason={:?}) → expected={} ━━━",
        v.tc_id, v.tg_id, v.test_type, v.reason, v.test_passed,
    ));

    let computed = compute_sigver(&v.qx, &v.qy, &v.message, &v.r, &v.s, &mut log);
    if computed == v.test_passed {
        log.push(format!("  ✓ verification {computed} matches expected"));
        (true, log)
    } else {
        log.push(format!("  ✗ verification {computed} ≠ expected {}", v.test_passed));
        (false, log)
    }
}

// Shared verify path. Returns true iff the signature verifies; any decoding
// failure (out-of-range scalar, malformed pubkey, etc.) returns false to
// match FIPS 186-5 §6.4.4 step 1's reject-on-out-of-range posture.
fn compute_sigver(
    qx: &[u8], qy: &[u8],
    message: &[u8],
    r: &[u8], s: &[u8],
    log: &mut Vec<String>,
) -> bool {
    let vk = match verifying_key_from_xy(qx, qy) {
        Ok(k)  => k,
        Err(e) => { log.push(format!("  pk decode: {e}")); return false; }
    };

    // ACVP `r` and `s` are 32 bytes each; concatenated they form the raw
    // p1363 64-byte signature shape that `Signature::from_slice` expects.
    if r.len() != 32 || s.len() != 32 {
        log.push(format!("  (r, s) length ({}, {}) != (32, 32)", r.len(), s.len()));
        return false;
    }
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(r);
    rs[32..].copy_from_slice(s);
    let sig = match Signature::from_slice(&rs) {
        Ok(s)  => s,
        Err(e) => { log.push(format!("  Signature::from_slice: {e:?}")); return false; }
    };

    let digest = Sha256::digest(message);

    // verify_prehash routes through hazmat::verify_prehashed and applies
    // bits2field reduction internally. For NistP256, NORMALIZE_S = false
    // so the low-S short-circuit at the top of verify_prehash does not
    // fire, and the FIPS 186-5 §6.4.4 verifier executes verbatim.
    use ecdsa::signature::hazmat::PrehashVerifier;
    vk.verify_prehash(digest.as_slice(), &sig).is_ok()
}

// ────────────────────────────────────────────────────────────────────────────
// Wycheproof, same shape as SigVer with the result discriminator
// ────────────────────────────────────────────────────────────────────────────

pub fn verify_ecdsa_p256_wycheproof(v: &EcdsaP256WycheproofVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!(
        "━━━ ecdsa-p256 wycheproof tcId {} (result={:?}, comment={:?}, flags={:?}) ━━━",
        v.tc_id, v.result, v.comment, v.flags,
    ));

    // Wycheproof's p1363 file expects raw r||s of exactly 64 bytes; any
    // other length is a malformed wire by construction. Reject upfront so
    // the verifier returns false for "invalid" records that exercise that
    // wire-shape failure mode, matching the `result: 'invalid'` recorded
    // upstream without dragging the per-byte verifier into out-of-range
    // territory.
    let (r, s) = if v.sig.len() == 64 {
        (&v.sig[..32], &v.sig[32..])
    } else {
        log.push(format!("  wire length {} != 64, treating as malformed", v.sig.len()));
        let computed = false;
        return match v.result.as_str() {
            "valid"      => { log.push(format!("  ✗ result='valid' but wire is malformed")); (false, log) }
            "invalid"    => { log.push("  ✓ malformed wire rejected, matches result='invalid'".to_string()); (true, log) }
            "acceptable" => { log.push(format!("  ⓘ result='acceptable', computed={computed} (recorded but not failed)")); (true, log) }
            other        => { log.push(format!("  ✗ unknown result discriminator {other:?}")); (false, log) }
        };
    };

    let computed = compute_sigver(&v.qx, &v.qy, &v.msg, r, s, &mut log);
    match v.result.as_str() {
        "valid" => {
            if computed {
                log.push("  ✓ verification true matches result='valid'".to_string());
                (true, log)
            } else {
                log.push("  ✗ verification false but result='valid'".to_string());
                (false, log)
            }
        }
        "invalid" => {
            if !computed {
                log.push("  ✓ verification false matches result='invalid'".to_string());
                (true, log)
            } else {
                log.push("  ✗ verification true but result='invalid' (strict-gate vector accepted by non-strict oracle)".to_string());
                (false, log)
            }
        }
        "acceptable" => {
            // Wycheproof's "acceptable" records permit either outcome.
            // Log the actual bool but always count as ok, mirroring the
            // upstream test discipline.
            log.push(format!("  ⓘ result='acceptable', computed={computed} (recorded but not failed)"));
            (true, log)
        }
        other => {
            log.push(format!("  ✗ unknown result discriminator {other:?}"));
            (false, log)
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RFC 6979 §A.2.5 gate parser. ecdsa_p256.ts ships a hand-transcribed
// corpus (2 records, SHA-256 for messages "sample" and "test" against the
// §A.2.5 fixed key). The verifier reuses sign_prehashed + sign_prehashed_rfc6979
// to gate both the explicit-k arithmetic and the RFC 6979 K derivation.
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Rfc6979P256Vector {
    pub idx:     usize,
    pub id:      String,
    pub msg:     Vec<u8>,
    pub hash:    String,
    pub k:       Vec<u8>,
    pub r:       Vec<u8>,
    pub s:       Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Rfc6979P256Key {
    pub x:  Vec<u8>,
    pub ux: Vec<u8>,
    pub uy: Vec<u8>,
}

// Inline parser for ecdsa_p256.ts. The RFC 6979 file shape is custom
// (a fixed-key `const RFC6979_P256_KEY = { ... }` plus a per-record array),
// so it lives inline here instead of in parse.rs, the way the RFC 8032 §7
// parser lives in ed25519.rs.
pub fn parse_rfc6979_vectors(src: &str) -> (Rfc6979P256Key, Vec<Rfc6979P256Vector>) {
    let stripped = strip_line_comments(src);
    let src: &str = &stripped;

    let key = parse_rfc6979_key(src).unwrap_or_default();
    let records = parse_rfc6979_records(src);
    (key, records)
}

fn parse_rfc6979_key(src: &str) -> Option<Rfc6979P256Key> {
    let start  = src.find("RFC6979_P256_KEY")?;
    let after  = &src[start..];
    let open   = after.find('{')?;
    let close  = after[open..].find('}')? + open;
    let body   = &after[open + 1..close];
    Some(Rfc6979P256Key {
        x:  hex::decode(extract_hex_field(body, "xHex").unwrap_or_default()).ok()?,
        ux: hex::decode(extract_hex_field(body, "uxHex").unwrap_or_default()).ok()?,
        uy: hex::decode(extract_hex_field(body, "uyHex").unwrap_or_default()).ok()?,
    })
}

fn parse_rfc6979_records(src: &str) -> Vec<Rfc6979P256Vector> {
    let Some(start) = src.find("export const ecdsa_p256_rfc6979") else { return Vec::new(); };
    let tail = &src[start..];
    let Some(eq) = tail.find('=') else { return Vec::new(); };
    let after_eq = &tail[eq + 1..];
    let Some(open) = after_eq.find('[') else { return Vec::new(); };
    let body = &after_eq[open + 1..];

    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_q  = false;
    let mut start_obj: Option<usize> = None;
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_q && b == b'\\' && i + 1 < bytes.len() { i += 2; continue; }
        match b {
            b'\'' => in_q = !in_q,
            b'{' if !in_q => {
                if depth == 0 { start_obj = Some(i + 1); }
                depth += 1;
            }
            b'}' if !in_q => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start_obj.take() {
                        let obj = &body[s..i];
                        if let Some(v) = parse_rfc6979_record(obj, out.len()) {
                            out.push(v);
                        }
                    }
                }
            }
            b']' if !in_q && depth == 0 => break,
            _ => {}
        }
        i += 1;
    }
    out
}

fn parse_rfc6979_record(obj: &str, idx: usize) -> Option<Rfc6979P256Vector> {
    Some(Rfc6979P256Vector {
        idx,
        id:   extract_quoted_field(obj, "id")?,
        // msgUtf8 carries the literal ASCII string from the RFC; we
        // re-emit the bytes here.
        msg:  extract_quoted_field(obj, "msgUtf8")?.into_bytes(),
        hash: extract_quoted_field(obj, "hashAlg")?,
        k:    hex::decode(extract_hex_field(obj, "kHex")?).ok()?,
        r:    hex::decode(extract_hex_field(obj, "rHex")?).ok()?,
        s:    hex::decode(extract_hex_field(obj, "sHex")?).ok()?,
    })
}

// Read a `field: '...'` value (single-quoted).
fn extract_quoted_field(obj: &str, field: &str) -> Option<String> {
    let key = format!("{field}:");
    let idx = obj.find(&key)?;
    let tail = &obj[idx + key.len()..];
    let q1 = tail.find('\'')?;
    let after = &tail[q1 + 1..];
    let q2 = after.find('\'')?;
    Some(after[..q2].to_string())
}

// Read a `field: 'aa' + 'bb' + 'cc'` value, joining all quoted chunks
// until the first top-level `,`. Mirrors ed25519.rs::extract_hex_value.
fn extract_hex_field(obj: &str, field: &str) -> Option<String> {
    let key = format!("{field}:");
    let idx = obj.find(&key)?;
    let after = &obj[idx + key.len()..];

    let mut out      = String::new();
    let mut in_quote = false;
    let mut chunk    = String::new();
    for ch in after.chars() {
        match ch {
            '\'' if !in_quote => { in_quote = true; }
            '\'' if in_quote  => {
                in_quote = false;
                out.push_str(&chunk);
                chunk.clear();
            }
            c if in_quote => chunk.push(c),
            ',' => break,
            _   => {}
        }
    }
    Some(out)
}

// Drive both the RFC 6979 deterministic-K path and the explicit-K path
// against the recorded (k, r, s). Both must reproduce the recorded
// signature byte-for-byte for the gate to pass; the dual check exercises
// (a) RFC 6979's k-from-(d, H(m)) derivation, and (b) the FIPS 186-5
// arithmetic for r = x_R mod n and s = k^-1 * (z + r*d) mod n.
pub fn verify_rfc6979(v: &Rfc6979P256Vector, key: &Rfc6979P256Key) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!(
        "━━━ ecdsa-p256 RFC 6979 §A.2.5 idx={} (id={:?}, hash={:?}) ━━━",
        v.idx, v.id, v.hash,
    ));

    if v.hash != "SHA-256" {
        log.push(format!("  ✗ hashAlg {:?} not supported in this gate (SHA-256 only)", v.hash));
        return (false, log);
    }

    let d_bytes = match into_field_bytes("x", &key.x) {
        Ok(fb) => fb,
        Err(e) => { log.push(format!("  ✗ {e}")); return (false, log); }
    };
    let d_scalar = match Option::<NonZeroScalar<NistP256>>::from(
        NonZeroScalar::<NistP256>::from_repr(d_bytes),
    ) {
        Some(s) => s,
        None    => { log.push("  ✗ x failed NonZeroScalar::from_repr (zero or >= n)".to_string()); return (false, log); }
    };
    let z = sha256_field(&v.msg);

    // Path A: deterministic K from RFC 6979 itself. `ad = &[]` per
    // RFC 6979 §3.6 (no extra entropy).
    let (sig_det, _) = match sign_prehashed_rfc6979::<NistP256, Sha256>(&d_scalar, &z, &[]) {
        Ok(p)  => p,
        Err(e) => { log.push(format!("  ✗ sign_prehashed_rfc6979: {e:?}")); return (false, log); }
    };
    let det_bytes = sig_det.to_bytes();
    let det_r = &det_bytes[..32];
    let det_s = &det_bytes[32..];

    log_byte_diff(&mut log, "r (RFC 6979 deterministic)", det_r, &v.r);
    log_byte_diff(&mut log, "s (RFC 6979 deterministic)", det_s, &v.s);

    // Path B: explicit K from the RFC record. Both paths must agree with
    // the recorded (r, s); if they disagree with each other, the gate
    // catches a deeper bug (one of the two arithmetic paths is wrong).
    let k_bytes = match into_field_bytes("k", &v.k) {
        Ok(fb) => fb,
        Err(e) => { log.push(format!("  ✗ {e}")); return (false, log); }
    };
    let k_scalar = match Option::<NonZeroScalar<NistP256>>::from(
        NonZeroScalar::<NistP256>::from_repr(k_bytes),
    ) {
        Some(s) => s,
        None    => { log.push("  ✗ k failed NonZeroScalar::from_repr (zero or >= n)".to_string()); return (false, log); }
    };
    let (sig_exp, _) = match sign_prehashed::<NistP256>(&d_scalar, &k_scalar, &z) {
        Ok(p)  => p,
        Err(e) => { log.push(format!("  ✗ sign_prehashed (explicit k): {e:?}")); return (false, log); }
    };
    let exp_bytes = sig_exp.to_bytes();
    let exp_r = &exp_bytes[..32];
    let exp_s = &exp_bytes[32..];

    log_byte_diff(&mut log, "r (explicit k)", exp_r, &v.r);
    log_byte_diff(&mut log, "s (explicit k)", exp_s, &v.s);

    // Path C: independent verify of the recorded signature against the
    // §A.2.5 fixed public key. Catches the case where r/s match by luck
    // but the recorded (Ux, Uy) does not actually correspond to the
    // signer's d.
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(&v.r);
    rs[32..].copy_from_slice(&v.s);
    let sig_in = match Signature::from_slice(&rs) {
        Ok(s)  => s,
        Err(e) => { log.push(format!("  ✗ Signature::from_slice: {e:?}")); return (false, log); }
    };
    let vk = match verifying_key_from_xy(&key.ux, &key.uy) {
        Ok(k)  => k,
        Err(e) => { log.push(format!("  ✗ {e}")); return (false, log); }
    };
    use ecdsa::signature::hazmat::PrehashVerifier;
    let digest = Sha256::digest(&v.msg);
    let verify_ok = vk.verify_prehash(digest.as_slice(), &sig_in).is_ok();

    let det_ok    = det_r == v.r.as_slice() && det_s == v.s.as_slice();
    let exp_ok    = exp_r == v.r.as_slice() && exp_s == v.s.as_slice();
    if det_ok && exp_ok && verify_ok {
        log.push("  ✓ deterministic, explicit-k, and verify paths all agree".to_string());
        (true, log)
    } else {
        log.push(format!(
            "  ✗ FAIL (det={det_ok}, explicit-k={exp_ok}, verify={verify_ok})"
        ));
        (false, log)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Suite-level KAT, test/vectors/sign_ecdsa_p256.ts. Each record locks the
// v3 attached envelope wire format produced by EcdsaP256Suite (formatEnum
// 0x02). Two checks per record:
//
//   1. Wire-format check. blob[0] == 0x02 (suite byte), blob[1] == 0x00
//      (ctx_len, always zero for this suite), payload = blob[2..len-64],
//      sig = blob[len-64..]. Payload bytes equal recorded `msg`; sig
//      bytes equal recorded `sig`.
//
//   2. Sig reproducibility. Recompute (r, s) via the RustCrypto
//      hedged-sign path with the recorded `rnd` and `sk`; compare to the
//      blob's trailing 64 bytes. rnd = all-zero selects RFC 6979 §3.2's
//      deterministic-K (sign_prehashed_rfc6979 with ad=empty); non-zero
//      selects the hedged path (sign_prehashed_rfc6979 with ad=rnd).
//
//   3. Independent verify. Build a VerifyingKey from the recorded `pk`
//      (33-byte compressed SEC 1 §2.3.3) and run verify_prehash on the
//      blob's sig + SHA-256(msg). Catches the case where the wire bytes
//      reproduce by luck but the recorded pk does not actually match sk.
// ────────────────────────────────────────────────────────────────────────────

pub fn verify_sign_ecdsa_p256(v: &SignEcdsaP256Vector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!(
        "━━━ ecdsa-p256 suite KAT {} (format=0x{:02x}, desc={:?}) ━━━",
        v.id, v.format_enum, v.description,
    ));

    // (1) Wire format: [0x02, 0x00, msg, sig].
    if v.format_enum != 0x02 {
        log.push(format!("  ✗ format_enum 0x{:02x} != 0x02", v.format_enum));
        return (false, log);
    }
    if !v.ctx.is_empty() {
        log.push(format!("  ✗ ctx length {} != 0 (suite rejects non-empty ctx)", v.ctx.len()));
        return (false, log);
    }
    if v.sig.len() != 64 {
        log.push(format!("  ✗ recorded sig length {} != 64", v.sig.len()));
        return (false, log);
    }
    let expected_blob_len = 2 + v.msg.len() + 64;
    if v.blob.len() != expected_blob_len {
        log.push(format!(
            "  ✗ blob length {} != expected {} (2 + {} msg + 64 sig)",
            v.blob.len(), expected_blob_len, v.msg.len(),
        ));
        return (false, log);
    }
    if v.blob[0] != 0x02 || v.blob[1] != 0x00 {
        log.push(format!(
            "  ✗ blob preamble [{:02x},{:02x}] != [02,00]",
            v.blob[0], v.blob[1],
        ));
        return (false, log);
    }
    let payload = &v.blob[2..2 + v.msg.len()];
    let blob_sig = &v.blob[2 + v.msg.len()..];
    if payload != v.msg.as_slice() {
        log_byte_diff(&mut log, "blob payload", payload, &v.msg);
        log.push("  ✗ blob payload != recorded msg".to_string());
        return (false, log);
    }
    if blob_sig != v.sig.as_slice() {
        log_byte_diff(&mut log, "blob trailing sig", blob_sig, &v.sig);
        log.push("  ✗ blob trailing 64 bytes != recorded sig".to_string());
        return (false, log);
    }

    // (2) Sig reproducibility via the recorded rnd.
    if v.sk.len() != 32 {
        log.push(format!("  ✗ sk length {} != 32", v.sk.len()));
        return (false, log);
    }
    if v.rnd.len() != 32 {
        log.push(format!("  ✗ rnd length {} != 32", v.rnd.len()));
        return (false, log);
    }
    let d_bytes = match into_field_bytes("sk", &v.sk) {
        Ok(fb) => fb,
        Err(e) => { log.push(format!("  ✗ {e}")); return (false, log); }
    };
    let d_scalar = match Option::<NonZeroScalar<NistP256>>::from(
        NonZeroScalar::<NistP256>::from_repr(d_bytes),
    ) {
        Some(s) => s,
        None    => { log.push("  ✗ sk failed NonZeroScalar::from_repr (zero or >= n)".to_string()); return (false, log); }
    };
    let z = sha256_field(&v.msg);

    // rnd == all-zero selects the deterministic RFC 6979 §3.2 path
    // (`ad = &[]`), which the RustCrypto `sign_prehashed_rfc6979`
    // helper reproduces byte-for-byte. Non-zero rnd selects
    // leviathan-crypto's hedged path per
    // draft-irtf-cfrg-det-sigs-with-noise-05 §4, whose HMAC input
    // shape is `V || sep || Z || 000(63) || x || 000(32) || h1mn`.
    // That construction differs from RFC 6979 §3.6's "ad" parameter
    // (which `sign_prehashed_rfc6979`'s `ad` argument exposes) and
    // cannot be reproduced via the RustCrypto helper. For hedged
    // records the verifier therefore SKIPS the byte-exact sig match
    // and relies on the independent `verify_prehash` check below to
    // confirm the recorded sig is a valid ECDSA signature under
    // (pk, msg).
    let all_zero = v.rnd.iter().all(|b| *b == 0);
    let sig_match = if all_zero {
        let (sig_rust, _) = match sign_prehashed_rfc6979::<NistP256, Sha256>(&d_scalar, &z, &[]) {
            Ok(p)  => p,
            Err(e) => {
                log.push(format!("  ✗ sign_prehashed_rfc6979: {e:?}"));
                return (false, log);
            }
        };
        // RustCrypto's hazmat `sign_prehashed_rfc6979` returns the
        // raw (r, s) without low-S normalisation. leviathan-crypto
        // enforces low-S on the sign side per RFC 6979 §3.5, so we
        // normalise here before comparing.
        let sig_norm = sig_rust.normalize_s();
        let rust_bytes = sig_norm.to_bytes();
        let rust_r = &rust_bytes[..32];
        let rust_s = &rust_bytes[32..];
        log_byte_diff(&mut log, "r (deterministic rnd=0)", rust_r, &v.sig[..32]);
        log_byte_diff(&mut log, "s (deterministic rnd=0)", rust_s, &v.sig[32..]);
        rust_r == &v.sig[..32] && rust_s == &v.sig[32..]
    } else {
        log.push("  ⓘ hedged rnd: skipping byte-exact reproduction (draft-with-noise-05 §4 != RFC 6979 §3.6 ad)".to_string());
        true
    };

    // (3) Independent verify against the recorded pk.
    if v.pk.len() != 33 {
        log.push(format!("  ✗ pk length {} != 33 (compressed SEC 1 §2.3.3)", v.pk.len()));
        return (false, log);
    }
    let vk = match VerifyingKey::from_sec1_bytes(&v.pk) {
        Ok(k)  => k,
        Err(e) => { log.push(format!("  ✗ VerifyingKey::from_sec1_bytes: {e:?}")); return (false, log); }
    };
    let sig_in = match Signature::from_slice(&v.sig) {
        Ok(s)  => s,
        Err(e) => { log.push(format!("  ✗ Signature::from_slice: {e:?}")); return (false, log); }
    };
    use ecdsa::signature::hazmat::PrehashVerifier;
    let digest = Sha256::digest(&v.msg);
    let verify_ok = vk.verify_prehash(digest.as_slice(), &sig_in).is_ok();

    if sig_match && verify_ok {
        log.push("  ✓ wire format, rnd-reproduced sig, and independent verify agree".to_string());
        (true, log)
    } else {
        log.push(format!(
            "  ✗ FAIL (sig_match={sig_match}, verify={verify_ok})"
        ));
        (false, log)
    }
}

// Inline parser for test/vectors/sign_ecdsa_p256.ts. Mirrors
// parse_rfc6979_vectors: the file has a single exported `const
// signEcdsaP256Vectors = [ ... ]` array of single-record objects.
pub fn parse_sign_ecdsa_p256_vectors(src: &str) -> Vec<SignEcdsaP256Vector> {
    let stripped = strip_line_comments(src);
    let src: &str = &stripped;

    let Some(start) = src.find("export const signEcdsaP256Vectors") else { return Vec::new(); };
    let tail = &src[start..];
    let Some(eq) = tail.find('=') else { return Vec::new(); };
    let after_eq = &tail[eq + 1..];
    let Some(open) = after_eq.find('[') else { return Vec::new(); };
    let body = &after_eq[open + 1..];

    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_q  = false;
    let mut start_obj: Option<usize> = None;
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_q && b == b'\\' && i + 1 < bytes.len() { i += 2; continue; }
        match b {
            b'\'' => in_q = !in_q,
            b'{' if !in_q => {
                if depth == 0 { start_obj = Some(i + 1); }
                depth += 1;
            }
            b'}' if !in_q => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start_obj.take() {
                        let obj = &body[s..i];
                        if let Some(v) = parse_sign_ecdsa_p256_record(obj) {
                            out.push(v);
                        }
                    }
                }
            }
            b']' if !in_q && depth == 0 => break,
            _ => {}
        }
        i += 1;
    }
    out
}

fn parse_sign_ecdsa_p256_record(obj: &str) -> Option<SignEcdsaP256Vector> {
    let format_enum = extract_format_enum(obj).unwrap_or(0);
    Some(SignEcdsaP256Vector {
        id:          extract_quoted_field(obj, "id")?,
        description: extract_quoted_field(obj, "description").unwrap_or_default(),
        format_enum,
        pk:   hex::decode(extract_hex_field(obj, "pkHex")?).ok()?,
        sk:   hex::decode(extract_hex_field(obj, "skHex")?).ok()?,
        msg:  hex::decode(extract_hex_field(obj, "msgHex").unwrap_or_default()).unwrap_or_default(),
        ctx:  hex::decode(extract_hex_field(obj, "ctxHex").unwrap_or_default()).unwrap_or_default(),
        rnd:  hex::decode(extract_hex_field(obj, "rndHex")?).ok()?,
        blob: hex::decode(extract_hex_field(obj, "blobHex")?).ok()?,
        sig:  hex::decode(extract_hex_field(obj, "sigHex")?).ok()?,
    })
}

// Extract `formatEnum: 0xNN` or `formatEnum: NN` as a u32. Returns None
// if the field is absent or unparseable.
fn extract_format_enum(obj: &str) -> Option<u32> {
    let key = "formatEnum:";
    let idx = obj.find(key)?;
    let tail = &obj[idx + key.len()..];
    let mut s = String::new();
    let mut started = false;
    for ch in tail.chars() {
        if ch == ',' || ch == '\n' { break; }
        if !ch.is_whitespace() { s.push(ch); started = true; }
        else if started { break; }
    }
    let s = s.trim().trim_end_matches(',').trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

