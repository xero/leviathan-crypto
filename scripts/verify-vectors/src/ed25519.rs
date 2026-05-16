// Independent verifier for Ed25519 vectors (RFC 8032 + ACVP EDDSA-1.0).
//
// Reads `ed25519.ts` (RFC 8032 §7 KATs), `ed25519_keygen.ts`,
// `ed25519_siggen.ts`, and `ed25519_sigver.ts` (ACVP EDDSA-1.0 filtered
// to ED-25519 records) and runs each record through dalek-cryptography's
// `ed25519-dalek` crate. The RFC §7 records route through the same
// primitive paths as the ACVP records: RFC pure tests go through
// `verify_ed25519_siggen` with `pre_hash = None`; the RFC §7.3 ph test
// goes through the prehash path with `pre_hash = Some("SHA-512")`.
//
// The verifier reproduces ACVP's expected outputs byte-for-byte and
// reproduces the boolean outcome that ACVP `testPassed` records:
//
//   keyGen, `SigningKey::from_bytes(&seed)` returns a SigningKey whose
//            `verifying_key().to_bytes()` is compared to ACVP `q`.
//
//   sigGen, pure path: `SigningKey::sign(&message)` and compare to
//            ACVP `signature`. Pure with non-empty context (Ed25519ctx)
//            does not appear in the ed25519 ACVP corpus (preHash=false
//            records all have context length 0), so the verifier does
//            not exercise the dalek non-existent ctx-signing path.
//            prehash path: build a `sha2::Sha512` digest object updated
//            with `message`, then call
//            `SigningKey::sign_prehashed(prehashed, Some(&context))`.
//            Compare to ACVP `signature`.
//
//   sigVer, pure path: `VerifyingKey::verify_strict(&message, &signature)`.
//            prehash path: `VerifyingKey::verify_prehashed_strict(
//            prehashed, Some(&context), &signature)`. Compare the
//            bool to ACVP `testPassed`. The `_strict` variants are
//            FIPS 186-5 §7.6.4 / RFC 8032 §5.1.7 cofactored
//            verification, matching ACVP `testPassed` semantics; the
//            non-strict `verify` would diverge on small-order /
//            mixed-order public-key records.
//
// Different lineage, same bytes out. The dalek family is independent
// of leviathan-crypto's WASM stack and of every RustCrypto crate
// already pinned in this verifier; agreement here is a real
// transcription audit for the EdDSA corpus.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

use crate::byte_diff::log_byte_diff;
use crate::parse::{Ed25519KeyGenVector, Ed25519SigGenVector, Ed25519SigVerVector};

// Strip `//` line comments from a TS source string. Quoted strings
// are honoured so a `//` inside a hex literal (none of our vectors
// have one, but the helper is defensive) is not treated as a
// comment. `\` is treated as a one-byte escape inside quotes so
// `\'` does not toggle the quote state.
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
            // Skip until newline; the newline itself is emitted so
            // subsequent line offsets stay sane.
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
// Helpers
// ────────────────────────────────────────────────────────────────────────────

fn into_array_32(label: &str, v: &[u8]) -> Result<[u8; 32], String> {
    if v.len() != 32 {
        return Err(format!("{label} length {} != 32", v.len()));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(v);
    Ok(a)
}

fn into_array_64(label: &str, v: &[u8]) -> Result<[u8; 64], String> {
    if v.len() != 64 {
        return Err(format!("{label} length {} != 64", v.len()));
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(v);
    Ok(a)
}

// Build the SHA-512 prehash object the dalek API expects (a Digest
// instance pre-updated with the message bytes).
fn sha512_of(message: &[u8]) -> Sha512 {
    let mut h = Sha512::new();
    h.update(message);
    h
}

// Validate context length per RFC 8032 §5.1.6: |C| <= 255 octets.
fn check_context(context: &[u8]) -> Result<(), String> {
    if context.len() > 255 {
        Err(format!("context length {} > 255 (RFC 8032 §5.1.6)", context.len()))
    } else {
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Public verifier entry points (one per ACVP shape)
// ────────────────────────────────────────────────────────────────────────────

pub fn verify_ed25519_keygen(v: &Ed25519KeyGenVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!("━━━ ed25519 keygen tcId {} ━━━", v.tc_id));

    let seed = match into_array_32("seed", &v.seed) {
        Ok(a)  => a,
        Err(e) => { log.push(format!("  ✗ {e}")); return (false, log); }
    };

    let sk = SigningKey::from_bytes(&seed);
    let pk_bytes = sk.verifying_key().to_bytes();

    log_byte_diff(&mut log, "q", &pk_bytes, &v.q);
    if pk_bytes.as_slice() == v.q.as_slice() {
        log.push(format!("  ✓ q (32 B) matches"));
        (true, log)
    } else {
        log.push("  ✗ FAIL".to_string());
        (false, log)
    }
}

pub fn verify_ed25519_siggen(v: &Ed25519SigGenVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!(
        "━━━ ed25519 sigGen tcId {} (tg={}, type={}, preHash={:?}, ctxLen={}) ━━━",
        v.tc_id, v.tg_id, v.test_type, v.pre_hash, v.context.len(),
    ));

    if let Err(e) = check_context(&v.context) {
        log.push(format!("  ✗ {e}"));
        return (false, log);
    }
    let seed = match into_array_32("sk", &v.sk) {
        Ok(a)  => a,
        Err(e) => { log.push(format!("  ✗ {e}")); return (false, log); }
    };
    let sk = SigningKey::from_bytes(&seed);

    let sig: Signature = match v.pre_hash.as_deref() {
        None => {
            // Pure Ed25519 (RFC 8032 §5.1.6). The ACVP ed25519 corpus
            // has context length 0 in every preHash=false record, so
            // we route through the bare `sign(&message)` path.
            if !v.context.is_empty() {
                log.push(format!(
                    "  ✗ pure record with non-empty context (Ed25519ctx); dalek 2.x does not expose ctx-signing"
                ));
                return (false, log);
            }
            sk.sign(&v.message)
        }
        Some(alg) if alg == "SHA-512" => {
            // Ed25519ph (RFC 8032 §5.1.7). dalek expects a Digest
            // instance pre-updated with the message bytes; context
            // is optional and may be empty.
            let ctx: Option<&[u8]> = Some(&v.context);
            match sk.sign_prehashed(sha512_of(&v.message), ctx) {
                Ok(s)  => s,
                Err(e) => {
                    log.push(format!("  ✗ sign_prehashed failed: {e:?}"));
                    return (false, log);
                }
            }
        }
        Some(other) => {
            log.push(format!("  ✗ unsupported preHash discriminator {other:?}"));
            return (false, log);
        }
    };

    let sig_bytes = sig.to_bytes();
    log_byte_diff(&mut log, "signature", &sig_bytes, &v.signature);
    if sig_bytes.as_slice() == v.signature.as_slice() {
        log.push(format!("  ✓ signature (64 B) matches"));
        (true, log)
    } else {
        log.push("  ✗ FAIL".to_string());
        (false, log)
    }
}

pub fn verify_ed25519_sigver(v: &Ed25519SigVerVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!(
        "━━━ ed25519 sigVer tcId {} (tg={}, type={}, preHash={:?}, ctxLen={}, reason={:?}) → expected={} ━━━",
        v.tc_id, v.tg_id, v.test_type, v.pre_hash, v.context.len(), v.reason, v.test_passed,
    ));

    let computed = compute_sigver(v, &mut log);
    if computed == v.test_passed {
        log.push(format!("  ✓ verification {computed} matches expected"));
        (true, log)
    } else {
        log.push(format!("  ✗ verification {computed} ≠ expected {}", v.test_passed));
        (false, log)
    }
}

fn compute_sigver(v: &Ed25519SigVerVector, log: &mut Vec<String>) -> bool {
    if let Err(e) = check_context(&v.context) {
        log.push(format!("  context check: {e}"));
        return false;
    }
    let pk_bytes = match into_array_32("pk", &v.pk) {
        Ok(a)  => a,
        Err(e) => { log.push(format!("  pk decode: {e}")); return false; }
    };
    let sig_bytes = match into_array_64("signature", &v.signature) {
        Ok(a)  => a,
        Err(e) => { log.push(format!("  signature decode: {e}")); return false; }
    };
    let vk = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k)  => k,
        Err(e) => { log.push(format!("  VerifyingKey::from_bytes: {e:?}")); return false; }
    };
    let sig = Signature::from_bytes(&sig_bytes);

    match v.pre_hash.as_deref() {
        None => {
            // RFC 8032 §5.1.7 strict cofactored verification, matching
            // FIPS 186-5 §7.6.4 + ACVP `testPassed`. The ACVP ed25519
            // sigVer corpus has context length 0 in every preHash=false
            // record (the parser surfaces "" / no context field as an
            // empty byte slice), so the bare `verify_strict` path
            // covers them; a non-empty pure context would be Ed25519ctx
            // and dalek 2.x does not expose strict-ctx verification.
            if !v.context.is_empty() {
                log.push(format!(
                    "  pure verify with non-empty context (Ed25519ctx); dalek 2.x does not expose strict-ctx verify"
                ));
                return false;
            }
            vk.verify_strict(&v.message, &sig).is_ok()
        }
        Some(alg) if alg == "SHA-512" => {
            let ctx: Option<&[u8]> = Some(&v.context);
            vk.verify_prehashed_strict(sha512_of(&v.message), ctx, &sig).is_ok()
        }
        Some(other) => {
            log.push(format!("  unsupported preHash discriminator {other:?}"));
            false
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RFC 8032 §7 vector loader. ed25519.ts ships a hand-transcribed corpus
// (4 pure + 1 ph), see test/vectors/ed25519.ts for the field semantics.
// The verifier reuses the ACVP sigGen / sigVer paths above; this loader
// just decodes the .ts shape into Ed25519SigGenVector + Ed25519SigVerVector
// twins so the per-record functions stay shared.
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Rfc8032Vector {
    pub idx:       usize,
    pub mode:      Option<String>, // None = pure, Some("SHA-512") = ph
    pub sk:        Vec<u8>,
    pub pk:        Vec<u8>,
    pub message:   Vec<u8>,
    pub context:   Vec<u8>,
    pub signature: Vec<u8>,
}

// Inline parser for the ed25519.ts shape. The file is small (5 records),
// hand-written, and uses a tagged-union form (`mode: 'pure'|'ph'`,
// `ctxHex?: string`) that the central parse helpers do not natively
// understand, so we read it inline.
pub fn parse_rfc8032_vectors(src: &str) -> Vec<Rfc8032Vector> {
    // Strip `//` line comments first; the vector file's prose comments
    // contain apostrophes (e.g. "Alice's", "Bob's") which would
    // otherwise toggle the quote-tracking state and confuse the
    // brace walker. Block comments `/* */` are not used in this file.
    let stripped = strip_line_comments(src);
    let src: &str = &stripped;

    let Some(start) = src.find("export const ed25519Vectors") else { return Vec::new(); };
    let tail = &src[start..];
    // Skip past the `=` so we land on the value's `[`, not the
    // `Ed25519Vector[]` of the type annotation.
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
                        if let Some(v) = parse_rfc_record(obj, out.len()) {
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

fn parse_rfc_record(obj: &str, idx: usize) -> Option<Rfc8032Vector> {
    let mode_str = extract_quoted_value(obj, "mode")?;
    let mode = match mode_str.as_str() {
        "pure" => None,
        "ph"   => Some("SHA-512".to_string()),
        _      => return None,
    };
    let sk        = hex::decode(extract_hex_value(obj, "skHex")?).ok()?;
    let pk        = hex::decode(extract_hex_value(obj, "pkHex")?).ok()?;
    let message   = hex::decode(extract_hex_value(obj, "msgHex").unwrap_or_default()).ok()?;
    let signature = hex::decode(extract_hex_value(obj, "sigHex")?).ok()?;
    let context   = hex::decode(extract_hex_value(obj, "ctxHex").unwrap_or_default()).ok()?;
    Some(Rfc8032Vector { idx, mode, sk, pk, message, context, signature })
}

// Read a `field: '...'` value (single-quoted, no concatenation needed).
fn extract_quoted_value(obj: &str, field: &str) -> Option<String> {
    let key = format!("{field}:");
    let idx = obj.find(&key)?;
    let tail = &obj[idx + key.len()..];
    let q1 = tail.find('\'')?;
    let after = &tail[q1 + 1..];
    let q2 = after.find('\'')?;
    Some(after[..q2].to_string())
}

// Read a `field: 'aa' + 'bb' + 'cc'` value, joining all quoted chunks
// until the first top-level `,`. Mirrors the central parse.rs
// `extract_hex` helper but stays self-contained for this module.
fn extract_hex_value(obj: &str, field: &str) -> Option<String> {
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

pub fn verify_rfc8032(v: &Rfc8032Vector) -> (bool, Vec<String>) {
    // Wrap into the ACVP sigGen + sigVer shapes and route through the
    // shared verifier paths so the same code exercises both.
    let sg = Ed25519SigGenVector {
        tc_id:     v.idx as u32,
        tg_id:     0,
        test_type: "RFC".to_string(),
        pre_hash:  v.mode.clone(),
        sk:        v.sk.clone(),
        pk:        v.pk.clone(),
        message:   v.message.clone(),
        context:   v.context.clone(),
        signature: v.signature.clone(),
    };
    let sv = Ed25519SigVerVector {
        tc_id:       v.idx as u32,
        tg_id:       0,
        test_type:   "RFC".to_string(),
        test_passed: true,
        pre_hash:    v.mode.clone(),
        reason:      "rfc-positive".to_string(),
        pk:          v.pk.clone(),
        sk:          v.sk.clone(),
        message:     v.message.clone(),
        context:     v.context.clone(),
        signature:   v.signature.clone(),
    };
    let (ok_sig, mut log) = verify_ed25519_siggen(&sg);
    let (ok_ver, mut log_ver) = verify_ed25519_sigver(&sv);
    log.append(&mut log_ver);
    (ok_sig && ok_ver, log)
}
