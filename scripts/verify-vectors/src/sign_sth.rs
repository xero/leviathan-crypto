// Independent verifier for `SignedLog.signCheckpoint` wire-format
// vectors per c2sp.org/tlog-cosignature §Format and §"Ed25519 signed
// message" / §"ML-DSA-44 signed message". Reproduces every layer of
// the cosignature flow from each record's structured inputs:
//
//   1. checkpoint body bytes      (RFC-style hand-rolled UTF-8 +
//                                  base64, matches merkle_checkpoint.rs)
//   2. cosignature signed message
//        Ed25519:   "cosignature/v1\ntime <ts>\n" || body
//        ML-DSA-44: cosigned_message struct
//   3. detached signature bytes
//        Ed25519:   ed25519_dalek::SigningKey::from_bytes(seed).sign
//        ML-DSA-44: ml-dsa sign_internal with rnd = 0³² over
//                   M' = 0x00 || |eff_ctx| || eff_ctx || cosigned_message
//                   where eff_ctx = buildEffectiveCtx('mldsa44-envelope-v3', empty)
//   4. timestamped_signature payload  u64_be(ts) || sig
//   5. key ID                          SHA-256(name || 0x0A || algo || pk)[:4]
//   6. signed-note envelope            body || 0x0A || em_dash || name ||
//                                      space || base64(keyId || payload) || 0x0A
//
// Cross-checks each layer's bytes against the recorded hex strings in
// test/vectors/sign_sth_ed25519.ts and test/vectors/sign_sth_mldsa44.ts.
// All dependencies are pre-pinned in the verify-vectors Cargo.toml; no
// new crate adds here.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use sha2::{Digest, Sha256};
use ed25519_dalek::SigningKey as EdSk;
use ed25519_dalek::Signer as _;
use ml_dsa::{KeyGen, MlDsa44};
use ml_dsa::signature::Keypair;
use ml_dsa::B32;

use crate::byte_diff::log_byte_diff;

// ── Shared serializer helpers ───────────────────────────────────────────────

fn serialize_checkpoint_body(origin: &str, tree_size: u64, root_hash: &[u8]) -> Vec<u8> {
    // c2sp.org/tlog-checkpoint §Note text: utf8(origin) || 0x0A ||
    // decimal(treeSize) || 0x0A || base64(rootHash) || 0x0A.
    let mut out = Vec::new();
    out.extend_from_slice(origin.as_bytes());
    out.push(0x0a);
    out.extend_from_slice(tree_size.to_string().as_bytes());
    out.push(0x0a);
    out.extend_from_slice(B64.encode(root_hash).as_bytes());
    out.push(0x0a);
    out
}

fn build_cosig_signed_message(body: &[u8], timestamp: u64) -> Vec<u8> {
    // c2sp.org/tlog-cosignature §"Ed25519 signed message".
    let header = b"cosignature/v1\ntime ";
    let mut out = Vec::with_capacity(header.len() + 24 + body.len());
    out.extend_from_slice(header);
    out.extend_from_slice(timestamp.to_string().as_bytes());
    out.push(0x0a);
    out.extend_from_slice(body);
    out
}

const COSIGNED_LABEL: [u8; 12] = [
    0x73, 0x75, 0x62, 0x74, 0x72, 0x65, 0x65, 0x2f,
    0x76, 0x31, 0x0a, 0x00,
];

fn build_cosigned_message(
    cosigner_name: &str,
    timestamp: u64,
    log_origin:    &str,
    start:         u64,
    end:           u64,
    hash:          &[u8],
) -> Vec<u8> {
    // c2sp.org/tlog-cosignature §"ML-DSA-44 signed message" struct.
    let cn = cosigner_name.as_bytes();
    let lo = log_origin.as_bytes();
    let mut out = Vec::with_capacity(70 + cn.len() + lo.len());
    out.extend_from_slice(&COSIGNED_LABEL);
    out.push(cn.len() as u8);
    out.extend_from_slice(cn);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.push(lo.len() as u8);
    out.extend_from_slice(lo);
    out.extend_from_slice(&start.to_be_bytes());
    out.extend_from_slice(&end.to_be_bytes());
    out.extend_from_slice(hash);
    out
}

fn derive_key_id(name: &str, algo_byte: u8, pubkey: &[u8]) -> [u8; 4] {
    // c2sp.org/signed-note §Signatures: SHA-256(name || 0x0A || algo || pk)[..4].
    let name_bytes = name.as_bytes();
    let mut buf = Vec::with_capacity(name_bytes.len() + 2 + pubkey.len());
    buf.extend_from_slice(name_bytes);
    buf.push(0x0a);
    buf.push(algo_byte);
    buf.extend_from_slice(pubkey);
    let d: [u8; 32] = Sha256::digest(&buf).into();
    [d[0], d[1], d[2], d[3]]
}

fn emit_cosig_payload(timestamp: u64, sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + sig.len());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(sig);
    out
}

fn emit_signed_note(body: &[u8], name: &str, key_id: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    // c2sp.org/signed-note §Format: body || 0x0A || em-dash space || name
    // || 0x20 || base64(keyId || payload) || 0x0A.
    let mut out = Vec::new();
    out.extend_from_slice(body);
    out.push(0x0a);
    out.extend_from_slice(&[0xe2, 0x80, 0x94, 0x20]);
    out.extend_from_slice(name.as_bytes());
    out.push(0x20);
    let mut pay = Vec::with_capacity(4 + payload.len());
    pay.extend_from_slice(key_id);
    pay.extend_from_slice(payload);
    out.extend_from_slice(B64.encode(&pay).as_bytes());
    out.push(0x0a);
    out
}

// ── ML-DSA-44 sign helper ──────────────────────────────────────────────────

// Reproduce the bytes that `MlDsa44.signDeterministic(sk, M, ctx)`
// produces. The deterministic primitive call: M' = 0x00 || |ctx| ||
// ctx || M, rnd = 0³², routed through `sign_internal`.
fn sign_mldsa44_deterministic(seed: &[u8; 32], signed_message: &[u8]) -> Vec<u8> {
    // Re-derive (vk, sk) from the seed via FIPS 204 §5.1 keygen.
    let xi: B32 = B32::from(*seed);
    let kp = <MlDsa44 as KeyGen>::from_seed(&xi);
    let sk = kp.signing_key();

    // effective_ctx for MlDsa44Suite: ctxDomain = "mldsa44-envelope-v3".
    // buildEffectiveCtx layout: domain_len(u8) || domain || user_ctx_len(u8) ||
    // user_ctx. user_ctx is empty (SignedLog passes EMPTY_CTX to suite.sign).
    let ctx_domain = b"mldsa44-envelope-v3";
    let mut effective_ctx = Vec::with_capacity(2 + ctx_domain.len());
    effective_ctx.push(ctx_domain.len() as u8);
    effective_ctx.extend_from_slice(ctx_domain);
    effective_ctx.push(0u8);

    // M' = 0x00 || |ctx| || ctx || M  (FIPS 204 §3.6 external pure path).
    let mut m_prime = Vec::with_capacity(2 + effective_ctx.len() + signed_message.len());
    m_prime.push(0x00);
    m_prime.push(effective_ctx.len() as u8);
    m_prime.extend_from_slice(&effective_ctx);
    m_prime.extend_from_slice(signed_message);

    // rnd = 0³² for `signDeterministic`.
    let rnd: B32 = B32::from([0u8; 32]);
    let sig = sk.sign_internal(&[&m_prime], &rnd);
    sig.encode().as_slice().to_vec()
}

// ── Vector parsing ──────────────────────────────────────────────────────────

struct SthRec {
    id:                  String,
    desc:                String,
    origin:              String,
    tree_size:           u64,
    root_hash_hex:       String,
    seed_hex:            String,
    sk_hex:              String,
    pk_hex:              String,
    timestamp:           u64,
    body_hex:            String,
    signed_message_hex:  String,
    key_id_hex:          String,
    sig_hex:             String,
    cosig_payload_hex:   String,
    envelope_hex:        String,
}

fn locate_array_open(src: &str, export_decl: &str) -> Option<usize> {
    let p = src.find(export_decl)?;
    let after_decl = p + export_decl.len();
    let eq_rel = src[after_decl..].find('=')?;
    let after_eq = after_decl + eq_rel + 1;
    let bracket_rel = src[after_eq..].find('[')?;
    Some(after_eq + bracket_rel + 1)
}

fn find_field(body: &str, field: &str) -> Option<usize> {
    let needle = format!("{}:", field);
    let mut cursor = 0usize;
    while let Some(rel) = body[cursor..].find(&needle) {
        let abs = cursor + rel;
        let prev_ok = abs == 0 || {
            let prev = body.as_bytes()[abs - 1];
            !(prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'$')
        };
        if prev_ok { return Some(abs); }
        cursor = abs + 1;
    }
    None
}

fn extract_single_quoted(body: &str, field: &str) -> String {
    let pat = format!("{}:", field);
    let Some(p) = find_field(body, field) else { return String::new(); };
    let after = p + pat.len();
    let mut out = String::new();
    let mut in_quote = false;
    for ch in body[after..].chars() {
        match ch {
            '\'' if !in_quote => { in_quote = true; }
            '\'' if in_quote  => { in_quote = false; }
            c if in_quote     => out.push(c),
            ',' => break,
            _   => {}
        }
    }
    out
}

fn extract_int(body: &str, field: &str) -> u64 {
    let pat = format!("{}:", field);
    let Some(p) = find_field(body, field) else { return 0; };
    let after = p + pat.len();
    let rest = body[after..].trim_start();
    if rest.starts_with("Number.MAX_SAFE_INTEGER") { return (1u64 << 53) - 1; }
    let mut digits = String::new();
    let mut seen = false;
    for ch in rest.chars() {
        if ch.is_ascii_digit() { digits.push(ch); seen = true; }
        else if seen { break; }
        else if ch == ',' || ch == '\n' { break; }
    }
    digits.parse().unwrap_or(0)
}

fn parse_records(src: &str, export_name: &str) -> Vec<SthRec> {
    let mut out = Vec::new();
    let needle = format!("export const {}", export_name);
    let Some(arr_start) = locate_array_open(src, &needle) else { return out; };
    let mut depth = 0i32;
    let mut rec_start: Option<usize> = None;
    let bytes = src.as_bytes();
    let mut i = arr_start;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '{' {
            if depth == 0 { rec_start = Some(i + 1); }
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                if let Some(s) = rec_start.take() {
                    let body = &src[s..i];
                    out.push(SthRec {
                        id:                  extract_single_quoted(body, "id"),
                        desc:                extract_single_quoted(body, "desc"),
                        origin:              extract_single_quoted(body, "origin"),
                        tree_size:           extract_int(body, "treeSize"),
                        root_hash_hex:       extract_single_quoted(body, "rootHashHex"),
                        seed_hex:            extract_single_quoted(body, "seedHex"),
                        sk_hex:              extract_single_quoted(body, "skHex"),
                        pk_hex:              extract_single_quoted(body, "pkHex"),
                        timestamp:           extract_int(body, "timestamp"),
                        body_hex:            extract_single_quoted(body, "bodyHex"),
                        signed_message_hex:  extract_single_quoted(body, "signedMessageHex"),
                        key_id_hex:          extract_single_quoted(body, "keyIdHex"),
                        sig_hex:             extract_single_quoted(body, "sigHex"),
                        cosig_payload_hex:   extract_single_quoted(body, "cosigPayloadHex"),
                        envelope_hex:        extract_single_quoted(body, "envelopeHex"),
                    });
                }
            }
        } else if c == ']' && depth == 0 {
            break;
        }
        i += 1;
    }
    out
}

// ── Per-record runners ──────────────────────────────────────────────────────

fn run_ed25519_record(rec: &SthRec, log: &mut Vec<String>) -> bool {
    let mut ok = true;
    let seed: [u8; 32] = hex::decode(&rec.seed_hex).unwrap().try_into().unwrap();
    let pk = hex::decode(&rec.pk_hex).unwrap();
    let root_hash = hex::decode(&rec.root_hash_hex).unwrap();
    let expected_envelope = hex::decode(&rec.envelope_hex).unwrap();

    // Body.
    let body = serialize_checkpoint_body(&rec.origin, rec.tree_size, &root_hash);
    let expected_body = hex::decode(&rec.body_hex).unwrap();
    if body != expected_body {
        log.push(format!("    ✗ {}: body bytes mismatch", rec.id));
        log_byte_diff(log, "body", &body, &expected_body);
        ok = false;
    }

    // Cosignature signed message.
    let signed = build_cosig_signed_message(&body, rec.timestamp);
    let expected_signed = hex::decode(&rec.signed_message_hex).unwrap();
    if signed != expected_signed {
        log.push(format!("    ✗ {}: cosig signed-message mismatch", rec.id));
        ok = false;
    }

    // Detached signature via ed25519-dalek.
    let sk = EdSk::from_bytes(&seed);
    let derived_pk = sk.verifying_key().to_bytes();
    if derived_pk.as_slice() != pk.as_slice() {
        log.push(format!("    ✗ {}: ed25519-dalek pk mismatch with recorded pk", rec.id));
        ok = false;
    }
    // Ed25519 secret key is the 32-byte seed (RFC 8032 §5.1.5); the recorded
    // skHex must equal the seed the signing key was derived from.
    let expected_sk = hex::decode(&rec.sk_hex).unwrap();
    if sk.to_bytes().as_slice() != expected_sk.as_slice() {
        log.push(format!("    ✗ {}: ed25519-dalek sk mismatch with recorded sk", rec.id));
        ok = false;
    }
    let sig = sk.sign(&signed);
    let sig_bytes = sig.to_bytes();
    let expected_sig = hex::decode(&rec.sig_hex).unwrap();
    if sig_bytes.as_slice() != expected_sig.as_slice() {
        log.push(format!("    ✗ {}: detached sig mismatch (dalek vs recorded)", rec.id));
        ok = false;
    }

    // Cosig payload.
    let payload = emit_cosig_payload(rec.timestamp, &sig_bytes);
    let expected_payload = hex::decode(&rec.cosig_payload_hex).unwrap();
    if payload != expected_payload {
        log.push(format!("    ✗ {}: cosig payload mismatch", rec.id));
        ok = false;
    }

    // Key ID.
    let key_id = derive_key_id(&rec.origin, 0x04, &pk);
    let expected_key_id = hex::decode(&rec.key_id_hex).unwrap();
    if key_id.as_slice() != expected_key_id.as_slice() {
        log.push(format!("    ✗ {}: keyId mismatch", rec.id));
        ok = false;
    }

    // Envelope.
    let env = emit_signed_note(&body, &rec.origin, &key_id, &payload);
    if env != expected_envelope {
        log.push(format!(
            "    ✗ {}: envelope mismatch (got {} bytes, expected {})",
            rec.id, env.len(), expected_envelope.len(),
        ));
        ok = false;
    }

    if ok {
        log.push(format!(
            "    ✓ Ed25519 {}: body, signed-message, dalek sig, payload, keyId, envelope all match ({} bytes)",
            rec.id, env.len(),
        ));
    }
    ok
}

fn run_mldsa44_record(rec: &SthRec, log: &mut Vec<String>) -> bool {
    let mut ok = true;
    let seed: [u8; 32] = hex::decode(&rec.seed_hex).unwrap().try_into().unwrap();
    let pk = hex::decode(&rec.pk_hex).unwrap();
    let root_hash = hex::decode(&rec.root_hash_hex).unwrap();
    let expected_envelope = hex::decode(&rec.envelope_hex).unwrap();

    // Body.
    let body = serialize_checkpoint_body(&rec.origin, rec.tree_size, &root_hash);
    let expected_body = hex::decode(&rec.body_hex).unwrap();
    if body != expected_body {
        log.push(format!("    ✗ {}: body bytes mismatch", rec.id));
        ok = false;
    }

    // cosigned_message struct (the ML-DSA-44 signed message).
    let signed = build_cosigned_message(
        &rec.origin,    // log self-cosignature: cosigner_name == origin
        rec.timestamp,
        &rec.origin,
        0,              // start (checkpoint cosignature)
        rec.tree_size,
        &root_hash,
    );
    let expected_signed = hex::decode(&rec.signed_message_hex).unwrap();
    if signed != expected_signed {
        log.push(format!("    ✗ {}: cosigned_message struct mismatch", rec.id));
        ok = false;
    }

    // pk parity check via ml-dsa keygen.
    let xi: B32 = B32::from(seed);
    let kp = <MlDsa44 as KeyGen>::from_seed(&xi);
    let derived_pk = kp.verifying_key().encode().as_slice().to_vec();
    if derived_pk.as_slice() != pk.as_slice() {
        log.push(format!("    ✗ {}: ml-dsa pk mismatch with recorded pk", rec.id));
        ok = false;
    }

    // sk parity: the seed-derived signing key, re-encoded via FIPS 204 §5.1
    // Algorithm 24 (skEncode), must equal the recorded skHex. `to_expanded` is
    // the only API yielding that 2560-byte form; the crate marks it deprecated
    // in favour of seed-form keys, but the encoding under test is the expanded
    // one the library stores.
    #[allow(deprecated)]
    let derived_sk = kp.signing_key().to_expanded();
    let expected_sk = hex::decode(&rec.sk_hex).unwrap();
    if derived_sk.as_slice() != expected_sk.as_slice() {
        log.push(format!(
            "    ✗ {}: ml-dsa sk mismatch with recorded sk, got {} expected {} bytes",
            rec.id, derived_sk.len(), expected_sk.len(),
        ));
        ok = false;
    }

    // Detached deterministic signature.
    let sig_bytes = sign_mldsa44_deterministic(&seed, &signed);
    let expected_sig = hex::decode(&rec.sig_hex).unwrap();
    if sig_bytes != expected_sig {
        log.push(format!(
            "    ✗ {}: detached sig mismatch (ml-dsa sign_internal vs recorded), got {} expected {} bytes",
            rec.id, sig_bytes.len(), expected_sig.len(),
        ));
        ok = false;
    }

    // Cosig payload.
    let payload = emit_cosig_payload(rec.timestamp, &sig_bytes);
    let expected_payload = hex::decode(&rec.cosig_payload_hex).unwrap();
    if payload != expected_payload {
        log.push(format!("    ✗ {}: cosig payload mismatch", rec.id));
        ok = false;
    }

    // Key ID.
    let key_id = derive_key_id(&rec.origin, 0x06, &pk);
    let expected_key_id = hex::decode(&rec.key_id_hex).unwrap();
    if key_id.as_slice() != expected_key_id.as_slice() {
        log.push(format!("    ✗ {}: keyId mismatch", rec.id));
        ok = false;
    }

    // Envelope.
    let env = emit_signed_note(&body, &rec.origin, &key_id, &payload);
    if env != expected_envelope {
        log.push(format!(
            "    ✗ {}: envelope mismatch (got {} bytes, expected {})",
            rec.id, env.len(), expected_envelope.len(),
        ));
        ok = false;
    }

    if ok {
        log.push(format!(
            "    ✓ ML-DSA-44 {}: body, cosigned_message, ml-dsa sig, payload, keyId, envelope all match ({} bytes)",
            rec.id, env.len(),
        ));
    }
    ok
}

// ── Runner ──────────────────────────────────────────────────────────────────

pub fn run(ed25519_src: &str, mldsa44_src: &str, log: &mut Vec<String>) -> bool {
    let mut all_ok = true;

    let ed_records = parse_records(ed25519_src, "signSthEd25519Vectors");
    if ed_records.is_empty() {
        log.push("    ✗ signSthEd25519Vectors parsed as empty".to_string());
        return false;
    }
    log.push(format!("    Ed25519 STH records parsed: {}", ed_records.len()));
    for rec in &ed_records {
        // Log the description to make failures easier to triage.
        if !rec.desc.is_empty() {
            log.push(format!("    {}: {}", rec.id, rec.desc));
        }
        if !run_ed25519_record(rec, log) { all_ok = false; }
    }

    let ml_records = parse_records(mldsa44_src, "signSthMldsa44Vectors");
    if ml_records.is_empty() {
        log.push("    ✗ signSthMldsa44Vectors parsed as empty".to_string());
        return false;
    }
    log.push(format!("    ML-DSA-44 STH records parsed: {}", ml_records.len()));
    for rec in &ml_records {
        if !rec.desc.is_empty() {
            log.push(format!("    {}: {}", rec.id, rec.desc));
        }
        if !run_mldsa44_record(rec, log) { all_ok = false; }
    }

    all_ok
}
