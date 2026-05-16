// Independent verifier for X25519 vectors (test/vectors/x25519.ts).
//
// Reads the RFC 7748 §5 + §6.1 KAT corpus as transcribed into
// `x25519.ts` (Alice/Bob exchange + iter=1 + iter=1000) and runs each
// record through dalek-cryptography's `x25519-dalek` crate.
//
//   §6.1 exchange: drive both directions of the Diffie-Hellman, build
//        StaticSecret/PublicKey from the per-side scalar and the peer
//        public key, compare the resulting shared secret to the RFC
//        value. The verifier also checks that
//        `StaticSecret::from(alice_sk) . diffie_hellman( base point )`
//        reproduces the RFC's `alicePk` (and similarly for Bob),
//        ensuring the clamp + scalar-mult path is exercised, not just
//        the Alice→Bob direction.
//
//   §5  iterated: implement the loop in pure Rust over
//        `x25519_dalek::x25519(scalar, u)` (the standalone primitive,
//        not the Diffie-Hellman wrapper). At iter=1000 this is fast;
//        iter=1000000 is deliberately deferred per docs/vector_audit.md.
//
// Different lineage, same bytes out. The dalek family is independent
// of leviathan-crypto's WASM stack and of every RustCrypto crate
// already pinned in this verifier. Note: x25519-dalek does NOT reject
// the all-zero shared secret at the function-call level (the spec's
// §6 small-order rejection is the consumer's responsibility); the
// verifier's job here is byte agreement on the raw scalar-mult output.
// Rejection-of-degenerate-pks is exercised separately at the
// TypeScript layer in TASK-E onward.

use x25519_dalek::{x25519, PublicKey, StaticSecret};

use crate::byte_diff::log_byte_diff;

// Strip `//` line comments from a TS source string. Quoted strings
// are honoured so a `//` inside a hex literal is not treated as a
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
// Vector shapes
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct X25519ExchangeVector {
    pub alice_sk: [u8; 32],
    pub alice_pk: [u8; 32],
    pub bob_sk:   [u8; 32],
    pub bob_pk:   [u8; 32],
    pub shared:   [u8; 32],
}

#[derive(Debug, Clone)]
pub struct X25519IteratedVector {
    pub iter:     u32,
    pub expected: [u8; 32],
}

pub enum X25519Vector {
    Exchange(X25519ExchangeVector),
    Iterated(X25519IteratedVector),
}

// ────────────────────────────────────────────────────────────────────────────
// Inline parser for x25519.ts. The shape is a single
// `export const x25519Vectors: readonly X25519Vector[] = [ {kind:..., ...}, ... ]`
// with two variants tagged by `kind: 'exchange'|'iterated'`. The corpus is
// small (3 records, all hand-written) and the shape is bespoke to this
// file, so an inline parser is cheaper than adding a fifth shape to
// the central parse.rs.
// ────────────────────────────────────────────────────────────────────────────

fn extract_quoted(obj: &str, field: &str) -> Option<String> {
    let key = format!("{field}:");
    let idx = obj.find(&key)?;
    let tail = &obj[idx + key.len()..];
    let q1 = tail.find('\'')?;
    let after = &tail[q1 + 1..];
    let q2 = after.find('\'')?;
    Some(after[..q2].to_string())
}

fn extract_int(obj: &str, field: &str) -> Option<u32> {
    let key = format!("{field}:");
    let idx = obj.find(&key)?;
    let tail = &obj[idx + key.len()..];
    let trimmed = tail.trim_start();
    let end = trimmed.find(|c: char| !c.is_ascii_digit())?;
    trimmed[..end].parse().ok()
}

fn parse_hex_32(obj: &str, field: &str) -> Option<[u8; 32]> {
    let hex_str = extract_quoted(obj, field)?;
    let bytes = hex::decode(&hex_str).ok()?;
    if bytes.len() != 32 { return None; }
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes);
    Some(a)
}

pub fn parse_x25519_vectors(src: &str) -> Vec<X25519Vector> {
    // Strip `//` line comments first; the vector file's prose comments
    // contain apostrophes (e.g. "Alice's", "Bob's") which would
    // otherwise toggle the quote-tracking state and confuse the
    // brace walker.
    let stripped = strip_line_comments(src);
    let src: &str = &stripped;

    let Some(start) = src.find("export const x25519Vectors") else { return Vec::new(); };
    let tail = &src[start..];
    // Skip past the `=` so we land on the value's `[`, not the
    // `X25519Vector[]` of the type annotation.
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
                        if let Some(v) = parse_record(obj) {
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

fn parse_record(obj: &str) -> Option<X25519Vector> {
    let kind = extract_quoted(obj, "kind")?;
    match kind.as_str() {
        "exchange" => Some(X25519Vector::Exchange(X25519ExchangeVector {
            alice_sk: parse_hex_32(obj, "aliceSkHex")?,
            alice_pk: parse_hex_32(obj, "alicePkHex")?,
            bob_sk:   parse_hex_32(obj, "bobSkHex")?,
            bob_pk:   parse_hex_32(obj, "bobPkHex")?,
            shared:   parse_hex_32(obj, "sharedHex")?,
        })),
        "iterated" => Some(X25519Vector::Iterated(X25519IteratedVector {
            iter:     extract_int(obj, "iter")?,
            expected: parse_hex_32(obj, "kHex")?,
        })),
        _ => None,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Verifiers
// ────────────────────────────────────────────────────────────────────────────

// X25519 initial value for the §5 iterated test: 0x09 followed by 31
// zero bytes (little-endian encoding of 9 in the low byte, RFC 7748 §5
// "test vectors" preamble).
const INITIAL_KU: [u8; 32] = [
    0x09, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0,
];

pub fn verify_x25519_exchange(v: &X25519ExchangeVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push("━━━ x25519 §6.1 Diffie-Hellman ━━━".to_string());

    // alicePk = X25519(alice_sk, base point 9). x25519-dalek's
    // `StaticSecret::from(bytes)` clamps the scalar internally and
    // `.public_key()` performs scalar-mult on the base point.
    let alice_secret = StaticSecret::from(v.alice_sk);
    let alice_pk_computed: [u8; 32] = PublicKey::from(&alice_secret).to_bytes();
    log_byte_diff(&mut log, "alice_pk", &alice_pk_computed, &v.alice_pk);

    let bob_secret = StaticSecret::from(v.bob_sk);
    let bob_pk_computed: [u8; 32] = PublicKey::from(&bob_secret).to_bytes();
    log_byte_diff(&mut log, "bob_pk", &bob_pk_computed, &v.bob_pk);

    // Both directions of the DH must yield the same shared secret
    // and must equal the RFC value.
    let shared_a_from_b: [u8; 32] = alice_secret.diffie_hellman(&PublicKey::from(v.bob_pk)).to_bytes();
    let shared_b_from_a: [u8; 32] = bob_secret.diffie_hellman(&PublicKey::from(v.alice_pk)).to_bytes();
    log_byte_diff(&mut log, "shared(a from b_pk)", &shared_a_from_b, &v.shared);
    log_byte_diff(&mut log, "shared(b from a_pk)", &shared_b_from_a, &v.shared);

    let ok = alice_pk_computed.as_slice() == v.alice_pk.as_slice()
          && bob_pk_computed.as_slice()   == v.bob_pk.as_slice()
          && shared_a_from_b.as_slice()   == v.shared.as_slice()
          && shared_b_from_a.as_slice()   == v.shared.as_slice();
    if ok {
        log.push("  ✓ both directions of the DH agree with the RFC shared secret".to_string());
    } else {
        log.push("  ✗ FAIL".to_string());
    }
    (ok, log)
}

pub fn verify_x25519_iterated(v: &X25519IteratedVector) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!("━━━ x25519 §5 iterated, iter={} ━━━", v.iter));

    let mut k = INITIAL_KU;
    let mut u = INITIAL_KU;
    for _ in 0..v.iter {
        let next = x25519(k, u);
        u = k;
        k = next;
    }
    log_byte_diff(&mut log, "k_final", &k, &v.expected);
    if k.as_slice() == v.expected.as_slice() {
        log.push(format!("  ✓ k after {} iterations matches", v.iter));
        (true, log)
    } else {
        log.push("  ✗ FAIL".to_string());
        (false, log)
    }
}

pub fn verify_one(v: &X25519Vector) -> (bool, Vec<String>) {
    match v {
        X25519Vector::Exchange(e) => verify_x25519_exchange(e),
        X25519Vector::Iterated(i) => verify_x25519_iterated(i),
    }
}
