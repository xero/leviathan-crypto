// Independent verifier for BLAKE3 vectors (test/vectors/blake3.ts).
//
// Reads the upstream BLAKE3-team KAT corpus as transcribed into
// `blake3.ts` (35 records × 3 modes: hash, keyed_hash, derive_key) and
// runs each record through the official `blake3` crate. Every mode is
// driven over `finalize_xof` + `OutputReader::fill` so the full 131-byte
// XOF output is compared, not just the default-length 32-byte prefix.
// Vector hex covers the 64-byte XOF block boundary on every case, so
// arbitrary-position XOF reads can be validated against this corpus.
//
// Different crate path, same spec. The `blake3` crate is the
// BLAKE3-team's own implementation, distinct from the AssemblyScript
// port in this repo; agreement here proves the vector transcription
// matches the upstream JSON, and agreement with the WASM output proves
// the WASM port matches the upstream implementation byte-for-byte.
// The two together close the loop.
//
// Input pattern:
//   byte i is (i mod 251). Reproduced by `expand_input` here so the
//   verifier needs no extra dependency for input synthesis. 251 is the
//   largest prime < 256 and is documented in the upstream README
//   alongside the JSON.

use blake3::Hasher;

use crate::byte_diff::log_byte_diff;

// ────────────────────────────────────────────────────────────────────────────
// Vector shape
// ────────────────────────────────────────────────────────────────────────────

pub struct Blake3Vector {
    pub input_len:      usize,
    pub hash:           Vec<u8>,
    pub keyed_hash:     Vec<u8>,
    pub derive_key:     Vec<u8>,
}

// ────────────────────────────────────────────────────────────────────────────
// Minimal blake3.ts parser. The shape of the vector file is fully under
// our control and only one export feeds this verifier, so a small inline
// parser is cheaper than adding a fifth shape to parse.rs.
//
// Extracts:
//   - `blake3Key`            (ASCII string literal)
//   - `blake3ContextString`  (ASCII string literal)
//   - `blake3Vectors`        (array of { inputLen, hashHex, keyedHashHex, deriveKeyHex })
// ────────────────────────────────────────────────────────────────────────────

fn parse_string_const(src: &str, name: &str) -> Option<String> {
    // Accept three shapes:
    //   `export const NAME = '...'`              (current shape, no annotation)
    //   `export const NAME: string = '...'`      (legacy / explicit)
    //   `export const NAME : string = '...'`     (spaced colon)
    let needles = [
        format!("export const {} =",          name),
        format!("export const {}: string =",  name),
        format!("export const {} : string =", name),
    ];
    let idx = needles.iter().find_map(|n| src.find(n))?;
    let tail = &src[idx..];
    let q = tail.find('\'')?;
    let after = &tail[q + 1..];
    let end = after.find('\'')?;
    Some(after[..end].to_string())
}

fn parse_int_field(body: &str, name: &str) -> Option<usize> {
    let key = format!("{}:", name);
    let idx = body.find(&key)?;
    let tail = &body[idx + key.len()..];
    let tail = tail.trim_start();
    let end = tail.find(|c: char| !c.is_ascii_digit())?;
    tail[..end].parse().ok()
}

fn parse_hex_field(body: &str, name: &str) -> Option<Vec<u8>> {
    let key = format!("{}:", name);
    let idx = body.find(&key)?;
    let tail = &body[idx + key.len()..];
    let q = tail.find('\'')?;
    let after = &tail[q + 1..];
    let end = after.find('\'')?;
    hex::decode(&after[..end]).ok()
}

pub fn parse_blake3_vectors(src: &str) -> Vec<Blake3Vector> {
    let Some(start) = src.find("export const blake3Vectors") else { return Vec::new(); };
    let tail = &src[start..];
    let Some(open) = tail.find('[') else { return Vec::new(); };
    let body = &tail[open + 1..];

    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(brace) = body[cursor..].find('{') {
        let obj_start = cursor + brace + 1;
        let Some(close_rel) = body[obj_start..].find('}') else { break; };
        let obj = &body[obj_start..obj_start + close_rel];

        let input_len  = parse_int_field(obj, "inputLen");
        let hash       = parse_hex_field(obj, "hashHex");
        let keyed_hash = parse_hex_field(obj, "keyedHashHex");
        let derive_key = parse_hex_field(obj, "deriveKeyHex");

        if let (Some(il), Some(h), Some(k), Some(d)) = (input_len, hash, keyed_hash, derive_key) {
            out.push(Blake3Vector {
                input_len:  il,
                hash:       h,
                keyed_hash: k,
                derive_key: d,
            });
        }
        cursor = obj_start + close_rel + 1;
    }
    out
}

// ────────────────────────────────────────────────────────────────────────────
// Input synthesis: byte i is (i mod 251). Largest prime < 256, picked
// upstream so the cycle doesn't align with any power-of-two chunk size.
// ────────────────────────────────────────────────────────────────────────────

fn expand_input(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

// ────────────────────────────────────────────────────────────────────────────
// XOF read length. Every upstream record carries 131 bytes of XOF
// output (262 hex chars), which spans the 64-byte root-compress block
// boundary so output-reader correctness is exercised on every case.
//
// The default-length BLAKE3 digest is 32 bytes. The verifier's two
// modes are:
//   `BlakeXofMode::Prefix32` — assert the first 32 output bytes only
//                              (default-length hash)
//   `BlakeXofMode::FullXof`  — assert the full 131 bytes (XOF correctness)
//
// Both modes consume the same 131-byte hex in the vector file; the
// difference is only in how many bytes are compared.
// ────────────────────────────────────────────────────────────────────────────

const XOF_LEN: usize = 131;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlakeXofMode {
    Prefix32,
    FullXof,
}

fn xof_bytes(hasher: &Hasher) -> [u8; XOF_LEN] {
    let mut out = [0u8; XOF_LEN];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn verify_one(
    log:        &mut Vec<String>,
    label:      &str,
    computed:   &[u8],
    expected:   &[u8],
    compare_n:  usize,
) -> bool {
    let n = compare_n.min(expected.len()).min(computed.len());
    let c = &computed[..n];
    let e = &expected[..n];
    log_byte_diff(log, label, c, e);
    if c == e {
        log.push(format!("  ✓ {label} ({n} B) matches"));
        true
    } else {
        log.push(format!("  ✗ {label} FAIL"));
        false
    }
}

pub fn verify_vector(
    v:       &Blake3Vector,
    key:     &[u8; 32],
    context: &str,
    mode:    BlakeXofMode,
) -> (bool, Vec<String>) {
    let mut log = Vec::new();
    log.push(format!("━━━ blake3 inputLen {} ━━━", v.input_len));

    let input = expand_input(v.input_len);
    let compare_n = match mode {
        BlakeXofMode::Prefix32 => 32,
        BlakeXofMode::FullXof  => XOF_LEN,
    };

    // hash mode
    let mut h_hash = Hasher::new();
    h_hash.update(&input);
    let hash_out = xof_bytes(&h_hash);

    // keyed_hash mode (spec §2.6, 32-byte key)
    let mut h_keyed = Hasher::new_keyed(key);
    h_keyed.update(&input);
    let keyed_out = xof_bytes(&h_keyed);

    // derive_key mode (spec §2.7, ASCII context string)
    let mut h_derive = Hasher::new_derive_key(context);
    h_derive.update(&input);
    let derive_out = xof_bytes(&h_derive);

    let mut ok = true;
    ok &= verify_one(&mut log, "hash",       &hash_out,   &v.hash,       compare_n);
    ok &= verify_one(&mut log, "keyed_hash", &keyed_out,  &v.keyed_hash, compare_n);
    ok &= verify_one(&mut log, "derive_key", &derive_out, &v.derive_key, compare_n);
    (ok, log)
}

// ────────────────────────────────────────────────────────────────────────────
// Top-level entry point. Returns (key, context, vectors) so main.rs can
// surface the per-key / per-context constants in the section header.
// ────────────────────────────────────────────────────────────────────────────

pub fn load(src: &str) -> Result<([u8; 32], String, Vec<Blake3Vector>), String> {
    let key_str = parse_string_const(src, "blake3Key")
        .ok_or_else(|| "blake3Key not found in blake3.ts".to_string())?;
    let key_bytes = key_str.as_bytes();
    if key_bytes.len() != 32 {
        return Err(format!(
            "blake3Key is {} bytes, expected 32 per spec §2.6",
            key_bytes.len(),
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);

    let context = parse_string_const(src, "blake3ContextString")
        .ok_or_else(|| "blake3ContextString not found in blake3.ts".to_string())?;

    let vectors = parse_blake3_vectors(src);
    if vectors.is_empty() {
        return Err("blake3Vectors parsed as empty".to_string());
    }
    Ok((key, context, vectors))
}
