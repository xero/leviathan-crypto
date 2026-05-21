// Independent RFC 9162 (Certificate Transparency Version 2.0) §2.1.1
// Merkle Hash Tree verifier. Re-derives the four gate KAT values and
// re-runs every transparency-dev/merkle inclusion / consistency record
// against a hand-rolled walker over the pinned `sha2` crate.
//
// The §2.1.3 / §2.1.4 chaining is hand-rolled here (different lineage
// from leviathan-crypto's AssemblyScript port) rather than pulled in
// via the `ct-merkle` crate. The crate exists but its public surface
// does not expose the testdata corpus's leaf-hash entry point cleanly
// (`ct_merkle::CtMerkleTree` insists on owning the leaves); hand-rolling
// the spec is shorter than wrapping it and keeps the audit surface
// scoped to bytes the verifier actually exercises.

use sha2::{Digest, Sha256};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use crate::byte_diff::log_byte_diff;

// ── RFC 9162 §2.1.1 primitives ──────────────────────────────────────────────

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn hash_empty() -> [u8; 32] { sha256(&[]) }

fn hash_leaf(leaf: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + leaf.len());
    buf.push(0x00);
    buf.extend_from_slice(leaf);
    sha256(&buf)
}

fn hash_internal(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + left.len() + right.len());
    buf.push(0x01);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha256(&buf)
}

// ── RFC 9162 §2.1.3 / §2.1.4 chaining ──────────────────────────────────────

fn bit_len(mut x: u64) -> u32 {
    let mut n = 0u32;
    while x > 0 { x >>= 1; n += 1; }
    n
}

fn popcount(mut x: u64) -> u32 {
    let mut n = 0u32;
    while x > 0 { if x & 1 == 1 { n += 1; } x >>= 1; }
    n
}

fn trailing_zeros(x: u64) -> u32 {
    // RFC 9162 §2.1.4 uses trailingZeros(size1); only called for size1 >= 1.
    x.trailing_zeros()
}

fn decomp(index: u64, size: u64) -> (u32, u32) {
    let inner = bit_len(index ^ (size - 1));
    let border = popcount(index >> inner);
    (inner, border)
}

fn chain_inner(seed: [u8; 32], proof: &[Vec<u8>], index: u64) -> [u8; 32] {
    let mut acc = seed;
    for (i, h) in proof.iter().enumerate() {
        let bit = (index >> (i as u64)) & 1;
        acc = if bit == 0 { hash_internal(&acc, h) } else { hash_internal(h, &acc) };
    }
    acc
}

fn chain_inner_right(seed: [u8; 32], proof: &[Vec<u8>], index: u64) -> [u8; 32] {
    let mut acc = seed;
    for (i, h) in proof.iter().enumerate() {
        let bit = (index >> (i as u64)) & 1;
        if bit == 1 { acc = hash_internal(h, &acc); }
    }
    acc
}

fn chain_border_right(seed: [u8; 32], proof: &[Vec<u8>]) -> [u8; 32] {
    let mut acc = seed;
    for h in proof { acc = hash_internal(h, &acc); }
    acc
}

#[derive(Debug, Clone)]
enum VerifyOutcome { Accept, Reject }

fn verify_inclusion(
    leaf_hash: &[u8],
    index: u64,
    size: u64,
    proof: &[Vec<u8>],
    root: &[u8],
) -> VerifyOutcome {
    if size == 0 || index >= size || root.len() != 32 { return VerifyOutcome::Reject; }
    if leaf_hash.len() != 32 { return VerifyOutcome::Reject; }
    let (inner, border) = decomp(index, size);
    if proof.len() as u32 != inner + border { return VerifyOutcome::Reject; }
    for h in proof { if h.len() != 32 { return VerifyOutcome::Reject; } }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(leaf_hash);
    let inner_part: Vec<Vec<u8>> = proof[..inner as usize].to_vec();
    let border_part: Vec<Vec<u8>> = proof[inner as usize..].to_vec();
    let res = chain_inner(seed, &inner_part, index);
    let res = chain_border_right(res, &border_part);
    if res.as_slice() == root { VerifyOutcome::Accept } else { VerifyOutcome::Reject }
}

fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &[u8],
    new_root: &[u8],
    proof: &[Vec<u8>],
) -> VerifyOutcome {
    if old_size > new_size { return VerifyOutcome::Reject; }
    if old_size == new_size {
        if !proof.is_empty() { return VerifyOutcome::Reject; }
        if old_root == new_root { return VerifyOutcome::Accept; }
        return VerifyOutcome::Reject;
    }
    if old_size == 0 { return VerifyOutcome::Reject; }
    if proof.is_empty() { return VerifyOutcome::Reject; }
    if old_root.len() != 32 || new_root.len() != 32 { return VerifyOutcome::Reject; }
    for h in proof { if h.len() != 32 { return VerifyOutcome::Reject; } }

    let (inner_full, border) = decomp(old_size - 1, new_size);
    let shift = trailing_zeros(old_size);
    let inner = inner_full - shift;

    let old_is_pow2 = old_size == (1u64 << shift);
    let (seed_bytes, start) = if old_is_pow2 {
        let mut s = [0u8; 32];
        s.copy_from_slice(old_root);
        (s, 0usize)
    } else {
        let mut s = [0u8; 32];
        s.copy_from_slice(&proof[0]);
        (s, 1usize)
    };
    let expected_len = start + inner as usize + border as usize;
    if proof.len() != expected_len { return VerifyOutcome::Reject; }
    let tail = &proof[start..];
    let inner_part: Vec<Vec<u8>> = tail[..inner as usize].to_vec();
    let border_part: Vec<Vec<u8>> = tail[inner as usize..].to_vec();

    let mask = (old_size - 1) >> shift;

    let hash1 = chain_inner_right(seed_bytes, &inner_part, mask);
    let hash1 = chain_border_right(hash1, &border_part);
    if hash1.as_slice() != old_root { return VerifyOutcome::Reject; }

    let hash2 = chain_inner(seed_bytes, &inner_part, mask);
    let hash2 = chain_border_right(hash2, &border_part);
    if hash2.as_slice() != new_root { return VerifyOutcome::Reject; }
    VerifyOutcome::Accept
}

// ── Vector parsing ──────────────────────────────────────────────────────────

fn find_field<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{}:", name);
    let mut cursor = 0usize;
    while let Some(rel) = body[cursor..].find(&needle) {
        let abs = cursor + rel;
        let prev_ok = abs == 0 || {
            let prev = body.as_bytes()[abs - 1];
            !(prev.is_ascii_alphanumeric() || prev == b'_')
        };
        if prev_ok { return Some(&body[abs + needle.len()..]); }
        cursor = abs + 1;
    }
    None
}

fn read_string_field(body: &str, name: &str) -> Option<String> {
    let tail = find_field(body, name)?;
    let q1 = tail.find('\'')?;
    let after = &tail[q1 + 1..];
    let q2 = after.find('\'')?;
    Some(after[..q2].to_string())
}

fn read_int_field(body: &str, name: &str) -> Option<u64> {
    let tail = find_field(body, name)?;
    let tail = tail.trim_start();
    let end = tail.find(|c: char| !c.is_ascii_digit()).unwrap_or(tail.len());
    let literal = &tail[..end];
    // Fast path: literal fits in u64.
    if let Ok(v) = literal.parse::<u64>() {
        return Some(v);
    }
    // Lossy path: the TS generator passed the value through
    // JSON.parse + Number, so integers above Number.MAX_SAFE_INTEGER
    // (2^53 - 1) lose precision and may exceed u64::MAX by a few units
    // when rounded. Both corpus records that hit this case set the
    // logical index to u64::MAX (i.e. wraparound after `0 - 1`), and
    // wantErr=true. Saturate so the downstream `index >= size` check
    // still rejects.
    Some(u64::MAX)
}

fn read_bool_field(body: &str, name: &str) -> Option<bool> {
    let tail = find_field(body, name)?;
    let tail = tail.trim_start();
    if tail.starts_with("true") { Some(true) }
    else if tail.starts_with("false") { Some(false) }
    else { None }
}

// Reads a proof array which is either `null`, `[]`, or `[ '...', '...' ]`.
fn read_proof_field(body: &str, name: &str) -> Option<Option<Vec<String>>> {
    let tail = find_field(body, name)?;
    let tail = tail.trim_start();
    if tail.starts_with("null") { return Some(None); }
    if !tail.starts_with('[') { return None; }
    let close = tail.find(']')?;
    let inner = &tail[1..close];
    let mut out = Vec::new();
    let mut rest = inner;
    while let Some(q1) = rest.find('\'') {
        let after = &rest[q1 + 1..];
        let q2 = after.find('\'')?;
        out.push(after[..q2].to_string());
        rest = &after[q2 + 1..];
    }
    Some(Some(out))
}

// Walks {...} blocks inside a `[ ... ]` array literal. Returns each
// block body (between '{' and '}'), excluding the braces.
fn extract_array_blocks(src: &str, export_name: &str) -> Vec<String> {
    let mut out = Vec::new();
    // Find `export const NAME` followed by `:` or ` ` (no whitespace
    // assumption between identifier and the type annotation).
    let needle = format!("export const {}", export_name);
    let Some(start) = src.find(&needle) else { return out; };
    let after_name = start + needle.len();
    // The next non-whitespace must be `:` (with annotation) or `=` (without).
    let next = src[after_name..].chars().next();
    if !matches!(next, Some(':') | Some(' ') | Some('=')) { return out; }
    let after_eq_idx = src[after_name..].find('=').map(|i| after_name + i + 1);
    let Some(after_eq) = after_eq_idx else { return out; };
    let open = src[after_eq..].find('[').map(|i| after_eq + i + 1);
    let Some(mut cursor) = open else { return out; };

    let bytes = src.as_bytes();
    while cursor < bytes.len() {
        // Skip until '{' or ']'
        while cursor < bytes.len() && bytes[cursor] != b'{' && bytes[cursor] != b']' { cursor += 1; }
        if cursor >= bytes.len() || bytes[cursor] == b']' { break; }
        let body_start = cursor + 1;
        let mut depth = 1usize;
        let mut i = body_start;
        let mut in_string = false;
        while i < bytes.len() && depth > 0 {
            let b = bytes[i];
            if in_string {
                if b == b'\\' { i += 2; continue; }
                if b == b'\'' { in_string = false; }
            } else {
                if b == b'\'' { in_string = true; }
                else if b == b'{' { depth += 1; }
                else if b == b'}' { depth -= 1; if depth == 0 { break; } }
            }
            i += 1;
        }
        if depth != 0 { break; }
        out.push(src[body_start..i].to_string());
        cursor = i + 1;
    }
    out
}

// ── KAT cross-check ────────────────────────────────────────────────────────

fn check_kat_constant(src: &str, name: &str, log: &mut Vec<String>) -> bool {
    // Locate `export const NAME: MerkleSha256Kat = {` then the body block.
    let needle = format!("export const {}", name);
    let Some(idx) = src.find(&needle) else {
        log.push(format!("    ✗ {}: not found in vector file", name));
        return false;
    };
    let tail = &src[idx..];
    let Some(brace) = tail.find('{') else { return false; };
    let body_start = brace + 1;
    let close = match tail[body_start..].find("};") {
        Some(i) => body_start + i,
        None => return false,
    };
    let body = &tail[body_start..close];

    let desc = read_string_field(body, "desc").unwrap_or_default();
    let expected_hex = read_string_field(body, "expectedHex").unwrap_or_default();
    let input_utf8 = read_string_field(body, "inputUtf8");
    let left_utf8 = read_string_field(body, "leftUtf8");
    let right_utf8 = read_string_field(body, "rightUtf8");

    let computed: [u8; 32] = match (input_utf8.as_deref(), left_utf8.as_deref(), right_utf8.as_deref()) {
        (None, None, None) => hash_empty(),
        (Some(s), None, None) => hash_leaf(s.as_bytes()),
        (None, Some(l), Some(r)) => hash_internal(l.as_bytes(), r.as_bytes()),
        _ => {
            log.push(format!("    ✗ {}: ambiguous field shape", name));
            return false;
        }
    };
    let expected = match hex::decode(&expected_hex) {
        Ok(b) => b,
        Err(_) => {
            log.push(format!("    ✗ {}: invalid expectedHex", name));
            return false;
        }
    };
    if computed.as_slice() == expected.as_slice() {
        log.push(format!("    ✓ {} ({})", name, desc));
        true
    } else {
        log.push(format!("    ✗ {} ({}): mismatch", name, desc));
        log_byte_diff(log, name, &computed, &expected);
        false
    }
}

// ── Inclusion / consistency record cross-checks ────────────────────────────

fn decode_b64(s: &str) -> Vec<u8> {
    B64.decode(s.as_bytes()).unwrap_or_default()
}

struct InclRec {
    source: String,
    desc: String,
    leaf_idx: u64,
    tree_size: u64,
    root: Vec<u8>,
    leaf_hash: Vec<u8>,
    proof: Vec<Vec<u8>>,
    want_err: bool,
}

struct ConsRec {
    source: String,
    desc: String,
    size1: u64,
    size2: u64,
    root1: Vec<u8>,
    root2: Vec<u8>,
    proof: Vec<Vec<u8>>,
    want_err: bool,
}

fn parse_inclusion_records(src: &str) -> Vec<InclRec> {
    extract_array_blocks(src, "merkleInclusionRecords")
        .iter()
        .map(|body| {
            let proof_opt = read_proof_field(body, "proofB64").unwrap_or(None);
            InclRec {
                source: read_string_field(body, "source").unwrap_or_default(),
                desc: read_string_field(body, "desc").unwrap_or_default(),
                leaf_idx: read_int_field(body, "leafIdx").unwrap_or(0),
                tree_size: read_int_field(body, "treeSize").unwrap_or(0),
                root: decode_b64(&read_string_field(body, "rootB64").unwrap_or_default()),
                leaf_hash: decode_b64(&read_string_field(body, "leafHashB64").unwrap_or_default()),
                proof: proof_opt.unwrap_or_default().iter().map(|s| decode_b64(s)).collect(),
                want_err: read_bool_field(body, "wantErr").unwrap_or(false),
            }
        })
        .collect()
}

fn parse_consistency_records(src: &str) -> Vec<ConsRec> {
    extract_array_blocks(src, "merkleConsistencyRecords")
        .iter()
        .map(|body| {
            let proof_opt = read_proof_field(body, "proofB64").unwrap_or(None);
            ConsRec {
                source: read_string_field(body, "source").unwrap_or_default(),
                desc: read_string_field(body, "desc").unwrap_or_default(),
                size1: read_int_field(body, "size1").unwrap_or(0),
                size2: read_int_field(body, "size2").unwrap_or(0),
                root1: decode_b64(&read_string_field(body, "root1B64").unwrap_or_default()),
                root2: decode_b64(&read_string_field(body, "root2B64").unwrap_or_default()),
                proof: proof_opt.unwrap_or_default().iter().map(|s| decode_b64(s)).collect(),
                want_err: read_bool_field(body, "wantErr").unwrap_or(false),
            }
        })
        .collect()
}

// ── Public driver, called from main.rs ─────────────────────────────────────

pub fn run(kat_src: &str, incl_src: &str, cons_src: &str, log: &mut Vec<String>) -> bool {
    let mut all_ok = true;

    log.push("    KAT constants (RFC 9162 §2.1.1):".to_string());
    for name in &[
        "merkleSha256EmptyKat",
        "merkleSha256EmptyLeafKat",
        "merkleSha256LeafKat",
        "merkleSha256NodeKat",
    ] {
        if !check_kat_constant(kat_src, name, log) { all_ok = false; }
    }

    let incl = parse_inclusion_records(incl_src);
    let cons = parse_consistency_records(cons_src);
    log.push(format!("    Inclusion records parsed: {}", incl.len()));
    log.push(format!("    Consistency records parsed: {}", cons.len()));
    if incl.is_empty() || cons.is_empty() {
        log.push("    ✗ vector files parsed as empty".to_string());
        return false;
    }

    let mut incl_ok = 0usize;
    let mut incl_fail = 0usize;
    for rec in &incl {
        let outcome = verify_inclusion(&rec.leaf_hash, rec.leaf_idx, rec.tree_size, &rec.proof, &rec.root);
        let accepted = matches!(outcome, VerifyOutcome::Accept);
        let match_ = if rec.want_err { !accepted } else { accepted };
        if match_ { incl_ok += 1; }
        else {
            incl_fail += 1;
            log.push(format!(
                "    ✗ inclusion {}: {} (wantErr={}, got accept={})",
                rec.source, rec.desc, rec.want_err, accepted,
            ));
        }
    }
    log.push(format!("    Inclusion: {} ok, {} failed", incl_ok, incl_fail));

    let mut cons_ok = 0usize;
    let mut cons_fail = 0usize;
    for rec in &cons {
        let outcome = verify_consistency(rec.size1, rec.size2, &rec.root1, &rec.root2, &rec.proof);
        let accepted = matches!(outcome, VerifyOutcome::Accept);
        let match_ = if rec.want_err { !accepted } else { accepted };
        if match_ { cons_ok += 1; }
        else {
            cons_fail += 1;
            log.push(format!(
                "    ✗ consistency {}: {} (wantErr={}, got accept={})",
                rec.source, rec.desc, rec.want_err, accepted,
            ));
        }
    }
    log.push(format!("    Consistency: {} ok, {} failed", cons_ok, cons_fail));

    if incl_fail > 0 || cons_fail > 0 { all_ok = false; }
    all_ok
}
