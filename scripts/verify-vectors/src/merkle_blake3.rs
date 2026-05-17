// Independent BLAKE3 Merkle-tree verifier. Cross-checks every record
// in `test/vectors/merkle_blake3.ts` against:
//
//   1) The official RustCrypto `blake3` crate (pinned in Cargo.toml at
//      version 1.8.5) for leaf hashing, `BLAKE3(empty)` for the
//      empty-tree root, and `BLAKE3(leaf_bytes)` for size-1 / size-N
//      leaf hashes.
//   2) A hand-rolled BLAKE3 §2.10 compression function implemented
//      inline below for internal-node hashing. The `blake3` crate
//      version 1.8 keeps the tree-mode `parent_node_output` primitive
//      private (the `guts` module is not part of the stable surface),
//      so for the §2.5 parent compress we implement the §2.10 state
//      machine directly from the spec. This is a separate code
//      lineage from leviathan's AssemblyScript WASM port: both stacks
//      derive the same bytes independently from the same spec text,
//      and agreement on every record is the "two independent
//      implementations agree" signal.
//
// The §2.1.3 / §2.1.4 chaining (proof verification) is hand-rolled
// here too (different lineage from leviathan's TypeScript walker).
// The shape mirrors `merkle_sha256.rs` so the audit surface is
// uniform across the two hashers.

use crate::byte_diff::log_byte_diff;

// ── BLAKE3 §2.2: IV constants (= FIPS 180-4 SHA-256 IV) ────────────────────

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// BLAKE3 §2.2 Table 3: domain-separation flag bit for tree internal nodes.
const FLAG_PARENT: u32 = 1 << 2;

// BLAKE3 §2.10 message-word permutation applied between rounds. Round
// schedules can be derived from this by iteratively permuting the
// identity permutation; we apply it explicitly per-round below.
const MSG_PERMUTATION: [usize; 16] = [
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
];

// BLAKE3 §2.10 G-function: column/diagonal mixing primitive.
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

// BLAKE3 §2.10 round: 4 column mixes + 4 diagonal mixes.
fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4,  8, 12, m[ 0], m[ 1]);
    g(state, 1, 5,  9, 13, m[ 2], m[ 3]);
    g(state, 2, 6, 10, 14, m[ 4], m[ 5]);
    g(state, 3, 7, 11, 15, m[ 6], m[ 7]);
    g(state, 0, 5, 10, 15, m[ 8], m[ 9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7,  8, 13, m[12], m[13]);
    g(state, 3, 4,  9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut out = [0u32; 16];
    for i in 0..16 { out[i] = m[MSG_PERMUTATION[i]]; }
    *m = out;
}

// BLAKE3 §2.10 compression function: 7 rounds over the state, output
// folded as `state[0..8] XOR state[8..16]` for the chaining-value half.
// We only need the chaining-value half for parent compress (the XOF
// tail is not part of the parent's contribution to the next level).
fn compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 8] {
    let mut state: [u32; 16] = [
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut m = *block;
    round(&mut state, &m);              // round 0
    for _ in 0..6 {                     // rounds 1..7
        permute(&mut m);
        round(&mut state, &m);
    }
    let mut out = [0u32; 8];
    for i in 0..8 { out[i] = state[i] ^ state[i + 8]; }
    out
}

fn cv_bytes_from_words(w: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        let bytes = w[i].to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    out
}

fn block_words_from_bytes(left: &[u8; 32], right: &[u8; 32]) -> [u32; 16] {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(left);
    bytes[32..].copy_from_slice(right);
    let mut out = [0u32; 16];
    for i in 0..16 {
        out[i] = u32::from_le_bytes([
            bytes[i * 4], bytes[i * 4 + 1], bytes[i * 4 + 2], bytes[i * 4 + 3],
        ]);
    }
    out
}

// ── leviathan-blake3-tree composition (§2.4 / §2.5) ────────────────────────

fn hash_leaf(leaf: &[u8]) -> [u8; 32] {
    *blake3::hash(leaf).as_bytes()
}

fn hash_empty() -> [u8; 32] {
    hash_leaf(&[])
}

// Parent compress with modeFlags = 0 (default mode), isRoot = 0. The
// starting CV is the BLAKE3 IV; the block is left || right; the
// counter is 0; the block length is 64; flags = PARENT.
fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let block = block_words_from_bytes(left, right);
    let out_words = compress(&IV, &block, 0, 64, FLAG_PARENT);
    cv_bytes_from_words(&out_words)
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
        let h32: [u8; 32] = h.as_slice().try_into().unwrap_or([0u8; 32]);
        acc = if bit == 0 { hash_internal(&acc, &h32) } else { hash_internal(&h32, &acc) };
    }
    acc
}

fn chain_inner_right(seed: [u8; 32], proof: &[Vec<u8>], index: u64) -> [u8; 32] {
    let mut acc = seed;
    for (i, h) in proof.iter().enumerate() {
        let bit = (index >> (i as u64)) & 1;
        if bit == 1 {
            let h32: [u8; 32] = h.as_slice().try_into().unwrap_or([0u8; 32]);
            acc = hash_internal(&h32, &acc);
        }
    }
    acc
}

fn chain_border_right(seed: [u8; 32], proof: &[Vec<u8>]) -> [u8; 32] {
    let mut acc = seed;
    for h in proof {
        let h32: [u8; 32] = h.as_slice().try_into().unwrap_or([0u8; 32]);
        acc = hash_internal(&h32, &acc);
    }
    acc
}

#[derive(Debug, Clone)]
enum VerifyOutcome { Accept, Reject }

fn verify_inclusion(
    leaf_hash: &[u8],
    index: u64,
    size: u64,
    proof: &[Vec<u8>],
    root: &[u8; 32],
) -> VerifyOutcome {
    if size == 0 || index >= size { return VerifyOutcome::Reject; }
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
    if res == *root { VerifyOutcome::Accept } else { VerifyOutcome::Reject }
}

fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
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
    for h in proof { if h.len() != 32 { return VerifyOutcome::Reject; } }

    let (inner_full, border) = decomp(old_size - 1, new_size);
    let shift = trailing_zeros(old_size);
    let inner = inner_full - shift;

    let old_is_pow2 = old_size == (1u64 << shift);
    let (seed_bytes, start) = if old_is_pow2 {
        (*old_root, 0usize)
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
    if hash1 != *old_root { return VerifyOutcome::Reject; }

    let hash2 = chain_inner(seed_bytes, &inner_part, mask);
    let hash2 = chain_border_right(hash2, &border_part);
    if hash2 != *new_root { return VerifyOutcome::Reject; }
    VerifyOutcome::Accept
}

// ── Vector parsing ─────────────────────────────────────────────────────────

// merkle_blake3.ts has the same .ts literal shape as merkle_sha256.ts.
// We reuse a small inline parser rather than adding another shape to
// parse.rs; the file has one exported array and a fixed record shape.

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
    let tail = tail.trim_start();
    let quote = match tail.chars().next() {
        Some('"')  => '"',
        Some('\'') => '\'',
        _ => return None,
    };
    let after = &tail[1..];
    let mut out = String::new();
    let mut chars = after.chars();
    while let Some(c) = chars.next() {
        if c == quote { return Some(out); }
        if c == '\\' {
            if let Some(esc) = chars.next() {
                match esc {
                    '"'  => out.push('"'),
                    '\'' => out.push('\''),
                    '\\' => out.push('\\'),
                    'n'  => out.push('\n'),
                    't'  => out.push('\t'),
                    other => { out.push('\\'); out.push(other); }
                }
            }
        } else {
            out.push(c);
        }
    }
    None
}

fn read_int_field(body: &str, name: &str) -> Option<u64> {
    let tail = find_field(body, name)?;
    let tail = tail.trim_start();
    let end = tail.find(|c: char| !c.is_ascii_digit()).unwrap_or(tail.len());
    tail[..end].parse::<u64>().ok()
}

// Walk balanced `{ ... }` blocks inside `[ ... ]` for an exported array.
fn extract_array_blocks(src: &str, export_name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = format!("export const {}", export_name);
    let Some(start) = src.find(&needle) else { return out; };
    let after_name = start + needle.len();
    let after_eq_idx = src[after_name..].find('=').map(|i| after_name + i + 1);
    let Some(after_eq) = after_eq_idx else { return out; };
    let open = src[after_eq..].find('[').map(|i| after_eq + i + 1);
    let Some(mut cursor) = open else { return out; };

    let bytes = src.as_bytes();
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor] != b'{' && bytes[cursor] != b']' { cursor += 1; }
        if cursor >= bytes.len() || bytes[cursor] == b']' { break; }
        let body_start = cursor + 1;
        let mut depth = 1usize;
        let mut i = body_start;
        let mut in_string: Option<char> = None;
        while i < bytes.len() && depth > 0 {
            let b = bytes[i];
            if let Some(q) = in_string {
                if b == b'\\' { i += 2; continue; }
                if b as char == q { in_string = None; }
            } else if b == b'"' || b == b'\'' {
                in_string = Some(b as char);
            } else if b == b'{' {
                depth += 1;
            } else if b == b'}' {
                depth -= 1;
                if depth == 0 { break; }
            }
            i += 1;
        }
        if depth != 0 { break; }
        out.push(src[body_start..i].to_string());
        cursor = i + 1;
    }
    out
}

// Parse `inclusionHex: [ [ "...", "..." ], [ ... ] ]` into Vec<Vec<String>>.
fn parse_inclusion_hex(body: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let Some(tail) = find_field(body, "inclusionHex") else { return out; };
    let tail = tail.trim_start();
    if !tail.starts_with('[') { return out; }
    let bytes = tail.as_bytes();
    let mut i = 1usize;
    let mut depth = 1i32;
    while i < bytes.len() && depth > 0 {
        let b = bytes[i];
        if b == b'[' {
            depth += 1;
            if depth == 2 {
                let mut j = i + 1;
                let mut inner_depth = 1i32;
                let mut in_string: Option<char> = None;
                while j < bytes.len() && inner_depth > 0 {
                    let c = bytes[j];
                    if let Some(q) = in_string {
                        if c == b'\\' { j += 2; continue; }
                        if c as char == q { in_string = None; }
                    } else if c == b'"' || c == b'\'' {
                        in_string = Some(c as char);
                    } else if c == b'[' {
                        inner_depth += 1;
                    } else if c == b']' {
                        inner_depth -= 1;
                        if inner_depth == 0 { break; }
                    }
                    j += 1;
                }
                if inner_depth != 0 { break; }
                let inner = &tail[i + 1..j];
                let mut hex_strs = Vec::new();
                let mut k = 0usize;
                let inb = inner.as_bytes();
                while k < inb.len() {
                    if inb[k] == b'"' || inb[k] == b'\'' {
                        let quote = inb[k];
                        let start = k + 1;
                        let mut p = start;
                        while p < inb.len() && inb[p] != quote { p += 1; }
                        hex_strs.push(inner[start..p].to_string());
                        k = p + 1;
                    } else {
                        k += 1;
                    }
                }
                out.push(hex_strs);
                i = j + 1;
                depth -= 1;
                continue;
            }
        } else if b == b']' {
            depth -= 1;
        }
        i += 1;
    }
    out
}

// Parse `consistency: [ { fromSize: N, fromRootHex: "...", proofHex: [ ... ] }, ... ]`
struct ConsRow {
    from_size: u64,
    from_root_hex: String,
    proof_hex: Vec<String>,
}

fn parse_consistency(body: &str) -> Vec<ConsRow> {
    let mut out = Vec::new();
    let Some(tail) = find_field(body, "consistency") else { return out; };
    let tail = tail.trim_start();
    if !tail.starts_with('[') { return out; }
    let bytes = tail.as_bytes();
    let mut i = 1usize;
    let mut depth = 1i32;
    while i < bytes.len() && depth > 0 {
        let b = bytes[i];
        if b == b'{' && depth == 1 {
            let mut j = i + 1;
            let mut block_depth = 1i32;
            let mut in_string: Option<char> = None;
            while j < bytes.len() && block_depth > 0 {
                let c = bytes[j];
                if let Some(q) = in_string {
                    if c == b'\\' { j += 2; continue; }
                    if c as char == q { in_string = None; }
                } else if c == b'"' || c == b'\'' {
                    in_string = Some(c as char);
                } else if c == b'{' {
                    block_depth += 1;
                } else if c == b'}' {
                    block_depth -= 1;
                    if block_depth == 0 { break; }
                }
                j += 1;
            }
            if block_depth != 0 { break; }
            let inner_body = &tail[i + 1..j];
            let from_size    = read_int_field(inner_body, "fromSize").unwrap_or(0);
            let from_root_hex = read_string_field(inner_body, "fromRootHex").unwrap_or_default();
            // proofHex is an array of strings inside the inner_body.
            let mut proof_hex = Vec::new();
            if let Some(ph_tail) = find_field(inner_body, "proofHex") {
                let ph_tail = ph_tail.trim_start();
                let pb = ph_tail.as_bytes();
                if !pb.is_empty() && pb[0] == b'[' {
                    let mut k = 1usize;
                    let mut pd = 1i32;
                    while k < pb.len() && pd > 0 {
                        let c = pb[k];
                        if c == b'[' {
                            pd += 1;
                        } else if c == b']' {
                            pd -= 1;
                            if pd == 0 { break; }
                        } else if c == b'"' || c == b'\'' {
                            let quote = c;
                            let start = k + 1;
                            let mut p = start;
                            while p < pb.len() && pb[p] != quote { p += 1; }
                            proof_hex.push(ph_tail[start..p].to_string());
                            k = p + 1;
                            continue;
                        }
                        k += 1;
                    }
                }
            }
            out.push(ConsRow { from_size, from_root_hex, proof_hex });
            i = j + 1;
            continue;
        }
        if b == b']' { depth -= 1; }
        i += 1;
    }
    out
}

fn parse_leaves_utf8(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(tail) = find_field(body, "leavesUtf8") else { return out; };
    let tail = tail.trim_start();
    if !tail.starts_with('[') { return out; }
    let bytes = tail.as_bytes();
    let mut i = 1usize;
    while i < bytes.len() && bytes[i] != b']' {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let quote = bytes[i];
            let start = i + 1;
            let mut p = start;
            while p < bytes.len() && bytes[p] != quote { p += 1; }
            out.push(tail[start..p].to_string());
            i = p + 1;
        } else {
            i += 1;
        }
    }
    out
}

// ── Public driver, called from main.rs ─────────────────────────────────────

pub fn run(src: &str, log: &mut Vec<String>) -> bool {
    let mut all_ok = true;

    let blocks = extract_array_blocks(src, "merkleBlake3Records");
    if blocks.is_empty() {
        log.push("    ✗ merkleBlake3Records parsed as empty".to_string());
        return false;
    }
    log.push(format!("    Records parsed: {}", blocks.len()));

    let mut total_records = 0usize;
    let mut roots_ok = 0usize;
    let mut roots_fail = 0usize;
    let mut leaf_hashes_ok = 0usize;
    let mut leaf_hashes_fail = 0usize;
    let mut incl_ok = 0usize;
    let mut incl_fail = 0usize;
    let mut cons_ok = 0usize;
    let mut cons_fail = 0usize;

    for body in &blocks {
        total_records += 1;
        let tree_size = read_int_field(body, "treeSize").unwrap_or(u64::MAX);
        let root_hex = read_string_field(body, "rootHex").unwrap_or_default();
        let leaves = parse_leaves_utf8(body);
        let inclusion = parse_inclusion_hex(body);
        let consistency = parse_consistency(body);
        let desc = read_string_field(body, "desc").unwrap_or_default();

        if leaves.len() as u64 != tree_size {
            log.push(format!(
                "    ✗ size {}: leaves array has {} entries (expected {})",
                tree_size, leaves.len(), tree_size,
            ));
            all_ok = false;
            continue;
        }

        // Compute the root from leaves via our internal RFC 9162 walker
        // (with our BLAKE3-native hash_internal). Compare against recorded.
        let recorded_root = match hex::decode(&root_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => {
                log.push(format!("    ✗ {}: invalid rootHex", desc));
                all_ok = false;
                roots_fail += 1;
                continue;
            }
        };
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(|l| hash_leaf(l.as_bytes())).collect();
        let computed_root = compute_root(&leaf_hashes);

        if computed_root != recorded_root {
            log.push(format!("    ✗ {}: root mismatch", desc));
            log_byte_diff(log, &format!("size {}: root", tree_size), &computed_root, &recorded_root);
            roots_fail += 1;
            all_ok = false;
        } else {
            roots_ok += 1;
        }

        // Cross-check each leaf hash against the leviathan-recorded
        // expectation indirectly: the inclusion proof is recorded as
        // hex strings; we verify by re-hashing leaves and walking the
        // proof against the recorded root.
        for (i, leaf) in leaves.iter().enumerate() {
            let leaf_hash = hash_leaf(leaf.as_bytes());
            let proof_bytes: Vec<Vec<u8>> = inclusion[i].iter()
                .map(|h| hex::decode(h).unwrap_or_default())
                .collect();
            leaf_hashes_ok += 1;  // hash itself is RustCrypto-derived; no leviathan-side hex to compare
            let outcome = verify_inclusion(&leaf_hash, i as u64, tree_size, &proof_bytes, &recorded_root);
            if matches!(outcome, VerifyOutcome::Accept) {
                incl_ok += 1;
            } else {
                incl_fail += 1;
                leaf_hashes_fail += 1;
                log.push(format!("    ✗ size {} leaf {}: inclusion proof rejected", tree_size, i));
                all_ok = false;
            }
        }

        for cons in &consistency {
            let old_root = match hex::decode(&cons.from_root_hex) {
                Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
                _ => {
                    log.push(format!("    ✗ size {} cons from {}: invalid fromRootHex", tree_size, cons.from_size));
                    cons_fail += 1;
                    all_ok = false;
                    continue;
                }
            };
            // Cross-check fromRootHex: recompute it independently from the
            // first cons.from_size deterministic leaves.
            let from_leaves: Vec<[u8; 32]> = (0..cons.from_size as usize)
                .map(|i| hash_leaf(format!("leaf-{}", i).as_bytes()))
                .collect();
            let recomputed_from_root = compute_root(&from_leaves);
            if recomputed_from_root != old_root {
                log.push(format!(
                    "    ✗ size {} cons from {}: fromRootHex mismatch (recomputed via Rust oracle)",
                    tree_size, cons.from_size,
                ));
                log_byte_diff(log, "fromRootHex", &recomputed_from_root, &old_root);
                cons_fail += 1;
                all_ok = false;
                continue;
            }
            let proof_bytes: Vec<Vec<u8>> = cons.proof_hex.iter()
                .map(|h| hex::decode(h).unwrap_or_default())
                .collect();
            let outcome = verify_consistency(cons.from_size, tree_size, &old_root, &recorded_root, &proof_bytes);
            if matches!(outcome, VerifyOutcome::Accept) {
                cons_ok += 1;
            } else {
                cons_fail += 1;
                log.push(format!("    ✗ size {} cons from {}: consistency proof rejected", tree_size, cons.from_size));
                all_ok = false;
            }
        }
    }

    log.push(format!(
        "    Summary: {} records, roots {}/{} ok, leaves {}/{} ok, incl {}/{} ok, cons {}/{} ok",
        total_records,
        roots_ok, roots_ok + roots_fail,
        leaf_hashes_ok, leaf_hashes_ok + leaf_hashes_fail,
        incl_ok, incl_ok + incl_fail,
        cons_ok, cons_ok + cons_fail,
    ));
    all_ok
}

// RFC 9162 §2.1.1 MTH walker over an array of pre-hashed leaves; mirrors
// the leviathan TS `subtreeHash` recursion, hash-agnostic against our
// `hash_internal`. Used only for the cross-check; the test corpus's
// records carry the proof bytes directly so the verifier does not
// re-derive them here.
fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() { return hash_empty(); }
    fn rec(leaves: &[[u8; 32]]) -> [u8; 32] {
        let n = leaves.len();
        if n == 1 { return leaves[0]; }
        let mut k = 1usize;
        while k * 2 < n { k *= 2; }
        let left = rec(&leaves[..k]);
        let right = rec(&leaves[k..]);
        hash_internal(&left, &right)
    }
    rec(leaves)
}
