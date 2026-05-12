// TS vector file parser. Handles two shapes:
//
//   SealXChachaV3Vector      , single-chunk seal blob, flat fields
//   SealStreamXChachaV3Vector, multi-chunk sealstream, with nested chunks array
//   SealSerpentV3Vector      , single-chunk seal blob, flat fields (Serpent)
//   SealStreamSerpentV3Vector, multi-chunk sealstream, with nested chunks array
//
// This parser only handles output produced by scripts/gen-seal-vectors.ts and
// scripts/gen-sealstream-vectors.ts. Hand-edited vector files are not
// supported. The vector files are immutable per AGENTS.md, so this is fine.
//
// Approach:
//   1. Find each `export const NAME: TYPE_NAME = { ... };` block.
//   2. Extract fields by name, joining concatenated string literals (`'a' + 'b'`)
//      into a single value.
//   3. For `chunks:` arrays, split the array body at top-level `},` and parse
//      each chunk object recursively for plaintext/ciphertext.

#[derive(Debug, Clone)]
pub struct SealVector {
    pub name:        String,
    pub description: String,
    pub key:         Vec<u8>,
    pub nonce:       Vec<u8>,
    pub plaintext:   Vec<u8>,
    pub preamble:    Vec<u8>,
    pub blob:        Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SealStreamVector {
    pub name:        String,
    pub description: String,
    pub key:         Vec<u8>,
    pub nonce:       Vec<u8>,
    pub chunk_size:  u32,
    pub framed:      bool,
    pub preamble:    Vec<u8>,
    pub chunks:      Vec<ChunkVector>,
}

#[derive(Debug, Clone)]
pub struct ChunkVector {
    pub plaintext:  Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn parse_seal_file(src: &str, type_name: &str) -> Vec<SealVector> {
    parse_blocks(src, type_name)
        .into_iter()
        .map(|(name, body)| SealVector {
            name,
            description: extract_string(&body, "description"),
            key:         hex::decode(extract_hex(&body, "key")).unwrap_or_default(),
            nonce:       hex::decode(extract_hex(&body, "nonce")).unwrap_or_default(),
            plaintext:   hex::decode(extract_hex(&body, "plaintext")).unwrap_or_default(),
            preamble:    hex::decode(extract_hex(&body, "preamble")).unwrap_or_default(),
            blob:        hex::decode(extract_hex(&body, "blob")).unwrap_or_default(),
        })
        .collect()
}

pub fn parse_sealstream_file(src: &str, type_name: &str) -> Vec<SealStreamVector> {
    parse_blocks(src, type_name)
        .into_iter()
        .map(|(name, body)| SealStreamVector {
            name,
            description: extract_string(&body, "description"),
            key:         hex::decode(extract_hex(&body, "key")).unwrap_or_default(),
            nonce:       hex::decode(extract_hex(&body, "nonce")).unwrap_or_default(),
            chunk_size:  extract_int(&body, "chunkSize").unwrap_or(0),
            framed:      extract_bool(&body, "framed").unwrap_or(false),
            preamble:    hex::decode(extract_hex(&body, "preamble")).unwrap_or_default(),
            chunks:      extract_chunks(&body),
        })
        .collect()
}

// Walk the source for `export const NAME: TYPE_NAME = { ... };` blocks.
// Returns (name, body) pairs where body is the contents between `{` and `};`.
fn parse_blocks(src: &str, type_name: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let needle  = "export const ";
    let mut cursor = 0usize;

    while let Some(start) = src[cursor..].find(needle) {
        let abs_start = cursor + start;
        let after     = abs_start + needle.len();

        let colon = match src[after..].find(':') {
            Some(i) => i,
            None    => break,
        };
        let name = src[after..after + colon].trim().to_string();

        // Confirm this is the right type
        let type_start = after + colon + 1;
        let eq_offset  = src[type_start..].find('=').unwrap_or(0);
        let type_end   = type_start + eq_offset;
        let parsed_type_name = src[type_start..type_end].trim();
        if parsed_type_name != type_name {
            cursor = type_end;
            continue;
        }

        // Find the block body { ... };
        let brace      = src[type_end..].find('{').unwrap();
        let body_start = type_end + brace + 1;
        // Inner chunks use `},` (no semicolon). Outer block ends with `};`.
        let body_end   = body_start + src[body_start..].find("};").unwrap();

        out.push((name, src[body_start..body_end].to_string()));
        cursor = body_end + 2;
    }
    out
}

// Extract a single human-readable string field (description). Returns the
// first single-quoted chunk after the field name.
fn extract_string(body: &str, field: &str) -> String {
    let needle = format!("{}:", field);
    let Some(start) = find_field_offset(body, field) else { return String::new(); };
    let after = start + needle.len();
    let q1 = match body[after..].find('\'') {
        Some(i) => after + i,
        None    => return String::new(),
    };
    let q2 = match body[q1 + 1..].find('\'') {
        Some(i) => q1 + 1 + i,
        None    => return String::new(),
    };
    body[q1 + 1..q2].to_string()
}

// Identifier boundary: previous char must be start-of-input or a non-identifier
// char so that a request for field "k" doesn't match the `k:` inside `ek:` /
// `dk:`. The seal/sealstream parsers' fields don't collide with each other,
// this is the surface where ML-KEM (`ek`, `dk`, `c`, `k`) and ML-DSA (`mu`,
// `sig`) need it.
fn find_field_offset(body: &str, field: &str) -> Option<usize> {
    let needle = format!("{}:", field);
    let mut cursor = 0usize;
    while let Some(rel) = body[cursor..].find(&needle) {
        let abs = cursor + rel;
        let prev_ok = abs == 0 || {
            let prev = body.as_bytes()[abs - 1];
            !(prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'$')
        };
        if prev_ok {
            return Some(abs);
        }
        cursor = abs + 1;
    }
    None
}

// Extract a hex field (possibly multi-line, joined by `+`). Concatenates
// all single-quoted chunks until the first `,` outside a quote.
fn extract_hex(body: &str, field: &str) -> String {
    let needle = format!("{}:", field);
    let Some(start) = find_field_offset(body, field) else { return String::new(); };
    let after = start + needle.len();

    let mut out      = String::new();
    let mut in_quote = false;
    let mut chunk    = String::new();
    for ch in body[after..].chars() {
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
    out
}

// Extract an integer literal field (chunkSize). Returns None if absent.
fn extract_int(body: &str, field: &str) -> Option<u32> {
    let needle = format!("{}:", field);
    let start  = find_field_offset(body, field)? + needle.len();
    let mut digits = String::new();
    let mut seen_digit = false;
    for ch in body[start..].chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            seen_digit = true;
        } else if seen_digit {
            break;
        } else if ch == ',' || ch == '\n' {
            break;
        }
    }
    digits.parse().ok()
}

// Extract a boolean field (framed). Returns None if absent.
fn extract_bool(body: &str, field: &str) -> Option<bool> {
    let needle = format!("{}:", field);
    let start  = find_field_offset(body, field)? + needle.len();
    let rest   = body[start..].trim_start();
    if rest.starts_with("true")  { return Some(true);  }
    if rest.starts_with("false") { return Some(false); }
    None
}

// ────────────────────────────────────────────────────────────────────────────
// AES-GCM-SIV vectors (RFC 8452 Appendix C, parsed from aes_gcm_siv.ts).
// ────────────────────────────────────────────────────────────────────────────

// The verifier exercises only (key, nonce, aad, plaintext, result). The
// other fields (record_auth_key, record_enc_key, polyval_input,
// polyval_result, polyval_xor_nonce, polyval_masked, tag,
// initial_counter) are gate-bisection fixtures for Phase 4b-impl unit
// tests and are intentionally read-but-not-used here.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct AesGcmSivVector {
    pub description:      String,
    pub plaintext:        Vec<u8>,
    pub aad:              Vec<u8>,
    pub key:              Vec<u8>,
    pub nonce:            Vec<u8>,
    pub record_auth_key:  Vec<u8>,
    pub record_enc_key:   Vec<u8>,
    pub polyval_input:    Vec<u8>,
    pub polyval_result:   Vec<u8>,
    pub polyval_xor_nonce:Vec<u8>,
    pub polyval_masked:   Vec<u8>,
    pub tag:              Vec<u8>,
    pub initial_counter:  Vec<u8>,
    pub result:           Vec<u8>,
}

/// Parse aes_gcm_siv.ts. Returns three arrays in declaration order:
///   - aesGcmSiv128Vectors             (24 records)
///   - aesGcmSiv256Vectors             (24 records)
///   - aesGcmSivCounterWrapVectors      ( 2 records)
pub fn parse_aes_gcm_siv_file(src: &str) -> (
    Vec<AesGcmSivVector>,
    Vec<AesGcmSivVector>,
    Vec<AesGcmSivVector>,
) {
    let v128  = parse_siv_array(src, "aesGcmSiv128Vectors");
    let v256  = parse_siv_array(src, "aesGcmSiv256Vectors");
    let vwrap = parse_siv_array(src, "aesGcmSivCounterWrapVectors");
    (v128, v256, vwrap)
}

fn parse_siv_array(src: &str, export_name: &str) -> Vec<AesGcmSivVector> {
    let needle = format!("export const {}:", export_name);
    let Some(start) = src.find(&needle) else { return Vec::new(); };
    // Skip the type annotation (which contains `[]`) by anchoring on the `=`.
    let Some(eq_rel) = src[start..].find('=') else { return Vec::new(); };
    let after_eq = start + eq_rel + 1;
    let lbracket = match src[after_eq..].find('[') {
        Some(i) => after_eq + i + 1,
        None    => return Vec::new(),
    };
    let rbracket = match find_matching_bracket(&src[lbracket..]) {
        Some(i) => lbracket + i,
        None    => return Vec::new(),
    };
    let body = &src[lbracket..rbracket];
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| AesGcmSivVector {
            description:        extract_string(&obj, "description"),
            plaintext:          hex::decode(extract_hex(&obj, "plaintext")).unwrap_or_default(),
            aad:                hex::decode(extract_hex(&obj, "aad")).unwrap_or_default(),
            key:                hex::decode(extract_hex(&obj, "key")).unwrap_or_default(),
            nonce:              hex::decode(extract_hex(&obj, "nonce")).unwrap_or_default(),
            record_auth_key:    hex::decode(extract_hex(&obj, "recordAuthKey")).unwrap_or_default(),
            record_enc_key:     hex::decode(extract_hex(&obj, "recordEncKey")).unwrap_or_default(),
            polyval_input:      hex::decode(extract_hex(&obj, "polyvalInput")).unwrap_or_default(),
            polyval_result:     hex::decode(extract_hex(&obj, "polyvalResult")).unwrap_or_default(),
            polyval_xor_nonce:  hex::decode(extract_hex(&obj, "polyvalXorNonce")).unwrap_or_default(),
            polyval_masked:     hex::decode(extract_hex(&obj, "polyvalMasked")).unwrap_or_default(),
            tag:                hex::decode(extract_hex(&obj, "tag")).unwrap_or_default(),
            initial_counter:    hex::decode(extract_hex(&obj, "initialCounter")).unwrap_or_default(),
            result:             hex::decode(extract_hex(&obj, "result")).unwrap_or_default(),
        })
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// POLYVAL vectors (RFC 8452 §7 + Appendix A, parsed from polyval.ts).
// ────────────────────────────────────────────────────────────────────────────

// PolyvalFieldOpsVector and PolyvalMulXVector are unit-test-only
// fixtures for Phase 4b-impl. The verifier reads them so the corpus is
// fully traversed end-to-end, but does not exercise them, RustCrypto's
// `polyval` crate does not expose dot() / mulX_GHASH directly, and the
// SIV vectors in aes_gcm_siv.ts transitively cover POLYVAL
// multiplication. The non-description fields are therefore intentionally
// read-but-not-used here.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct PolyvalFieldOpsVector {
    pub description: String,
    pub a:           Vec<u8>,
    pub b:           Vec<u8>,
    pub sum:         Vec<u8>,
    pub product:     Vec<u8>,
    pub dot:         Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct PolyvalMulXVector {
    pub description:  String,
    pub input:        Vec<u8>,
    pub mul_x_ghash:  Vec<u8>,
    pub mul_x_polyval:Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct PolyvalHashVector {
    pub description: String,
    pub h:           Vec<u8>,
    pub blocks:      Vec<Vec<u8>>,
    pub expected:    Vec<u8>,
}

pub fn parse_polyval_file(src: &str) -> (
    Option<PolyvalFieldOpsVector>,
    Vec<PolyvalMulXVector>,
    Vec<PolyvalHashVector>,
) {
    let field_ops = parse_polyval_fieldops(src);
    let mul_x     = parse_polyval_mulx(src);
    let hashes    = parse_polyval_hashes(src);
    (field_ops, mul_x, hashes)
}

fn parse_polyval_fieldops(src: &str) -> Option<PolyvalFieldOpsVector> {
    // `export const polyvalFieldOps: PolyvalFieldOpsVector = { ... };`
    let needle = "export const polyvalFieldOps:";
    let start  = src.find(needle)?;
    let lbrace = start + src[start..].find('{')?;
    let rbrace = lbrace + find_matching_brace(&src[lbrace..])?;
    let obj    = &src[lbrace + 1..rbrace];
    Some(PolyvalFieldOpsVector {
        description: extract_string(obj, "description"),
        a:           hex::decode(extract_hex(obj, "a")).unwrap_or_default(),
        b:           hex::decode(extract_hex(obj, "b")).unwrap_or_default(),
        sum:         hex::decode(extract_hex(obj, "sum")).unwrap_or_default(),
        product:     hex::decode(extract_hex(obj, "product")).unwrap_or_default(),
        dot:         hex::decode(extract_hex(obj, "dot")).unwrap_or_default(),
    })
}

fn parse_polyval_mulx(src: &str) -> Vec<PolyvalMulXVector> {
    let needle = "export const polyvalMulXVectors:";
    let Some(start) = src.find(needle) else { return Vec::new(); };
    let Some(eq_rel) = src[start..].find('=') else { return Vec::new(); };
    let after_eq = start + eq_rel + 1;
    let Some(rel)   = src[after_eq..].find('[') else { return Vec::new(); };
    let lbracket    = after_eq + rel + 1;
    let Some(end)   = find_matching_bracket(&src[lbracket..]) else { return Vec::new(); };
    let body        = &src[lbracket..lbracket + end];
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| PolyvalMulXVector {
            description:   extract_string(&obj, "description"),
            input:         hex::decode(extract_hex(&obj, "input")).unwrap_or_default(),
            mul_x_ghash:   hex::decode(extract_hex(&obj, "mulX_ghash")).unwrap_or_default(),
            mul_x_polyval: hex::decode(extract_hex(&obj, "mulX_polyval")).unwrap_or_default(),
        })
        .collect()
}

fn parse_polyval_hashes(src: &str) -> Vec<PolyvalHashVector> {
    let needle = "export const polyvalHashVectors:";
    let Some(start) = src.find(needle) else { return Vec::new(); };
    let Some(eq_rel) = src[start..].find('=') else { return Vec::new(); };
    let after_eq = start + eq_rel + 1;
    let Some(rel)   = src[after_eq..].find('[') else { return Vec::new(); };
    let lbracket    = after_eq + rel + 1;
    let Some(end)   = find_matching_bracket(&src[lbracket..]) else { return Vec::new(); };
    let body        = &src[lbracket..lbracket + end];
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| PolyvalHashVector {
            description: extract_string(&obj, "description"),
            h:           hex::decode(extract_hex(&obj, "h")).unwrap_or_default(),
            blocks:      extract_hex_array(&obj, "blocks"),
            expected:    hex::decode(extract_hex(&obj, "expected")).unwrap_or_default(),
        })
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// New shared helpers for the SIV / POLYVAL parsers.
// (Existing `extract_string` / `extract_hex` / `extract_int` / `extract_bool`
// / `extract_chunks` are unchanged and still serve the original seal +
// sealstream parsers.)
// ────────────────────────────────────────────────────────────────────────────

// Inside single-quoted strings, treat `\<next>` as a single escaped unit so
// `\'` and `\\` do not toggle the quote state. kmac.ts customization fields
// regularly contain `\'`; chacha20.ts uses it in a few RFC sample strings.
// Outside quotes, `\` is treated as a normal byte (no .ts vector file uses
// `\` outside a quote).
fn find_matching_bracket(s: &str) -> Option<usize> {
    let mut depth = 1i32;
    let mut in_q  = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_q && b == b'\\' && i + 1 < bytes.len() { i += 2; continue; }
        match b {
            b'\'' => in_q = !in_q,
            b'[' if !in_q => depth += 1,
            b']' if !in_q => {
                depth -= 1;
                if depth == 0 { return Some(i); }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn find_matching_brace(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_q  = false;
    let mut started = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_q && b == b'\\' && i + 1 < bytes.len() { i += 2; continue; }
        match b {
            b'\'' => in_q = !in_q,
            b'{' if !in_q => { depth += 1; started = true; }
            b'}' if !in_q => {
                depth -= 1;
                if started && depth == 0 { return Some(i); }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

// Split a top-level array body into individual `{ ... }` object bodies.
// Honours nested braces and single-quoted strings (with `\\` / `\'`
// escapes treated as opaque inside the quote). Comma-and-whitespace
// between objects is discarded.
fn split_top_level_objects(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_q  = false;
    let mut start = None::<usize>;
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_q && b == b'\\' && i + 1 < bytes.len() { i += 2; continue; }
        match b {
            b'\'' => in_q = !in_q,
            b'{' if !in_q => {
                if depth == 0 { start = Some(i + 1); }
                depth += 1;
            }
            b'}' if !in_q => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start.take() {
                        out.push(body[s..i].to_string());
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

// Parse a `field: ['hex1', 'hex2', ...]` array. Elements may be multi-line
// concatenated via `'a' + 'b'` in the same way extract_hex handles single
// fields; here each top-level comma-separated item joins all its quoted
// fragments into a single hex string and returns the decoded bytes.
fn extract_hex_array(body: &str, field: &str) -> Vec<Vec<u8>> {
    let needle = format!("{}:", field);
    let Some(start) = body.find(&needle) else { return Vec::new(); };
    let after = start + needle.len();
    let Some(rel) = body[after..].find('[') else { return Vec::new(); };
    let lbracket = after + rel + 1;
    let Some(end) = find_matching_bracket(&body[lbracket..]) else { return Vec::new(); };
    let arr = &body[lbracket..lbracket + end];

    // Comma-separated entries; each entry is one or more single-quoted hex
    // chunks joined by `+`.
    let mut entries = Vec::new();
    let mut cur     = String::new();
    let mut in_q    = false;
    let mut chunk   = String::new();
    let push_entry = |s: &mut String, out: &mut Vec<Vec<u8>>| {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            out.push(hex::decode(trimmed).unwrap_or_default());
        }
        s.clear();
    };
    for ch in arr.chars() {
        match ch {
            '\'' if !in_q => { in_q = true; }
            '\'' if in_q  => {
                in_q = false;
                cur.push_str(&chunk);
                chunk.clear();
            }
            c if in_q => chunk.push(c),
            ',' => push_entry(&mut cur, &mut entries),
            _ => {}
        }
    }
    push_entry(&mut cur, &mut entries);
    entries
}

// ────────────────────────────────────────────────────────────────────────────
// AES-mode vectors (aes.ts, aes_cbc.ts, aes_ctr.ts, aes_gcm.ts).
//
// These files use two TS conveniences that the seal/sealstream/SIV
// parsers above do not need to handle:
//
//   - top-level const declarations (`const SHARED_PT = '6bc1...' + '...';`)
//     referenced in record fields as bare identifiers (`pt: SHARED_PT,`)
//   - cross-array record references (`key: aesCbcEncryptVectors[0].key,`)
//     used by the decrypt arrays to mirror the encrypt arrays without
//     re-typing the hex.
//
// The preprocessing helpers below textually substitute both patterns
// with `'<hex>'` literals before the array-of-records walker runs, so
// the existing extract_hex/extract_string helpers Just Work on the
// rewritten source.
// ────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct AesBlockVector {
    pub description: String,
    pub key:         Vec<u8>,
    pub pt:          Vec<u8>,
    pub ct:          Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct AesKeyExpansionVector {
    pub description:        String,
    pub key_bits:            u32,
    pub key:                 Vec<u8>,
    pub round_key_schedule:  Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct AesRoundIntermediateVector {
    pub description:       String,
    pub round:             u32,
    pub start:             Vec<u8>,
    pub after_sub_bytes:   Vec<u8>,
    pub after_shift_rows:  Vec<u8>,
    pub after_mix_columns: Vec<u8>,
    pub round_key:         Vec<u8>,
    pub end:               Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct AesVectors {
    pub cipher_128:       Vec<AesBlockVector>,
    pub cipher_192:       Vec<AesBlockVector>,
    pub cipher_256:       Vec<AesBlockVector>,
    pub key_expansion:    Vec<AesKeyExpansionVector>,
    pub sbox:             Option<Vec<u8>>,
    pub round_inter_128:  Vec<AesRoundIntermediateVector>,
    pub round_inter_192:  Vec<AesRoundIntermediateVector>,
    pub round_inter_256:  Vec<AesRoundIntermediateVector>,
}

#[derive(Debug, Clone, Default)]
pub struct AesCbcVector {
    pub description: String,
    pub key:         Vec<u8>,
    pub iv:          Vec<u8>,
    pub pt:          Vec<u8>,
    pub ct:          Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct AesCtrVector {
    pub description:     String,
    pub key:             Vec<u8>,
    pub initial_counter: Vec<u8>,
    pub pt:              Vec<u8>,
    pub ct:              Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct AesGcmVector {
    pub description: String,
    pub key:         Vec<u8>,
    pub iv:          Vec<u8>,
    pub aad:         Vec<u8>,
    pub pt:          Vec<u8>,
    pub ct:          Vec<u8>,
    pub tag:         Vec<u8>,
}

// ──── aes.ts ────

pub fn parse_aes_file(src: &str) -> AesVectors {
    let s = preprocess_consts(src);
    AesVectors {
        cipher_128:       parse_block_array(&s, "aes128CipherVectors"),
        cipher_192:       parse_block_array(&s, "aes192CipherVectors"),
        cipher_256:       parse_block_array(&s, "aes256CipherVectors"),
        key_expansion:    parse_key_expansion_array(&s, "aesKeyExpansionVectors"),
        sbox:             parse_uint8_array_literal(&s, "aesSboxTable"),
        round_inter_128:  parse_round_inter_array(&s, "aesRoundIntermediates128"),
        round_inter_192:  parse_round_inter_array(&s, "aesRoundIntermediates192"),
        round_inter_256:  parse_round_inter_array(&s, "aesRoundIntermediates256"),
    }
}

fn parse_block_array(src: &str, export_name: &str) -> Vec<AesBlockVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| AesBlockVector {
            description: extract_string(&obj, "description"),
            key:         hex::decode(extract_hex(&obj, "key")).unwrap_or_default(),
            pt:          hex::decode(extract_hex(&obj, "pt")).unwrap_or_default(),
            ct:          hex::decode(extract_hex(&obj, "ct")).unwrap_or_default(),
        })
        .collect()
}

fn parse_key_expansion_array(src: &str, export_name: &str) -> Vec<AesKeyExpansionVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| AesKeyExpansionVector {
            description:       extract_string(&obj, "description"),
            key_bits:           extract_int(&obj, "keyBits").unwrap_or(0),
            key:                hex::decode(extract_hex(&obj, "key")).unwrap_or_default(),
            round_key_schedule: hex::decode(extract_hex(&obj, "roundKeySchedule")).unwrap_or_default(),
        })
        .collect()
}

fn parse_round_inter_array(src: &str, export_name: &str) -> Vec<AesRoundIntermediateVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| AesRoundIntermediateVector {
            description:       extract_string(&obj, "description"),
            round:             extract_int(&obj, "round").unwrap_or(0),
            start:             hex::decode(extract_hex(&obj, "start")).unwrap_or_default(),
            after_sub_bytes:   hex::decode(extract_hex(&obj, "afterSubBytes")).unwrap_or_default(),
            after_shift_rows:  hex::decode(extract_hex(&obj, "afterShiftRows")).unwrap_or_default(),
            after_mix_columns: hex::decode(extract_hex(&obj, "afterMixColumns")).unwrap_or_default(),
            round_key:         hex::decode(extract_hex(&obj, "roundKey")).unwrap_or_default(),
            end:               hex::decode(extract_hex(&obj, "end")).unwrap_or_default(),
        })
        .collect()
}

// `export const aesSboxTable: Uint8Array = new Uint8Array([0x63, 0x7c, ...]);`
fn parse_uint8_array_literal(src: &str, export_name: &str) -> Option<Vec<u8>> {
    let needle = format!("export const {}", export_name);
    let start  = src.find(&needle)?;
    // Find the `[` that opens the byte list (the second `[` after the
    // type annotation `Uint8Array`).
    let after_eq = start + src[start..].find('=')? + 1;
    let lbracket = after_eq + src[after_eq..].find('[')? + 1;
    let len      = find_matching_bracket(&src[lbracket..])?;
    let body     = &src[lbracket..lbracket + len];

    // Strip `//` line comments, aes.ts annotates each S-box row with
    // `// row 0xN_:` headers, and a comment-leading comma-segment would
    // otherwise eat the first byte of the following row.
    let stripped: String = body.lines()
        .map(|l| match l.find("//") { Some(i) => &l[..i], None => l })
        .collect::<Vec<_>>()
        .join("\n");

    let mut bytes = Vec::with_capacity(256);
    for tok in stripped.split(',') {
        let t = tok.trim();
        if t.is_empty() { continue; }
        // Hex literal `0x..` or decimal byte.
        let v: Option<u8> = if let Some(s) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            u8::from_str_radix(s, 16).ok()
        } else {
            t.parse().ok()
        };
        if let Some(b) = v { bytes.push(b); }
    }
    if bytes.is_empty() { None } else { Some(bytes) }
}

// ──── aes_cbc.ts ────

pub fn parse_aes_cbc_file(src: &str) -> (Vec<AesCbcVector>, Vec<AesCbcVector>) {
    let s_consts = preprocess_consts(src);
    let enc = parse_cbc_array(&s_consts, "aesCbcEncryptVectors");
    let s_refs = preprocess_array_refs(&s_consts, "aesCbcEncryptVectors", &cbc_to_field_map(&enc));
    let dec = parse_cbc_array(&s_refs, "aesCbcDecryptVectors");
    (enc, dec)
}

fn parse_cbc_array(src: &str, export_name: &str) -> Vec<AesCbcVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| AesCbcVector {
            description: extract_string(&obj, "description"),
            key:         hex::decode(extract_hex(&obj, "key")).unwrap_or_default(),
            iv:          hex::decode(extract_hex(&obj, "iv")).unwrap_or_default(),
            pt:          hex::decode(extract_hex(&obj, "pt")).unwrap_or_default(),
            ct:          hex::decode(extract_hex(&obj, "ct")).unwrap_or_default(),
        })
        .collect()
}

fn cbc_to_field_map(records: &[AesCbcVector]) -> Vec<Vec<(&'static str, Vec<u8>)>> {
    records.iter().map(|r| vec![
        ("key",         r.key.clone()),
        ("iv",          r.iv.clone()),
        ("pt",          r.pt.clone()),
        ("ct",          r.ct.clone()),
    ]).collect()
}

// ──── aes_ctr.ts ────

pub fn parse_aes_ctr_file(src: &str) -> (Vec<AesCtrVector>, Vec<AesCtrVector>) {
    let s_consts = preprocess_consts(src);
    let enc = parse_ctr_array(&s_consts, "aesCtrEncryptVectors");
    let s_refs = preprocess_array_refs(&s_consts, "aesCtrEncryptVectors", &ctr_to_field_map(&enc));
    let dec = parse_ctr_array(&s_refs, "aesCtrDecryptVectors");
    (enc, dec)
}

fn parse_ctr_array(src: &str, export_name: &str) -> Vec<AesCtrVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| AesCtrVector {
            description:     extract_string(&obj, "description"),
            key:             hex::decode(extract_hex(&obj, "key")).unwrap_or_default(),
            initial_counter: hex::decode(extract_hex(&obj, "initialCounter")).unwrap_or_default(),
            pt:              hex::decode(extract_hex(&obj, "pt")).unwrap_or_default(),
            ct:              hex::decode(extract_hex(&obj, "ct")).unwrap_or_default(),
        })
        .collect()
}

fn ctr_to_field_map(records: &[AesCtrVector]) -> Vec<Vec<(&'static str, Vec<u8>)>> {
    records.iter().map(|r| vec![
        ("key",            r.key.clone()),
        ("initialCounter", r.initial_counter.clone()),
        ("pt",             r.pt.clone()),
        ("ct",             r.ct.clone()),
    ]).collect()
}

// ──── aes_gcm.ts ────

pub fn parse_aes_gcm_file(src: &str) -> Vec<AesGcmVector> {
    // No SHARED_* consts or cross-array refs in this file.
    let Some(body) = locate_array_body(src, "aesGcmVectors") else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| AesGcmVector {
            description: extract_string(&obj, "description"),
            key:         hex::decode(extract_hex(&obj, "key")).unwrap_or_default(),
            iv:          hex::decode(extract_hex(&obj, "iv")).unwrap_or_default(),
            aad:         hex::decode(extract_hex(&obj, "aad")).unwrap_or_default(),
            pt:          hex::decode(extract_hex(&obj, "pt")).unwrap_or_default(),
            ct:          hex::decode(extract_hex(&obj, "ct")).unwrap_or_default(),
            tag:         hex::decode(extract_hex(&obj, "tag")).unwrap_or_default(),
        })
        .collect()
    // NOTE: GcmFailVector negative vectors are not present in
    // McGrew-Viega Appendix B and would require a separate export to
    // parse. If `aesGcmFailVectors` is ever added, this parser needs
    // an extension.
}

// ──── shared helpers for the AES-mode parsers ────

// Find `export const NAME ... = [ ... ];` and return the body between
// the matched array brackets. Skips the type annotation's `[]`.
fn locate_array_body<'a>(src: &'a str, export_name: &str) -> Option<&'a str> {
    let needle = format!("export const {}:", export_name);
    let start  = src.find(&needle)?;
    let after_eq = start + src[start..].find('=')? + 1;
    let lbracket = after_eq + src[after_eq..].find('[')? + 1;
    let len      = find_matching_bracket(&src[lbracket..])?;
    Some(&src[lbracket..lbracket + len])
}

// Walk top-level `const NAME = '...' + '...' + ...;` declarations and
// substitute each NAME with a single quoted hex literal in the source.
// Identifiers must be SCREAMING_SNAKE_CASE so we don't accidentally
// rewrite normal variables. Multiple consts are processed in order.
fn preprocess_consts(src: &str) -> String {
    let mut out = src.to_string();
    let mut consts: Vec<(String, String)> = Vec::new();

    // Iterate over `const NAME = ` occurrences at line starts (allowing
    // leading whitespace). Each declaration ends at the first `;` after
    // the `=`.
    let mut cursor = 0usize;
    while let Some(rel) = out[cursor..].find("const ") {
        let abs_start = cursor + rel;
        // Require this `const` to be at line start (or preceded by
        // whitespace only on its line) to avoid matching inside strings.
        let line_start = out[..abs_start].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let prefix = &out[line_start..abs_start];
        if !prefix.trim().is_empty() {
            cursor = abs_start + 6;
            continue;
        }

        let after_const = abs_start + 6;
        // Read the identifier.
        let name_end = match out[after_const..].find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            Some(i) => after_const + i,
            None    => break,
        };
        let name = out[after_const..name_end].to_string();
        // Only screaming snake.
        if !name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
           || name.is_empty()
        {
            cursor = name_end;
            continue;
        }
        // Find `=` and `;`.
        let eq_pos = match out[name_end..].find('=') { Some(i) => name_end + i + 1, None => break };
        let semi   = match out[eq_pos..].find(';')   { Some(i) => eq_pos + i,        None => break };
        let rhs    = &out[eq_pos..semi];

        // Concatenate every quoted fragment in the RHS.
        let mut hex = String::new();
        let mut in_q = false;
        let mut chunk = String::new();
        for ch in rhs.chars() {
            match ch {
                '\'' if !in_q => in_q = true,
                '\'' if in_q  => { in_q = false; hex.push_str(&chunk); chunk.clear(); }
                c if in_q => chunk.push(c),
                _ => {}
            }
        }
        if !hex.is_empty() {
            consts.push((name, hex));
        }
        cursor = semi + 1;
    }

    // Substitute each NAME (token-bounded) with `'hex'`.
    for (name, hex) in consts {
        out = replace_identifier_token(&out, &name, &format!("'{}'", hex));
    }
    out
}

// Replace whole-identifier occurrences of `name` with `replacement`,
// honouring identifier-character boundaries on both sides so
// substrings inside other identifiers (or comments containing the
// name) are not rewritten.
fn replace_identifier_token(src: &str, name: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(name.as_bytes()) {
            let before_ok = i == 0 || !is_ident_char(bytes[i - 1]);
            let after_idx = i + name.len();
            let after_ok  = after_idx >= bytes.len() || !is_ident_char(bytes[after_idx]);
            if before_ok && after_ok {
                out.push_str(replacement);
                i = after_idx;
                continue;
            }
        }
        // Push next char (must respect UTF-8 boundary).
        let ch_len = next_utf8_len(bytes, i);
        out.push_str(&src[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn next_utf8_len(bytes: &[u8], i: usize) -> usize {
    let b = bytes[i];
    if b < 0x80          { 1 }
    else if b < 0xc0     { 1 } // continuation; shouldn't start here, but be safe
    else if b < 0xe0     { 2 }
    else if b < 0xf0     { 3 }
    else                 { 4 }
}

// Replace `array_name[idx].field` references with the corresponding
// hex literal from the supplied per-record field map.
fn preprocess_array_refs(
    src:        &str,
    array_name: &str,
    records:    &[Vec<(&'static str, Vec<u8>)>],
) -> String {
    let mut out = src.to_string();
    for (idx, fields) in records.iter().enumerate() {
        for (field, value) in fields {
            let pat = format!("{}[{}].{}", array_name, idx, field);
            let replacement = format!("'{}'", hex::encode(value));
            out = out.replace(&pat, &replacement);
        }
    }
    out
}

// Extract the chunks: [...] array. Each chunk object has plaintext and
// ciphertext fields. The array body is split at top-level `},` boundaries.
fn extract_chunks(body: &str) -> Vec<ChunkVector> {
    let needle = "chunks:";
    let Some(start) = body.find(needle) else { return Vec::new(); };
    let after = start + needle.len();
    // Find the opening [
    let lbracket = match body[after..].find('[') {
        Some(i) => after + i + 1,
        None    => return Vec::new(),
    };
    // Find the closing ] at depth 0.
    let mut depth_bracket = 1i32;
    let mut rbracket      = lbracket;
    let mut in_quote      = false;
    for (i, ch) in body[lbracket..].char_indices() {
        match ch {
            '\'' => in_quote = !in_quote,
            '[' if !in_quote => depth_bracket += 1,
            ']' if !in_quote => {
                depth_bracket -= 1;
                if depth_bracket == 0 {
                    rbracket = lbracket + i;
                    break;
                }
            }
            _ => {}
        }
    }

    let array_body = &body[lbracket..rbracket];

    // Split at top-level `}` characters, keeping the prior `{...}` content.
    // Easier approach: walk and emit a chunk at each closing `}` at depth 0.
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut depth   = 0i32;
    let mut in_q    = false;
    for ch in array_body.chars() {
        match ch {
            '\'' => { in_q = !in_q; current.push(ch); }
            '{' if !in_q => { depth += 1; current.push(ch); }
            '}' if !in_q => {
                depth -= 1;
                current.push(ch);
                if depth == 0 {
                    let chunk_body = current.trim_start_matches(|c: char| c.is_whitespace() || c == ',' || c == '{');
                    let chunk_body = chunk_body.trim_end_matches(|c: char| c.is_whitespace() || c == '}');
                    chunks.push(ChunkVector {
                        plaintext:  hex::decode(extract_hex(chunk_body, "plaintext")).unwrap_or_default(),
                        ciphertext: hex::decode(extract_hex(chunk_body, "ciphertext")).unwrap_or_default(),
                    });
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    chunks
}

// ────────────────────────────────────────────────────────────────────────────
// ML-KEM vectors (kyber_keygen.ts, kyber_encapdecap.ts).
//
// All ACVP records use single-line concatenated hex strings (no `+` joins),
// so the existing `extract_hex` and `extract_int` helpers work directly on
// each `{ ... }` body produced by `split_top_level_objects`.
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct MlKemKeyGenVector {
    pub tc_id: u32,
    pub d:     Vec<u8>,
    pub z:     Vec<u8>,
    pub ek:    Vec<u8>,
    pub dk:    Vec<u8>,
}

#[allow(dead_code)] // dk/ek surfaced for diagnostic logging; verifier
                    // exercises ek (encap) or dk (decap) but not both
#[derive(Debug, Clone, Default)]
pub struct MlKemEncapVector {
    pub tc_id: u32,
    pub ek:    Vec<u8>,
    pub dk:    Vec<u8>,
    pub c:     Vec<u8>,
    pub k:     Vec<u8>,
    pub m:     Vec<u8>,
}

#[allow(dead_code)] // ek surfaced for diagnostic logging; verifier uses dk
#[derive(Debug, Clone, Default)]
pub struct MlKemDecapVector {
    pub tc_id:  u32,
    pub ek:     Vec<u8>,
    pub dk:     Vec<u8>,
    pub c:      Vec<u8>,
    pub k:      Vec<u8>,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct MlKemKeyCheckVector {
    pub tc_id:       u32,
    pub test_passed: bool,
    pub ek:          Vec<u8>,
    pub dk:          Vec<u8>,
    #[allow(dead_code)]
    pub reason:      String,
}

pub fn parse_mlkem_keygen_array(src: &str, export_name: &str) -> Vec<MlKemKeyGenVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| MlKemKeyGenVector {
            tc_id: extract_int(&obj, "tcId").unwrap_or(0),
            d:     hex::decode(extract_hex(&obj, "d")).unwrap_or_default(),
            z:     hex::decode(extract_hex(&obj, "z")).unwrap_or_default(),
            ek:    hex::decode(extract_hex(&obj, "ek")).unwrap_or_default(),
            dk:    hex::decode(extract_hex(&obj, "dk")).unwrap_or_default(),
        })
        .collect()
}

pub fn parse_mlkem_encap_array(src: &str, export_name: &str) -> Vec<MlKemEncapVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| MlKemEncapVector {
            tc_id: extract_int(&obj, "tcId").unwrap_or(0),
            ek:    hex::decode(extract_hex(&obj, "ek")).unwrap_or_default(),
            dk:    hex::decode(extract_hex(&obj, "dk")).unwrap_or_default(),
            c:     hex::decode(extract_hex(&obj, "c")).unwrap_or_default(),
            k:     hex::decode(extract_hex(&obj, "k")).unwrap_or_default(),
            m:     hex::decode(extract_hex(&obj, "m")).unwrap_or_default(),
        })
        .collect()
}

pub fn parse_mlkem_decap_array(src: &str, export_name: &str) -> Vec<MlKemDecapVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| MlKemDecapVector {
            tc_id:  extract_int(&obj, "tcId").unwrap_or(0),
            ek:     hex::decode(extract_hex(&obj, "ek")).unwrap_or_default(),
            dk:     hex::decode(extract_hex(&obj, "dk")).unwrap_or_default(),
            c:      hex::decode(extract_hex(&obj, "c")).unwrap_or_default(),
            k:      hex::decode(extract_hex(&obj, "k")).unwrap_or_default(),
            reason: extract_string(&obj, "reason"),
        })
        .collect()
}

pub fn parse_mlkem_keycheck_array(src: &str, export_name: &str) -> Vec<MlKemKeyCheckVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| MlKemKeyCheckVector {
            tc_id:       extract_int(&obj, "tcId").unwrap_or(0),
            test_passed: extract_bool(&obj, "testPassed").unwrap_or(false),
            ek:          hex::decode(extract_hex(&obj, "ek")).unwrap_or_default(),
            dk:          hex::decode(extract_hex(&obj, "dk")).unwrap_or_default(),
            reason:      extract_string(&obj, "reason"),
        })
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// ML-DSA vectors (mldsa_keygen.ts, mldsa_siggen.ts, mldsa_sigver.ts).
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct MlDsaKeyGenVector {
    pub tc_id: u32,
    pub seed:  Vec<u8>,
    pub pk:    Vec<u8>,
    pub sk:    Vec<u8>,
}

#[allow(dead_code)] // parameter_set + pk surfaced for diagnostics; verifier
                    // dispatches by paramset at the run_mldsa level and
                    // signs via sk, comparing the produced signature.
                    // corner_case is parsed for forward-compat: ACVP may
                    // populate it with discriminator strings (e.g.
                    // shortMaxNorm, highMaxNorm) in future revisions; the
                    // verifier currently branches only on signature_interface,
                    // pre_hash, and external_mu. TODO: dispatch on corner_case
                    // when ACVP publishes corner-case-specific behavior.
#[derive(Debug, Clone, Default)]
pub struct MlDsaSigGenVector {
    pub tc_id:                u32,
    pub tg_id:                u32,
    pub parameter_set:        String,
    pub signature_interface:  String,
    pub pre_hash:             String,
    pub external_mu:          bool,
    pub deterministic:        bool,
    pub corner_case:          String,
    pub hash_alg:             String,
    pub pk:                   Vec<u8>,
    pub sk:                   Vec<u8>,
    pub message:              Option<Vec<u8>>,
    pub mu:                   Option<Vec<u8>>,
    pub context:              Option<Vec<u8>>,
    pub rnd:                  Option<Vec<u8>>,
    pub signature:            Vec<u8>,
}

#[allow(dead_code)] // parameter_set surfaced for diagnostics; verifier
                    // dispatches by paramset at run_mldsa
#[derive(Debug, Clone, Default)]
pub struct MlDsaSigVerVector {
    pub tc_id:                u32,
    pub tg_id:                u32,
    pub test_passed:          bool,
    pub parameter_set:        String,
    pub signature_interface:  String,
    pub pre_hash:             String,
    pub external_mu:          bool,
    pub hash_alg:             String,
    pub reason:               String,
    pub pk:                   Vec<u8>,
    pub signature:            Vec<u8>,
    pub message:              Option<Vec<u8>>,
    pub mu:                   Option<Vec<u8>>,
    pub context:              Option<Vec<u8>>,
}

pub fn parse_mldsa_keygen_array(src: &str, export_name: &str) -> Vec<MlDsaKeyGenVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| MlDsaKeyGenVector {
            tc_id: extract_int(&obj, "tcId").unwrap_or(0),
            seed:  hex::decode(extract_hex(&obj, "seed")).unwrap_or_default(),
            pk:    hex::decode(extract_hex(&obj, "pk")).unwrap_or_default(),
            sk:    hex::decode(extract_hex(&obj, "sk")).unwrap_or_default(),
        })
        .collect()
}

// Optional hex field: returns Some(bytes) iff the body contains `field:`,
// else None. Distinct from `extract_hex` which collapses absence to "".
fn extract_optional_hex(body: &str, field: &str) -> Option<Vec<u8>> {
    if find_field_offset(body, field).is_none() {
        return None;
    }
    Some(hex::decode(extract_hex(body, field)).unwrap_or_default())
}

pub fn parse_mldsa_siggen_array(src: &str, export_name: &str) -> Vec<MlDsaSigGenVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| MlDsaSigGenVector {
            tc_id:               extract_int(&obj, "tcId").unwrap_or(0),
            tg_id:               extract_int(&obj, "tgId").unwrap_or(0),
            parameter_set:       extract_string(&obj, "parameterSet"),
            signature_interface: extract_string(&obj, "signatureInterface"),
            pre_hash:            extract_string(&obj, "preHash"),
            external_mu:         extract_bool(&obj, "externalMu").unwrap_or(false),
            deterministic:       extract_bool(&obj, "deterministic").unwrap_or(false),
            corner_case:         extract_string(&obj, "cornerCase"),
            hash_alg:            extract_string(&obj, "hashAlg"),
            pk:                  hex::decode(extract_hex(&obj, "pk")).unwrap_or_default(),
            sk:                  hex::decode(extract_hex(&obj, "sk")).unwrap_or_default(),
            message:             extract_optional_hex(&obj, "message"),
            mu:                  extract_optional_hex(&obj, "mu"),
            context:             extract_optional_hex(&obj, "context"),
            rnd:                 extract_optional_hex(&obj, "rnd"),
            signature:           hex::decode(extract_hex(&obj, "signature")).unwrap_or_default(),
        })
        .collect()
}

pub fn parse_mldsa_sigver_array(src: &str, export_name: &str) -> Vec<MlDsaSigVerVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| MlDsaSigVerVector {
            tc_id:               extract_int(&obj, "tcId").unwrap_or(0),
            tg_id:               extract_int(&obj, "tgId").unwrap_or(0),
            test_passed:         extract_bool(&obj, "testPassed").unwrap_or(false),
            parameter_set:       extract_string(&obj, "parameterSet"),
            signature_interface: extract_string(&obj, "signatureInterface"),
            pre_hash:            extract_string(&obj, "preHash"),
            external_mu:         extract_bool(&obj, "externalMu").unwrap_or(false),
            hash_alg:            extract_string(&obj, "hashAlg"),
            reason:              extract_string(&obj, "reason"),
            pk:                  hex::decode(extract_hex(&obj, "pk")).unwrap_or_default(),
            signature:           hex::decode(extract_hex(&obj, "signature")).unwrap_or_default(),
            message:             extract_optional_hex(&obj, "message"),
            mu:                  extract_optional_hex(&obj, "mu"),
            context:             extract_optional_hex(&obj, "context"),
        })
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// SLH-DSA vectors (slhdsa_keygen.ts, slhdsa_siggen.ts, slhdsa_sigver.ts).
//
// Phase 2 scope: SHAKE-fast variants (128f / 192f / 256f) only. preHash
// records carry the original message + hashAlg; the verifier hashes them
// in-band and builds HashSLH-DSA M' per FIPS 205 §10.2 before calling
// slh_sign_internal / slh_verify_internal on the slh-dsa crate.
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SlhDsaKeyGenVector {
    pub tc_id:   u32,
    pub sk_seed: Vec<u8>,
    pub sk_prf:  Vec<u8>,
    pub pk_seed: Vec<u8>,
    pub pk:      Vec<u8>,
    pub sk:      Vec<u8>,
}

#[allow(dead_code)] // parameter_set + signature_interface surfaced for
                    // diagnostics; the verifier dispatches by param set
                    // via the function name (verify_siggen_128f etc.)
                    // and branches on pre_hash + deterministic.
#[derive(Debug, Clone, Default)]
pub struct SlhDsaSigGenVector {
    pub tc_id:                 u32,
    pub tg_id:                 u32,
    pub parameter_set:         String,
    pub signature_interface:   String,
    pub pre_hash:              String,
    pub deterministic:         bool,
    pub hash_alg:              String,
    pub sk:                    Vec<u8>,
    pub pk:                    Vec<u8>,
    pub message:               Vec<u8>,
    pub context:               Vec<u8>,
    pub additional_randomness: Option<Vec<u8>>,
    pub signature:             Vec<u8>,
}

#[allow(dead_code)] // parameter_set + signature_interface surfaced for
                    // diagnostics; verifier dispatches by param set via
                    // the function name.
#[derive(Debug, Clone, Default)]
pub struct SlhDsaSigVerVector {
    pub tc_id:               u32,
    pub tg_id:               u32,
    pub test_passed:         bool,
    pub parameter_set:       String,
    pub signature_interface: String,
    pub pre_hash:            String,
    pub hash_alg:            String,
    pub reason:              String,
    pub pk:                  Vec<u8>,
    pub signature:           Vec<u8>,
    pub message:             Vec<u8>,
    pub context:             Vec<u8>,
}

pub fn parse_slhdsa_keygen_array(src: &str, export_name: &str) -> Vec<SlhDsaKeyGenVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| SlhDsaKeyGenVector {
            tc_id:   extract_int(&obj, "tcId").unwrap_or(0),
            sk_seed: hex::decode(extract_hex(&obj, "skSeed")).unwrap_or_default(),
            sk_prf:  hex::decode(extract_hex(&obj, "skPrf")).unwrap_or_default(),
            pk_seed: hex::decode(extract_hex(&obj, "pkSeed")).unwrap_or_default(),
            pk:      hex::decode(extract_hex(&obj, "pk")).unwrap_or_default(),
            sk:      hex::decode(extract_hex(&obj, "sk")).unwrap_or_default(),
        })
        .collect()
}

pub fn parse_slhdsa_siggen_array(src: &str, export_name: &str) -> Vec<SlhDsaSigGenVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| SlhDsaSigGenVector {
            tc_id:                 extract_int(&obj, "tcId").unwrap_or(0),
            tg_id:                 extract_int(&obj, "tgId").unwrap_or(0),
            parameter_set:         extract_string(&obj, "parameterSet"),
            signature_interface:   extract_string(&obj, "signatureInterface"),
            pre_hash:              extract_string(&obj, "preHash"),
            deterministic:         extract_bool(&obj, "deterministic").unwrap_or(false),
            hash_alg:              extract_string(&obj, "hashAlg"),
            sk:                    hex::decode(extract_hex(&obj, "sk")).unwrap_or_default(),
            pk:                    hex::decode(extract_hex(&obj, "pk")).unwrap_or_default(),
            message:               hex::decode(extract_hex(&obj, "message")).unwrap_or_default(),
            context:               hex::decode(extract_hex(&obj, "context")).unwrap_or_default(),
            additional_randomness: extract_optional_hex(&obj, "additionalRandomness"),
            signature:             hex::decode(extract_hex(&obj, "signature")).unwrap_or_default(),
        })
        .collect()
}

pub fn parse_slhdsa_sigver_array(src: &str, export_name: &str) -> Vec<SlhDsaSigVerVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| SlhDsaSigVerVector {
            tc_id:               extract_int(&obj, "tcId").unwrap_or(0),
            tg_id:               extract_int(&obj, "tgId").unwrap_or(0),
            test_passed:         extract_bool(&obj, "testPassed").unwrap_or(false),
            parameter_set:       extract_string(&obj, "parameterSet"),
            signature_interface: extract_string(&obj, "signatureInterface"),
            pre_hash:            extract_string(&obj, "preHash"),
            hash_alg:            extract_string(&obj, "hashAlg"),
            reason:              extract_string(&obj, "reason"),
            pk:                  hex::decode(extract_hex(&obj, "pk")).unwrap_or_default(),
            signature:           hex::decode(extract_hex(&obj, "signature")).unwrap_or_default(),
            message:             hex::decode(extract_hex(&obj, "message")).unwrap_or_default(),
            context:             hex::decode(extract_hex(&obj, "context")).unwrap_or_default(),
        })
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// Hybrid PQ vectors (sign_hybrid_pq.ts).
//
// Self-generated composite KAT vectors for the three PQ-only hybrids
// (0x30 / 0x31 / 0x32). The wire format is leviathan-defined, as documented
// in docs/signaturesuite.md: pk = pk_mldsa || pk_slhdsa, sig = sig_mldsa ||
// sig_slhdsa. Sizes are catalog-known per hybrid.
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SignHybridPqVector {
    pub id:                String,
    pub description:       String,
    pub format_enum:       u32,
    pub prehash_algorithm: String,
    // Seeds are parsed for completeness (the vectors file ships them so
    // both halves' keygenDerand can be reproduced) but the verifier reads
    // pk/sk directly without re-running keygen, so these fields are
    // read-but-not-exercised here.
    #[allow(dead_code)]
    pub mldsa_seed:        Vec<u8>,
    #[allow(dead_code)]
    pub slhdsa_seed:       Vec<u8>,
    pub pk:                Vec<u8>,
    pub sk:                Vec<u8>,
    pub msg:               Vec<u8>,
    pub ctx:               Vec<u8>,
    pub blob:              Vec<u8>,
}

// Extract a hex integer literal field (formatEnum: 0x30,). Returns None
// if absent or unparseable.
fn extract_hex_int(body: &str, field: &str) -> Option<u32> {
    let needle = format!("{}:", field);
    let start = find_field_offset(body, field)? + needle.len();
    let rest  = body[start..].trim_start();
    if let Some(stripped) = rest.strip_prefix("0x") {
        let end = stripped.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(stripped.len());
        return u32::from_str_radix(&stripped[..end], 16).ok();
    }
    None
}

pub fn parse_sign_hybrid_pq_array(src: &str, export_name: &str) -> Vec<SignHybridPqVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| SignHybridPqVector {
            id:                extract_string(&obj, "id"),
            description:       extract_string(&obj, "description"),
            format_enum:       extract_hex_int(&obj, "formatEnum").unwrap_or(0),
            prehash_algorithm: extract_string(&obj, "prehashAlgorithm"),
            mldsa_seed:        hex::decode(extract_hex(&obj, "mldsaSeedHex")).unwrap_or_default(),
            slhdsa_seed:       hex::decode(extract_hex(&obj, "slhdsaSeedHex")).unwrap_or_default(),
            pk:                hex::decode(extract_hex(&obj, "pkHex")).unwrap_or_default(),
            sk:                hex::decode(extract_hex(&obj, "skHex")).unwrap_or_default(),
            msg:               hex::decode(extract_hex(&obj, "msgHex")).unwrap_or_default(),
            ctx:               hex::decode(extract_hex(&obj, "ctxHex")).unwrap_or_default(),
            blob:              hex::decode(extract_hex(&obj, "blobHex")).unwrap_or_default(),
        })
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// KMAC and cSHAKE vectors (kmac.ts).
//
// Four TS interfaces, four Rust structs. Sample vectors carry an ASCII
// description and inputs as hex; ACVP vectors carry tcId/tgId + the
// per-record xof/hexCustomization flags. All length fields are in bits,
// and every pinned record is byte-aligned (the byte-alignment filter ran
// at Phase 1; bit-level cases were dropped to match leviathan-crypto's
// byte-oriented WASM API).
//
// Customization / function-name strings in KMAC ACVP records can contain
// literal `'` chars escaped as `\'`. The seal/sealstream parser's
// `extract_string` finds the first `'` without honoring escapes, which
// truncates those values. `extract_string_escaped` below decodes the two
// escape sequences the kmac.ts generator emits (`\'` and `\\`) and is
// used in the KMAC parsers.
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct CshakeSampleVector {
    pub description:    String,
    pub msg:            Vec<u8>,
    pub msg_len_bits:   u32,
    pub n:              String,
    pub s:              String,
    pub out_len_bits:   u32,
    pub expected:       Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct KmacSampleVector {
    pub description:    String,
    pub key:            Vec<u8>,
    pub key_len_bits:   u32,
    pub msg:            Vec<u8>,
    pub msg_len_bits:   u32,
    pub s:              String,
    pub out_len_bits:   u32,
    pub expected:       Vec<u8>,
}

// tg_id is parsed for failure-log traceability (verifier surfaces it on
// mismatch). The verifier dispatches per export name, not per tgId, so
// the field is otherwise unused.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct CshakeAcvpVector {
    pub tc_id:             u32,
    pub tg_id:             u32,
    pub hex_customization: bool,
    pub msg:               Vec<u8>,
    pub msg_len_bits:      u32,
    pub function_name:     String,
    pub customization:     String,
    pub md:                Vec<u8>,
    pub out_len_bits:      u32,
}

// Two split string/hex customization fields mirror the TS interface
// `customization?` / `customizationHex?`. Exactly one is populated per
// record (determined by hex_customization). test_passed is populated
// only for MVT records; AFT records leave it None and the verifier
// branches on test_type instead.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct KmacAcvpVector {
    pub tc_id:              u32,
    pub tg_id:              u32,
    pub test_type:          String,   // "AFT" or "MVT"
    pub xof:                bool,
    pub hex_customization:  bool,
    pub key:                Vec<u8>,
    pub key_len_bits:       u32,
    pub msg:                Vec<u8>,
    pub msg_len_bits:       u32,
    pub customization:      Option<String>,
    pub customization_hex:  Option<Vec<u8>>,
    pub mac:                Vec<u8>,
    pub mac_len_bits:       u32,
    pub test_passed:        Option<bool>,
}

// Escape-aware single-quoted string extractor. Handles `\'` and `\\`
// (the two escapes the kmac.ts generator emits). Other backslash
// sequences pass through unchanged, the corpus does not contain any.
fn extract_string_escaped(body: &str, field: &str) -> String {
    let needle = format!("{}:", field);
    let Some(start) = find_field_offset(body, field) else { return String::new(); };
    let after = start + needle.len();
    let bytes = body.as_bytes();
    // Locate the opening quote.
    let mut i = after;
    while i < bytes.len() && bytes[i] != b'\'' { i += 1; }
    if i >= bytes.len() { return String::new(); }
    i += 1;
    let mut out = String::new();
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next == b'\'' || next == b'\\' {
                out.push(next as char);
                i += 2;
                continue;
            }
        }
        if b == b'\'' { return out; }
        out.push(b as char);
        i += 1;
    }
    out
}

// Same shape as extract_string_escaped, but returns Option so an absent
// field is distinguishable from an explicitly empty one.
fn extract_optional_string_escaped(body: &str, field: &str) -> Option<String> {
    if find_field_offset(body, field).is_none() { return None; }
    Some(extract_string_escaped(body, field))
}

pub fn parse_cshake_sample_array(src: &str, export_name: &str) -> Vec<CshakeSampleVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| CshakeSampleVector {
            description:  extract_string_escaped(&obj, "description"),
            msg:          hex::decode(extract_hex(&obj, "msg")).unwrap_or_default(),
            msg_len_bits: extract_int(&obj, "msgLenBits").unwrap_or(0),
            n:            extract_string_escaped(&obj, "N"),
            s:            extract_string_escaped(&obj, "S"),
            out_len_bits: extract_int(&obj, "outLenBits").unwrap_or(0),
            expected:     hex::decode(extract_hex(&obj, "expected")).unwrap_or_default(),
        })
        .collect()
}

pub fn parse_kmac_sample_array(src: &str, export_name: &str) -> Vec<KmacSampleVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| KmacSampleVector {
            description:  extract_string_escaped(&obj, "description"),
            key:          hex::decode(extract_hex(&obj, "key")).unwrap_or_default(),
            key_len_bits: extract_int(&obj, "keyLenBits").unwrap_or(0),
            msg:          hex::decode(extract_hex(&obj, "msg")).unwrap_or_default(),
            msg_len_bits: extract_int(&obj, "msgLenBits").unwrap_or(0),
            s:            extract_string_escaped(&obj, "S"),
            out_len_bits: extract_int(&obj, "outLenBits").unwrap_or(0),
            expected:     hex::decode(extract_hex(&obj, "expected")).unwrap_or_default(),
        })
        .collect()
}

pub fn parse_cshake_acvp_array(src: &str, export_name: &str) -> Vec<CshakeAcvpVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| CshakeAcvpVector {
            tc_id:             extract_int(&obj, "tcId").unwrap_or(0),
            tg_id:             extract_int(&obj, "tgId").unwrap_or(0),
            hex_customization: extract_bool(&obj, "hexCustomization").unwrap_or(false),
            msg:               hex::decode(extract_hex(&obj, "msg")).unwrap_or_default(),
            msg_len_bits:      extract_int(&obj, "msgLenBits").unwrap_or(0),
            function_name:     extract_string_escaped(&obj, "functionName"),
            customization:     extract_string_escaped(&obj, "customization"),
            md:                hex::decode(extract_hex(&obj, "md")).unwrap_or_default(),
            out_len_bits:      extract_int(&obj, "outLenBits").unwrap_or(0),
        })
        .collect()
}

pub fn parse_kmac_acvp_array(src: &str, export_name: &str) -> Vec<KmacAcvpVector> {
    let Some(body) = locate_array_body(src, export_name) else { return Vec::new(); };
    split_top_level_objects(body)
        .into_iter()
        .map(|obj| KmacAcvpVector {
            tc_id:              extract_int(&obj, "tcId").unwrap_or(0),
            tg_id:              extract_int(&obj, "tgId").unwrap_or(0),
            test_type:          extract_string_escaped(&obj, "testType"),
            xof:                extract_bool(&obj, "xof").unwrap_or(false),
            hex_customization:  extract_bool(&obj, "hexCustomization").unwrap_or(false),
            key:                hex::decode(extract_hex(&obj, "key")).unwrap_or_default(),
            key_len_bits:       extract_int(&obj, "keyLenBits").unwrap_or(0),
            msg:                hex::decode(extract_hex(&obj, "msg")).unwrap_or_default(),
            msg_len_bits:       extract_int(&obj, "msgLenBits").unwrap_or(0),
            customization:      extract_optional_string_escaped(&obj, "customization"),
            customization_hex:  extract_optional_hex(&obj, "customizationHex"),
            mac:                hex::decode(extract_hex(&obj, "mac")).unwrap_or_default(),
            mac_len_bits:       extract_int(&obj, "macLenBits").unwrap_or(0),
            test_passed:        extract_bool(&obj, "testPassed"),
        })
        .collect()
}
