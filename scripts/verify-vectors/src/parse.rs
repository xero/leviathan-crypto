// TS vector file parser. Handles two shapes:
//
//   SealXChachaV3Vector       — single-chunk seal blob, flat fields
//   SealStreamXChachaV3Vector — multi-chunk sealstream, with nested chunks array
//   SealSerpentV3Vector       — single-chunk seal blob, flat fields (Serpent)
//   SealStreamSerpentV3Vector — multi-chunk sealstream, with nested chunks array
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
    let Some(start) = body.find(&needle) else { return String::new(); };
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

// Extract a hex field (possibly multi-line, joined by `+`). Concatenates
// all single-quoted chunks until the first `,` outside a quote.
fn extract_hex(body: &str, field: &str) -> String {
    let needle = format!("{}:", field);
    let Some(start) = body.find(&needle) else { return String::new(); };
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
    let start  = body.find(&needle)? + needle.len();
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
    let start  = body.find(&needle)? + needle.len();
    let rest   = body[start..].trim_start();
    if rest.starts_with("true")  { return Some(true);  }
    if rest.starts_with("false") { return Some(false); }
    None
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
