// Independent verifier for the c2sp.org/tlog-checkpoint (Transparency
// Log Checkpoints) §Note text canonical body codec and the
// c2sp.org/signed-note (Note) §Format envelope codec.
//
// Reproduces the body and envelope bytes from each record in
// test/vectors/merkle_checkpoint.ts and test/vectors/merkle_signed_note.ts
// via a hand-rolled UTF-8 / decimal / base64 serializer (RustCrypto
// `sha2` and the pinned `base64` crate), independent of leviathan's
// AssemblyScript stack. Different language, different libraries, same
// bytes out.
//
// For checkpoints the per-record `expectedBody` literal in the vector
// file pins the expected byte sequence (the GATE record is the
// c2sp.org/tlog-checkpoint §Note text worked example). For signed-note
// envelopes the per-record `expectedEnvelopeSha256Hex` digest pins the
// byte sequence without storing the full envelope literal.
//
// For deriveKeyId, the first record is spec-anchored against the
// c2sp.org/signed-note §Verifier keys §Example value
// `example.com/foo+530d903a+...`; the rest are self-generated and
// frozen via `expectedKeyIdHex`.

use sha2::{Digest, Sha256};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use crate::byte_diff::log_byte_diff;

// ── shared helpers ──────────────────────────────────────────────────────────

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_default()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn derive_key_id(name: &str, algo_byte: u8, pubkey: &[u8]) -> [u8; 4] {
    // c2sp.org/signed-note §Signatures:
    //   key_id = SHA-256(utf8(name) || 0x0A || algo_byte || pubkey)[:4]
    let name_bytes = name.as_bytes();
    let mut buf = Vec::with_capacity(name_bytes.len() + 2 + pubkey.len());
    buf.extend_from_slice(name_bytes);
    buf.push(0x0a);
    buf.push(algo_byte);
    buf.extend_from_slice(pubkey);
    let d = sha256(&buf);
    [d[0], d[1], d[2], d[3]]
}

fn serialize_checkpoint_body(origin: &str, tree_size: u64, root_hash: &[u8]) -> Vec<u8> {
    // c2sp.org/tlog-checkpoint §Note text:
    //   utf8(origin) || 0x0A || utf8(decimal(treeSize)) || 0x0A
    //       || base64(rootHash) || 0x0A
    let mut out = Vec::new();
    out.extend_from_slice(origin.as_bytes());
    out.push(0x0a);
    out.extend_from_slice(tree_size.to_string().as_bytes());
    out.push(0x0a);
    out.extend_from_slice(B64.encode(root_hash).as_bytes());
    out.push(0x0a);
    out
}

fn emit_signed_note(body: &[u8], sigs: &[(String, [u8; 4], Vec<u8>)]) -> Vec<u8> {
    // c2sp.org/signed-note §Format:
    //   body || '\n' || (— name b64(keyId||sig) '\n')+
    let mut out = Vec::new();
    out.extend_from_slice(body);
    out.push(0x0a); // blank-line separator between body and signatures
    for (name, key_id, sig) in sigs {
        // em dash U+2014 in UTF-8 is e2 80 94.
        out.extend_from_slice(&[0xe2, 0x80, 0x94, 0x20]);
        out.extend_from_slice(name.as_bytes());
        out.push(0x20);
        let mut payload = Vec::with_capacity(4 + sig.len());
        payload.extend_from_slice(key_id);
        payload.extend_from_slice(sig);
        out.extend_from_slice(B64.encode(&payload).as_bytes());
        out.push(0x0a);
    }
    out
}

// ── checkpoint vector parsing ──────────────────────────────────────────────

struct CheckpointRec {
    desc:           String,
    origin:         String,
    tree_size:      u64,
    root_hash_b64:  String,
    expected_body:  String,
}

// Parse the `CHECKPOINT_RECORDS` array from test/vectors/merkle_checkpoint.ts.
// The vector file uses the same `desc:`, single-quoted-string idiom as every
// other leviathan vector file, so the existing `find` / brace-walk approach
// works without bespoke tooling.
fn parse_checkpoint_records(src: &str) -> Vec<CheckpointRec> {
    let mut out = Vec::new();
    let needle = "export const CHECKPOINT_RECORDS";
    let Some(arr_start) = locate_array_open(src, needle) else { return out; };
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
                    out.push(CheckpointRec {
                        desc:          extract_single_quoted(body, "desc"),
                        origin:        extract_single_quoted(body, "origin"),
                        tree_size:     extract_int(body, "treeSize"),
                        root_hash_b64: extract_single_quoted(body, "rootHashB64"),
                        expected_body: extract_multiline_quoted(body, "expectedBody"),
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

fn extract_single_quoted(body: &str, field: &str) -> String {
    // Field: 'value', with possible whitespace, identifier reference, or
    // trailing comma. If the value is an identifier (no leading quote),
    // resolve it against the known fixture table; the TS vector file
    // uses a handful of IIFE-computed hex/string constants for the
    // larger pubkey and signature payloads.
    let pat = format!("{}:", field);
    let Some(p) = find_field(body, field) else { return String::new(); };
    let after = p + pat.len();
    let rest = body[after..].trim_start();
    if rest.starts_with('\'') {
        // Multi-line `'a' + 'b'` form: concatenate every quoted segment
        // up to the first unquoted comma.
        return extract_multiline_quoted(body, field);
    }
    // Identifier form: read up to the next comma or whitespace boundary.
    let mut ident = String::new();
    for ch in rest.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' { ident.push(ch); }
        else { break; }
    }
    resolve_fixture(&ident)
}

// Known fixture identifiers from test/vectors/merkle_signed_note.ts and
// test/vectors/merkle_checkpoint.ts. Each is reproduced from the same
// recipe documented in the JS file's comments. Coupling is explicit:
// if the JS recipes change, this table must change too.
fn resolve_fixture(name: &str) -> String {
    match name {
        "ED25519_PK_HEX_FIXTURE" => {
            // 32-byte ramp: byte i = i.
            (0u32..32).map(|i| format!("{:02x}", i & 0xff)).collect()
        }
        "MLDSA44_PK_HEX_FIXTURE" => {
            // 1312-byte ramp: byte i = (7i + 3) mod 256.
            (0u32..1312).map(|i| format!("{:02x}", (i.wrapping_mul(7).wrapping_add(3)) & 0xff)).collect()
        }
        "ED25519_COSIG_72_HEX" => {
            // 72 bytes: 8-byte u64-BE timestamp `6565a70000000000` then
            // 64-byte ramp byte i = (5i + 1) mod 256.
            let mut s = String::from("6565a70000000000");
            for i in 0u32..64 {
                s.push_str(&format!("{:02x}", (i.wrapping_mul(5).wrapping_add(1)) & 0xff));
            }
            s
        }
        "MLDSA44_COSIG_2428_HEX" => {
            // 2428 bytes: 8-byte u64-BE timestamp `6565a70100000000` then
            // 2420-byte ramp byte i = (3i + 7) mod 256.
            let mut s = String::from("6565a70100000000");
            for i in 0u32..2420 {
                s.push_str(&format!("{:02x}", (i.wrapping_mul(3).wrapping_add(7)) & 0xff));
            }
            s
        }
        "GATE_BODY" => {
            // c2sp.org/tlog-checkpoint §Note text worked example.
            "example.com/behind-the-sofa\n20852163\n\
             CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n".to_string()
        }
        _ => String::new(),
    }
}

// Concatenates all single-quoted segments between the field's `:` and the
// terminating comma at the field's brace depth. Supports multi-line string
// values built with the `+` operator (one quoted segment per line).
fn extract_multiline_quoted(body: &str, field: &str) -> String {
    let pat = format!("{}:", field);
    let Some(p) = find_field(body, field) else { return String::new(); };
    let after = p + pat.len();
    // If the value starts with an identifier (no leading quote and not a
    // numeric literal), resolve it from the known fixture table.
    let rest = body[after..].trim_start();
    if !rest.starts_with('\'') {
        let mut ident = String::new();
        for ch in rest.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' { ident.push(ch); }
            else { break; }
        }
        if !ident.is_empty() && !ident.chars().next().unwrap().is_ascii_digit() {
            return resolve_fixture(&ident);
        }
    }
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
    decode_ts_string_escapes(&out)
}

fn decode_ts_string_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n')  => out.push('\n'),
                Some('r')  => out.push('\r'),
                Some('t')  => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('\'') => out.push('\''),
                Some('"')  => out.push('"'),
                Some(other) => { out.push('\\'); out.push(other); }
                None => break,
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn extract_int(body: &str, field: &str) -> u64 {
    let pat = format!("{}:", field);
    let Some(p) = find_field(body, field) else { return 0; };
    let after = p + pat.len();
    // Match either a plain decimal literal, a `0xNN` hex literal, or a
    // `Number.MAX_SAFE_INTEGER` reference. The tree-size = 2^53 - 1
    // record uses the constant; algoByte fields use 0xNN form.
    let rest = body[after..].trim_start();
    if rest.starts_with("Number.MAX_SAFE_INTEGER") {
        return (1u64 << 53) - 1;
    }
    if rest.starts_with("0x") || rest.starts_with("0X") {
        let mut hex_digits = String::new();
        for ch in rest[2..].chars() {
            if ch.is_ascii_hexdigit() { hex_digits.push(ch); }
            else { break; }
        }
        return u64::from_str_radix(&hex_digits, 16).unwrap_or(0);
    }
    let mut digits = String::new();
    let mut seen = false;
    for ch in rest.chars() {
        if ch.is_ascii_digit() { digits.push(ch); seen = true; }
        else if seen { break; }
        else if ch == ',' || ch == '\n' { break; }
    }
    digits.parse().unwrap_or(0)
}

// Locate the byte offset immediately after the `=` that opens an
// `export const <NAME>: <TYPE> = [...]` array literal. The `<TYPE>`
// annotation often contains its own `[]` (`readonly Foo[]`), so naive
// `find('[')` after the export name would match the type's brackets,
// not the array's. Skip past `=` first, then locate the next `[`.
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

// ── signed-note vector parsing ─────────────────────────────────────────────

struct KeyIdRec {
    desc:                String,
    name:                String,
    algo_byte:           u8,
    pubkey_hex:          String,
    expected_key_id_hex: String,
}

fn parse_key_id_records(src: &str) -> Vec<KeyIdRec> {
    let mut out = Vec::new();
    let Some(arr_start) = locate_array_open(src, "export const KEY_ID_RECORDS") else { return out; };
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
                    let algo = extract_int(body, "algoByte") as u8;
                    out.push(KeyIdRec {
                        desc:                extract_single_quoted(body, "desc"),
                        name:                extract_single_quoted(body, "name"),
                        algo_byte:           algo,
                        pubkey_hex:          extract_single_quoted(body, "pubkeyHex"),
                        expected_key_id_hex: extract_single_quoted(body, "expectedKeyIdHex"),
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

struct SigRec {
    name:            String,
    algo_byte:       u8,
    pubkey_hex:      String,
    sig_payload_hex: String,
}

struct RoundtripRec {
    desc:                          String,
    origin:                        String,
    tree_size:                     u64,
    root_hash_b64:                 String,
    sigs:                          Vec<SigRec>,
    expected_envelope_len:         u64,
    expected_envelope_sha256_hex:  String,
}

fn parse_roundtrip_records(src: &str) -> Vec<RoundtripRec> {
    let mut out = Vec::new();
    let Some(arr_start) = locate_array_open(src, "export const ROUNDTRIP_RECORDS") else { return out; };
    // Walk top-level records: each record is `{ ... }` at brace depth 1
    // inside the outer `[...]`. Inner objects (each signature line) are
    // also brace-delimited, so we cannot use a simple split-on-brace.
    let mut depth = 0i32;
    let mut rec_start: Option<usize> = None;
    let bytes = src.as_bytes();
    let mut i = arr_start;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '{' {
            if depth == 0 { rec_start = Some(i); }
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                if let Some(s) = rec_start.take() {
                    let body = &src[s + 1..i];
                    out.push(parse_one_roundtrip(body));
                }
            }
        } else if c == ']' && depth == 0 {
            break;
        }
        i += 1;
    }
    out
}

fn parse_one_roundtrip(body: &str) -> RoundtripRec {
    // Parse the inner signatures array first (a `[ { ... }, { ... } ]`),
    // then pull the rest of the scalar fields from the outer body.
    let mut sigs = Vec::new();
    if let Some(sigs_at) = find_field(body, "signatures") {
        let after = sigs_at + "signatures:".len();
        if let Some(open) = body[after..].find('[').map(|j| after + j + 1) {
            let bytes = body.as_bytes();
            let mut depth = 0i32;
            let mut rec_start: Option<usize> = None;
            let mut k = open;
            while k < bytes.len() {
                let c = bytes[k] as char;
                if c == '{' {
                    if depth == 0 { rec_start = Some(k + 1); }
                    depth += 1;
                } else if c == '}' {
                    depth -= 1;
                    if depth == 0 {
                        if let Some(s) = rec_start.take() {
                            let sb = &body[s..k];
                            let algo = extract_int(sb, "algoByte") as u8;
                            sigs.push(SigRec {
                                name:            extract_single_quoted(sb, "name"),
                                algo_byte:       algo,
                                pubkey_hex:      extract_single_quoted(sb, "pubkeyHex"),
                                sig_payload_hex: extract_single_quoted(sb, "sigPayloadHex"),
                            });
                        }
                    }
                } else if c == ']' && depth == 0 {
                    break;
                }
                k += 1;
            }
        }
    }
    RoundtripRec {
        desc:                         extract_single_quoted(body, "desc"),
        origin:                       extract_single_quoted(body, "origin"),
        tree_size:                    extract_int(body, "treeSize"),
        root_hash_b64:                extract_single_quoted(body, "rootHashB64"),
        sigs,
        expected_envelope_len:        extract_int(body, "expectedEnvelopeLen"),
        expected_envelope_sha256_hex: extract_single_quoted(body, "expectedEnvelopeSha256Hex"),
    }
}

// ── runner ─────────────────────────────────────────────────────────────────

pub fn run(checkpoint_src: &str, signed_note_src: &str, log: &mut Vec<String>) -> bool {
    let mut all_ok = true;

    // Checkpoint body codec.
    let cp_records = parse_checkpoint_records(checkpoint_src);
    if cp_records.is_empty() {
        log.push("    ✗ CHECKPOINT_RECORDS parsed as empty".to_string());
        return false;
    }
    log.push(format!("    Checkpoint records parsed: {}", cp_records.len()));

    for rec in &cp_records {
        let root = match B64.decode(&rec.root_hash_b64) {
            Ok(b) => b,
            Err(e) => {
                log.push(format!("    ✗ {}: rootHashB64 decode failed: {}", rec.desc, e));
                all_ok = false;
                continue;
            }
        };
        let body = serialize_checkpoint_body(&rec.origin, rec.tree_size, &root);
        let expected = rec.expected_body.as_bytes();
        if body != expected {
            log.push(format!("    ✗ {}: body bytes mismatch", rec.desc));
            log_byte_diff(log, "body", &body, expected);
            all_ok = false;
        } else {
            log.push(format!("    ✓ checkpoint body: {}", rec.desc));
        }
    }

    // Key-ID derivation.
    let kid_records = parse_key_id_records(signed_note_src);
    if kid_records.is_empty() {
        log.push("    ✗ KEY_ID_RECORDS parsed as empty".to_string());
        return false;
    }
    log.push(format!("    Key-ID records parsed: {}", kid_records.len()));

    for rec in &kid_records {
        let pk = unhex(&rec.pubkey_hex);
        let kid = derive_key_id(&rec.name, rec.algo_byte, &pk);
        let got_hex = hex::encode(kid);
        if got_hex != rec.expected_key_id_hex {
            log.push(format!(
                "    ✗ {}: keyId mismatch, got {} expected {}",
                rec.desc, got_hex, rec.expected_key_id_hex,
            ));
            all_ok = false;
        } else {
            log.push(format!("    ✓ keyId: {}", rec.desc));
        }
    }

    // Signed-note envelope round-trip.
    let rt_records = parse_roundtrip_records(signed_note_src);
    if rt_records.is_empty() {
        log.push("    ✗ ROUNDTRIP_RECORDS parsed as empty".to_string());
        return false;
    }
    log.push(format!("    Round-trip records parsed: {}", rt_records.len()));

    for rec in &rt_records {
        let root = match B64.decode(&rec.root_hash_b64) {
            Ok(b) => b,
            Err(e) => {
                log.push(format!("    ✗ {}: rootHashB64 decode failed: {}", rec.desc, e));
                all_ok = false;
                continue;
            }
        };
        let body = serialize_checkpoint_body(&rec.origin, rec.tree_size, &root);
        let sigs: Vec<(String, [u8; 4], Vec<u8>)> = rec.sigs.iter().map(|s| {
            let pk = unhex(&s.pubkey_hex);
            let payload = unhex(&s.sig_payload_hex);
            let kid = derive_key_id(&s.name, s.algo_byte, &pk);
            (s.name.clone(), kid, payload)
        }).collect();
        let envelope = emit_signed_note(&body, &sigs);
        if envelope.len() as u64 != rec.expected_envelope_len {
            log.push(format!(
                "    ✗ {}: envelope length {} expected {}",
                rec.desc, envelope.len(), rec.expected_envelope_len,
            ));
            all_ok = false;
            continue;
        }
        let digest = sha256(&envelope);
        let digest_hex = hex::encode(digest);
        if digest_hex != rec.expected_envelope_sha256_hex {
            log.push(format!(
                "    ✗ {}: envelope SHA-256 mismatch, got {} expected {}",
                rec.desc, digest_hex, rec.expected_envelope_sha256_hex,
            ));
            all_ok = false;
        } else {
            log.push(format!("    ✓ envelope: {} (len {} bytes)", rec.desc, envelope.len()));
        }
    }

    all_ok
}
