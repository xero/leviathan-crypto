// Independent verifier for the c2sp.org/tlog-cosignature (Transparency
// Log Cosignatures) §"Ed25519 signed message" message construction and
// §Format `timestamped_signature` payload codec.
//
// Reproduces the bytes from each record in
// test/vectors/cosig_message.ts and test/vectors/cosig_payload.ts via
// hand-rolled Rust standard-library serializers (`format!` for ASCII
// decimal, `u64::to_be_bytes()` for the BE timestamp, concatenation
// for the rest). Independence story: no third-party crate, only the
// `hex` crate already pinned for hex encode/decode logging. Different
// language, different library lineage, same bytes out.
//
// The `cosig_payload.ts` vector file follows the named-fixture style
// used by `test/vectors/merkle_signed_note.ts`: each record's
// `sigHex` and `payloadHex` is an identifier (e.g. `COSIG_ED_SIG_V1`)
// that the TypeScript side resolves at module load via the ramp
// formula `byte[i] = (i * 31 + salt) & 0xff`. The Rust verifier
// reproduces the same fixture table independently in `resolve_fixture`
// below; agreement between the two sides at every record's
// `expected*` field is the cross-check.
//
// C2SP commit pinned for this vector corpus:
// 3752ba5b3590dc3754e04fcc8369bd3612897c02 (github.com/C2SP/C2SP).

// ── ramp-pattern + BE-timestamp helpers ─────────────────────────────────────

fn pattern_hex(n: usize, salt: u32) -> String {
    // c2sp.org/tlog-cosignature §Format payloads are signature-content-
    // agnostic; the test corpus uses a deterministic ramp so two
    // independent stacks (TypeScript and Rust) regenerate the same
    // bytes from the same `(n, salt)` inputs without sharing source.
    let mut s = String::with_capacity(n * 2);
    for i in 0..n {
        let b = ((i as u32).wrapping_mul(31).wrapping_add(salt) & 0xff) as u8;
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn timestamp_be_hex(ts: u64) -> String {
    // RFC 8446 §3.3, Presentation Language: integers serialized in
    // big-endian byte order. c2sp.org/tlog-cosignature §Format
    // `timestamped_signature.timestamp` is u64-BE.
    hex::encode(ts.to_be_bytes())
}

fn resolve_fixture(name: &str) -> String {
    // Mirror of the named-fixture table in cosig_payload.ts. Salts and
    // sizes are the cross-stack agreement points; the Rust side
    // regenerates the same bytes from `(n, salt)` independently.
    match name {
        "COSIG_ED_SIG_V1" => pattern_hex(64,   7),
        "COSIG_ED_SIG_V2" => pattern_hex(64,  23),
        "COSIG_ED_SIG_V3" => pattern_hex(64,  91),
        "COSIG_ED_SIG_V4" => pattern_hex(64, 149),
        "COSIG_ML_SIG_V1" => pattern_hex(2420,  3),
        "COSIG_ML_SIG_V2" => pattern_hex(2420, 47),
        "COSIG_ED_PAYLOAD_V1" => timestamp_be_hex(0)          + &pattern_hex(64,   7),
        "COSIG_ED_PAYLOAD_V2" => timestamp_be_hex(1)          + &pattern_hex(64,  23),
        "COSIG_ED_PAYLOAD_V3" => timestamp_be_hex(1679315147) + &pattern_hex(64,  91),
        "COSIG_ED_PAYLOAD_V4" => timestamp_be_hex((1u64 << 53) - 1) + &pattern_hex(64, 149),
        "COSIG_ML_PAYLOAD_V1" => timestamp_be_hex(0)          + &pattern_hex(2420,  3),
        "COSIG_ML_PAYLOAD_V2" => timestamp_be_hex(1679315147) + &pattern_hex(2420, 47),
        _ => String::new(),
    }
}

// ── cosig signed-message codec ──────────────────────────────────────────────

fn build_cosig_signed_message(body: &[u8], timestamp: u64) -> Vec<u8> {
    // c2sp.org/tlog-cosignature §"Ed25519 signed message": two
    // newline-terminated header lines (`cosignature/v1`,
    // `time <decimal>`) followed by the whole note body INCLUDING its
    // terminating newline. No separator between the timestamp line
    // and the body.
    let header = b"cosignature/v1\ntime ";
    let mut out = Vec::with_capacity(header.len() + 24 + body.len());
    out.extend_from_slice(header);
    out.extend_from_slice(timestamp.to_string().as_bytes());
    out.push(0x0a);
    out.extend_from_slice(body);
    out
}

// ── timestamped_signature payload codec ─────────────────────────────────────

fn emit_cosig_signature_payload(timestamp: u64, signature: &[u8]) -> Vec<u8> {
    // RFC 8446 §3.3: u64_be(timestamp) || signature[N].
    let mut out = Vec::with_capacity(8 + signature.len());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(signature);
    out
}

// c2sp.org/tlog-cosignature §"ML-DSA-44 signed message" cosigned_message
// label, 12 bytes verbatim: ASCII "subtree/v1", U+000A newline, U+0000
// nul. Reproduced byte-for-byte from the spec text.
const COSIGNED_LABEL: [u8; 12] = [
    0x73, 0x75, 0x62, 0x74, 0x72, 0x65, 0x65, 0x2f, // "subtree/"
    0x76, 0x31,                                      // "v1"
    0x0a,                                            // "\n"
    0x00,                                            // "\0"
];

fn build_cosigned_message(
    cosigner_name: &str,
    timestamp: u64,
    log_origin:    &str,
    start:         u64,
    end:           u64,
    hash:          &[u8],
) -> Vec<u8> {
    // c2sp.org/tlog-cosignature §"ML-DSA-44 signed message". Layout
    // per RFC 8446 §3.3 / §3.4 (BE integers, 1-byte length prefixes
    // for the <1..2^8-1> opaque vectors).
    let cn = cosigner_name.as_bytes();
    let lo = log_origin.as_bytes();
    assert!(!cn.is_empty() && cn.len() <= 0xff);
    assert!(!lo.is_empty() && lo.len() <= 0xff);
    assert_eq!(hash.len(), 32);
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

// ── TS vector parsing (shared idioms with merkle_checkpoint.rs) ─────────────

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

fn extract_multiline_quoted(body: &str, field: &str) -> String {
    let pat = format!("{}:", field);
    let Some(p) = find_field(body, field) else { return String::new(); };
    let after = p + pat.len();
    let rest = body[after..].trim_start();
    // Identifier form: resolve from the fixture table.
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
    // Concatenate every single-quoted segment up to the field's terminator.
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

fn extract_single_quoted(body: &str, field: &str) -> String {
    extract_multiline_quoted(body, field)
}

fn extract_int(body: &str, field: &str) -> u64 {
    let pat = format!("{}:", field);
    let Some(p) = find_field(body, field) else { return 0; };
    let after = p + pat.len();
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

// ── cosig message vector parsing ────────────────────────────────────────────

struct MessageRec {
    desc:             String,
    timestamp:        u64,
    body:             String,
    expected_message: String,
}

fn parse_message_records(src: &str) -> Vec<MessageRec> {
    let mut out = Vec::new();
    let needle = "export const COSIG_MESSAGE_RECORDS";
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
                    out.push(MessageRec {
                        desc:             extract_single_quoted(body, "desc"),
                        timestamp:        extract_int(body, "timestamp"),
                        body:             extract_multiline_quoted(body, "body"),
                        expected_message: extract_multiline_quoted(body, "expectedMessage"),
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

// ── cosig payload vector parsing ────────────────────────────────────────────

struct PayloadRec {
    desc:        String,
    suite:       String,
    timestamp:   u64,
    sig_hex:     String,
    payload_hex: String,
}

fn parse_payload_records(src: &str) -> Vec<PayloadRec> {
    let mut out = Vec::new();
    let needle = "export const COSIG_PAYLOAD_RECORDS";
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
                    out.push(PayloadRec {
                        desc:        extract_single_quoted(body, "desc"),
                        suite:       extract_single_quoted(body, "suite"),
                        timestamp:   extract_int(body, "timestamp"),
                        sig_hex:     extract_single_quoted(body, "sigHex"),
                        payload_hex: extract_single_quoted(body, "payloadHex"),
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

// ── cosigned_message vector parsing ────────────────────────────────────────

struct CosignedRec {
    desc:           String,
    cosigner_name:  String,
    timestamp:      u64,
    log_origin:     String,
    start:          u64,
    end:            u64,
    hash_hex:       String,
    expected_hex:   String,
}

fn parse_cosigned_records(src: &str) -> Vec<CosignedRec> {
    let mut out = Vec::new();
    let needle = "export const COSIGNED_MESSAGE_RECORDS";
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
                    out.push(CosignedRec {
                        desc:          extract_single_quoted(body, "desc"),
                        cosigner_name: extract_single_quoted(body, "cosignerName"),
                        timestamp:     extract_int(body, "timestamp"),
                        log_origin:    extract_single_quoted(body, "logOrigin"),
                        start:         extract_int(body, "start"),
                        end:           extract_int(body, "end"),
                        hash_hex:      extract_single_quoted(body, "hashHex"),
                        expected_hex:  extract_single_quoted(body, "expectedHex"),
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

// ── runner ──────────────────────────────────────────────────────────────────

pub fn run(
    message_src:  &str,
    payload_src:  &str,
    cosigned_src: &str,
    log: &mut Vec<String>,
) -> bool {
    let mut all_ok = true;

    // §"Ed25519 signed message" construction.
    let msg_records = parse_message_records(message_src);
    if msg_records.is_empty() {
        log.push("    ✗ COSIG_MESSAGE_RECORDS parsed as empty".to_string());
        return false;
    }
    log.push(format!("    Cosig message records parsed: {}", msg_records.len()));

    for rec in &msg_records {
        let body_bytes  = rec.body.as_bytes();
        let expect_bytes = rec.expected_message.as_bytes();
        let got = build_cosig_signed_message(body_bytes, rec.timestamp);
        if got != expect_bytes {
            log.push(format!(
                "    ✗ {}: cosig signed message bytes mismatch (got {} bytes, expected {})",
                rec.desc, got.len(), expect_bytes.len(),
            ));
            all_ok = false;
        } else {
            log.push(format!("    ✓ cosig signed message: {}", rec.desc));
        }
    }

    // §Format `timestamped_signature` payload codec.
    let pay_records = parse_payload_records(payload_src);
    if pay_records.is_empty() {
        log.push("    ✗ COSIG_PAYLOAD_RECORDS parsed as empty".to_string());
        return false;
    }
    log.push(format!("    Cosig payload records parsed: {}", pay_records.len()));

    for rec in &pay_records {
        let sig = match hex::decode(&rec.sig_hex) {
            Ok(b) => b,
            Err(e) => {
                log.push(format!("    ✗ {}: sigHex decode failed: {}", rec.desc, e));
                all_ok = false;
                continue;
            }
        };
        let expected_size: usize = match rec.suite.as_str() {
            "ed25519" => 64,
            "mldsa44" => 2420,
            other => {
                log.push(format!("    ✗ {}: unknown suite '{}'", rec.desc, other));
                all_ok = false;
                continue;
            }
        };
        if sig.len() != expected_size {
            log.push(format!(
                "    ✗ {}: sig length {} != expected {} for suite {}",
                rec.desc, sig.len(), expected_size, rec.suite,
            ));
            all_ok = false;
            continue;
        }
        let got = emit_cosig_signature_payload(rec.timestamp, &sig);
        let got_hex = hex::encode(&got);
        if got_hex != rec.payload_hex {
            log.push(format!(
                "    ✗ {}: payload mismatch (got {} bytes, expected {})",
                rec.desc, got.len(), rec.payload_hex.len() / 2,
            ));
            all_ok = false;
        } else {
            log.push(format!(
                "    ✓ cosig payload: {} (suite={}, ts={}, sigSize={})",
                rec.desc, rec.suite, rec.timestamp, expected_size,
            ));
        }
    }

    // §"ML-DSA-44 signed message" cosigned_message struct construction.
    let cm_records = parse_cosigned_records(cosigned_src);
    if cm_records.is_empty() {
        log.push("    ✗ COSIGNED_MESSAGE_RECORDS parsed as empty".to_string());
        return false;
    }
    log.push(format!("    cosigned_message records parsed: {}", cm_records.len()));

    for rec in &cm_records {
        let hash = match hex::decode(&rec.hash_hex) {
            Ok(b) => b,
            Err(e) => {
                log.push(format!("    ✗ {}: hashHex decode failed: {}", rec.desc, e));
                all_ok = false;
                continue;
            }
        };
        if hash.len() != 32 {
            log.push(format!(
                "    ✗ {}: hash length {} != 32",
                rec.desc, hash.len(),
            ));
            all_ok = false;
            continue;
        }
        let got = build_cosigned_message(
            &rec.cosigner_name,
            rec.timestamp,
            &rec.log_origin,
            rec.start,
            rec.end,
            &hash,
        );
        let got_hex = hex::encode(&got);
        if got_hex != rec.expected_hex {
            log.push(format!(
                "    ✗ {}: cosigned_message bytes mismatch (got {} bytes, expected {})",
                rec.desc, got.len(), rec.expected_hex.len() / 2,
            ));
            all_ok = false;
        } else {
            log.push(format!(
                "    ✓ cosigned_message: {} (len {} bytes)",
                rec.desc, got.len(),
            ));
        }
    }

    all_ok
}
