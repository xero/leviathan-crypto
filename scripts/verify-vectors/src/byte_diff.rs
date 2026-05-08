// Shared byte-diff helpers used by every per-corpus verifier.
//
// `log_byte_diff` is the only public surface; `first_diff` is the
// private byte-walk it delegates to. Hoisted out of mlkem.rs / mldsa.rs
// so the log format stays uniform across all verifiers.

fn first_diff(computed: &[u8], expected: &[u8]) -> Option<(usize, u8, u8)> {
    for (i, (a, b)) in computed.iter().zip(expected.iter()).enumerate() {
        if a != b { return Some((i, *a, *b)); }
    }
    None
}

pub fn log_byte_diff(log: &mut Vec<String>, label: &str, computed: &[u8], expected: &[u8]) {
    if computed != expected {
        if let Some((i, a, b)) = first_diff(computed, expected) {
            log.push(format!(
                "  ✗ {label} first byte mismatch at offset {i}: computed=0x{a:02x}, expected=0x{b:02x}",
            ));
        }
        if computed.len() != expected.len() {
            log.push(format!(
                "  ✗ {label} length mismatch: computed={} expected={}",
                computed.len(), expected.len(),
            ));
        }
    }
}
