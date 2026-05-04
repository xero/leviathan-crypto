// HChaCha20 — RFC 8439 §2.3 ChaCha20 block function variant.
// Inputs:  key (32 bytes), nonce (16 bytes)
// Output:  subkey (32 bytes) = state words 0..3 ‖ 12..15 after 20 rounds,
//          WITHOUT the final add-back-the-input step.
//
// Hand-rolled here because none of the RustCrypto crates expose HChaCha20
// as a standalone primitive — it only surfaces inside XChaCha20Poly1305.
// Leviathan-crypto exposes it because the STREAM construction needs the
// subkey separately from any AEAD call. This is ~30 lines of arithmetic
// against RFC 8439 §2.3 with zero external dependencies.

const CONST: &[u8; 16] = b"expand 32-byte k";

#[inline(always)]
fn rotl32(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

#[inline(always)]
fn quarterround(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = rotl32(s[d], 16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = rotl32(s[b], 12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = rotl32(s[d],  8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = rotl32(s[b],  7);
}

pub fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    // State layout (16 × u32 LE):
    //   constants[0..4] || key[4..12] || nonce16[12..16]
    let mut state = [0u32; 16];

    for i in 0..4 {
        state[i] = u32::from_le_bytes(CONST[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes(nonce16[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // 20 rounds = 10 double-rounds: 4 column rounds + 4 diagonal rounds each
    for _ in 0..10 {
        quarterround(&mut state,  0,  4,  8, 12);
        quarterround(&mut state,  1,  5,  9, 13);
        quarterround(&mut state,  2,  6, 10, 14);
        quarterround(&mut state,  3,  7, 11, 15);
        quarterround(&mut state,  0,  5, 10, 15);
        quarterround(&mut state,  1,  6, 11, 12);
        quarterround(&mut state,  2,  7,  8, 13);
        quarterround(&mut state,  3,  4,  9, 14);
    }

    // HChaCha20: emit words 0..3 and 12..15, NO add-back-the-input step.
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }
    for i in 0..4 {
        out[16 + i * 4..16 + (i + 1) * 4].copy_from_slice(&state[12 + i].to_le_bytes());
    }
    out
}
