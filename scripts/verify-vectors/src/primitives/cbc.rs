// Hand-rolled CBC mode of operation on top of a generic 16-byte block cipher.
//
// Verifies-by-construction: the verifier sees the entire CBC chain in source,
// so a bug in the cipher crate's mode-of-operation glue cannot pass through.
// Only the block cipher itself is the trust anchor.
//
// CBC encrypt:
//   c_0 = E_K(p_0 XOR iv)
//   c_i = E_K(p_i XOR c_{i-1})
//
// Inputs are PKCS#7-padded by the caller before this function runs; this
// function only does CBC chaining over an already-padded input.

const BLOCK_SIZE: usize = 16;

/// CBC-encrypt `padded_plaintext` using the provided block-encrypt closure.
/// Caller must ensure `padded_plaintext.len() % 16 == 0` and `iv.len() == 16`.
pub fn cbc_encrypt(
    iv:               &[u8],
    padded_plaintext: &[u8],
    mut encrypt_block: impl FnMut(&mut [u8; 16]),
) -> Vec<u8> {
    assert_eq!(iv.len(), BLOCK_SIZE, "CBC IV must be 16 bytes");
    assert_eq!(
        padded_plaintext.len() % BLOCK_SIZE,
        0,
        "CBC plaintext must be a multiple of 16 bytes (PKCS#7 pad before calling)",
    );

    let mut out = Vec::with_capacity(padded_plaintext.len());
    let mut prev = [0u8; BLOCK_SIZE];
    prev.copy_from_slice(iv);

    for chunk in padded_plaintext.chunks(BLOCK_SIZE) {
        let mut block = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            block[i] = chunk[i] ^ prev[i];
        }
        encrypt_block(&mut block);
        out.extend_from_slice(&block);
        prev = block;
    }
    out
}
