// PKCS#7 padding (RFC 5652 §6.3).
//
// To pad to a 16-byte block boundary: compute pad = 16 - (len mod 16). Always
// in [1, 16]. Append `pad` copies of the byte value `pad`.
//
// "Always" includes the case where the input is already aligned: a full
// block of 16 padding bytes (each equal to 0x10) is appended. This is
// what keeps unpad unambiguous — every padded ciphertext has a non-empty
// padding tail.

const BLOCK_SIZE: usize = 16;

pub fn pad(plaintext: &[u8]) -> Vec<u8> {
    let pad_len = BLOCK_SIZE - (plaintext.len() % BLOCK_SIZE);
    let mut out = Vec::with_capacity(plaintext.len() + pad_len);
    out.extend_from_slice(plaintext);
    out.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    out
}
