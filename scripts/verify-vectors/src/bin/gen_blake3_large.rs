// Emit BLAKE3 expected-hash hex for the large-input regression test
// (test/unit/blake3/blake3-large-input.test.ts). Uses the official
// BLAKE3-team Rust crate as the independent oracle; the test file
// embeds the printed values verbatim so the cross-check is an
// embedded-expected comparison (matches the rest of the BLAKE3
// corpus posture in `test/vectors/blake3.ts`).
//
// Input pattern: byte i is (i mod 251), matching the upstream KAT
// convention. Output: full 131-byte XOF hex per (mode, size) pair
// so the test can exercise the §2.5 squeeze path past the 32-byte
// default cap.

use blake3::Hasher;

// Sizes outside the upstream 35-record KAT corpus, picked to fit inside
// the v3 BLAKE3 module's per-call input staging (INPUT_SCRATCH_MAX =
// 114688 bytes, see src/ts/blake3/index.ts). 8000 lands between the
// KAT's 7169 and 8192 inputs; 65536 and 100000 land in the gap between
// 31744 and 102400.
const SIZES: &[usize] = &[8000, 65536, 100000];

const KEY: &[u8; 32] = b"whats the Elvish word for friend";
const CONTEXT: &str  = "BLAKE3 2019-12-27 16:29:52 test vectors context";

const XOF_LEN: usize = 131;

fn make_input(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn xof(h: &Hasher) -> [u8; XOF_LEN] {
    let mut out = [0u8; XOF_LEN];
    h.finalize_xof().fill(&mut out);
    out
}

fn main() {
    for &n in SIZES {
        let input = make_input(n);

        let mut h_hash = Hasher::new();
        h_hash.update(&input);
        let hash_out = xof(&h_hash);

        let mut h_keyed = Hasher::new_keyed(KEY);
        h_keyed.update(&input);
        let keyed_out = xof(&h_keyed);

        let mut h_derive = Hasher::new_derive_key(CONTEXT);
        h_derive.update(&input);
        let derive_out = xof(&h_derive);

        println!("// inputLen = {}", n);
        println!("hash:       '{}',",  hex::encode(hash_out));
        println!("keyedHash:  '{}',",  hex::encode(keyed_out));
        println!("deriveKey:  '{}',",  hex::encode(derive_out));
        println!();
    }
}
