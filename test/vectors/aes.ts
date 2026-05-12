// test/vectors/aes.ts
//
// AES (Rijndael with 128-bit block, 128/192/256-bit keys) test vectors.
//
// Sources:
//   FIPS 197, Advanced Encryption Standard, Update 1 (May 9, 2023)
//   @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
//   Sections covered: §5.1.1 Figure 7 (forward S-box table),
//                     Appendix A.1 (AES-128 key expansion),
//                     Appendix A.2 (AES-192 key expansion),
//                     Appendix A.3 (AES-256 key expansion),
//                     Appendix B (AES-128 cipher example with
//                                 per-round intermediate states).
//
//   FIPS 197, Advanced Encryption Standard (original, November 26, 2001)
//   @see https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
//   Sections covered: Appendix C.2 (AES-192 cipher example with per-round
//                                   intermediate states),
//                     Appendix C.3 (AES-256 cipher example with per-round
//                                   intermediate states).
//
// Note on Appendix C: FIPS 197 Update 1 (May 2023) removed the worked
// cipher examples that the original FIPS 197 (November 2001) carried in
// Appendix C, replacing them with a pointer to the NIST CSRC AES project
// page. The original 2001 publication remains an authoritative spec
// source for those AES-192/256 vectors, the AES algorithm itself was
// not modified by upd1 (only editorial revisions were applied). The
// 2001 publication is hash-pinned in research-docs/specs/nist.fips.197.pdf
// for direct citation here.
//
// Note on §C.1 (AES-128, original 2001 publication): contains a separate
// AES-128 worked example with key 000102…0e0f and plaintext 00112233…
// ddeeff that differs from the §B example below. It was intentionally
// not transcribed into this corpus, gate 3 (single-round verification)
// is anchored by the §B example, and the AESAVS KAT/MMT/MCT files
// (aes_ECB*128.rsp) provide independent block-cipher-level coverage for
// AES-128. Adding §C.1 would have required a tagging mechanism for the
// round-intermediate array; the additional witness was not justified
// given the existing CAVP coverage.
//
// All hex strings are lowercase, no separators.
// State strings (round intermediates) are 32 hex characters (16 bytes =
// one AES block) in column-major byte order matching the AES state-array
// layout (FIPS 197 §3.4).
//
// Audit status: VERIFIED, per-vector citations in each export below.

// ============================================================
// Interfaces
// ============================================================

export interface BlockVector {
	description: string;
	key: string;  // hex (32, 48, or 64 chars = 16, 24, or 32 bytes)
	pt:  string;  // hex (32 chars = 16 bytes)
	ct:  string;  // hex (32 chars = 16 bytes)
}

export interface KeyExpansionVector {
	description:      string;
	keyBits:          128 | 192 | 256;
	key:              string;  // hex (16/24/32 bytes)
	roundKeySchedule: string;  // hex; concatenation of all w[0]..w[N-1] words
	                           //   AES-128: 44 words = 176 bytes (352 hex)
	                           //   AES-192: 52 words = 208 bytes (416 hex)
	                           //   AES-256: 60 words = 240 bytes (480 hex)
}

// ============================================================
// FIPS 197 §B, AES-128 cipher example
// ============================================================

/** FIPS 197 Appendix B worked example for the AES-128 block cipher. */
export const aes128CipherVectors: BlockVector[] = [
	{
		description: 'FIPS 197 §B: AES-128 cipher example',
		key: '2b7e151628aed2a6abf7158809cf4f3c',
		pt: '3243f6a8885a308d313198a2e0370734',
		ct: '3925841d02dc09fbdc118597196a0b32',
	},
];

// ============================================================
// FIPS 197 (2001) §C.2, AES-192 cipher example
// ============================================================

/** FIPS 197 (2001) Appendix C.2 worked example for the AES-192 block cipher. */
export const aes192CipherVectors: BlockVector[] = [
	{
		description: 'FIPS 197 (2001) §C.2: AES-192 cipher example',
		key: '000102030405060708090a0b0c0d0e0f1011121314151617',
		pt: '00112233445566778899aabbccddeeff',
		ct: 'dda97ca4864cdfe06eaf70a0ec0d7191',
	},
];

// ============================================================
// FIPS 197 (2001) §C.3, AES-256 cipher example
// ============================================================

/** FIPS 197 (2001) Appendix C.3 worked example for the AES-256 block cipher. */
export const aes256CipherVectors: BlockVector[] = [
	{
		description: 'FIPS 197 (2001) §C.3: AES-256 cipher example',
		key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
		pt: '00112233445566778899aabbccddeeff',
		ct: '8ea2b7ca516745bfeafc49904b496089',
	},
];

/** Convenience grouping for parameterized tests. */
export const aesCipherVectorsByKeySize: Record<128 | 192 | 256, BlockVector[]> = {
	128: aes128CipherVectors,
	192: aes192CipherVectors,
	256: aes256CipherVectors,
};

// ============================================================
// FIPS 197 §A, Key expansion examples
// ============================================================

/**
 * FIPS 197 Appendix A worked examples for the AES KeyExpansion routine.
 * Each entry is the full round-key schedule produced from the given key,
 * encoded as the big-endian byte sequence of w[0] || w[1] || ... || w[N-1]
 * where N = 4*(Nr+1) and Nr is the round count for the key size.
 */
export const aesKeyExpansionVectors: KeyExpansionVector[] = [
	{
		description: 'FIPS 197 §A.1: AES-128 KeyExpansion (Nk=4, 44 words)',
		keyBits: 128,
		key: '2b7e151628aed2a6abf7158809cf4f3c',
		roundKeySchedule:
			'2b7e151628aed2a6abf7158809cf4f3c' +
			'a0fafe1788542cb123a339392a6c7605' +
			'f2c295f27a96b9435935807a7359f67f' +
			'3d80477d4716fe3e1e237e446d7a883b' +
			'ef44a541a8525b7fb671253bdb0bad00' +
			'd4d1c6f87c839d87caf2b8bc11f915bc' +
			'6d88a37a110b3efddbf98641ca0093fd' +
			'4e54f70e5f5fc9f384a64fb24ea6dc4f' +
			'ead27321b58dbad2312bf5607f8d292f' +
			'ac7766f319fadc2128d12941575c006e' +
			'd014f9a8c9ee2589e13f0cc8b6630ca6',
	},
	{
		description: 'FIPS 197 §A.2: AES-192 KeyExpansion (Nk=6, 52 words)',
		keyBits: 192,
		key: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
		roundKeySchedule:
			'8e73b0f7da0e6452c810f32b809079e5' +
			'62f8ead2522c6b7bfe0c91f72402f5a5' +
			'ec12068e6c827f6b0e7a95b95c56fec2' +
			'4db7b4bd69b5411885a74796e92538fd' +
			'e75fad44bb095386485af05721efb14f' +
			'a448f6d94d6dce24aa326360113b30e6' +
			'a25e7ed583b1cf9a27f939436a94f767' +
			'c0a69407d19da4e1ec1786eb6fa64971' +
			'485f703222cb8755e26d135233f0b7b3' +
			'40beeb282f18a2596747d26b458c553e' +
			'a7e1466c9411f1df821f750aad07d753' +
			'ca4005388fcc5006282d166abc3ce7b5' +
			'e98ba06f448c773c8ecc720401002202',
	},
	{
		description: 'FIPS 197 §A.3: AES-256 KeyExpansion (Nk=8, 60 words)',
		keyBits: 256,
		key: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
		roundKeySchedule:
			'603deb1015ca71be2b73aef0857d7781' +
			'1f352c073b6108d72d9810a30914dff4' +
			'9ba354118e6925afa51a8b5f2067fcde' +
			'a8b09c1a93d194cdbe49846eb75d5b9a' +
			'd59aecb85bf3c917fee94248de8ebe96' +
			'b5a9328a2678a647983122292f6c79b3' +
			'812c81addadf48ba24360af2fab8b464' +
			'98c5bfc9bebd198e268c3ba709e04214' +
			'68007bacb2df331696e939e46c518d80' +
			'c814e20476a9fb8a5025c02d59c58239' +
			'de1369676ccc5a71fa2563959674ee15' +
			'5886ca5d2e2f31d77e0af1fa27cf73c3' +
			'749c47ab18501ddae2757e4f7401905a' +
			'cafaaae3e4d59b349adf6acebd10190d' +
			'fe4890d1e6188d0b046df344706c631e',
	},
];

// ============================================================
// FIPS 197 (Update 1) §5.1.1 Figure 7, AES forward S-box table
// ============================================================

/**
 * The 256-byte AES forward S-box. `aesSboxTable[b]` is the substituted
 * byte for input b. Used by SubBytes (FIPS 197 §5.1.1) and SubWord during
 * key expansion (§5.2).
 *
 * Source: FIPS 197 (Update 1, May 9, 2023) §5.1.1 Figure 7, Table 4
 *   "SBOX(): substitution values for the byte xy (in hexadecimal format)"
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
 *
 * Audit status: VERIFIED, values transcribed directly from the FIPS 197
 *   PDF (independent two-pass transcription). Each comment line below
 *   corresponds to one row of Figure 7. The table is a permutation of
 *   the bytes 0x00..0xff (verifiable property: `new Set(aesSboxTable).size
 *   === 256`). Per AGENTS.md §1-3, derivation must come from the FIPS 197
 *   spec only, not from any other AES implementation.
 */
export const aesSboxTable: Uint8Array = new Uint8Array([
	// row 0x0_:
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	// row 0x1_:
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	// row 0x2_:
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	// row 0x3_:
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	// row 0x4_:
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	// row 0x5_:
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	// row 0x6_:
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	// row 0x7_:
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	// row 0x8_:
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	// row 0x9_:
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	// row 0xa_:
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	// row 0xb_:
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	// row 0xc_:
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	// row 0xd_:
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	// row 0xe_:
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	// row 0xf_:
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

// ============================================================
// FIPS 197, Per-round intermediate states (cipher example dissections)
// ============================================================

/**
 * Per-round state values for the AES Cipher() function. Each entry is one
 * round's complete state breakdown, the input (`start`) plus each
 * post-transformation snapshot (`afterSubBytes`, `afterShiftRows`,
 * `afterMixColumns`, `end`) and the round key XORed at the end of the
 * round. The chain invariant `rounds[i].end === rounds[i+1].start` holds
 * within each cipher example.
 *
 * State byte order: column-major, matching the AES state-array layout
 * (FIPS 197 §3.4). For the 4×4 matrix
 *
 *     | s00 s01 s02 s03 |
 *     | s10 s11 s12 s13 |
 *     | s20 s21 s22 s23 |
 *     | s30 s31 s32 s33 |
 *
 * the hex string is the byte sequence
 *   s00 s10 s20 s30 s01 s11 s21 s31 s02 s12 s22 s32 s03 s13 s23 s33.
 *
 * The final round of each cipher (round 10 for AES-128, round 12 for
 * AES-192, round 14 for AES-256) has no MixColumns step; its
 * `afterMixColumns` field is the empty string. For non-final rounds,
 * `end === afterMixColumns ⊕ roundKey`; for the final round,
 * `end === afterShiftRows ⊕ roundKey === <ciphertext>`.
 */
export interface RoundIntermediateVector {
	description:     string;
	round:           number; // 1..N where N = round count for the key size
	start:           string; // hex (32 chars), state at start of round
	afterSubBytes:   string; // hex (32 chars)
	afterShiftRows:  string; // hex (32 chars)
	afterMixColumns: string; // hex (32 chars), '' for the final round only
	roundKey:        string; // hex (32 chars), the round key XORed at end
	end:             string; // hex (32 chars), state after AddRoundKey;
	                         // equals start of next round (non-final) or
	                         // ciphertext (final round)
}

/**
 * AES-128 per-round intermediate states for the §B cipher example.
 *
 * Source: FIPS 197 (Update 1, May 9, 2023) Appendix B
 *   "Cipher Example", 10 rounds, plaintext 32 43 f6 a8…07 34, key
 *   2b 7e 15 16…4f 3c, ciphertext 39 25 84 1d…0b 32.
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
 *
 * Audit status: VERIFIED, every state transcribed directly from the
 *   FIPS 197 PDF, no value derived algorithmically. Round keys
 *   cross-check against `aesKeyExpansionVectors[0].roundKeySchedule`
 *   (FIPS 197 §A.1, same input key).
 */
export const aesRoundIntermediates128: RoundIntermediateVector[] = [
	{
		description: 'FIPS 197 §B Round 1',
		round: 1,
		start: '193de3bea0f4e22b9ac68d2ae9f84808',
		afterSubBytes: 'd42711aee0bf98f1b8b45de51e415230',
		afterShiftRows: 'd4bf5d30e0b452aeb84111f11e2798e5',
		afterMixColumns: '046681e5e0cb199a48f8d37a2806264c',
		roundKey: 'a0fafe1788542cb123a339392a6c7605',
		end: 'a49c7ff2689f352b6b5bea43026a5049',
	},
	{
		description: 'FIPS 197 §B Round 2',
		round: 2,
		start: 'a49c7ff2689f352b6b5bea43026a5049',
		afterSubBytes: '49ded28945db96f17f39871a7702533b',
		afterShiftRows: '49db873b453953897f02d2f177de961a',
		afterMixColumns: '584dcaf11b4b5aacdbe7caa81b6bb0e5',
		roundKey: 'f2c295f27a96b9435935807a7359f67f',
		end: 'aa8f5f0361dde3ef82d24ad26832469a',
	},
	{
		description: 'FIPS 197 §B Round 3',
		round: 3,
		start: 'aa8f5f0361dde3ef82d24ad26832469a',
		afterSubBytes: 'ac73cf7befc111df13b5d6b545235ab8',
		afterShiftRows: 'acc1d6b8efb55a7b1323cfdf457311b5',
		afterMixColumns: '75ec0993200b633353c0cf7cbb25d0dc',
		roundKey: '3d80477d4716fe3e1e237e446d7a883b',
		end: '486c4eee671d9d0d4de3b138d65f58e7',
	},
	{
		description: 'FIPS 197 §B Round 4',
		round: 4,
		start: '486c4eee671d9d0d4de3b138d65f58e7',
		afterSubBytes: '52502f2885a45ed7e311c807f6cf6a94',
		afterShiftRows: '52a4c89485116a28e3cf2fd7f6505e07',
		afterMixColumns: '0fd6daa9603138bf6fc0106b5eb31301',
		roundKey: 'ef44a541a8525b7fb671253bdb0bad00',
		end: 'e0927fe8c86363c0d9b1355085b8be01',
	},
	{
		description: 'FIPS 197 §B Round 5',
		round: 5,
		start: 'e0927fe8c86363c0d9b1355085b8be01',
		afterSubBytes: 'e14fd29be8fbfbba35c89653976cae7c',
		afterShiftRows: 'e1fb967ce8c8ae9b356cd2ba974ffb53',
		afterMixColumns: '25d1a9adbd11d168b63a338e4c4cc0b0',
		roundKey: 'd4d1c6f87c839d87caf2b8bc11f915bc',
		end: 'f1006f55c1924cef7cc88b325db5d50c',
	},
	{
		description: 'FIPS 197 §B Round 6',
		round: 6,
		start: 'f1006f55c1924cef7cc88b325db5d50c',
		afterSubBytes: 'a163a8fc784f29df10e83d234cd503fe',
		afterShiftRows: 'a14f3dfe78e803fc10d5a8df4c632923',
		afterMixColumns: '4b868d6d2c4a8980339df4e837d218d8',
		roundKey: '6d88a37a110b3efddbf98641ca0093fd',
		end: '260e2e173d41b77de86472a9fdd28b25',
	},
	{
		description: 'FIPS 197 §B Round 7',
		round: 7,
		start: '260e2e173d41b77de86472a9fdd28b25',
		afterSubBytes: 'f7ab31f02783a9ff9b4340d354b53d3f',
		afterShiftRows: 'f783403f27433df09bb531ff54aba9d3',
		afterMixColumns: '1415b5bf461615ec274656d7342ad843',
		roundKey: '4e54f70e5f5fc9f384a64fb24ea6dc4f',
		end: '5a4142b11949dc1fa3e019657a8c040c',
	},
	{
		description: 'FIPS 197 §B Round 8',
		round: 8,
		start: '5a4142b11949dc1fa3e019657a8c040c',
		afterSubBytes: 'be832cc8d43b86c00ae1d44dda64f2fe',
		afterShiftRows: 'be3bd4fed4e1f2c80a642cc0da83864d',
		afterMixColumns: '00512fd1b1c889ff54766dcdfa1b99ea',
		roundKey: 'ead27321b58dbad2312bf5607f8d292f',
		end: 'ea835cf00445332d655d98ad8596b0c5',
	},
	{
		description: 'FIPS 197 §B Round 9',
		round: 9,
		start: 'ea835cf00445332d655d98ad8596b0c5',
		afterSubBytes: '87ec4a8cf26ec3d84d4c46959790e7a6',
		afterShiftRows: '876e46a6f24ce78c4d904ad897ecc395',
		afterMixColumns: '473794ed40d4e4a5a3703aa64c9f42bc',
		roundKey: 'ac7766f319fadc2128d12941575c006e',
		end: 'eb40f21e592e38848ba113e71bc342d2',
	},
	{
		description: 'FIPS 197 §B Round 10',
		round: 10,
		start: 'eb40f21e592e38848ba113e71bc342d2',
		afterSubBytes: 'e9098972cb31075f3d327d94af2e2cb5',
		afterShiftRows: 'e9317db5cb322c723d2e895faf090794',
		afterMixColumns: '',
		roundKey: 'd014f9a8c9ee2589e13f0cc8b6630ca6',
		end: '3925841d02dc09fbdc118597196a0b32',
	},
];

/**
 * AES-192 per-round intermediate states for the §C.2 cipher example.
 *
 * Source: FIPS 197 (November 26, 2001) Appendix C.2
 *   "AES-192 (Nk=6, Nr=12)", 12 rounds, plaintext 00112233…ddeeff,
 *   key 00010203…14151617, ciphertext dda97ca4…ec0d7191.
 * @see https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 *
 * Audit status: VERIFIED, every state transcribed directly from the
 *   FIPS 197 (2001) PDF, no value derived algorithmically.
 */
export const aesRoundIntermediates192: RoundIntermediateVector[] = [
	{
		description: 'FIPS 197 (2001) §C.2 Round 1',
		round: 1,
		start: '00102030405060708090a0b0c0d0e0f0',
		afterSubBytes: '63cab7040953d051cd60e0e7ba70e18c',
		afterShiftRows: '6353e08c0960e104cd70b751bacad0e7',
		afterMixColumns: '5f72641557f5bc92f7be3b291db9f91a',
		roundKey: '10111213141516175846f2f95c43f4fe',
		end: '4f63760643e0aa85aff8c9d041fa0de4',
	},
	{
		description: 'FIPS 197 (2001) §C.2 Round 2',
		round: 2,
		start: '4f63760643e0aa85aff8c9d041fa0de4',
		afterSubBytes: '84fb386f1ae1ac977941dd70832dd769',
		afterShiftRows: '84e1dd691a41d76f792d389783fbac70',
		afterMixColumns: '9f487f794f955f662afc86abd7f1ab29',
		roundKey: '544afef55847f0fa4856e2e95c43f4fe',
		end: 'cb02818c17d2af9c62aa64428bb25fd7',
	},
	{
		description: 'FIPS 197 (2001) §C.2 Round 3',
		round: 3,
		start: 'cb02818c17d2af9c62aa64428bb25fd7',
		afterSubBytes: '1f770c64f0b579deaaac432c3d37cf0e',
		afterShiftRows: '1fb5430ef0accf64aa370cde3d77792c',
		afterMixColumns: 'b7a53ecbbf9d75a0c40efc79b674cc11',
		roundKey: '40f949b31cbabd4d48f043b810b7b342',
		end: 'f75c7778a327c8ed8cfebfc1a6c37f53',
	},
	{
		description: 'FIPS 197 (2001) §C.2 Round 4',
		round: 4,
		start: 'f75c7778a327c8ed8cfebfc1a6c37f53',
		afterSubBytes: '684af5bc0acce85564bb0878242ed2ed',
		afterShiftRows: '68cc08ed0abbd2bc642ef555244ae878',
		afterMixColumns: '7a1e98bdacb6d1141a6944dd06eb2d3e',
		roundKey: '58e151ab04a2a5557effb5416245080c',
		end: '22ffc916a81474416496f19c64ae2532',
	},
	{
		description: 'FIPS 197 (2001) §C.2 Round 5',
		round: 5,
		start: '22ffc916a81474416496f19c64ae2532',
		afterSubBytes: '9316dd47c2fa92834390a1de43e43f23',
		afterShiftRows: '93faa123c2903f4743e4dd83431692de',
		afterMixColumns: 'aaa755b34cffe57cef6f98e1f01c13e6',
		roundKey: '2ab54bb43a02f8f662e3a95d66410c08',
		end: '80121e0776fd1d8a8d8c31bc965d1fee',
	},
	{
		description: 'FIPS 197 (2001) §C.2 Round 6',
		round: 6,
		start: '80121e0776fd1d8a8d8c31bc965d1fee',
		afterSubBytes: 'cdc972c53854a47e5d64c765904cc028',
		afterShiftRows: 'cd54c7283864c0c55d4c727e90c9a465',
		afterMixColumns: '921f748fd96e937d622d7725ba8ba50c',
		roundKey: 'f501857297448d7ebdf1c6ca87f33e3c',
		end: '671ef1fd4e2a1e03dfdcb1ef3d789b30',
	},
	{
		description: 'FIPS 197 (2001) §C.2 Round 7',
		round: 7,
		start: '671ef1fd4e2a1e03dfdcb1ef3d789b30',
		afterSubBytes: '8572a1542fe5727b9e86c8df27bc1404',
		afterShiftRows: '85e5c8042f8614549ebca17b277272df',
		afterMixColumns: 'e913e7b18f507d4b227ef652758acbcc',
		roundKey: 'e510976183519b6934157c9ea351f1e0',
		end: '0c0370d00c01e622166b8accd6db3a2c',
	},
	{
		description: 'FIPS 197 (2001) §C.2 Round 8',
		round: 8,
		start: '0c0370d00c01e622166b8accd6db3a2c',
		afterSubBytes: 'fe7b5170fe7c8e93477f7e4bf6b98071',
		afterShiftRows: 'fe7c7e71fe7f807047b95193f67b8e4b',
		afterMixColumns: '6cf5edf996eb0a069c4ef21cbfc25762',
		roundKey: '1ea0372a995309167c439e77ff12051e',
		end: '7255dad30fb80310e00d6c6b40d0527c',
	},
	{
		description: 'FIPS 197 (2001) §C.2 Round 9',
		round: 9,
		start: '7255dad30fb80310e00d6c6b40d0527c',
		afterSubBytes: '40fc5766766c7bcae1d7507f09700010',
		afterShiftRows: '406c501076d70066e17057ca09fc7b7f',
		afterMixColumns: '7478bcdce8a50b81d4327a9009188262',
		roundKey: 'dd7e0e887e2fff68608fc842f9dcc154',
		end: 'a906b254968af4e9b4bdb2d2f0c44336',
	},
	{
		description: 'FIPS 197 (2001) §C.2 Round 10',
		round: 10,
		start: 'a906b254968af4e9b4bdb2d2f0c44336',
		afterSubBytes: 'd36f3720907ebf1e8d7a37b58c1c1a05',
		afterShiftRows: 'd37e3705907a1a208d1c371e8c6fbfb5',
		afterMixColumns: '0d73cc2d8f6abe8b0cf2dd9bb83d422e',
		roundKey: '859f5f237a8d5a3dc0c02952beefd63a',
		end: '88ec930ef5e7e4b6cc32f4c906d29414',
	},
	{
		description: 'FIPS 197 (2001) §C.2 Round 11',
		round: 11,
		start: '88ec930ef5e7e4b6cc32f4c906d29414',
		afterSubBytes: 'c4cedcabe694694e4b23bfdd6fb522fa',
		afterShiftRows: 'c494bffae62322ab4bb5dc4e6fce69dd',
		afterMixColumns: '71d720933b6d677dc00b8f28238e0fb7',
		roundKey: 'de601e7827bcdf2ca223800fd8aeda32',
		end: 'afb73eeb1cd1b85162280f27fb20d585',
	},
	{
		description: 'FIPS 197 (2001) §C.2 Round 12',
		round: 12,
		start: 'afb73eeb1cd1b85162280f27fb20d585',
		afterSubBytes: '79a9b2e99c3e6cd1aa3476cc0fb70397',
		afterShiftRows: '793e76979c3403e9aab7b2d10fa96ccc',
		afterMixColumns: '',
		roundKey: 'a4970a331a78dc09c418c271e3a41d5d',
		end: 'dda97ca4864cdfe06eaf70a0ec0d7191',
	},
];

/**
 * AES-256 per-round intermediate states for the §C.3 cipher example.
 *
 * Source: FIPS 197 (November 26, 2001) Appendix C.3
 *   "AES-256 (Nk=8, Nr=14)", 14 rounds, plaintext 00112233…ddeeff,
 *   key 00010203…1c1d1e1f, ciphertext 8ea2b7ca…4b496089.
 * @see https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
 *
 * Audit status: VERIFIED, every state transcribed directly from the
 *   FIPS 197 (2001) PDF, no value derived algorithmically.
 */
export const aesRoundIntermediates256: RoundIntermediateVector[] = [
	{
		description: 'FIPS 197 (2001) §C.3 Round 1',
		round: 1,
		start: '00102030405060708090a0b0c0d0e0f0',
		afterSubBytes: '63cab7040953d051cd60e0e7ba70e18c',
		afterShiftRows: '6353e08c0960e104cd70b751bacad0e7',
		afterMixColumns: '5f72641557f5bc92f7be3b291db9f91a',
		roundKey: '101112131415161718191a1b1c1d1e1f',
		end: '4f63760643e0aa85efa7213201a4e705',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 2',
		round: 2,
		start: '4f63760643e0aa85efa7213201a4e705',
		afterSubBytes: '84fb386f1ae1ac97df5cfd237c49946b',
		afterShiftRows: '84e1fd6b1a5c946fdf4938977cfbac23',
		afterMixColumns: 'bd2a395d2b6ac438d192443e615da195',
		roundKey: 'a573c29fa176c498a97fce93a572c09c',
		end: '1859fbc28a1c00a078ed8aadc42f6109',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 3',
		round: 3,
		start: '1859fbc28a1c00a078ed8aadc42f6109',
		afterSubBytes: 'adcb0f257e9c63e0bc557e951c15ef01',
		afterShiftRows: 'ad9c7e017e55ef25bc150fe01ccb6395',
		afterMixColumns: '810dce0cc9db8172b3678c1e88a1b5bd',
		roundKey: '1651a8cd0244beda1a5da4c10640bade',
		end: '975c66c1cb9f3fa8a93a28df8ee10f63',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 4',
		round: 4,
		start: '975c66c1cb9f3fa8a93a28df8ee10f63',
		afterSubBytes: '884a33781fdb75c2d380349e19f876fb',
		afterShiftRows: '88db34fb1f807678d3f833c2194a759e',
		afterMixColumns: 'b2822d81abe6fb275faf103a078c0033',
		roundKey: 'ae87dff00ff11b68a68ed5fb03fc1567',
		end: '1c05f271a417e04ff921c5c104701554',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 5',
		round: 5,
		start: '1c05f271a417e04ff921c5c104701554',
		afterSubBytes: '9c6b89a349f0e18499fda678f2515920',
		afterShiftRows: '9cf0a62049fd59a399518984f26be178',
		afterMixColumns: 'aeb65ba974e0f822d73f567bdb64c877',
		roundKey: '6de1f1486fa54f9275f8eb5373b8518d',
		end: 'c357aae11b45b7b0a2c7bd28a8dc99fa',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 6',
		round: 6,
		start: 'c357aae11b45b7b0a2c7bd28a8dc99fa',
		afterSubBytes: '2e5bacf8af6ea9e73ac67a34c286ee2d',
		afterShiftRows: '2e6e7a2dafc6eef83a86ace7c25ba934',
		afterMixColumns: 'b951c33c02e9bd29ae25cdb1efa08cc7',
		roundKey: 'c656827fc9a799176f294cec6cd5598b',
		end: '7f074143cb4e243ec10c815d8375d54c',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 7',
		round: 7,
		start: '7f074143cb4e243ec10c815d8375d54c',
		afterSubBytes: 'd2c5831a1f2f36b278fe0c4cec9d0329',
		afterShiftRows: 'd22f0c291ffe031a789d83b2ecc5364c',
		afterMixColumns: 'ebb19e1c3ee7c9e87d7535e9ed6b9144',
		roundKey: '3de23a75524775e727bf9eb45407cf39',
		end: 'd653a4696ca0bc0f5acaab5db96c5e7d',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 8',
		round: 8,
		start: 'd653a4696ca0bc0f5acaab5db96c5e7d',
		afterSubBytes: 'f6ed49f950e06576be74624c565058ff',
		afterShiftRows: 'f6e062ff507458f9be50497656ed654c',
		afterMixColumns: '5174c8669da98435a8b3e62ca974a5ea',
		roundKey: '0bdc905fc27b0948ad5245a4c1871c2f',
		end: '5aa858395fd28d7d05e1a38868f3b9c5',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 9',
		round: 9,
		start: '5aa858395fd28d7d05e1a38868f3b9c5',
		afterSubBytes: 'bec26a12cfb55dff6bf80ac4450d56a6',
		afterShiftRows: 'beb50aa6cff856126b0d6aff45c25dc4',
		afterMixColumns: '0f77ee31d2ccadc05430a83f4ef96ac3',
		roundKey: '45f5a66017b2d387300d4d33640a820a',
		end: '4a824851c57e7e47643de50c2af3e8c9',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 10',
		round: 10,
		start: '4a824851c57e7e47643de50c2af3e8c9',
		afterSubBytes: 'd61352d1a6f3f3a04327d9fee50d9bdd',
		afterShiftRows: 'd6f3d9dda6279bd1430d52a0e513f3fe',
		afterMixColumns: 'bd86f0ea748fc4f4630f11c1e9331233',
		roundKey: '7ccff71cbeb4fe5413e6bbf0d261a7df',
		end: 'c14907f6ca3b3aa070e9aa313b52b5ec',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 11',
		round: 11,
		start: 'c14907f6ca3b3aa070e9aa313b52b5ec',
		afterSubBytes: '783bc54274e280e0511eacc7e200d5ce',
		afterShiftRows: '78e2acce741ed5425100c5e0e23b80c7',
		afterMixColumns: 'af8690415d6e1dd387e5fbedd5c89013',
		roundKey: 'f01afafee7a82979d7a5644ab3afe640',
		end: '5f9c6abfbac634aa50409fa766677653',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 12',
		round: 12,
		start: '5f9c6abfbac634aa50409fa766677653',
		afterSubBytes: 'cfde0208f4b418ac5309db5c338538ed',
		afterShiftRows: 'cfb4dbedf4093808538502ac33de185c',
		afterMixColumns: '7427fae4d8a695269ce83d315be0392b',
		roundKey: '2541fe719bf500258813bbd55a721c0a',
		end: '516604954353950314fb86e401922521',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 13',
		round: 13,
		start: '516604954353950314fb86e401922521',
		afterSubBytes: 'd133f22a1aed2a7bfa0f44697c4f3ffd',
		afterShiftRows: 'd1ed44fd1a0f3f2afa4ff27b7c332a69',
		afterMixColumns: '2c21a820306f154ab712c75eee0da04f',
		roundKey: '4e5a6699a9f24fe07e572baacdf8cdea',
		end: '627bceb9999d5aaac945ecf423f56da5',
	},
	{
		description: 'FIPS 197 (2001) §C.3 Round 14',
		round: 14,
		start: '627bceb9999d5aaac945ecf423f56da5',
		afterSubBytes: 'aa218b56ee5ebeacdd6ecebf26e63c06',
		afterShiftRows: 'aa5ece06ee6e3c56dde68bac2621bebf',
		afterMixColumns: '',
		roundKey: '24fc79ccbf0979e9371ac23c6d68de36',
		end: '8ea2b7ca516745bfeafc49904b496089',
	},
];
