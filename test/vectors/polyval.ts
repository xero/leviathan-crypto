// test/vectors/polyval.ts
//
// POLYVAL primitive test vectors (RFC 8452 §3, §7, Appendix A).
//
// Sources:
//   RFC 8452, Gueron, Langley, Lindell, "AES-GCM-SIV: Nonce
//   Misuse-Resistant Authenticated Encryption", April 2019.
//   @see https://www.rfc-editor.org/rfc/rfc8452.txt
//   Sections covered:
//     §3       , POLYVAL definition and the GHASH bridge identity.
//     §7       , Field Operation Examples (a + b, a · b, dot(a, b)).
//     Appendix A, The Relationship between POLYVAL and GHASH
//                 (mulX_GHASH / mulX_POLYVAL examples and the
//                  POLYVAL(H, X_1, X_2) worked hash trace).
//
// All hex strings are lowercase, no separators. Empty fields are
// encoded as the empty string '' (none appear here).
//
// These vectors target the WASM POLYVAL primitive (not yet
// implemented as of this file's introduction). They exist for
// Phase 4b-impl's gate tests plus the cross-verifier in
// `scripts/verify-vectors`. The §7 algebraic vectors and the
// Appendix A mulX vectors are unit-test-only fixtures: the verifier
// reads them but does not exercise them, since RustCrypto's
// `polyval` crate does not expose `dot()` or `mulX_GHASH` directly.
// The Appendix A POLYVAL(H, X_1, X_2) hash trace is the sole vector
// the verifier runs end-to-end. The full AES-GCM-SIV vector corpus
// in `aes_gcm_siv.ts` transitively exercises POLYVAL multiplication.
//
// Audit status: VERIFIED, every byte transcribed directly from
//   RFC 8452 text, no value derived from any POLYVAL implementation.

// ============================================================
// Interfaces
// ============================================================

/**
 * The §7 Field Operation Examples, algebraic identities in
 * GF(2^128) under the POLYVAL irreducible polynomial. The `dot`
 * value is the operation POLYVAL itself uses on field elements:
 * dot(a, b) = a · b · x^-128.
 */
export interface PolyvalFieldOpsVector {
	description: string;
	a:           string;  // hex, 32 chars
	b:           string;  // hex, 32 chars
	sum:         string;  // a XOR b
	product:     string;  // a · b in POLYVAL field
	dot:         string;  // dot(a, b) = a · b · x^-128
}

/**
 * Appendix A mulX examples. The same input under the two conventions
 * gives different outputs, these vectors lock down both directions
 * of the GHASH ↔ POLYVAL bridge that AES-GCM-SIV implementations
 * rely on (whether they use a reflection wrapper or a native
 * POLYVAL multiplier, mulX is a one-time setup step).
 */
export interface PolyvalMulXVector {
	description:  string;
	input:        string;  // hex, 32 chars
	mulX_ghash:   string;  // input · x in GHASH field, GHASH bit-storage
	mulX_polyval: string;  // input · x in POLYVAL field, POLYVAL bit-storage
}

/**
 * Appendix A POLYVAL hash trace, the worked example showing
 * POLYVAL(H, X_1, X_2) for a specific H and two-block input.
 */
export interface PolyvalHashVector {
	description: string;
	h:           string;     // hash subkey, hex, 32 chars
	blocks:      string[];   // X_1, X_2, ..., X_n; each 32 chars hex
	expected:    string;     // POLYVAL(H, X_1..n), hex, 32 chars
}

// ============================================================
// §7, Field Operation Examples (1 record)
// ============================================================

export const polyvalFieldOps: PolyvalFieldOpsVector = {
	description: 'RFC 8452 §7, Field Operation Examples (a + b, a * b, dot(a, b))',
	a: '66e94bd4ef8a2c3b884cfa59ca342b2e',
	b: 'ff000000000000000000000000000000',
	sum: '99e94bd4ef8a2c3b884cfa59ca342b2e',
	product: '37856175e9dc9df26ebc6d6171aa0ae9',
	dot: 'ebe563401e7e91ea3ad6426b8140c394',
};

// ============================================================
// Appendix A, mulX_GHASH / mulX_POLYVAL examples (2 records)
// ============================================================

export const polyvalMulXVectors: PolyvalMulXVector[] = [
	{
		description: 'RFC 8452 Appendix A, mulX vectors for input 0x010000...0000',
		input: '01000000000000000000000000000000',
		mulX_ghash: '00800000000000000000000000000000',
		mulX_polyval: '02000000000000000000000000000000',
	},
	{
		description: 'RFC 8452 Appendix A, mulX vectors for input 0x9c98c04df9387ded828175a92ba652d8',
		input: '9c98c04df9387ded828175a92ba652d8',
		mulX_ghash: '4e4c6026fc9c3ef6c140bad495d3296c',
		mulX_polyval: '3931819bf271fada0503eb52574ca5f2',
	},
];

// ============================================================
// Appendix A, POLYVAL(H, X_1, X_2) worked hash trace (1 record)
// ============================================================

export const polyvalHashVectors: PolyvalHashVector[] = [
	{
		description: 'RFC 8452 Appendix A, POLYVAL(H, X_1, X_2) worked example',
		h: '25629347589242761d31f826ba4b757b',
		blocks: [
			'4f4f95668c83dfb6401762bb2d01a262',
			'd1a24ddd2721d006bbe45f20d3c9f362',
		],
		expected: 'f7a3b47b846119fae5b7866cf5e5b77e',
	},
];
