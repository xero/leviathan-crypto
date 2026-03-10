// Argon2id test vectors
//
// Source:
//   RFC 9106 — Argon2 Memory-Hard Function for Password Hashing and
//   Proof-of-Work Applications
//   @see https://www.rfc-editor.org/rfc/rfc9106
//   Section 5.3 — Argon2id test vector
//
// All hex values sourced directly from the RFC.
// Audit status: VERIFIED against RFC 9106 §5.3

export interface Argon2idVector {
	description: string
	password: Uint8Array
	salt: Uint8Array
	secret: Uint8Array
	data: Uint8Array
	params: {
		timeCost: number
		memoryCost: number
		parallelism: number
		hashLength: number
	}
	expected: Uint8Array
}

// RFC 9106 §5.3 — Argon2id (type 0x02) test vector
// password: 32 bytes of 0x01
// salt:     16 bytes of 0x02
// secret:    8 bytes of 0x03
// ad:       12 bytes of 0x04
// params:   t=3, m=32, p=4, tagLength=32
export const argon2idVectors: Argon2idVector[] = [
	{
		description: 'RFC 9106 §5.3 — Argon2id official KAT',
		password: new Uint8Array(32).fill(0x01),
		salt: new Uint8Array(16).fill(0x02),
		secret: new Uint8Array(8).fill(0x03),
		data: new Uint8Array(12).fill(0x04),
		params: {
			timeCost: 3,
			memoryCost: 32,
			parallelism: 4,
			hashLength: 32,
		},
		expected: new Uint8Array([
			0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
			0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
			0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
			0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
		]),
	},
];
