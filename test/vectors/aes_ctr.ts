// test/vectors/aes_ctr.ts
//
// AES-CTR mode test vectors.
//
// Sources:
//   NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation:
//   Methods and Techniques (December 2001).
//   @see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
//   Sections covered: Appendix F.5, CTR Example Vectors
//                       F.5.1 CTR-AES128.Encrypt   F.5.2 CTR-AES128.Decrypt
//                       F.5.3 CTR-AES192.Encrypt   F.5.4 CTR-AES192.Decrypt
//                       F.5.5 CTR-AES256.Encrypt   F.5.6 CTR-AES256.Decrypt
//
// `initialCounter` is the full 128-bit "Initial Counter Block" the spec
// uses, not a separately-split nonce/counter. SP 800-38A increments the
// whole block as a 128-bit big-endian integer between blocks (Appendix
// B.1, the Standard Incrementing Function). Test code that wants a split
// representation can take the first 8/12 bytes as the nonce and the last
// 8/4 bytes as the starting counter.
//
// The encrypt and decrypt vectors are the same (key, initialCounter, pt,
// ct) tuples viewed from opposite directions; they are kept as separate
// exports so test files can target encrypt and decrypt code paths
// independently.
//
// All hex strings are lowercase, no separators.
// Audit status: VERIFIED, per-vector citations in each export below.

export interface CtrVector {
	description:    string;
	key:            string;  // hex (32, 48, or 64 chars = 16, 24, or 32 bytes)
	initialCounter: string;  // hex (32 chars = 16 bytes); the full 128-bit
	                         // counter block at the start of the operation
	pt:             string;  // hex (multi-block)
	ct:             string;  // hex (same length as pt)
}

// SP 800-38A §F.5 reuses the §F.2 plaintext blocks and a single shared
// initial counter across all six examples.
//   Block 1: 6bc1bee22e409f96e93d7e117393172a
//   Block 2: ae2d8a571e03ac9c9eb76fac45af8e51
//   Block 3: 30c81c46a35ce411e5fbc1191a0a52ef
//   Block 4: f69f2445df4f9b17ad2b417be66c3710
const SHARED_PT =
	'6bc1bee22e409f96e93d7e117393172a' +
	'ae2d8a571e03ac9c9eb76fac45af8e51' +
	'30c81c46a35ce411e5fbc1191a0a52ef' +
	'f69f2445df4f9b17ad2b417be66c3710';
const SHARED_IC = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';

// ============================================================
// SP 800-38A §F.5, CTR encryption
// ============================================================

export const aesCtrEncryptVectors: CtrVector[] = [
	{
		description: 'SP 800-38A §F.5.1: CTR-AES128.Encrypt',
		key: '2b7e151628aed2a6abf7158809cf4f3c',
		initialCounter: SHARED_IC,
		pt: SHARED_PT,
		ct:
			'874d6191b620e3261bef6864990db6ce' +
			'9806f66b7970fdff8617187bb9fffdff' +
			'5ae4df3edbd5d35e5b4f09020db03eab' +
			'1e031dda2fbe03d1792170a0f3009cee',
	},
	{
		description: 'SP 800-38A §F.5.3: CTR-AES192.Encrypt',
		key: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
		initialCounter: SHARED_IC,
		pt: SHARED_PT,
		ct:
			'1abc932417521ca24f2b0459fe7e6e0b' +
			'090339ec0aa6faefd5ccc2c6f4ce8e94' +
			'1e36b26bd1ebc670d1bd1d665620abf7' +
			'4f78a7f6d29809585a97daec58c6b050',
	},
	{
		description: 'SP 800-38A §F.5.5: CTR-AES256.Encrypt',
		key: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
		initialCounter: SHARED_IC,
		pt: SHARED_PT,
		ct:
			'601ec313775789a5b7a7f504bbf3d228' +
			'f443e3ca4d62b59aca84e990cacaf5c5' +
			'2b0930daa23de94ce87017ba2d84988d' +
			'dfc9c58db67aada613c2dd08457941a6',
	},
];

// ============================================================
// SP 800-38A §F.5, CTR decryption
// ============================================================

export const aesCtrDecryptVectors: CtrVector[] = [
	{
		description: 'SP 800-38A §F.5.2: CTR-AES128.Decrypt',
		key: aesCtrEncryptVectors[0].key,
		initialCounter: aesCtrEncryptVectors[0].initialCounter,
		pt: aesCtrEncryptVectors[0].pt,
		ct: aesCtrEncryptVectors[0].ct,
	},
	{
		description: 'SP 800-38A §F.5.4: CTR-AES192.Decrypt',
		key: aesCtrEncryptVectors[1].key,
		initialCounter: aesCtrEncryptVectors[1].initialCounter,
		pt: aesCtrEncryptVectors[1].pt,
		ct: aesCtrEncryptVectors[1].ct,
	},
	{
		description: 'SP 800-38A §F.5.6: CTR-AES256.Decrypt',
		key: aesCtrEncryptVectors[2].key,
		initialCounter: aesCtrEncryptVectors[2].initialCounter,
		pt: aesCtrEncryptVectors[2].pt,
		ct: aesCtrEncryptVectors[2].ct,
	},
];
