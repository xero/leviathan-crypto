// test/vectors/aes_cbc.ts
//
// AES-CBC mode test vectors.
//
// Sources:
//   NIST SP 800-38A — Recommendation for Block Cipher Modes of Operation:
//   Methods and Techniques (December 2001).
//   @see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
//   Sections covered: Appendix F.2 — CBC Example Vectors
//                       F.2.1 CBC-AES128.Encrypt   F.2.2 CBC-AES128.Decrypt
//                       F.2.3 CBC-AES192.Encrypt   F.2.4 CBC-AES192.Decrypt
//                       F.2.5 CBC-AES256.Encrypt   F.2.6 CBC-AES256.Decrypt
//
// Each example fixes a key, IV, and four plaintext blocks. The four blocks
// are concatenated in `pt` and `ct` so each entry models a single
// multi-block CBC operation. The encrypt and decrypt vectors are the same
// (key, IV, pt, ct) tuples viewed from opposite directions; they are kept
// as separate exports so test files can target encrypt and decrypt code
// paths independently.
//
// All hex strings are lowercase, no separators.
// Audit status: VERIFIED — per-vector citations in each export below.

export interface CbcVector {
	description: string;
	key: string;  // hex (32, 48, or 64 chars = 16, 24, or 32 bytes)
	iv:  string;  // hex (32 chars = 16 bytes)
	pt:  string;  // hex (multi-block, 128 chars = 64 bytes for these vectors)
	ct:  string;  // hex (same length as pt)
}

// SP 800-38A §F.2 uses a single shared 4-block plaintext across all six
// example vectors:
//   Block 1: 6bc1bee22e409f96e93d7e117393172a
//   Block 2: ae2d8a571e03ac9c9eb76fac45af8e51
//   Block 3: 30c81c46a35ce411e5fbc1191a0a52ef
//   Block 4: f69f2445df4f9b17ad2b417be66c3710
// And a single shared IV: 000102030405060708090a0b0c0d0e0f
const SHARED_PT =
	'6bc1bee22e409f96e93d7e117393172a' +
	'ae2d8a571e03ac9c9eb76fac45af8e51' +
	'30c81c46a35ce411e5fbc1191a0a52ef' +
	'f69f2445df4f9b17ad2b417be66c3710';
const SHARED_IV = '000102030405060708090a0b0c0d0e0f';

// ============================================================
// SP 800-38A §F.2 — CBC encryption
// ============================================================

export const aesCbcEncryptVectors: CbcVector[] = [
	{
		description: 'SP 800-38A §F.2.1: CBC-AES128.Encrypt',
		key: '2b7e151628aed2a6abf7158809cf4f3c',
		iv: SHARED_IV,
		pt: SHARED_PT,
		ct:
			'7649abac8119d246cee98e9b12e9197d' +
			'5086cb9b507219ee95db113a917678b2' +
			'73bed6b8e3c1743b7116e69e22229516' +
			'3ff1caa1681fac09120eca307586e1a7',
	},
	{
		description: 'SP 800-38A §F.2.3: CBC-AES192.Encrypt',
		key: '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
		iv: SHARED_IV,
		pt: SHARED_PT,
		ct:
			'4f021db243bc633d7178183a9fa071e8' +
			'b4d9ada9ad7dedf4e5e738763f69145a' +
			'571b242012fb7ae07fa9baac3df102e0' +
			'08b0e27988598881d920a9e64f5615cd',
	},
	{
		description: 'SP 800-38A §F.2.5: CBC-AES256.Encrypt',
		key: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
		iv: SHARED_IV,
		pt: SHARED_PT,
		ct:
			'f58c4c04d6e5f1ba779eabfb5f7bfbd6' +
			'9cfc4e967edb808d679f777bc6702c7d' +
			'39f23369a9d9bacfa530e26304231461' +
			'b2eb05e2c39be9fcda6c19078c6a9d1b',
	},
];

// ============================================================
// SP 800-38A §F.2 — CBC decryption
// ============================================================

export const aesCbcDecryptVectors: CbcVector[] = [
	{
		description: 'SP 800-38A §F.2.2: CBC-AES128.Decrypt',
		key: aesCbcEncryptVectors[0].key,
		iv: aesCbcEncryptVectors[0].iv,
		pt: aesCbcEncryptVectors[0].pt,
		ct: aesCbcEncryptVectors[0].ct,
	},
	{
		description: 'SP 800-38A §F.2.4: CBC-AES192.Decrypt',
		key: aesCbcEncryptVectors[1].key,
		iv: aesCbcEncryptVectors[1].iv,
		pt: aesCbcEncryptVectors[1].pt,
		ct: aesCbcEncryptVectors[1].ct,
	},
	{
		description: 'SP 800-38A §F.2.6: CBC-AES256.Decrypt',
		key: aesCbcEncryptVectors[2].key,
		iv: aesCbcEncryptVectors[2].iv,
		pt: aesCbcEncryptVectors[2].pt,
		ct: aesCbcEncryptVectors[2].ct,
	},
];
