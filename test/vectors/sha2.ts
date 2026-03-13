// SHA-2 and HMAC-SHA2 test vectors
//
// Sources:
//   FIPS 180-4 — Secure Hash Standard (SHS), August 2015
//   @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
//   Appendix B — SHA-256 examples (B.1, B.2, B.3)
//   Appendix C — SHA-512 examples (C.1, C.2, C.3)
//   Appendix D — SHA-384 examples (D.1, D.2, D.3)
//
//   RFC 4231 — Identifiers and Test Vectors for HMAC-SHA-224/256/384/512
//   @see https://www.rfc-editor.org/rfc/rfc4231
//   Sections covered: §4.2 (TC1), §4.3 (TC2), §4.7 (TC6)
//
// All hex strings are lowercase, no separators.
// Every expected value verified with openssl / Python hashlib / Python hmac.
// Audit status: VERIFIED

// ============================================================
// Interfaces
// ============================================================

export interface HashVector {
	description: string;
	input: string;       // hex-encoded input bytes (empty string = empty message)
	inputText?: string;  // human-readable if ASCII (documentation only)
	expected: string;    // hex-encoded digest
}

export interface HmacVector {
	description: string;
	key: string;         // hex-encoded key bytes
	input: string;       // hex-encoded message bytes
	inputText?: string;
	expected: string;    // hex-encoded MAC tag
}

export interface HkdfVector {
	description: string;
	ikm: string;          // hex-encoded input keying material
	salt: string;         // hex-encoded salt (empty string = no salt)
	info: string;         // hex-encoded context/info (empty string = no info)
	length: number;       // output length in bytes
	prk?: string;         // hex-encoded PRK (extract output, if provided)
	okm: string;          // hex-encoded output keying material
}

// ============================================================
// SHA-256 — FIPS 180-4 Appendix B
// ============================================================

/** SHA-256 test vectors from FIPS 180-4 + boundary cases. */
export const sha256Vectors: HashVector[] = [
	{
		// Verified: echo -n "" | openssl sha256
		description: 'empty message',
		input: '',
		inputText: '',
		expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
	},
	{
		// FIPS 180-4 Appendix B.1 — "abc" (24-bit message)
		description: 'FIPS 180-4 §B.1: "abc" (3 bytes)',
		input: '616263',
		inputText: 'abc',
		expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
	},
	{
		// FIPS 180-4 Appendix B.2 — 448-bit (56-byte) message
		description: 'FIPS 180-4 §B.2: 448-bit message (56 bytes)',
		input: '6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071',
		inputText: 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
		expected: '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
	},
	{
		// FIPS 180-4 Appendix B.3 — "a" × 1,000,000
		// Verified: python3 hashlib.sha256(b'a'*1000000).hexdigest()
		description: 'FIPS 180-4 §B.3: "a" × 1,000,000',
		input: '61'.repeat(1000000),
		inputText: '"a" repeated 1,000,000 times',
		expected: 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
	},
	{
		// 55 bytes — one byte short of padding boundary (55 + 1 + 8 = 64)
		// Verified: python3 hashlib.sha256(b'a'*55).hexdigest()
		description: 'boundary: 55 bytes (one short of padding boundary)',
		input: '61'.repeat(55),
		inputText: '"a" repeated 55 times',
		expected: '9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318',
	},
	{
		// 56 bytes — at padding boundary, forces second block
		// Verified: python3 hashlib.sha256(b'a'*56).hexdigest()
		description: 'boundary: 56 bytes (at padding boundary — forces second block)',
		input: '61'.repeat(56),
		inputText: '"a" repeated 56 times',
		expected: 'b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a',
	},
	{
		// 64 bytes — one full SHA-256 block
		// Verified: python3 hashlib.sha256(b'a'*64).hexdigest()
		description: 'boundary: 64 bytes (one full block)',
		input: '61'.repeat(64),
		inputText: '"a" repeated 64 times',
		expected: 'ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb',
	},
];

// ============================================================
// SHA-512 — FIPS 180-4 Appendix C
// ============================================================

/** SHA-512 test vectors from FIPS 180-4 + boundary cases. */
export const sha512Vectors: HashVector[] = [
	{
		// Verified: echo -n "" | openssl sha512
		description: 'empty message',
		input: '',
		inputText: '',
		expected:
			'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce' +
			'47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
	},
	{
		// FIPS 180-4 Appendix C.1 — "abc"
		description: 'FIPS 180-4 §C.1: "abc" (3 bytes)',
		input: '616263',
		inputText: 'abc',
		expected:
			'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
			'2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
	},
	{
		// FIPS 180-4 Appendix C.2 — 896-bit (112-byte) message
		description: 'FIPS 180-4 §C.2: 896-bit message (112 bytes)',
		input:
			'61626364656667686263646566676869636465666768696a6465666768696a6b' +
			'65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e' +
			'6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f7071' +
			'72736d6e6f70717273746e6f707172737475',
		inputText: 'abcdefghbcdefghi...nopqrstu (112 bytes)',
		expected:
			'8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018' +
			'501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909',
	},
	{
		// FIPS 180-4 Appendix C.3 — "a" × 1,000,000
		// Verified: python3 hashlib.sha512(b'a'*1000000).hexdigest()
		description: 'FIPS 180-4 §C.3: "a" × 1,000,000',
		input: '61'.repeat(1000000),
		inputText: '"a" repeated 1,000,000 times',
		expected:
			'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb' +
			'de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b',
	},
	{
		// 111 bytes — one short of SHA-512 padding boundary (111 + 1 + 16 = 128)
		// Verified: python3 hashlib.sha512(b'a'*111).hexdigest()
		description: 'boundary: 111 bytes (one short of padding boundary)',
		input: '61'.repeat(111),
		inputText: '"a" repeated 111 times',
		expected:
			'fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2',
	},
	{
		// 112 bytes — at padding boundary, forces second block
		// Verified: python3 hashlib.sha512(b'a'*112).hexdigest()
		description: 'boundary: 112 bytes (at padding boundary — forces second block)',
		input: '61'.repeat(112),
		inputText: '"a" repeated 112 times',
		expected:
			'c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca',
	},
	{
		// 128 bytes — one full SHA-512 block
		// Verified: python3 hashlib.sha512(b'a'*128).hexdigest()
		description: 'boundary: 128 bytes (one full block)',
		input: '61'.repeat(128),
		inputText: '"a" repeated 128 times',
		expected:
			'b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321',
	},
];

// ============================================================
// SHA-384 — FIPS 180-4 Appendix D
// ============================================================

/** SHA-384 test vectors from FIPS 180-4. */
export const sha384Vectors: HashVector[] = [
	{
		// Verified: echo -n "" | openssl sha384
		description: 'empty message',
		input: '',
		inputText: '',
		expected:
			'38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
	},
	{
		// FIPS 180-4 Appendix D.1 — "abc"
		description: 'FIPS 180-4 §D.1: "abc" (3 bytes)',
		input: '616263',
		inputText: 'abc',
		expected:
			'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
	},
	{
		// FIPS 180-4 Appendix D.2 — 896-bit (112-byte) message
		description: 'FIPS 180-4 §D.2: 896-bit message (112 bytes)',
		input:
			'61626364656667686263646566676869636465666768696a6465666768696a6b' +
			'65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e' +
			'6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f7071' +
			'72736d6e6f70717273746e6f707172737475',
		inputText: 'abcdefghbcdefghi...nopqrstu (112 bytes)',
		expected:
			'09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039',
	},
];

// ============================================================
// HMAC-SHA256 — RFC 4231
// ============================================================

/** HMAC-SHA256 test vectors from RFC 4231. */
export const hmacSha256Vectors: HmacVector[] = [
	{
		// RFC 4231 §4.2 (TC1) — 20-byte key
		// Verified: python3 hmac.new(key, b'Hi There', hashlib.sha256).hexdigest()
		description: 'RFC 4231 §4.2 (TC1): 20-byte key, "Hi There"',
		key: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
		input: '4869205468657265',
		inputText: 'Hi There',
		expected: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
	},
	{
		// RFC 4231 §4.3 (TC2) — "Jefe" key
		// Verified: python3 hmac.new(b'Jefe', msg, hashlib.sha256).hexdigest()
		description: 'RFC 4231 §4.3 (TC2): "Jefe" key',
		key: '4a656665',
		input: '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
		inputText: 'what do ya want for nothing?',
		expected: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
	},
	{
		// RFC 4231 §4.7 (TC6) — 131-byte key (exceeds 64-byte SHA-256 block size)
		// Key must be pre-hashed with SHA-256 per RFC 2104 §3
		// Verified: python3 hmac.new(b'\xaa'*131, msg, hashlib.sha256).hexdigest()
		description: 'RFC 4231 §4.7 (TC6): 131-byte key (exceeds block size, key pre-hashed)',
		key: 'aa'.repeat(131),
		input: '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374',
		inputText: 'Test Using Larger Than Block-Size Key - Hash Key First',
		expected: '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
	},
];

// ============================================================
// HMAC-SHA512 — RFC 4231
// ============================================================

/** HMAC-SHA512 test vectors from RFC 4231. */
export const hmacSha512Vectors: HmacVector[] = [
	{
		// RFC 4231 §4.2 (TC1)
		// Verified: python3 hmac.new(key, b'Hi There', hashlib.sha512).hexdigest()
		description: 'RFC 4231 §4.2 (TC1): 20-byte key, "Hi There"',
		key: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
		input: '4869205468657265',
		inputText: 'Hi There',
		expected:
			'87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde' +
			'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
	},
	{
		// RFC 4231 §4.3 (TC2)
		// Verified: python3 hmac.new(b'Jefe', msg, hashlib.sha512).hexdigest()
		description: 'RFC 4231 §4.3 (TC2): "Jefe" key',
		key: '4a656665',
		input: '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
		inputText: 'what do ya want for nothing?',
		expected:
			'164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554' +
			'9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
	},
	{
		// RFC 4231 §4.7 (TC6) — 131-byte key (exceeds 128-byte HMAC-SHA512 block size)
		// Key must be pre-hashed with SHA-512 per RFC 2104 §3
		// Verified: python3 hmac.new(b'\xaa'*131, msg, hashlib.sha512).hexdigest()
		description: 'RFC 4231 §4.7 (TC6): 131-byte key (exceeds block size, key pre-hashed)',
		key: 'aa'.repeat(131),
		input: '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374',
		inputText: 'Test Using Larger Than Block-Size Key - Hash Key First',
		expected:
			'80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352' +
			'6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598',
	},
];

// ============================================================
// HMAC-SHA384 — RFC 4231
// ============================================================

/** HMAC-SHA384 test vectors from RFC 4231. */
export const hmacSha384Vectors: HmacVector[] = [
	{
		// RFC 4231 §4.2 (TC1)
		// Verified: python3 hmac.new(key, b'Hi There', hashlib.sha384).hexdigest()
		description: 'RFC 4231 §4.2 (TC1): 20-byte key, "Hi There"',
		key: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
		input: '4869205468657265',
		inputText: 'Hi There',
		expected:
			'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
	},
	{
		// RFC 4231 §4.3 (TC2)
		// Verified: python3 hmac.new(b'Jefe', msg, hashlib.sha384).hexdigest()
		description: 'RFC 4231 §4.3 (TC2): "Jefe" key',
		key: '4a656665',
		input: '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
		inputText: 'what do ya want for nothing?',
		expected:
			'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649',
	},
	{
		// RFC 4231 §4.7 (TC6) — 131-byte key (exceeds 128-byte HMAC-SHA384 block size)
		// Key must be pre-hashed with SHA-384 per RFC 2104 §3
		// Verified: python3 hmac.new(b'\xaa'*131, msg, hashlib.sha384).hexdigest()
		description: 'RFC 4231 §4.7 (TC6): 131-byte key (exceeds block size, key pre-hashed)',
		key: 'aa'.repeat(131),
		input: '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374',
		inputText: 'Test Using Larger Than Block-Size Key - Hash Key First',
		expected:
			'4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952',
	},
];

// ============================================================
// HKDF-SHA256 — RFC 5869 Appendix A
// ============================================================

/** HKDF-SHA256 test vectors from RFC 5869 Appendix A. */
export const hkdfSha256Vectors: HkdfVector[] = [
	{
		// RFC 5869 Appendix A.1
		description: 'RFC 5869 §A.1: basic test case',
		ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
		salt: '000102030405060708090a0b0c',
		info: 'f0f1f2f3f4f5f6f7f8f9',
		length: 42,
		prk: '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
		okm: '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
	},
	{
		// RFC 5869 Appendix A.2
		description: 'RFC 5869 §A.2: longer inputs',
		ikm: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
			'202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' +
			'404142434445464748494a4b4c4d4e4f',
		salt: '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' +
			'808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' +
			'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
		info: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
			'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
			'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
		length: 82,
		okm: 'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c' +
			'59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71' +
			'cc30c58179ec3e87c14c01d5c1f3434f1d87',
	},
	{
		// RFC 5869 Appendix A.3 — no salt, no info
		description: 'RFC 5869 §A.3: no salt, no info',
		ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
		salt: '',
		info: '',
		length: 42,
		prk: '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
		okm: '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
	},
];

// ============================================================
// HKDF-SHA512 — verified against Node.js crypto.hkdfSync
// ============================================================

/** HKDF-SHA512 test vectors. Same inputs as RFC 5869 A.1–A.3, SHA-512 output. */
export const hkdfSha512Vectors: HkdfVector[] = [
	{
		// Verified: node -e "require('crypto').hkdfSync('sha512', ...)"
		description: 'S512-1: same inputs as RFC A.1, L=42',
		ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
		salt: '000102030405060708090a0b0c',
		info: 'f0f1f2f3f4f5f6f7f8f9',
		length: 42,
		okm: '832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb',
	},
	{
		// Verified: node -e "require('crypto').hkdfSync('sha512', ...)"
		description: 'S512-2: same inputs as RFC A.2, L=82',
		ikm: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
			'202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' +
			'404142434445464748494a4b4c4d4e4f',
		salt: '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' +
			'808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' +
			'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
		info: 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
			'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
			'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
		length: 82,
		okm: 'ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1' +
			'b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235' +
			'f6a2056ce3af1de44d572097a8505d9e7a93',
	},
	{
		// Verified: node -e "require('crypto').hkdfSync('sha512', ...)"
		description: 'S512-3: no salt, no info, L=42',
		ikm: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
		salt: '',
		info: '',
		length: 42,
		okm: 'f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac',
	},
];

// ── leviathan cross-check vectors ───────────────────────────────────────────
// Values verified against Node.js crypto (createHash / createHmac).
// Inputs are the four standard cross-check inputs shared across all SHA-2 tests.

export interface CrossCheckVector {
	description: string;
	input: string;   // hex-encoded input
	expected: string;
}

export interface HmacCrossCheckVector {
	description: string;
	key: string;     // hex-encoded key
	msg: string;     // hex-encoded message
	expected: string;
}

// Verified: node crypto.createHash('sha256').update(Buffer.from(input,'hex')).digest('hex')
export const sha256CrossCheck: CrossCheckVector[] = [
	{ description: 'empty',   input: '',              expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
	{ description: '"abc"',   input: '616263',         expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' },
	{ description: 'fox',     input: '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67', expected: 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592' },
	{ description: '"a"×200', input: '61'.repeat(200), expected: 'c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5' },
];

// Verified: node crypto.createHash('sha512').update(Buffer.from(input,'hex')).digest('hex')
export const sha512CrossCheck: CrossCheckVector[] = [
	{ description: 'empty',   input: '',              expected: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e' },
	{ description: '"abc"',   input: '616263',         expected: 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f' },
	{ description: 'fox',     input: '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67', expected: '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6' },
	{ description: '"a"×200', input: '61'.repeat(200), expected: '4b11459c33f52a22ee8236782714c150a3b2c60994e9acee17fe68947a3e6789f31e7668394592da7bef827cddca88c4e6f86e4df7ed1ae6cba71f3e98faee9f' },
];

// Verified: node crypto.createHash('sha384').update(Buffer.from(input,'hex')).digest('hex')
export const sha384CrossCheck: CrossCheckVector[] = [
	{ description: 'empty',  input: '',              expected: '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b' },
	{ description: '"abc"',  input: '616263',         expected: 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7' },
	{ description: 'fox',    input: '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67', expected: 'ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1' },
];

// key: 0x42 × 32  msg: UTF-8 'leviathan cross-check message'
// Verified: node crypto.createHmac(alg, Buffer.from(key,'hex')).update(Buffer.from(msg,'hex')).digest('hex')
export const hmacCrossCheck: HmacCrossCheckVector[] = [
	{
		description: 'HMAC-SHA256 leviathan cross-check',
		key: '42'.repeat(32),
		msg: '6c657669617468616e2063726f73732d636865636b206d657373616765',
		expected: 'b3e42787e890590efbfb8c8fb3a905b655bfa6b0e0e68d4c0883e861203b58fb',
	},
	{
		description: 'HMAC-SHA512 leviathan cross-check',
		key: '42'.repeat(32),
		msg: '6c657669617468616e2063726f73732d636865636b206d657373616765',
		expected: 'c024d889341c1c341f1b5e44bcdd82556e263e2d757dcba4d91550d8872594eced5fcab776bb9178e96c62a9933a01ab13e4b785877735e9c890bf8803f52cb0',
	},
	{
		description: 'HMAC-SHA384 leviathan cross-check',
		key: '42'.repeat(32),
		msg: '6c657669617468616e2063726f73732d636865636b206d657373616765',
		expected: 'e63f7b89cc4023b166b44377be5fdf171993c5f2d480b79b3ae015a002e23992cd75cc979706a922d2104b0690318d18',
	},
];
