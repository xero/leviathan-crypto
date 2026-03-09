// SHA-3 and SHAKE test vectors
//
// Sources:
//   FIPS 202 — SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
//   @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
//   Appendix A — SHA-3 examples
//
// All hex strings are lowercase, no separators.
// Every expected value verified with Node.js crypto.createHash() / Python hashlib.
// Audit status: VERIFIED

// ============================================================
// Interfaces
// ============================================================

export interface HashVector {
	description: string;
	input: string;       // hex-encoded input bytes
	inputText?: string;
	expected: string;    // hex-encoded digest
}

export interface ShakeVector {
	description: string;
	input: string;        // hex-encoded input bytes
	inputText?: string;
	outputLength: number; // requested output in bytes
	expected: string;     // hex-encoded output
}

// ============================================================
// SHA3-256 — FIPS 202 (rate = 136 bytes)
// ============================================================

/** SHA3-256 test vectors from FIPS 202 + rate boundary cases. */
export const sha3_256Vectors: HashVector[] = [
	{
		// Verified: node crypto.createHash('sha3-256').update(Buffer.from('','hex')).digest('hex')
		description: 'FIPS 202 §A.1: empty message',
		input: '',
		inputText: '',
		expected: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
	},
	{
		// FIPS 202 §A.1 — "abc"
		// Verified: node crypto.createHash('sha3-256').update('abc').digest('hex')
		description: 'FIPS 202 §A.1: "abc" (3 bytes)',
		input: '616263',
		inputText: 'abc',
		expected: '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
	},
	{
		// FIPS 202 §A.1 — 448-bit (56-byte) message
		// Verified: node crypto.createHash('sha3-256').update(msg).digest('hex')
		description: 'FIPS 202 §A.1: 448-bit message (56 bytes)',
		input: '6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071',
		inputText: 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
		expected: '41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376',
	},
	{
		// 135 bytes — one short of rate boundary (rate = 136)
		// Verified: python3 hashlib.sha3_256(b'a'*135).hexdigest()
		description: 'boundary: 135 bytes (one short of rate = 136)',
		input: '61'.repeat(135),
		inputText: '"a" repeated 135 times',
		expected: '8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9',
	},
	{
		// 136 bytes — at rate boundary
		// Verified: python3 hashlib.sha3_256(b'a'*136).hexdigest()
		description: 'boundary: 136 bytes (at rate boundary)',
		input: '61'.repeat(136),
		inputText: '"a" repeated 136 times',
		expected: '3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1',
	},
	{
		// 137 bytes — one past rate boundary
		// Verified: python3 hashlib.sha3_256(b'a'*137).hexdigest()
		description: 'boundary: 137 bytes (one past rate boundary)',
		input: '61'.repeat(137),
		inputText: '"a" repeated 137 times',
		expected: 'f8d6846cedd2ccfadf15c5879ef95af724d799eed7391fb1c91f95344e738614',
	},
];

// ============================================================
// SHA3-512 — FIPS 202 (rate = 72 bytes)
// ============================================================

/** SHA3-512 test vectors from FIPS 202 + rate boundary cases. */
export const sha3_512Vectors: HashVector[] = [
	{
		// Verified: node crypto.createHash('sha3-512').update(Buffer.from('','hex')).digest('hex')
		description: 'FIPS 202 §A.4: empty message',
		input: '',
		inputText: '',
		expected:
			'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6' +
			'15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
	},
	{
		// FIPS 202 §A.4 — "abc"
		// Verified: node crypto.createHash('sha3-512').update('abc').digest('hex')
		description: 'FIPS 202 §A.4: "abc" (3 bytes)',
		input: '616263',
		inputText: 'abc',
		expected:
			'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e' +
			'10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
	},
	{
		// 71 bytes — one short of rate boundary (rate = 72)
		// Verified: python3 hashlib.sha3_512(b'a'*71).hexdigest()
		description: 'boundary: 71 bytes (one short of rate = 72)',
		input: '61'.repeat(71),
		inputText: '"a" repeated 71 times',
		expected:
			'070faf98d2a8fddf8ed886408744dc06456096c2e045f26f3c7b010530e6bbb3' +
			'db535a54d636856f4e0e1e982461cb9a7e8e57ff8895cff1619af9f0e486e28c',
	},
	{
		// 72 bytes — at rate boundary
		// Verified: python3 hashlib.sha3_512(b'a'*72).hexdigest()
		description: 'boundary: 72 bytes (at rate boundary)',
		input: '61'.repeat(72),
		inputText: '"a" repeated 72 times',
		expected:
			'a8ae722a78e10cbbc413886c02eb5b369a03f6560084aff566bd597bb7ad8c1c' +
			'cd86e81296852359bf2faddb5153c0a7445722987875e74287adac21adebe952',
	},
	{
		// 73 bytes — one past rate boundary
		// Verified: python3 hashlib.sha3_512(b'a'*73).hexdigest()
		description: 'boundary: 73 bytes (one past rate boundary)',
		input: '61'.repeat(73),
		inputText: '"a" repeated 73 times',
		expected:
			'23e6a8815f8201dbbf6a5463be8dcadb1acea9df5f8998954e59ac9565cf6d29' +
			'b17aa27a5e8b0fc06343db6122d6e544d27583ddc78504d08203217e7e65b6bd',
	},
];

// ============================================================
// SHA3-384 — FIPS 202 (rate = 104 bytes)
// ============================================================

/** SHA3-384 test vectors from FIPS 202 + rate boundary cases. */
export const sha3_384Vectors: HashVector[] = [
	{
		// Verified: node crypto.createHash('sha3-384').update(Buffer.from('','hex')).digest('hex')
		description: 'FIPS 202: empty message',
		input: '',
		inputText: '',
		expected:
			'0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004',
	},
	{
		// FIPS 202 §A — "abc"
		// Verified: node crypto.createHash('sha3-384').update('abc').digest('hex')
		description: 'FIPS 202: "abc" (3 bytes)',
		input: '616263',
		inputText: 'abc',
		expected:
			'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25',
	},
	{
		// 103 bytes — one short of rate boundary (rate = 104)
		// Verified: python3 hashlib.sha3_384(b'a'*103).hexdigest()
		description: 'boundary: 103 bytes (one short of rate = 104)',
		input: '61'.repeat(103),
		inputText: '"a" repeated 103 times',
		expected:
			'af61fb4fd1c6afe80857fcba888318a0a1426635b4509f09707e3787630bdb621655ffa54f5884088ccc000f81436414',
	},
	{
		// 104 bytes — at rate boundary
		// Verified: python3 hashlib.sha3_384(b'a'*104).hexdigest()
		description: 'boundary: 104 bytes (at rate boundary)',
		input: '61'.repeat(104),
		inputText: '"a" repeated 104 times',
		expected:
			'3a4f3b6284e571238884e95655e8c8a60e068e4059a9734abc08823a900d161592860243f00619ae699a29092ed91a16',
	},
];

// ============================================================
// SHA3-224 — FIPS 202 (rate = 144 bytes)
// ============================================================

/** SHA3-224 test vectors from FIPS 202 + rate boundary cases. */
export const sha3_224Vectors: HashVector[] = [
	{
		// Verified: node crypto.createHash('sha3-224').update(Buffer.from('','hex')).digest('hex')
		description: 'FIPS 202: empty message',
		input: '',
		inputText: '',
		expected: '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7',
	},
	{
		// FIPS 202 §A — "abc"
		// Verified: node crypto.createHash('sha3-224').update('abc').digest('hex')
		description: 'FIPS 202: "abc" (3 bytes)',
		input: '616263',
		inputText: 'abc',
		expected: 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf',
	},
	{
		// 143 bytes — one short of rate boundary (rate = 144)
		// Verified: python3 hashlib.sha3_224(b'a'*143).hexdigest()
		description: 'boundary: 143 bytes (one short of rate = 144)',
		input: '61'.repeat(143),
		inputText: '"a" repeated 143 times',
		expected: '73b1b22b54f515f626a6abdde6af25cd4801dc6e9dc7fa3f77e1c122',
	},
	{
		// 144 bytes — at rate boundary
		// Verified: python3 hashlib.sha3_224(b'a'*144).hexdigest()
		description: 'boundary: 144 bytes (at rate boundary)',
		input: '61'.repeat(144),
		inputText: '"a" repeated 144 times',
		expected: 'f9019111996dcf160e284e320fd6d8825cabcd41a5ffdc4c5e9d64b6',
	},
];

// ============================================================
// SHAKE128 — FIPS 202 (rate = 168 bytes)
// ============================================================

/** SHAKE128 test vectors from FIPS 202. */
export const shake128Vectors: ShakeVector[] = [
	{
		// Verified: node crypto.createHash('shake128',{outputLength:32}).update(Buffer.from('','hex')).digest('hex')
		description: 'FIPS 202: empty message, 32-byte output',
		input: '',
		inputText: '',
		outputLength: 32,
		expected: '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
	},
	{
		// Verified: node crypto.createHash('shake128',{outputLength:32}).update('abc').digest('hex')
		description: 'FIPS 202: "abc", 32-byte output',
		input: '616263',
		inputText: 'abc',
		outputLength: 32,
		expected: '5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8',
	},
	{
		// Verified: node crypto.createHash('shake128',{outputLength:64}).update(Buffer.from('','hex')).digest('hex')
		description: 'FIPS 202: empty message, 64-byte output',
		input: '',
		inputText: '',
		outputLength: 64,
		expected:
			'7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26' +
			'3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2',
	},
	{
		// 167 bytes — one short of rate boundary (rate = 168)
		// Verified: python3 hashlib.shake_128(b'a'*167).hexdigest(32)
		description: 'boundary: 167 bytes (one short of rate = 168), 32-byte output',
		input: '61'.repeat(167),
		inputText: '"a" repeated 167 times',
		outputLength: 32,
		expected: '4f5c6c53ae8190a8ff8a55b2125d28703052d10278570960c2066a905d916c34',
	},
	{
		// 168 bytes — at rate boundary
		// Verified: python3 hashlib.shake_128(b'a'*168).hexdigest(32)
		description: 'boundary: 168 bytes (at rate boundary), 32-byte output',
		input: '61'.repeat(168),
		inputText: '"a" repeated 168 times',
		outputLength: 32,
		expected: 'c22e11586c22b713bde373fce93314d76829de2c21d940a28eb659b8dec953a2',
	},
];

// ============================================================
// SHAKE256 — FIPS 202 (rate = 136 bytes)
// ============================================================

/** SHAKE256 test vectors from FIPS 202. */
export const shake256Vectors: ShakeVector[] = [
	{
		// Verified: node crypto.createHash('shake256',{outputLength:32}).update(Buffer.from('','hex')).digest('hex')
		description: 'FIPS 202: empty message, 32-byte output',
		input: '',
		inputText: '',
		outputLength: 32,
		expected: '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f',
	},
	{
		// Verified: node crypto.createHash('shake256',{outputLength:64}).update('abc').digest('hex')
		description: 'FIPS 202: "abc", 64-byte output',
		input: '616263',
		inputText: 'abc',
		outputLength: 64,
		expected:
			'483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739' +
			'd5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4',
	},
	{
		// 135 bytes — one short of rate boundary (rate = 136)
		// Verified: python3 hashlib.shake_256(b'a'*135).hexdigest(32)
		description: 'boundary: 135 bytes (one short of rate = 136), 32-byte output',
		input: '61'.repeat(135),
		inputText: '"a" repeated 135 times',
		outputLength: 32,
		expected: '55b991ece1e567b6e7c2c714444dd201cd51f4f3832d08e1d26bebc63e07a3d7',
	},
	{
		// 136 bytes — at rate boundary
		// Verified: python3 hashlib.shake_256(b'a'*136).hexdigest(32)
		description: 'boundary: 136 bytes (at rate boundary), 32-byte output',
		input: '61'.repeat(136),
		inputText: '"a" repeated 136 times',
		outputLength: 32,
		expected: '8fcc5a08f0a1f6827c9cf64ee8d16e0443106359ca6c8efd230759256f44996a',
	},
];
