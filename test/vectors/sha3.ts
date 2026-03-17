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
	{
		// Verified: node crypto.createHash('shake128',{outputLength:200}).update(Buffer.from('','hex')).digest('hex')
		// Cross-checked: Python hashlib.shake_128(b'').hexdigest(200)
		description: 'SHAKE128 empty → 200 bytes (multi-block)',
		input: '',
		outputLength: 200,
		expected:
			'7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26' +
			'3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2' +
			'35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2' +
			'badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea' +
			'17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef' +
			'aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d' +
			'ef58538b8d23f877',
	},
	{
		// Verified: node crypto.createHash('shake128',{outputLength:336}).update(Buffer.from('','hex')).digest('hex')
		description: 'SHAKE128 empty → 336 bytes (exactly 2× rate blocks)',
		input: '',
		outputLength: 336,
		expected:
			'7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26' +
			'3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2' +
			'35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2' +
			'badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea' +
			'17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef' +
			'aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d' +
			'ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9' +
			'22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619' +
			'f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b' +
			'1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f' +
			'1368ec2967fc84ef2ae9aff268e0b170',
	},
	{
		// Verified: node crypto.createHash('shake128',{outputLength:400}).update(Buffer.from('','hex')).digest('hex')
		description: 'SHAKE128 empty → 400 bytes (multi-block, crosses 2nd boundary)',
		input: '',
		outputLength: 400,
		expected:
			'7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26' +
			'3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2' +
			'35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2' +
			'badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea' +
			'17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef' +
			'aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d' +
			'ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9' +
			'22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619' +
			'f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b' +
			'1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f' +
			'1368ec2967fc84ef2ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06' +
			'bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9' +
			'd83c6d5e8ce803aa62b8d654db53d09b',
	},
	{
		// Verified: node crypto.createHash('shake128',{outputLength:200}).update(Buffer.from('abc')).digest('hex')
		description: 'SHAKE128 "abc" → 200 bytes (multi-block)',
		input: '616263',
		inputText: 'abc',
		outputLength: 200,
		expected:
			'5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8' +
			'44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378' +
			'9a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232' +
			'a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4' +
			'a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49a' +
			'cc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd' +
			'4818cb006aa5b4cd',
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
	{
		// Verified: node crypto.createHash('shake256',{outputLength:200}).update(Buffer.from('','hex')).digest('hex')
		// Cross-checked: Python hashlib.shake_256(b'').hexdigest(200)
		description: 'SHAKE256 empty → 200 bytes (multi-block)',
		input: '',
		outputLength: 200,
		expected:
			'46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f' +
			'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be' +
			'141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853' +
			'349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86' +
			'f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6' +
			'77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c' +
			'aaae314ed9083dab',
	},
	{
		// Verified: node crypto.createHash('shake256',{outputLength:272}).update(Buffer.from('','hex')).digest('hex')
		description: 'SHAKE256 empty → 272 bytes (exactly 2× rate blocks)',
		input: '',
		outputLength: 272,
		expected:
			'46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f' +
			'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be' +
			'141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853' +
			'349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86' +
			'f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6' +
			'77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c' +
			'aaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea2' +
			'03bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f' +
			'5a1aaa96d313eacc890936c173cdcd0f',
	},
	{
		// Verified: node crypto.createHash('shake256',{outputLength:300}).update(Buffer.from('','hex')).digest('hex')
		description: 'SHAKE256 empty → 300 bytes (multi-block, crosses 2nd boundary)',
		input: '',
		outputLength: 300,
		expected:
			'46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f' +
			'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be' +
			'141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853' +
			'349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86' +
			'f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6' +
			'77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c' +
			'aaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea2' +
			'03bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f' +
			'5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390b' +
			'f9a66d1368b208e21f7c10d0',
	},
	{
		// Verified: node crypto.createHash('shake256',{outputLength:200}).update(Buffer.from('abc')).digest('hex')
		description: 'SHAKE256 "abc" → 200 bytes (multi-block)',
		input: '616263',
		inputText: 'abc',
		outputLength: 200,
		expected:
			'483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739' +
			'd5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4' +
			'1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78' +
			'dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334' +
			'e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b3' +
			'3a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b67' +
			'7513771af6bfe119',
	},
];

// ── leviathan cross-check vectors ───────────────────────────────────────────
// Values verified against Node.js crypto and the leviathan TypeScript reference.

export interface CrossCheckVector {
	description: string;
	input: string;   // hex-encoded input
	expected: string;
}

// Verified: node crypto.createHash('sha3-256').update(Buffer.from(input,'hex')).digest('hex')
export const sha3_256CrossCheck: CrossCheckVector[] = [
	{ description: 'empty',   input: '',              expected: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a' },
	{ description: '"abc"',   input: '616263',         expected: '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532' },
	{ description: 'fox',     input: '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67', expected: '69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04' },
	{ description: '"a"×200', input: '61'.repeat(200), expected: 'cce34485baf2bf2aca99b94833892a4f52896d3d153f7b840cc4f9fe695f1387' },
];

// Verified: node crypto.createHash('sha3-512').update(Buffer.from(input,'hex')).digest('hex')
export const sha3_512CrossCheck: CrossCheckVector[] = [
	{ description: 'empty',   input: '',              expected: 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26' },
	{ description: '"abc"',   input: '616263',         expected: 'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0' },
	{ description: 'fox',     input: '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67', expected: '01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450' },
	{ description: '"a"×200', input: '61'.repeat(200), expected: 'eae6c85c6904f11075de9f9d5e1064371d000510fa3d2d79d40cf9be34892fb01859d0a0234e138bcb0ad5c84f6c0dca226a414b0c9a2897cb695f5185fe36ec' },
];

// Verified: node crypto.createHash('sha3-384').update(Buffer.from(input,'hex')).digest('hex')
export const sha3_384CrossCheck: CrossCheckVector[] = [
	{ description: 'empty',   input: '',              expected: '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004' },
	{ description: '"abc"',   input: '616263',         expected: 'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25' },
	{ description: 'fox',     input: '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67', expected: '7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41' },
	{ description: '"a"×200', input: '61'.repeat(200), expected: 'f97756776c1874724c94a8008f7f155553b4bf00fbf8fbeac246624ad59c258a3c0977d9f2543d7cbd75b9ac8fdc0d40' },
];

// Verified: node crypto.createHash('sha3-224').update(Buffer.from(input,'hex')).digest('hex')
export const sha3_224CrossCheck: CrossCheckVector[] = [
	{ description: 'empty', input: '',       expected: '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7' },
	{ description: '"abc"', input: '616263', expected: 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf' },
];
