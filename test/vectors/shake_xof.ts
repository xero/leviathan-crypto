// SELF-GENERATED
//
// test/vectors/shake_xof.ts
//
// Multi-squeeze (sequential squeeze() call) test vectors for SHAKE128 and SHAKE256.
//
// All values are slices of existing externally-verified KATs in test/vectors/sha3.ts.
// Verified: node crypto.createHash('shake128'/'shake256', {outputLength:N})
//             .update(Buffer.from(input,'hex')).digest('hex')
//
// Derivation:
//   expectedChunks[0] == KAT[0, squeezes[0])
//   expectedChunks[1] == KAT[squeezes[0], squeezes[0]+squeezes[1])
//   concat(expectedChunks) == single-call squeeze(sum(squeezes))

export interface MultiSqueezeVector {
	description:    string;
	input:          string;    // hex-encoded absorb input
	squeezes:       number[];  // requested byte counts per sequential squeeze() call
	expectedChunks: string[];  // expected hex output per chunk (parallel to squeezes)
}

// ── SHAKE128 (rate = 168 bytes) ──────────────────────────────────────────────

export const shake128MultiSqueezeVectors: MultiSqueezeVector[] = [
	{
		// Slices of: shake128Vectors 'SHAKE128 empty → 200 bytes (multi-block)'
		// squeeze(168) lands exactly on a rate block boundary; squeeze(32) reads into block 2.
		description: 'MS-1: empty, squeeze(168) rate-aligned + squeeze(32) into block 2',
		input: '',
		squeezes: [168, 32],
		expectedChunks: [
			'7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26' +
			'3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2' +
			'35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2' +
			'badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea' +
			'17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef' +
			'aee7eef47cb0fca9',
			'767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f877',
		],
	},
	{
		// Slices of: shake128Vectors 'SHAKE128 empty → 200 bytes (multi-block)'
		// squeeze(100) ends at byte 100 (inside block 1); squeeze(100) crosses
		// the block boundary at byte 168 — primary rate-crossing test.
		description: 'MS-2: empty, squeeze(100) + squeeze(100) crosses rate boundary at byte 168',
		input: '',
		squeezes: [100, 100],
		expectedChunks: [
			'7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26' +
			'3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2' +
			'35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2' +
			'badfd6df',
			'aac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cf' +
			'ad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef4' +
			'7cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b' +
			'8d23f877',
		],
	},
	{
		// Slices of: shake128Vectors 'SHAKE128 "abc" → 200 bytes (multi-block)'
		// Input is "abc" — verifies rate-crossing is input-agnostic.
		description: 'MS-2b: "abc", squeeze(100) + squeeze(100) crosses rate boundary',
		input: '616263',
		squeezes: [100, 100],
		expectedChunks: [
			'5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8' +
			'44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378' +
			'9a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232' +
			'a0294c85',
			'7c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4a0ed296c' +
			'801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49acc29082f' +
			'5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd4818cb00' +
			'6aa5b4cd',
		],
	},
	{
		// Slices of: shake128Vectors 'SHAKE128 empty → 336 bytes (exactly 2× rate blocks)'
		// Each squeeze() produces exactly one full rate block.
		description: 'MS-3: empty, squeeze(168) + squeeze(168) — two full rate blocks',
		input: '',
		squeezes: [168, 168],
		expectedChunks: [
			'7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26' +
			'3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2' +
			'35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2' +
			'badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea' +
			'17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef' +
			'aee7eef47cb0fca9',
			'767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f877' +
			'32ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c922a96188d032675c' +
			'8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c26' +
			'4029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b1de33fd75081f592' +
			'305f2e4526edc09631b10958f464d889f31ba010250fda7f1368ec2967fc84ef' +
			'2ae9aff268e0b170',
		],
	},
	{
		// Slices of: shake128Vectors 'SHAKE128 empty → 200 bytes (multi-block)'
		// Three squeeze calls summing to 200 bytes; chunk[1] crosses the rate boundary.
		description: 'MS-5: empty, squeeze(64) + squeeze(100) + squeeze(36) — three segments',
		input: '',
		squeezes: [64, 100, 36],
		expectedChunks: [
			'7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26' +
			'3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2',
			'35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2' +
			'badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea' +
			'17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef' +
			'aee7eef4',
			'7cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b' +
			'8d23f877',
		],
	},
];

// ── SHAKE256 (rate = 136 bytes) ──────────────────────────────────────────────

export const shake256MultiSqueezeVectors: MultiSqueezeVector[] = [
	{
		// Slices of: shake256Vectors 'SHAKE256 empty → 200 bytes'
		// squeeze(136) lands exactly on a rate block boundary; squeeze(64) reads into block 2.
		description: 'MS-6: empty, squeeze(136) rate-aligned + squeeze(64) into block 2',
		input: '',
		squeezes: [136, 64],
		expectedChunks: [
			'46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f' +
			'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be' +
			'141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853' +
			'349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86' +
			'f3d122109e3b1fdd',
			'943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f614729' +
			'3b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab',
		],
	},
	{
		// Slices of: shake256Vectors 'SHAKE256 empty → 200 bytes'
		// squeeze(100) ends at byte 100 (inside block 1); squeeze(100) crosses
		// the block boundary at byte 136.
		description: 'MS-7: empty, squeeze(100) + squeeze(100) crosses rate boundary at byte 136',
		input: '',
		squeezes: [100, 100],
		expectedChunks: [
			'46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f' +
			'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be' +
			'141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853' +
			'349ec755',
			'46f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d12210' +
			'9e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395' +
			'f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314e' +
			'd9083dab',
		],
	},
];
