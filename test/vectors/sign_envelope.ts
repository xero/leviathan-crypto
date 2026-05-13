// Sign envelope wire-format vectors
//
// Locks the v3 attached envelope byte layout used by Sign.sign /
// Sign.verify. The signature bytes are produced by an in-test fixture
// suite (TASK-B), not a real cryptographic primitive, so these vectors
// are wire-format gates only. Real-suite KAT vectors land in TASK-E /
// the integration vector suite.
//
// Wire format:
//   [suite_byte: u8][ctx_len: u8][ctx: ctx_len bytes]
//   [payload: ...][sig: 64 bytes for the fixture suite]
//
// Fixture sk (32 bytes, identical to fixture pk):
//   00 01 02 ... 1f
//
// Fixture sign formula:
//   sig[i] = sk[i mod 32]
//          ^ (msg.length > 0 ? msg[i mod msg.length] : 0)
//          ^ (ctx.length > 0 ? ctx[i mod ctx.length] : 0)
//          ^ (i & 0xff)
//
// All hex strings are lowercase, no separators.
// Audit status: SELF-GENERATED (wire-format gate).

export interface SignEnvelopeVector {
	description: string;
	formatEnum: number;  // suite_byte
	ctxHex: string;      // wire ctx bytes
	payloadHex: string;  // payload bytes
	sigHex: string;      // signature bytes, exactly suite.sigSize
	expectedBlobHex: string; // full envelope blob
}

// 32-byte fixture sk = pk = [0x00, 0x01, ..., 0x1f].
export const FIXTURE_SK_HEX =
	'000102030405060708090a0b0c0d0e0f' +
	'101112131415161718191a1b1c1d1e1f';

export const signEnvelopeVectors: SignEnvelopeVector[] = [
	{
		description: 'V1, empty ctx, empty payload',
		formatEnum: 0xff,
		ctxHex: '',
		payloadHex: '',
		sigHex:
			'00000000000000000000000000000000' +
			'00000000000000000000000000000000' +
			'20202020202020202020202020202020' +
			'20202020202020202020202020202020',
		expectedBlobHex:
			'ff00' +
			'00000000000000000000000000000000' +
			'00000000000000000000000000000000' +
			'20202020202020202020202020202020' +
			'20202020202020202020202020202020',
	},
	{
		description: 'V2, 5-byte ctx, 16-byte payload',
		formatEnum: 0xff,
		ctxHex: '1011121314',
		payloadHex: 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
		sigHex:
			'b0b0b0b0b0b5b7b5bbbdbababebebabf' +
			'b1b3b1b7b4b4b4b4bcb9bbb9bfb9bebe' +
			'929296939597959398989898989d9f9d' +
			'9395929296969297999b999f9c9c9c9c',
		expectedBlobHex:
			'ff05' +
			'1011121314' +
			'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf' +
			'b0b0b0b0b0b5b7b5bbbdbababebebabf' +
			'b1b3b1b7b4b4b4b4bcb9bbb9bfb9bebe' +
			'929296939597959398989898989d9f9d' +
			'9395929296969297999b999f9c9c9c9c',
	},
	{
		description: 'V3, 200-byte ctx (USER_CTX_MAX), 128-byte payload',
		formatEnum: 0xff,
		ctxHex:
			'000102030405060708090a0b0c0d0e0f' +
			'101112131415161718191a1b1c1d1e1f' +
			'202122232425262728292a2b2c2d2e2f' +
			'303132333435363738393a3b3c3d3e3f' +
			'404142434445464748494a4b4c4d4e4f' +
			'505152535455565758595a5b5c5d5e5f' +
			'606162636465666768696a6b6c6d6e6f' +
			'707172737475767778797a7b7c7d7e7f' +
			'808182838485868788898a8b8c8d8e8f' +
			'909192939495969798999a9b9c9d9e9f' +
			'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf' +
			'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
			'c0c1c2c3c4c5c6c7',
		payloadHex:
			'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0' +
			'efeeedecebeae9e8e7e6e5e4e3e2e1e0' +
			'dfdedddcdbdad9d8d7d6d5d4d3d2d1d0' +
			'cfcecdcccbcac9c8c7c6c5c4c3c2c1c0' +
			'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0' +
			'afaeadacabaaa9a8a7a6a5a4a3a2a1a0' +
			'9f9e9d9c9b9a99989796959493929190' +
			'8f8e8d8c8b8a89888786858483828180',
		sigHex:
			'ffffffffffffffffffffffffffffffff' +
			'ffffffffffffffffffffffffffffffff' +
			'dfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdf' +
			'dfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdf',
		expectedBlobHex:
			'ffc8' +
			'000102030405060708090a0b0c0d0e0f' +
			'101112131415161718191a1b1c1d1e1f' +
			'202122232425262728292a2b2c2d2e2f' +
			'303132333435363738393a3b3c3d3e3f' +
			'404142434445464748494a4b4c4d4e4f' +
			'505152535455565758595a5b5c5d5e5f' +
			'606162636465666768696a6b6c6d6e6f' +
			'707172737475767778797a7b7c7d7e7f' +
			'808182838485868788898a8b8c8d8e8f' +
			'909192939495969798999a9b9c9d9e9f' +
			'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf' +
			'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
			'c0c1c2c3c4c5c6c7' +
			'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0' +
			'efeeedecebeae9e8e7e6e5e4e3e2e1e0' +
			'dfdedddcdbdad9d8d7d6d5d4d3d2d1d0' +
			'cfcecdcccbcac9c8c7c6c5c4c3c2c1c0' +
			'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0' +
			'afaeadacabaaa9a8a7a6a5a4a3a2a1a0' +
			'9f9e9d9c9b9a99989796959493929190' +
			'8f8e8d8c8b8a89888786858483828180' +
			'ffffffffffffffffffffffffffffffff' +
			'ffffffffffffffffffffffffffffffff' +
			'dfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdf' +
			'dfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdf',
	},
];
