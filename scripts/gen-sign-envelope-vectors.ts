// scripts/gen-sign-envelope-vectors.ts
//
// One-shot generator for test/vectors/sign_envelope.ts. The fixture
// "suite" is an in-test XOR-keyed identity, not a real cryptographic
// primitive; these vectors lock the v3 attached envelope wire-format
// gate. Real-suite KAT vectors live in the per-primitive vector files.
//
// Run as:
//   bun scripts/gen-sign-envelope-vectors.ts
// then commit the regenerated vectors file.
//
// Fixture sk (32 bytes, identical to fixture pk):
//   00 01 02 ... 1f
//
// Fixture sign formula:
//   sig[i] = sk[i mod 32]
//          ^ (msg.length > 0 ? msg[i mod msg.length] : 0)
//          ^ (ctx.length > 0 ? ctx[i mod ctx.length] : 0)
//          ^ (i & 0xff)

import {bytesToHex, hexToBytes} from '../src/ts/utils.js'
import {writeFileSync} from 'node:fs'

const HEADER = `// Sign envelope wire-format vectors
//
// Locks the v3 attached envelope byte layout used by Sign.sign /
// Sign.verify. The signature bytes are produced by an in-test fixture
// suite, not a real cryptographic primitive, so these vectors are
// wire-format gates only; real-suite KAT vectors live in the
// per-primitive integration vector files.
//
// Wire format:
//   [suite_byte: u8][ctx_len: u8][ctx: ctx_len bytes]
//   [payload_len: u32 BE][payload: payload_len bytes]
//   [sig: 64 bytes for the fixture suite]
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

`

const FIXTURE_SK_HEX =
	'000102030405060708090a0b0c0d0e0f' +
	'101112131415161718191a1b1c1d1e1f'

interface Spec {
	description: string
	formatEnum: number
	ctxHex: string
	payloadHex: string
}

const SPECS: Spec[] = [
	{
		description: 'V1, empty ctx, empty payload',
		formatEnum: 0xff,
		ctxHex: '',
		payloadHex: '',
	},
	{
		description: 'V2, 5-byte ctx, 16-byte payload',
		formatEnum: 0xff,
		ctxHex: '1011121314',
		payloadHex: 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
	},
	{
		description: 'V3, 200-byte ctx, 128-byte payload',
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
	},
]

const SK = hexToBytes(FIXTURE_SK_HEX)

function fixtureSig(msg: Uint8Array, ctx: Uint8Array): Uint8Array {
	const out = new Uint8Array(64)
	for (let i = 0; i < 64; i++) {
		let b = SK[i % 32]
		if (msg.length > 0) b ^= msg[i % msg.length]
		if (ctx.length > 0) b ^= ctx[i % ctx.length]
		b ^= i & 0xff
		out[i] = b
	}
	return out
}

function assembleBlob(suiteByte: number, ctx: Uint8Array, payload: Uint8Array, sig: Uint8Array): Uint8Array {
	const out = new Uint8Array(2 + ctx.length + 4 + payload.length + sig.length)
	let pos = 0
	out[pos++] = suiteByte
	out[pos++] = ctx.length
	out.set(ctx, pos); pos += ctx.length
	out[pos++] = (payload.length >>> 24) & 0xff
	out[pos++] = (payload.length >>> 16) & 0xff
	out[pos++] = (payload.length >>>  8) & 0xff
	out[pos++] =  payload.length         & 0xff
	out.set(payload, pos); pos += payload.length
	out.set(sig, pos)
	return out
}

function chunkHex(hex: string, perLine = 32): string {
	const parts: string[] = []
	for (let i = 0; i < hex.length; i += perLine) parts.push(hex.slice(i, i + perLine))
	return parts.map((p, i) => `\t\t\t'${p}'${i === parts.length - 1 ? '' : ' +'}`).join('\n')
}

function recordHexLine(label: string, hex: string): string {
	if (hex.length === 0) return `\t\t${label}: '',`
	if (hex.length <= 32) return `\t\t${label}: '${hex}',`
	return `\t\t${label}:\n${chunkHex(hex)},`
}

const records: string[] = []
for (const spec of SPECS) {
	const ctx = hexToBytes(spec.ctxHex)
	const payload = hexToBytes(spec.payloadHex)
	const sig = fixtureSig(payload, ctx)
	const blob = assembleBlob(spec.formatEnum, ctx, payload, sig)
	records.push(`\t{
\t\tdescription: ${JSON.stringify(spec.description)},
\t\tformatEnum: 0x${spec.formatEnum.toString(16).padStart(2, '0')},
${recordHexLine('ctxHex', spec.ctxHex)}
${recordHexLine('payloadHex', spec.payloadHex)}
${recordHexLine('sigHex', bytesToHex(sig))}
${recordHexLine('expectedBlobHex', bytesToHex(blob))}
\t},`)
}

const file =
	HEADER +
	`export interface SignEnvelopeVector {
\tdescription: string;
\tformatEnum: number;  // suite_byte
\tctxHex: string;      // wire ctx bytes
\tpayloadHex: string;  // payload bytes
\tsigHex: string;      // signature bytes, exactly suite.sigMaxSize
\texpectedBlobHex: string; // full envelope blob
}

// 32-byte fixture sk = pk = [0x00, 0x01, ..., 0x1f].
export const FIXTURE_SK_HEX =
\t'000102030405060708090a0b0c0d0e0f' +
\t'101112131415161718191a1b1c1d1e1f';

export const signEnvelopeVectors: SignEnvelopeVector[] = [
${records.join('\n')}
];
`

writeFileSync('test/vectors/sign_envelope.ts', file)
console.log('Wrote test/vectors/sign_envelope.ts with', SPECS.length, 'records')
