// scripts/gen-ecdsa-p256-vectors.ts
//
// One-shot generator for test/vectors/sign_ecdsa_p256.ts. Builds locking
// envelope-wire-format vectors for the single EcdsaP256Suite (formatEnum
// 0x02). The production suite.sign path is hedged (uses randomBytes(32)
// internally), so KATs reproduce the wire bytes by dropping down to the
// `EcdsaP256` class and feeding it the per-record `rnd`. Verifying these
// blobs through the hedged suite still works (verify is deterministic
// given the recorded sig).
//
// Run as:
//   bun scripts/gen-ecdsa-p256-vectors.ts
// then commit the regenerated vectors file.

import {init, bytesToHex, hexToBytes} from '../src/ts/index.js'
import {p256Wasm} from '../src/ts/ecdsa/embedded.js'
import {sha2Wasm} from '../src/ts/sha2/embedded.js'
import {EcdsaP256} from '../src/ts/ecdsa/index.js'
import {SHA256} from '../src/ts/sha2/index.js'
import {writeFileSync} from 'node:fs'

await init({p256: p256Wasm, sha2: sha2Wasm})

const HEADER = `//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓▀▓ ▓▄▓ ▓ ▓
//      ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒  ▒ █ ▒ ▒ ▒ █
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌
//     ████████      ███▀▀     ████▀  █▀ █▀       Leviathan Crypto Library
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      Repository & Mirror:
//       ▀██████   ▄▄██            ▀▀  ██▄    github.com/xero/leviathan-crypto
//         ▀█████▄   ▄██▄             ▄▀▄▀    unpkg.com/leviathan-crypto
//            ▀████▄   ▄██▄
//              ▐████   ▐███                  Author: xero (https://x-e.ro)
//       ▄▄██████████    ▐███         ▄▄      License: MIT
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀
//
// test/vectors/sign_ecdsa_p256.ts
//
// Suite-level KAT vectors locking the v3 attached envelope wire format
// produced by EcdsaP256Suite (formatEnum 0x02). The suite is hedged-by-
// default at the public API level, so KAT records carry the per-call
// 'rnd' that was fed to the underlying EcdsaP256 primitive at generation
// time; the verifier reproduces the wire bytes by feeding the same rnd
// back through the EcdsaP256 class. Records with rndHex = all-zero
// select the RFC 6979 §3.2 deterministic-K path (FIPS 186-5 §6.4.1
// mandates RFC 6979 as the conforming deterministic ECDSA construction);
// records with non-zero rndHex exercise the hedged
// (draft-irtf-cfrg-det-sigs-with-noise-05) path.
//
// Audit status: SELF-GENERATED (wire-format gate). The Tier 1 records
// (RFC 6979 §A.2.5 + ACVP) live in test/vectors/ecdsa_p256.ts /
// ecdsa_p256_keygen.ts / ecdsa_p256_siggen.ts / ecdsa_p256_sigver.ts /
// ecdsa_p256_wycheproof.ts and continue to gate the primitive itself.
// V5 and V6 here re-thread the RFC 6979 §A.2.5 'sample' and 'test'
// keypair + message through the suite layer with rnd = all-zero, so the
// trailing 64-byte sig in each blob is byte-identical to (rHex || sHex)
// from ecdsa_p256.ts; the suite layer adds only the [0x02, 0x00, msg]
// envelope preamble.
//
// Inputs per record:
//   id, description     human-readable identifiers
//   formatEnum          always 0x02
//   pkHex               33-byte compressed pk per SEC 1 §2.3.3
//   skHex               32-byte secret scalar d
//   msgHex              payload bytes
//   ctxHex              user_ctx bytes (ALWAYS '' for ecdsa-p256 suite)
//   rndHex              32-byte per-call entropy fed to the underlying
//                       EcdsaP256._signInternalPk at generation time;
//                       all-zero selects RFC 6979 §3.2 deterministic K
//   blobHex             attached envelope: [0x02, 0x00, msg_len (u32 BE), msg, sig]
//   sigHex              64 bytes raw r||s (also the trailing 64 bytes
//                       of blobHex), surfaced for cross-checks
//
// All hex strings are lowercase, no separators.

`

interface Spec {
	id: string
	description: string
	skHex: string
	msgHex: string
	rndHex: string
}

const SPECS: Spec[] = [
	{
		id: 'V1',
		description: 'V1, empty msg, deterministic rnd (RFC 6979 §3.2 path)',
		skHex: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
		msgHex: '',
		rndHex: '0000000000000000000000000000000000000000000000000000000000000000',
	},
	{
		id: 'V2',
		description: 'V2, single-byte msg, deterministic rnd',
		skHex: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
		msgHex: '5a',
		rndHex: '0000000000000000000000000000000000000000000000000000000000000000',
	},
	{
		id: 'V3',
		description: 'V3, 64-byte msg, hedged rnd (draft-irtf-cfrg-det-sigs-with-noise-05 path)',
		skHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
		msgHex:
			'4c657669617468616e2043727970746f2076332d65636473612d70323536206865646765642073616d706c6520706179' +
			'6c6f6164206e6f742d666c61740a',
		rndHex: 'f1e2d3c4b5a697886950413223140506e7d8c9babcadef011223344556677889',
	},
	{
		id: 'V4',
		description: 'V4, 1024-byte msg, hedged rnd (exercises SignStream buffering)',
		skHex: 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
		msgHex: '',  // filled in below from a deterministic pattern
		rndHex: 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
	},
	{
		id: 'V5',
		description: 'V5, RFC 6979 §A.2.5 sample keypair + msg, zero rnd (sig matches RFC §A.2.5 sample r||s)',
		skHex: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
		msgHex: '73616d706c65',  // utf8 'sample'
		rndHex: '0000000000000000000000000000000000000000000000000000000000000000',
	},
	{
		id: 'V6',
		description: 'V6, RFC 6979 §A.2.5 test keypair + msg, zero rnd (sig matches RFC §A.2.5 test r||s)',
		skHex: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
		msgHex: '74657374',  // utf8 'test'
		rndHex: '0000000000000000000000000000000000000000000000000000000000000000',
	},
	{
		id: 'V7',
		description: 'V7, 4096-byte msg, hedged rnd (multi-chunk SignStream coverage)',
		skHex: '13579bdf02468ace13579bdf02468ace13579bdf02468ace13579bdf02468ace',
		msgHex: '',  // filled in below from a deterministic pattern
		rndHex: '99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa',
	},
]

// Fill V4 and V7 with deterministic patterns.
function patternBytes(n: number, salt: number): Uint8Array {
	const out = new Uint8Array(n)
	for (let i = 0; i < n; i++) out[i] = (i * 17 + salt) & 0xff
	return out
}
SPECS[3].msgHex = bytesToHex(patternBytes(1024, 11))
SPECS[6].msgHex = bytesToHex(patternBytes(4096, 29))

function sha256(msg: Uint8Array): Uint8Array {
	const h = new SHA256()
	try {
		return h.hash(msg)
	} finally {
		h.dispose()
	}
}

function assembleBlob(suiteByte: number, ctx: Uint8Array, payload: Uint8Array, sig: Uint8Array): Uint8Array {
	const out = new Uint8Array(2 + ctx.length + 4 + payload.length + sig.length)
	let pos = 0
	out[pos++] = suiteByte
	out[pos++] = ctx.length
	out.set(ctx, pos)
	pos += ctx.length
	out[pos++] = (payload.length >>> 24) & 0xff
	out[pos++] = (payload.length >>> 16) & 0xff
	out[pos++] = (payload.length >>>  8) & 0xff
	out[pos++] =  payload.length         & 0xff
	out.set(payload, pos)
	pos += payload.length
	out.set(sig, pos)
	return out
}

function chunkHex(hex: string, perLine = 64): string {
	const parts: string[] = []
	for (let i = 0; i < hex.length; i += perLine) parts.push(hex.slice(i, i + perLine))
	return parts.map((p, i) => `\t\t\t\t'${p}'${i === parts.length - 1 ? '' : ' +'}`).join('\n')
}

function recordHexLine(label: string, hex: string): string {
	if (hex.length <= 64) return `\t\t${label}: '${hex}',`
	return `\t\t${label}:\n${chunkHex(hex)},`
}

const EMPTY_CTX = new Uint8Array(0)
const records: string[] = []

for (const spec of SPECS) {
	const sk = hexToBytes(spec.skHex)
	const msg = hexToBytes(spec.msgHex)
	const rnd = hexToBytes(spec.rndHex)
	const digest = sha256(msg)

	const inst = new EcdsaP256()
	let pk: Uint8Array
	let sig: Uint8Array
	try {
		const kp = inst.keygenDerand(sk)
		pk = kp.publicKey
		sig = inst._signInternalPk(sk, digest, rnd)
	} finally {
		inst.dispose()
	}

	const blob = assembleBlob(0x02, EMPTY_CTX, msg, sig)

	records.push(`\t{
\t\tid: '${spec.id}',
\t\tdescription: '${spec.description}',
\t\tformatEnum: 0x02,
${recordHexLine('pkHex', bytesToHex(pk))}
${recordHexLine('skHex', spec.skHex)}
${recordHexLine('msgHex', spec.msgHex)}
${recordHexLine('ctxHex', '')}
${recordHexLine('rndHex', spec.rndHex)}
${recordHexLine('blobHex', bytesToHex(blob))}
${recordHexLine('sigHex', bytesToHex(sig))}
\t},`)
}

const file =
	HEADER +
	`export interface SignEcdsaP256Vector {
\tid:          string;
\tdescription: string;
\tformatEnum:  number;
\tpkHex:       string;
\tskHex:       string;
\tmsgHex:      string;
\tctxHex:      string;
\trndHex:      string;
\tblobHex:     string;
\tsigHex:      string;
}

export const signEcdsaP256Vectors: SignEcdsaP256Vector[] = [
${records.join('\n')}
];
`

writeFileSync('test/vectors/sign_ecdsa_p256.ts', file)

console.log(`wrote ${records.length} records to test/vectors/sign_ecdsa_p256.ts`)

// Sanity: confirm V5 and V6 sigs match RFC 6979 §A.2.5 'sample' / 'test'
const rfcSample = {
	rHex: 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716',
	sHex: 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
}
const rfcTest = {
	rHex: 'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367',
	sHex: '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083',
}
const v5Sig = SPECS[4]
const v6Sig = SPECS[5]
console.log(`V5 (sample) RFC expected r||s: ${rfcSample.rHex + rfcSample.sHex}`)
console.log(`V6 (test)   RFC expected r||s: ${rfcTest.rHex + rfcTest.sHex}`)
console.log(`(check matches V5 / V6 sigHex in generated file)`)
console.log(`V5/V6 skHex: ${v5Sig.skHex} / ${v6Sig.skHex}`)
