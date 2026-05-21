// scripts/gen-ed25519-vectors.ts
//
// One-shot generator for test/vectors/sign_ed25519.ts. Builds locking
// envelope-wire-format vectors for the Ed25519Suite (pure, RFC 8032
// §5.1.6) and Ed25519PreHashSuite (prehash, RFC 8032 §5.1.7 dom2 with
// the suite's ctxDomain bound into effective_ctx). Both modes are fully
// deterministic per RFC 8032, so KAT byte-equality is meaningful for
// both suites.
//
// Run as:
//   bun scripts/gen-ed25519-vectors.ts
// then commit the regenerated vectors file.

import {init, bytesToHex, hexToBytes} from '../src/ts/index.js'
import {ed25519Wasm} from '../src/ts/ed25519/embedded.js'
import {sha2Wasm} from '../src/ts/sha2/embedded.js'
import {Ed25519} from '../src/ts/ed25519/index.js'
import {
	Ed25519Suite,
	Ed25519PreHashSuite,
} from '../src/ts/sign/index.js'
import type {SignatureSuite, StreamableSignatureSuite} from '../src/ts/sign/index.js'
import {buildEffectiveCtx} from '../src/ts/sign/ctx.js'
import {SHA512} from '../src/ts/sha2/index.js'
import {utf8ToBytes} from '../src/ts/utils.js'
import {writeFileSync} from 'node:fs'

await init({ed25519: ed25519Wasm, sha2: sha2Wasm})

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
// test/vectors/sign_ed25519.ts
//
// Suite-level KAT vectors locking the v3 attached envelope wire format
// produced by the Ed25519 suite consts: \`Ed25519Suite\` (formatEnum 0x01,
// pure Ed25519 per RFC 8032 §5.1.6) and \`Ed25519PreHashSuite\`
// (formatEnum 0x11, Ed25519ph per RFC 8032 §5.1.7 with the
// \`ed25519-prehash-envelope-v3\` ctxDomain bound via \`buildEffectiveCtx\`
// into the dom2(F=1, effective_ctx) construction). Unlike ML-DSA, both
// Ed25519 modes are fully deterministic per RFC 8032, so KATs cover
// both pure and prehash records.
//
// Audit status: SELF-GENERATED (wire-format gate). Records V1-V3 use
// the RFC 8032 §7.1 TEST 1 / 2 / 3 seeds and messages; V1-V3 sig bytes
// inside the envelope match the RFC §7.1 expected sigs verbatim (the
// envelope's [formatEnum, ctxLen, ...] preamble simply prefixes them).
// Records V4-V7 use the RFC §7.3 TEST abc seed; the sig bytes diverge
// from the RFC §7.3 expected sig because the suite always binds its
// ctxDomain into the effective_ctx fed to dom2 (the RFC's reference
// signature is computed with ctx=empty).
//
// Inputs per record:
//   id, description     human-readable identifiers
//   formatEnum          0x01 for pure, 0x11 for prehash
//   mode                'pure' | 'prehash' discriminator
//   seedHex             32-byte RFC 8032 secret seed
//   pkHex, skHex        32-byte verifying key + 32-byte sk (= seed)
//   msgHex              payload bytes
//   ctxHex              user_ctx bytes (always '' for pure records;
//                       the pure suite rejects non-empty user_ctx)
//   blobHex             attached envelope: [formatEnum, ctxLen, ctx,
//                       payload_len (u32 BE), payload, sig]
//
// All hex strings are lowercase, no separators.

`

type Mode = 'pure' | 'prehash'

interface Spec {
	id: string
	description: string
	mode: Mode
	suite: SignatureSuite | StreamableSignatureSuite
	formatEnum: number
	seedHex: string
	msgHex: string
	ctxHex: string
}

const SPECS: Spec[] = [
	{
		id: 'V1',
		description: 'V1, pure Ed25519, RFC 8032 §7.1 TEST 1 seed, empty msg, empty ctx',
		mode: 'pure',
		suite: Ed25519Suite,
		formatEnum: 0x01,
		seedHex: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
		msgHex: '',
		ctxHex: '',
	},
	{
		id: 'V2',
		description: 'V2, pure Ed25519, RFC 8032 §7.1 TEST 2 seed, 1-byte msg 0x72, empty ctx',
		mode: 'pure',
		suite: Ed25519Suite,
		formatEnum: 0x01,
		seedHex: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
		msgHex: '72',
		ctxHex: '',
	},
	{
		id: 'V3',
		description: 'V3, pure Ed25519, RFC 8032 §7.1 TEST 3 seed, 2-byte msg 0xaf82, empty ctx',
		mode: 'pure',
		suite: Ed25519Suite,
		formatEnum: 0x01,
		seedHex: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
		msgHex: 'af82',
		ctxHex: '',
	},
	{
		id: 'V4',
		description: 'V4, Ed25519ph, RFC 8032 §7.3 TEST abc seed, msg "abc", empty ctx',
		mode: 'prehash',
		suite: Ed25519PreHashSuite,
		formatEnum: 0x11,
		seedHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		msgHex: bytesToHex(utf8ToBytes('abc')),
		ctxHex: '',
	},
	{
		id: 'V5',
		description: "V5, Ed25519ph, RFC 8032 §7.3 seed, 38-byte msg, ctx = utf8('v3-suite-kat')",
		mode: 'prehash',
		suite: Ed25519PreHashSuite,
		formatEnum: 0x11,
		seedHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		msgHex: bytesToHex(utf8ToBytes('Leviathan Crypto, Ed25519 v3 SUITE KAT')),
		ctxHex: bytesToHex(utf8ToBytes('v3-suite-kat')),
	},
	{
		id: 'V6',
		description: 'V6, Ed25519ph, RFC 8032 §7.3 seed, 40-byte msg, 100-byte ctx',
		mode: 'prehash',
		suite: Ed25519PreHashSuite,
		formatEnum: 0x11,
		seedHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		msgHex: bytesToHex(utf8ToBytes('Leviathan Crypto v3-pm-100-ctx gate-kat')),
		ctxHex: bytesToHex(syntheticCtx(100, 0x1f, 7)),
	},
	{
		id: 'V7',
		description: 'V7, Ed25519ph, RFC 8032 §7.3 seed, 40-byte msg, 200-byte ctx',
		mode: 'prehash',
		suite: Ed25519PreHashSuite,
		formatEnum: 0x11,
		seedHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		msgHex: bytesToHex(utf8ToBytes('Leviathan Crypto v3-pm-200-ctx boundary')),
		ctxHex: bytesToHex(syntheticCtx(200, 0x05, 13)),
	},
]

function syntheticCtx(n: number, start: number, step: number): Uint8Array {
	const out = new Uint8Array(n)
	let v = start
	for (let i = 0; i < n; i++) {
		out[i] = v
		v = (v + step) & 0xff
	}
	return out
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
	return parts.map((p, i) => `\t\t\t'${p}'${i === parts.length - 1 ? '' : ' +'}`).join('\n')
}

function recordHexLine(label: string, hex: string): string {
	if (hex.length <= 64) return `\t\t${label}: '${hex}',`
	return `\t\t${label}:\n${chunkHex(hex)},`
}

const records: string[] = []
for (const spec of SPECS) {
	const seed = hexToBytes(spec.seedHex)
	const msg  = hexToBytes(spec.msgHex)
	const ctx  = hexToBytes(spec.ctxHex)
	const inst = new Ed25519()
	let pkBytes: Uint8Array
	let sig: Uint8Array
	try {
		const kp = inst.keygenDerand(seed)
		pkBytes = kp.publicKey
		if (spec.mode === 'pure') {
			sig = inst._signInternalPk(seed, msg)
		} else {
			const effectiveCtx = buildEffectiveCtx(spec.suite.ctxDomain, ctx)
			const sh = new SHA512()
			let digest: Uint8Array
			try {
				digest = sh.hash(msg)
			} finally {
				sh.dispose()
			}
			sig = inst._signPrehashedInternalPk(seed, digest, effectiveCtx)
		}
	} finally {
		inst.dispose()
	}

	const blob = assembleBlob(spec.formatEnum, ctx, msg, sig)

	// Sanity-check via the suite verify path.
	const ok = spec.suite.verify(pkBytes, msg, sig, ctx)
	if (!ok) throw new Error(`${spec.id}: suite.verify rejected freshly-generated sig`)

	records.push(`\t{
\t\tid: '${spec.id}',
\t\tdescription: ${JSON.stringify(spec.description)},
\t\tformatEnum: 0x${spec.formatEnum.toString(16).padStart(2, '0')},
\t\tmode: '${spec.mode}',
${recordHexLine('seedHex', bytesToHex(seed))}
${recordHexLine('pkHex', bytesToHex(pkBytes))}
${recordHexLine('skHex', bytesToHex(seed))}
${recordHexLine('msgHex', bytesToHex(msg))}
${recordHexLine('ctxHex', bytesToHex(ctx))}
${recordHexLine('blobHex', bytesToHex(blob))}
\t},`)
}

const file =
	HEADER +
	`export type SignEd25519Mode = 'pure' | 'prehash';

export interface SignEd25519Vector {
\tid:          string;
\tdescription: string;
\tformatEnum:  number;
\tmode:        SignEd25519Mode;
\tseedHex:     string;
\tpkHex:       string;
\tskHex:       string;
\tmsgHex:      string;
\tctxHex:      string;
\tblobHex:     string;
}

export const signEd25519Vectors: SignEd25519Vector[] = [
${records.join('\n')}
];
`

writeFileSync('test/vectors/sign_ed25519.ts', file)
console.log('Wrote test/vectors/sign_ed25519.ts with', SPECS.length, 'records')
