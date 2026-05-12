// scripts/gen-slhdsa-vectors.ts
//
// One-shot generator for test/vectors/sign_slhdsa.ts. Builds locking
// envelope-wire-format vectors for the six SLH-DSA suites using
// deterministic sub-sign so the output bytes are reproducible. Run as:
//   bun scripts/gen-slhdsa-vectors.ts
// then commit the regenerated vectors file.

import {init, bytesToHex, hexToBytes} from '../src/ts/index.js'
import {slhdsaWasm} from '../src/ts/slhdsa/embedded.js'
import {sha3Wasm} from '../src/ts/sha3/embedded.js'
import {
	SlhDsa128f,
	SlhDsa192f,
	SlhDsa256f,
	SLHDSA128F,
	SLHDSA192F,
	SLHDSA256F,
} from '../src/ts/slhdsa/index.js'
import type {SlhDsaParams} from '../src/ts/slhdsa/index.js'
import {
	SlhDsa128fSuite,
	SlhDsa192fSuite,
	SlhDsa256fSuite,
	SlhDsa128fPreHashSuite,
	SlhDsa192fPreHashSuite,
	SlhDsa256fPreHashSuite,
} from '../src/ts/sign/index.js'
import {buildEffectiveCtx} from '../src/ts/sign/ctx.js'
import type {SignatureSuite, StreamableSignatureSuite} from '../src/ts/sign/index.js'
import {utf8ToBytes} from '../src/ts/utils.js'
import {writeFileSync} from 'node:fs'

await init({slhdsa: slhdsaWasm, sha3: sha3Wasm})

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
// test/vectors/sign_slhdsa.ts
//
// Suite-level KAT vectors locking the v3 attached envelope wire format
// produced by the SLH-DSA pure and prehash suites. Sigs are generated
// with signDeterministic / signHashPrehashedDeterministic so the wire
// bytes are byte-stable; the production suite.sign path is hedged and
// therefore unsuitable for KAT byte-equality assertions. Verifying these
// blobs through the hedged suite still works (verify is deterministic
// given the recorded sig).
//
// Audit status: SELF-GENERATED (wire-format gate).
//
// Inputs per record:
//   seedHex   3·n-byte hex seed fed to keygenDerand to derive (pk, sk).
//   pkHex     verificationKey bytes (params.pkBytes).
//   skHex     signingKey bytes      (params.skBytes).
//   msgHex    payload bytes (UTF-8 of the per-record message string).
//   ctxHex    user_ctx bytes        (UTF-8 of "v3-suite-kat").
//   blobHex   attached envelope: [formatEnum, ctxLen, ctx, payload, sig]
//
// All hex strings are lowercase, no separators.

`

type SlhClass = typeof SlhDsa128f | typeof SlhDsa192f | typeof SlhDsa256f

interface PureSpec {
	id: string
	description: string
	formatEnum: number
	suite: SignatureSuite
	SlhDsaClass: SlhClass
	params: SlhDsaParams
	prehashAlgorithm?: undefined
	prehashName: '' // pure
	msg: string
}

interface PrehashSpec {
	id: string
	description: string
	formatEnum: number
	suite: StreamableSignatureSuite
	SlhDsaClass: SlhClass
	params: SlhDsaParams
	prehashAlgorithm: 'shake-128' | 'shake-256'
	prehashName: 'SHAKE128' | 'SHAKE256'
	msg: string
}

type Spec = PureSpec | PrehashSpec

const SPECS: Spec[] = [
	{
		id: 'V1',
		description: 'V1, SLH-DSA-128f (pure)',
		formatEnum: 0x06,
		suite: SlhDsa128fSuite,
		SlhDsaClass: SlhDsa128f,
		params: SLHDSA128F,
		prehashName: '',
		msg: 'leviathan-crypto slhdsa128f pure',
	},
	{
		id: 'V2',
		description: 'V2, SLH-DSA-192f (pure)',
		formatEnum: 0x07,
		suite: SlhDsa192fSuite,
		SlhDsaClass: SlhDsa192f,
		params: SLHDSA192F,
		prehashName: '',
		msg: 'leviathan-crypto slhdsa192f pure',
	},
	{
		id: 'V3',
		description: 'V3, SLH-DSA-256f (pure)',
		formatEnum: 0x08,
		suite: SlhDsa256fSuite,
		SlhDsaClass: SlhDsa256f,
		params: SLHDSA256F,
		prehashName: '',
		msg: 'leviathan-crypto slhdsa256f pure',
	},
	{
		id: 'V4',
		description: 'V4, SLH-DSA-128f + SHAKE128 prehash',
		formatEnum: 0x16,
		suite: SlhDsa128fPreHashSuite,
		SlhDsaClass: SlhDsa128f,
		params: SLHDSA128F,
		prehashAlgorithm: 'shake-128',
		prehashName: 'SHAKE128',
		msg: 'leviathan-crypto slhdsa128f prehash',
	},
	{
		id: 'V5',
		description: 'V5, SLH-DSA-192f + SHAKE256 prehash',
		formatEnum: 0x17,
		suite: SlhDsa192fPreHashSuite,
		SlhDsaClass: SlhDsa192f,
		params: SLHDSA192F,
		prehashAlgorithm: 'shake-256',
		prehashName: 'SHAKE256',
		msg: 'leviathan-crypto slhdsa192f prehash',
	},
	{
		id: 'V6',
		description: 'V6, SLH-DSA-256f + SHAKE256 prehash',
		formatEnum: 0x18,
		suite: SlhDsa256fPreHashSuite,
		SlhDsaClass: SlhDsa256f,
		params: SLHDSA256F,
		prehashAlgorithm: 'shake-256',
		prehashName: 'SHAKE256',
		msg: 'leviathan-crypto slhdsa256f prehash',
	},
]

function seedFor(params: SlhDsaParams, byte: number): Uint8Array {
	return new Uint8Array(3 * params.n).fill(byte)
}

function assembleBlob(suiteByte: number, ctx: Uint8Array, payload: Uint8Array, sig: Uint8Array): Uint8Array {
	const out = new Uint8Array(2 + ctx.length + payload.length + sig.length)
	let pos = 0
	out[pos++] = suiteByte
	out[pos++] = ctx.length
	out.set(ctx, pos)
	pos += ctx.length
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

const CTX = utf8ToBytes('v3-suite-kat')

const records: string[] = []
let seedByte = 0xaa
for (const spec of SPECS) {
	const seed = seedFor(spec.params, seedByte++)
	const inst = new spec.SlhDsaClass()
	let pkBytes: Uint8Array
	let skBytes: Uint8Array
	let sig: Uint8Array
	try {
		const kp = inst.keygenDerand(seed)
		pkBytes = kp.verificationKey
		skBytes = kp.signingKey
		const msgBytes = utf8ToBytes(spec.msg)
		const effectiveCtx = buildEffectiveCtx(spec.suite.ctxDomain, CTX)
		if (spec.prehashName === '') {
			sig = inst.signDeterministic(skBytes, msgBytes, effectiveCtx)
		} else {
			sig = inst.signHashDeterministic(skBytes, msgBytes, spec.prehashName, effectiveCtx)
		}
	} finally {
		inst.dispose()
	}

	const msgBytes = utf8ToBytes(spec.msg)
	const blob = assembleBlob(spec.formatEnum, CTX, msgBytes, sig)

	const prehashLine =
		spec.prehashName === ''
			? `\t\tprehashAlgorithm: undefined,`
			: `\t\tprehashAlgorithm: '${spec.prehashAlgorithm}',`

	const recordHexLine = (label: string, hex: string): string => {
		if (hex.length <= 64) return `\t\t${label}: '${hex}',`
		return `\t\t${label}:\n${chunkHex(hex)},`
	}

	records.push(`\t{
\t\tid: '${spec.id}',
\t\tdescription: '${spec.description}',
\t\tformatEnum: 0x${spec.formatEnum.toString(16).padStart(2, '0')},
${prehashLine}
${recordHexLine('seedHex', bytesToHex(seed))}
${recordHexLine('pkHex', bytesToHex(pkBytes))}
${recordHexLine('skHex', bytesToHex(skBytes))}
${recordHexLine('msgHex', bytesToHex(msgBytes))}
${recordHexLine('ctxHex', bytesToHex(CTX))}
${recordHexLine('blobHex', bytesToHex(blob))}
\t},`)

	// Sanity-check the blob: hex round-trips, parts line up.
	const reparsed = hexToBytes(bytesToHex(blob))
	if (reparsed.length !== blob.length) throw new Error(`${spec.id}: round-trip length mismatch`)
}

const file =
	HEADER +
	`export interface SignSlhdsaVector {
\tid:               string;
\tdescription:      string;
\tformatEnum:       number;
\tprehashAlgorithm: 'shake-128' | 'shake-256' | undefined;
\tseedHex:          string;
\tpkHex:            string;
\tskHex:            string;
\tmsgHex:           string;
\tctxHex:           string;
\tblobHex:          string;
}

export const signSlhdsaVectors: SignSlhdsaVector[] = [
${records.join('\n')}
];
`

writeFileSync('test/vectors/sign_slhdsa.ts', file)
console.log('Wrote test/vectors/sign_slhdsa.ts with', SPECS.length, 'records')
