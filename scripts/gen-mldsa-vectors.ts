// scripts/gen-mldsa-vectors.ts
//
// One-shot generator for test/vectors/sign_mldsa.ts. Builds locking
// envelope-wire-format vectors for the three ML-DSA prehash suites
// using deterministic prehashed sign so the output bytes are
// reproducible. Run as:
//   bun scripts/gen-mldsa-vectors.ts
// then commit the regenerated vectors file.
//
// Three deterministic vectors cover MlDsa{44,65,87}PreHashSuite. Sigs
// are generated with signHashPrehashedDeterministic so the wire bytes
// are byte-stable; the production suite.sign path is hedged. Verifying
// these blobs through the hedged suite still works (verify is
// deterministic given the recorded sig).

import {init, bytesToHex} from '../src/ts/index.js'
import {mldsaWasm} from '../src/ts/mldsa/embedded.js'
import {sha3Wasm} from '../src/ts/sha3/embedded.js'
import {
	MlDsa44, MlDsa65, MlDsa87,
	MLDSA44, MLDSA65, MLDSA87,
} from '../src/ts/mldsa/index.js'
import type {MlDsaParams, MlDsaKeyPair} from '../src/ts/mldsa/index.js'
import {
	MlDsa44PreHashSuite,
	MlDsa65PreHashSuite,
	MlDsa87PreHashSuite,
} from '../src/ts/sign/index.js'
import type {StreamableSignatureSuite} from '../src/ts/sign/index.js'
import {buildEffectiveCtx} from '../src/ts/sign/ctx.js'
import {SHA3_256, SHA3_512} from '../src/ts/sha3/index.js'
import {utf8ToBytes} from '../src/ts/utils.js'
import {writeFileSync} from 'node:fs'

await init({mldsa: mldsaWasm, sha3: sha3Wasm})

const HEADER = `//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄███████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//        ▄█████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓▀▓ ▓▄▓ ▓ ▓
//      ▄████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒  ▒ █ ▒ ▒ ▒ █
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
// test/vectors/sign_mldsa.ts
//
// Suite-level KAT vectors locking the v3 attached envelope wire format
// produced by the ML-DSA prehash suites. Sigs are generated with
// signHashPrehashedDeterministic so the wire bytes are byte-stable; the
// production suite.sign path is hedged and therefore unsuitable for KAT
// byte-equality assertions. Verifying these blobs through the hedged
// suite still works (verify is deterministic given the recorded sig).
//
// Audit status: SELF-GENERATED (wire-format gate).
//
// Inputs per record:
//   seedHex   32-byte hex seed fed to keygenDerand to derive (pk, sk).
//   pkHex     verificationKey bytes (params.pkBytes).
//   skHex     signingKey bytes      (params.skBytes).
//   msgHex    payload bytes (UTF-8 of the per-record message string).
//   ctxHex    user_ctx bytes        (UTF-8 of "v3-suite-kat").
//   blobHex   attached envelope: [formatEnum, ctxLen, ctx, payload_len (u32 BE), payload, sig]
//
// All hex strings are lowercase, no separators.

`

type MlDsaClass = typeof MlDsa44 | typeof MlDsa65 | typeof MlDsa87

interface Spec {
	id: string
	description: string
	formatEnum: number
	suite: StreamableSignatureSuite
	MlDsaClass: MlDsaClass
	params: MlDsaParams
	prehashAlgorithm: 'sha3-256' | 'sha3-512'
	seedByte: number
	msg: string
}

const SPECS: Spec[] = [
	{
		id: 'V1',
		description: 'V1, ML-DSA-44 + SHA3-256',
		formatEnum: 0x13,
		suite: MlDsa44PreHashSuite,
		MlDsaClass: MlDsa44,
		params: MLDSA44,
		prehashAlgorithm: 'sha3-256',
		seedByte: 0xaa,
		msg: 'Leviathan Crypto, ML-DSA-44 KAT vector v3',
	},
	{
		id: 'V2',
		description: 'V2, ML-DSA-65 + SHA3-256',
		formatEnum: 0x14,
		suite: MlDsa65PreHashSuite,
		MlDsaClass: MlDsa65,
		params: MLDSA65,
		prehashAlgorithm: 'sha3-256',
		seedByte: 0xbb,
		msg: 'Leviathan Crypto, ML-DSA-65 KAT vector v3',
	},
	{
		id: 'V3',
		description: 'V3, ML-DSA-87 + SHA3-512',
		formatEnum: 0x15,
		suite: MlDsa87PreHashSuite,
		MlDsaClass: MlDsa87,
		params: MLDSA87,
		prehashAlgorithm: 'sha3-512',
		seedByte: 0xcc,
		msg: 'Leviathan Crypto, ML-DSA-87 KAT vector v3',
	},
]

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

function digestFor(algo: 'sha3-256' | 'sha3-512', msg: Uint8Array): Uint8Array {
	if (algo === 'sha3-256') {
		const h = new SHA3_256()
		try { return h.hash(msg) } finally { h.dispose() }
	}
	const h = new SHA3_512()
	try { return h.hash(msg) } finally { h.dispose() }
}

const CTX = utf8ToBytes('v3-suite-kat')

const records: string[] = []
for (const spec of SPECS) {
	const seed = new Uint8Array(32).fill(spec.seedByte)
	const inst = new spec.MlDsaClass()
	let kp: MlDsaKeyPair
	let sig: Uint8Array
	const msgBytes = utf8ToBytes(spec.msg)
	const digest = digestFor(spec.prehashAlgorithm, msgBytes)
	const effectiveCtx = buildEffectiveCtx(spec.suite.ctxDomain, CTX)
	const mldsaHash = spec.prehashAlgorithm === 'sha3-256' ? 'SHA3-256' : 'SHA3-512'
	try {
		kp = inst.keygenDerand(seed)
		sig = inst.signHashPrehashedDeterministic(
			kp.signingKey, digest, mldsaHash, effectiveCtx,
		)
	} finally {
		inst.dispose()
	}

	const blob = assembleBlob(spec.formatEnum, CTX, msgBytes, sig)

	// Sanity-check via the suite verify path.
	const ok = spec.suite.verify(kp.verificationKey, msgBytes, sig, CTX)
	if (!ok) throw new Error(`${spec.id}: suite.verify rejected freshly-generated sig`)

	records.push(`\t{
\t\tid: '${spec.id}',
\t\tdescription: '${spec.description}',
\t\tformatEnum: 0x${spec.formatEnum.toString(16).padStart(2, '0')},
\t\tprehashAlgorithm: '${spec.prehashAlgorithm}',
${recordHexLine('seedHex', bytesToHex(seed))}
${recordHexLine('pkHex', bytesToHex(kp.verificationKey))}
${recordHexLine('skHex', bytesToHex(kp.signingKey))}
${recordHexLine('msgHex', bytesToHex(msgBytes))}
${recordHexLine('ctxHex', bytesToHex(CTX))}
${recordHexLine('blobHex', bytesToHex(blob))}
\t},`)
}

const file =
	HEADER +
	`export interface SignMldsaVector {
\tid:         string;
\tdescription: string;
\tformatEnum: number;
\tprehashAlgorithm: 'sha3-256' | 'sha3-512';
\tseedHex: string;
\tpkHex:   string;
\tskHex:   string;
\tmsgHex:  string;
\tctxHex:  string;
\tblobHex: string;
}

export const signMldsaVectors: SignMldsaVector[] = [
${records.join('\n')}
];
`

writeFileSync('test/vectors/sign_mldsa.ts', file)
console.log('Wrote test/vectors/sign_mldsa.ts with', SPECS.length, 'records')
