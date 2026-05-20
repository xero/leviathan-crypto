// scripts/gen-hybrid-classical-vectors.ts
//
// One-shot generator for test/vectors/sign_hybrid_classical.ts. Ingests
// the four Appendix E test cases for the Composite ML-DSA hybrid
// classical+PQ suites from the pinned draft text file at
//
//   ../research-docs/specs/draft-ietf-lamps-pq-composite-sigs-19.txt
//
// Per draft-ietf-lamps-pq-composite-sigs-19 (Composite Module-Lattice-Based
// Digital Signature Algorithm) §6 (Algorithm Identifiers and Parameters)
// and Appendix E (Test Vectors), each tcId carries a base64-encoded raw
// composite pk, a base64-encoded composite sk (mldsaSeed || trad_sk_encoded
// per §4.2), a signature `s` over the global message m with an empty user
// ctx, and a signature `sWithContext` over the same m with the global ctx
// string. We emit eight leviathan vector records: one per (suite, ctx)
// pair, four suites times two ctx variants.
//
// Each record's blobHex wraps the spec's composite sig in the leviathan v3
// attached envelope:
//
//   [suite_byte:  u8]            1 byte
//   [ctx_len:     u8]            1 byte
//   [ctx:         ctx_len]       0-255 bytes
//   [payload_len: u32 BE]        4 bytes
//   [payload:     payload_len]   message bytes
//   [sig:         remainder]     composite-sigs §4.3 wire (mldsaSig || tradSig)
//
// Run:
//   bun scripts/gen-hybrid-classical-vectors.ts
// then commit the regenerated vectors file.
//
// Idempotent: running twice produces byte-identical output.

import {readFileSync, writeFileSync} from 'node:fs'
import {bytesToHex} from '../src/ts/index.js'

const DRAFT_VERSION = 19
const SPEC_PATH = `../research-docs/specs/draft-ietf-lamps-pq-composite-sigs-${DRAFT_VERSION}.txt`

// Per-suite catalog metadata. Sizes from composite-sigs Appendix A Table 4,
// cross-checked against FIPS 204 (Module-Lattice-Based Digital Signature
// Standard) §4 Table 1 (ML-DSA-44 pk=1312, sig=2420; ML-DSA-65 pk=1952,
// sig=3309), RFC 8032 (Edwards-Curve Digital Signature Algorithm) §5.1
// (Ed25519 pk=32, sk=32, sig=64), SEC1 v2 §2.3.3-§2.3.4 (ECDSA-P256
// uncompressed pk=65), RFC 5915 (ECPrivateKey DER, 51 bytes for P-256),
// and RFC 3279 §2.2.3 (Ecdsa-Sig-Value DER, variable length, max 72).
interface SuiteSpec {
	tcId:            string
	formatEnum:      number
	suiteName:       string
	mldsaPkBytes:    number
	mldsaSigBytes:   number
	tradPkBytes:     number  // wire encoding size of the traditional pk half
	tradSkBytes:     number  // wire encoding size of the traditional sk half
	tradSigVariable: boolean // false for Ed25519 (exact 64); true for ECDSA DER
}

const SUITES: SuiteSpec[] = [
	{
		tcId:            'id-MLDSA44-Ed25519-SHA512',
		formatEnum:      0x20,
		suiteName:       'MlDsa44Ed25519Suite',
		mldsaPkBytes:    1312,
		mldsaSigBytes:   2420,
		tradPkBytes:     32,
		tradSkBytes:     32,
		tradSigVariable: false,
	},
	{
		tcId:            'id-MLDSA65-Ed25519-SHA512',
		formatEnum:      0x21,
		suiteName:       'MlDsa65Ed25519Suite',
		mldsaPkBytes:    1952,
		mldsaSigBytes:   3309,
		tradPkBytes:     32,
		tradSkBytes:     32,
		tradSigVariable: false,
	},
	{
		tcId:            'id-MLDSA44-ECDSA-P256-SHA256',
		formatEnum:      0x22,
		suiteName:       'MlDsa44EcdsaP256Suite',
		mldsaPkBytes:    1312,
		mldsaSigBytes:   2420,
		tradPkBytes:     65,
		tradSkBytes:     51,
		tradSigVariable: true,
	},
	{
		tcId:            'id-MLDSA65-ECDSA-P256-SHA512',
		formatEnum:      0x23,
		suiteName:       'MlDsa65EcdsaP256Suite',
		mldsaPkBytes:    1952,
		mldsaSigBytes:   3309,
		tradPkBytes:     65,
		tradSkBytes:     51,
		tradSigVariable: true,
	},
]

// Strip Internet-Draft page-header lines ('Ounsworth, et al. ... [Page NN]'
// + 'Internet-Draft  Composite ML-DSA  ...'); lets multi-line base64
// fields concatenate cleanly.
function stripPageHeaders(text: string): string {
	return text
		.split('\n')
		.filter((line) => {
			const t = line.trim()
			if (t.startsWith('Ounsworth, et al.') && t.includes('[Page ')) return false
			if (t.startsWith('Internet-Draft') && t.includes('Composite ML-DSA')) return false
			return true
		})
		.join('\n')
}

// Extract `"key": "..."` starting at/after startOffset. Base64 alphabet
// excludes '"', so closing quote = next '"'. Returns {value, after}.
function extractStringField(
	text: string,
	key: string,
	startOffset: number,
): {value: string; after: number} {
	const needle = `"${key}":`
	const at = text.indexOf(needle, startOffset)
	if (at < 0) throw new Error(`field "${key}" not found from offset ${startOffset}`)
	let p = at + needle.length
	while (p < text.length && /\s/.test(text[p])) p++
	if (text[p] !== '"') throw new Error(`expected opening quote for "${key}" at offset ${p}`)
	p++
	const end = text.indexOf('"', p)
	if (end < 0) throw new Error(`closing quote not found for "${key}"`)
	const raw = text.slice(p, end).replace(/[^A-Za-z0-9+/=]/g, '')
	return {value: raw, after: end + 1}
}

function findTcIdAnchor(text: string, tcId: string): number {
	const needle = `"tcId": "${tcId}"`
	const at = text.indexOf(needle)
	if (at < 0) throw new Error(`tcId "${tcId}" not present in spec text`)
	return at
}

function b64decode(s: string): Uint8Array {
	return new Uint8Array(Buffer.from(s, 'base64'))
}

function assembleBlob(
	suiteByte: number,
	ctx: Uint8Array,
	payload: Uint8Array,
	sig: Uint8Array,
): Uint8Array {
	if (ctx.length > 255) throw new Error('ctx length exceeds 255 bytes')
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

function chunkHex(hex: string, perLine = 64): string {
	const parts: string[] = []
	for (let i = 0; i < hex.length; i += perLine) parts.push(hex.slice(i, i + perLine))
	return parts.map((p, i) => `\t\t\t\t'${p}'${i === parts.length - 1 ? '' : ' +'}`).join('\n')
}

function recordHexLine(label: string, hex: string): string {
	if (hex.length <= 64) return `\t\t${label}: '${hex}',`
	return `\t\t${label}:\n${chunkHex(hex)},`
}

// ────────────────────────────────────────────────────────────────────────────
// Main
// ────────────────────────────────────────────────────────────────────────────

const raw = readFileSync(SPEC_PATH, 'utf8')
const spec = stripPageHeaders(raw)

// Global m and ctx live inside the top-level JSON object that wraps the
// tests array. They appear before the first tcId entry.
const firstTcId = spec.indexOf('"tcId":')
if (firstTcId < 0) throw new Error('no tcId entries found in spec text')
const mField = extractStringField(spec, 'm', 0)
if (mField.after >= firstTcId)
	throw new Error('global m field overlaps first tcId entry (parser misaligned)')
const ctxField = extractStringField(spec, 'ctx', mField.after)
if (ctxField.after >= firstTcId)
	throw new Error('global ctx field overlaps first tcId entry (parser misaligned)')

const globalMsg = b64decode(mField.value)
const globalCtx = b64decode(ctxField.value)

// Sanity: the global m and ctx are the published Composite ML-DSA test inputs.
const EXPECTED_MSG = 'The quick brown fox jumps over the lazy dog.'
const EXPECTED_CTX = 'The lethargic, colorless dog sat beneath the energetic, stationary fox.'
if (new TextDecoder().decode(globalMsg) !== EXPECTED_MSG)
	throw new Error(`global m mismatch: got "${new TextDecoder().decode(globalMsg)}"`)
if (new TextDecoder().decode(globalCtx) !== EXPECTED_CTX)
	throw new Error(`global ctx mismatch: got "${new TextDecoder().decode(globalCtx)}"`)

interface OutRecord {
	id:              string
	tcId:            string
	formatEnum:      number
	suiteName:       string
	mldsaPkBytes:    number
	mldsaSigBytes:   number
	tradPkBytes:     number
	tradSigVariable: boolean
	pk:              Uint8Array
	sk:              Uint8Array
	msg:             Uint8Array
	ctx:             Uint8Array
	sig:             Uint8Array
	blob:            Uint8Array
}

const records: OutRecord[] = []

for (const suite of SUITES) {
	const anchor = findTcIdAnchor(spec, suite.tcId)
	// Skip x5c / sk_pkcs8: alternative encodings of pk / sk already captured raw.
	const pkF  = extractStringField(spec, 'pk',           anchor)
	const skF  = extractStringField(spec, 'sk',           pkF.after)
	const sF   = extractStringField(spec, 's',            skF.after)
	const swcF = extractStringField(spec, 'sWithContext', sF.after)

	const pk  = b64decode(pkF.value)
	const sk  = b64decode(skF.value)
	const sig = b64decode(sF.value)
	const swc = b64decode(swcF.value)

	// Composite wire-format size checks (composite-sigs §4.1, §4.2, §4.3).
	const expectPk = suite.mldsaPkBytes + suite.tradPkBytes
	const expectSk = 32 /* mldsaSeed */ + suite.tradSkBytes
	if (pk.length !== expectPk)
		throw new Error(`${suite.tcId}: pk size ${pk.length} != ${expectPk}`)
	if (sk.length !== expectSk)
		throw new Error(`${suite.tcId}: sk size ${sk.length} != ${expectSk}`)
	// ML-DSA half of every signature is exact; the traditional half is
	// either exact (Ed25519) or variable (ECDSA DER).
	if (sig.length < suite.mldsaSigBytes)
		throw new Error(`${suite.tcId}: s shorter than ML-DSA half (${sig.length} < ${suite.mldsaSigBytes})`)
	if (swc.length < suite.mldsaSigBytes)
		throw new Error(`${suite.tcId}: sWithContext shorter than ML-DSA half (${swc.length} < ${suite.mldsaSigBytes})`)
	if (!suite.tradSigVariable) {
		const expectSig = suite.mldsaSigBytes + 64
		if (sig.length !== expectSig)
			throw new Error(`${suite.tcId}: s size ${sig.length} != ${expectSig}`)
		if (swc.length !== expectSig)
			throw new Error(`${suite.tcId}: sWithContext size ${swc.length} != ${expectSig}`)
	}

	// Empty-ctx record.
	const emptyCtx = new Uint8Array(0)
	records.push({
		id:              `${suite.tcId}--empty-ctx`,
		tcId:            suite.tcId,
		formatEnum:      suite.formatEnum,
		suiteName:       suite.suiteName,
		mldsaPkBytes:    suite.mldsaPkBytes,
		mldsaSigBytes:   suite.mldsaSigBytes,
		tradPkBytes:     suite.tradPkBytes,
		tradSigVariable: suite.tradSigVariable,
		pk, sk,
		msg:             globalMsg,
		ctx:             emptyCtx,
		sig:             sig,
		blob:            assembleBlob(suite.formatEnum, emptyCtx, globalMsg, sig),
	})

	// Non-empty-ctx record.
	records.push({
		id:              `${suite.tcId}--with-ctx`,
		tcId:            suite.tcId,
		formatEnum:      suite.formatEnum,
		suiteName:       suite.suiteName,
		mldsaPkBytes:    suite.mldsaPkBytes,
		mldsaSigBytes:   suite.mldsaSigBytes,
		tradPkBytes:     suite.tradPkBytes,
		tradSigVariable: suite.tradSigVariable,
		pk, sk,
		msg:             globalMsg,
		ctx:             globalCtx,
		sig:             swc,
		blob:            assembleBlob(suite.formatEnum, globalCtx, globalMsg, swc),
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Emit
// ────────────────────────────────────────────────────────────────────────────

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
// test/vectors/sign_hybrid_classical.ts
//
// Composite KAT vectors for the four classical+PQ hybrid suites
// (MlDsa44Ed25519Suite, MlDsa65Ed25519Suite, MlDsa44EcdsaP256Suite,
// MlDsa65EcdsaP256Suite). Eight records: four suites times two ctx variants
// (empty ctx \`s\`, non-empty global ctx \`sWithContext\`).
//
// Audit status: SPEC-ANCHORED. Bytes are ingested verbatim from Appendix E
// of draft-ietf-lamps-pq-composite-sigs-19 via scripts/gen-hybrid-classical-vectors.ts.
// The composite signature value is the spec's own \`s\` / \`sWithContext\`;
// the wrapping blob is the leviathan v3 attached envelope around it.
//
// The KAT path is verify-against-spec, not sign-and-reproduce. The spec's
// reference implementation uses hedged ML-DSA, and for the ECDSA suites
// the underlying ECDSA half is also non-deterministic; only the verify
// direction is byte-stable from these inputs.
//
// Inputs per record:
//   pkHex          composite pk = mldsaPk || tradPk (composite-sigs §4.1).
//   skHex          composite sk = mldsaSeed (32 bytes) || tradSkEncoded
//                  (composite-sigs §4.2; tradSkEncoded is RFC 8032 §5.1.5
//                  32-byte raw seed for Ed25519, RFC 5915 51-byte DER
//                  ECPrivateKey for ECDSA-P256).
//   msgHex         payload bytes (ASCII of the global Appendix E message
//                  "The quick brown fox jumps over the lazy dog.").
//   ctxHex         user_ctx: empty for \`--empty-ctx\` records, the
//                  Appendix E global ctx string for \`--with-ctx\` records.
//   sigHex         composite signature = mldsaSig || tradSig
//                  (composite-sigs §4.3). For Ed25519 suites tradSig is
//                  exactly 64 bytes (RFC 8032 §5.1.6 R||S); for ECDSA
//                  suites tradSig is RFC 3279 §2.2.3 Ecdsa-Sig-Value DER,
//                  variable length up to 72 bytes.
//   blobHex        v3 attached envelope:
//                  [formatEnum, ctxLen, ctx, payload_len (u32 BE), payload, sig].
//
// All hex strings are lowercase, no separators.

`

const recordSnippets = records.map((r) => `\t{
\t\tid: '${r.id}',
\t\ttcId: '${r.tcId}',
\t\tformatEnum: 0x${r.formatEnum.toString(16).padStart(2, '0')},
\t\tsuiteName: '${r.suiteName}',
\t\tmldsaPkBytes: ${r.mldsaPkBytes},
\t\tmldsaSigBytes: ${r.mldsaSigBytes},
\t\ttradPkBytes: ${r.tradPkBytes},
\t\ttradSigVariable: ${r.tradSigVariable ? 'true' : 'false'},
${recordHexLine('pkHex',   bytesToHex(r.pk))}
${recordHexLine('skHex',   bytesToHex(r.sk))}
${recordHexLine('msgHex',  bytesToHex(r.msg))}
${recordHexLine('ctxHex',  bytesToHex(r.ctx))}
${recordHexLine('sigHex',  bytesToHex(r.sig))}
${recordHexLine('blobHex', bytesToHex(r.blob))}
\t},`)

const file = HEADER + `export interface SignHybridClassicalVector {
\tid:              string;
\ttcId:            string;
\tformatEnum:      number;
\tsuiteName:       string;
\tmldsaPkBytes:    number;
\tmldsaSigBytes:   number;
\ttradPkBytes:     number;
\ttradSigVariable: boolean;
\tpkHex:           string;
\tskHex:           string;
\tmsgHex:          string;
\tctxHex:          string;
\tsigHex:          string;
\tblobHex:         string;
}

export const signHybridClassicalVectors: SignHybridClassicalVector[] = [
${recordSnippets.join('\n')}
];
`

writeFileSync('test/vectors/sign_hybrid_classical.ts', file)
console.log(`Wrote test/vectors/sign_hybrid_classical.ts with ${records.length} records`)
