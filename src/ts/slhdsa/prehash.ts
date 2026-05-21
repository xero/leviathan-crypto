//                  ▄▄▄▄▄▄▄▄▄▄
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
// src/ts/slhdsa/prehash.ts
//
// HashSLH-DSA pre-hash dispatcher and OID DER table.
// FIPS 205 §10.2.2 Algorithm 23 (HashSLH-DSA-Sign) and Algorithm 25
// (HashSLH-DSA-Verify) build M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID ‖ PH_M, where
//   • PH_M = H_PH(M) for the caller-selected approved pre-hash function PH
//   • OID  = the DER encoding of PH's NIST CSOR object identifier
//
// The M' construction is BYTE-IDENTICAL to FIPS 204 §5.4 HashML-DSA's M'.
// `src/ts/mldsa/hashvariant.ts:constructMPrimeHash` already implements
// this byte layout; the duplication is intentional and extraction is
// deferred until a third consumer materialises.
//
// All OIDs share the 10-byte DER prefix `06 09 60 86 48 01 65 03 04 02`
// (joint-iso-itu-t.country(2).us(16).organization(840).gov(1).csor(101)
// .nistalgorithm(3).hashalgs(4).hashalg(2)) and are distinguished by the
// trailing arc byte. Spec authority: FIPS 205 §10.2.2 Algorithm 23 lines
// 10, 13, 16, 19 enumerate SHA-256 (.01), SHA-512 (.03), SHAKE128 (.0B),
// SHAKE256 (.0C) by example; the remaining eight arcs are the NIST CSOR
// registrations on the same 2.16.840.1.101.3.4.2.x branch and must match
// the verifying-party expectation byte-for-byte.

import type { Sha3Exports } from '../mldsa/types.js';
import type { Sha2Exports } from '../sha2/types.js';
import { sha3Absorb } from '../mldsa/sha3-helpers.js';

/** FIPS 205 §10.2.2 approved pre-hash functions, same surface as FIPS 204
 *  §5.4.1. Names follow the FIPS 204 / FIPS 205 spelling (no hyphen
 *  between SHAKE and the digit). The SHAKE entries are XOFs with fixed
 *  output lengths set by FIPS 205 §10.2.2 Algorithm 23: SHAKE128 → 256-bit
 *  (32-byte) output, SHAKE256 → 512-bit (64-byte). */
export type PreHashAlgorithm =
	| 'SHA2-224'
	| 'SHA2-256'
	| 'SHA2-384'
	| 'SHA2-512'
	| 'SHA2-512/224'
	| 'SHA2-512/256'
	| 'SHA3-224'
	| 'SHA3-256'
	| 'SHA3-384'
	| 'SHA3-512'
	| 'SHAKE128'
	| 'SHAKE256';

// ── OID DER table, FIPS 205 §10.2.2 ────────────────────────────────────────
// Shared 10-byte DER prefix: tag 0x06 (OBJECT IDENTIFIER), length 0x09,
// then the encoded ancestor arcs 2.16.840.1.101.3.4.2. The trailing byte
// is the per-algorithm arc.

const DER_PREFIX = Object.freeze<number[]>(
	[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02],
);

function oid(arc: number): Uint8Array {
	const out = new Uint8Array(11);
	for (let i = 0; i < 10; i++) out[i] = DER_PREFIX[i];
	out[10] = arc & 0xFF;
	return out;
}

// id-sha224, 2.16.840.1.101.3.4.2.4
const OID_SHA2_224     = oid(0x04);
// id-sha256, 2.16.840.1.101.3.4.2.1 (FIPS 205 §10.2.2 Algorithm 23 line 10)
const OID_SHA2_256     = oid(0x01);
// id-sha384, 2.16.840.1.101.3.4.2.2
const OID_SHA2_384     = oid(0x02);
// id-sha512, 2.16.840.1.101.3.4.2.3 (FIPS 205 §10.2.2 Algorithm 23 line 13)
const OID_SHA2_512     = oid(0x03);
// id-sha512-224, 2.16.840.1.101.3.4.2.5
const OID_SHA2_512_224 = oid(0x05);
// id-sha512-256, 2.16.840.1.101.3.4.2.6
const OID_SHA2_512_256 = oid(0x06);
// id-sha3-224, 2.16.840.1.101.3.4.2.7
const OID_SHA3_224     = oid(0x07);
// id-sha3-256, 2.16.840.1.101.3.4.2.8
const OID_SHA3_256     = oid(0x08);
// id-sha3-384, 2.16.840.1.101.3.4.2.9
const OID_SHA3_384     = oid(0x09);
// id-sha3-512, 2.16.840.1.101.3.4.2.10
const OID_SHA3_512     = oid(0x0A);
// id-shake128, 2.16.840.1.101.3.4.2.11 (FIPS 205 §10.2.2 Algorithm 23 line 16)
const OID_SHAKE128     = oid(0x0B);
// id-shake256, 2.16.840.1.101.3.4.2.12 (FIPS 205 §10.2.2 Algorithm 23 line 19)
const OID_SHAKE256     = oid(0x0C);

const OID_TABLE: Readonly<Record<PreHashAlgorithm, Uint8Array>> = Object.freeze({
	'SHA2-224': OID_SHA2_224,
	'SHA2-256': OID_SHA2_256,
	'SHA2-384': OID_SHA2_384,
	'SHA2-512': OID_SHA2_512,
	'SHA2-512/224': OID_SHA2_512_224,
	'SHA2-512/256': OID_SHA2_512_256,
	'SHA3-224': OID_SHA3_224,
	'SHA3-256': OID_SHA3_256,
	'SHA3-384': OID_SHA3_384,
	'SHA3-512': OID_SHA3_512,
	'SHAKE128': OID_SHAKE128,
	'SHAKE256': OID_SHAKE256,
});

/** Look up the FIPS 205 §10.2.2 OID DER bytes for `algo`. Returns a fresh
 *  Uint8Array each call so callers can wipe / mutate without aliasing the
 *  module-private constant. */
export function getOid(algo: PreHashAlgorithm): Uint8Array {
	const tab = OID_TABLE[algo];
	if (!tab)
		throw new RangeError(`leviathan-crypto: unsupported HashSLH-DSA pre-hash algorithm '${algo as string}'`);
	return tab.slice();
}

/** FIPS 205 §10.2.2 PH_M byte length for `algo`. SHAKE128 / SHAKE256 are
 *  XOFs but the spec fixes their HashSLH-DSA output to 32 / 64 bytes
 *  respectively; the SHA-3 and SHA-2 entries return their natural digest
 *  size. Used by `validateDigest` to bound the caller-supplied prehash.
 *
 *  Duplicated from `src/ts/mldsa/hashvariant.ts:digestSize`; extraction
 *  is deferred until a third consumer materialises. */
export function digestSize(algo: PreHashAlgorithm): number {
	switch (algo) {
	case 'SHA2-224':     return 28;
	case 'SHA2-256':     return 32;
	case 'SHA2-384':     return 48;
	case 'SHA2-512':     return 64;
	case 'SHA2-512/224': return 28;
	case 'SHA2-512/256': return 32;
	case 'SHA3-224':     return 28;
	case 'SHA3-256':     return 32;
	case 'SHA3-384':     return 48;
	case 'SHA3-512':     return 64;
	case 'SHAKE128':     return 32;
	case 'SHAKE256':     return 64;
	default: {
		const exhaustive: never = algo;
		throw new RangeError(`leviathan-crypto: unsupported HashSLH-DSA pre-hash algorithm '${exhaustive as string}'`);
	}
	}
}

/** True iff `algo` is one of the SHA-2 family pre-hashes (and therefore
 *  requires `init({ sha2: ... })`). The SHA-3 family and SHAKE variants
 *  use the `sha3` module. */
export function algoNeedsSha2(algo: PreHashAlgorithm): boolean {
	switch (algo) {
	case 'SHA2-224':
	case 'SHA2-256':
	case 'SHA2-384':
	case 'SHA2-512':
	case 'SHA2-512/224':
	case 'SHA2-512/256':
		return true;
	default:
		return false;
	}
}

/** True iff `algo` is a SHA-3 or SHAKE pre-hash (and therefore requires
 *  `init({ sha3: ... })`). slhdsa's own embedded Keccak permutation is
 *  used internally by `slh_sign_internal` / `slh_verify_internal`, but the
 *  HashSLH-DSA prehash dispatcher routes through the `sha3` module to keep
 *  the public surface byte-identical with `src/ts/mldsa/hashvariant.ts`
 *  (which also uses the sha3 module). */
export function algoNeedsSha3(algo: PreHashAlgorithm): boolean {
	switch (algo) {
	case 'SHA3-224':
	case 'SHA3-256':
	case 'SHA3-384':
	case 'SHA3-512':
	case 'SHAKE128':
	case 'SHAKE256':
		return true;
	default:
		return false;
	}
}

// ── M' construction (FIPS 205 §10.2.2) ─────────────────────────────────────

/**
 * Build the HashSLH-DSA M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID ‖ PH_M.
 *
 * FIPS 205 §10.2.2 Algorithm 23 lines 18-19 (sign) and §10.3 Algorithm 25
 * lines 16-17 (verify). The leading byte is 0x01 (vs 0x00 for pure
 * SLH-DSA), domain separation across pure / pre-hash modes per FIPS 205
 * §10.2 narrative. Caller has already validated ctx.length ≤ 255.
 *
 * Byte-identical to FIPS 204 §5.4 Algorithm 4 M' construction; see
 * src/ts/mldsa/hashvariant.ts and src/ts/mldsa/format.ts:constructMPrimeHash
 * for the ML-DSA mirror. Q7 resolution: duplicate, do not extract.
 */
export function constructMPrimeHash(
	digest: Uint8Array,
	ph:     PreHashAlgorithm,
	ctx:    Uint8Array,
): Uint8Array {
	const o = OID_TABLE[ph];
	if (!o)
		throw new RangeError(`leviathan-crypto: unsupported HashSLH-DSA pre-hash algorithm '${ph as string}'`);
	const out = new Uint8Array(2 + ctx.length + o.length + digest.length);
	out[0] = 0x01;
	out[1] = ctx.length & 0xFF;
	out.set(ctx,    2);
	out.set(o,      2 + ctx.length);
	out.set(digest, 2 + ctx.length + o.length);
	return out;
}

/**
 * Build the pure-mode M' = 0x00 ‖ |ctx| ‖ ctx ‖ M for FIPS 205 §10.2.1
 * Algorithm 22 line 8 (sign) and §10.3 Algorithm 24 line 8 (verify).
 *
 * Caller has already validated ctx.length ≤ 255. The leading byte is 0x00,
 * which separates pure SLH-DSA signatures from HashSLH-DSA signatures (the
 * latter prepends 0x01 via constructMPrimeHash) on the same key per the
 * §10.2 narrative.
 */
export function constructMPrimePure(M: Uint8Array, ctx: Uint8Array): Uint8Array {
	const out = new Uint8Array(2 + ctx.length + M.length);
	out[0] = 0x00;
	out[1] = ctx.length & 0xFF;
	out.set(ctx, 2);
	out.set(M,   2 + ctx.length);
	return out;
}

// ── SHA-2 driver (matches src/ts/mldsa/hashvariant.ts:sha2Hash) ────────────

function feedSha2(
	x: Sha2Exports,
	msg: Uint8Array,
	inputOff: number,
	chunkSize: number,
	updateFn: (len: number) => void,
): void {
	const mem = new Uint8Array(x.memory.buffer);
	let pos = 0;
	while (pos < msg.length) {
		const n = Math.min(msg.length - pos, chunkSize);
		mem.set(msg.subarray(pos, pos + n), inputOff);
		updateFn(n);
		pos += n;
	}
}

function sha2Hash(
	x: Sha2Exports,
	msg: Uint8Array,
	initFn: () => void,
	finalFn: () => void,
	inputOff: number,
	outOff: number,
	blockSize: number,
	updateFn: (len: number) => void,
	outLen: number,
): Uint8Array {
	initFn();
	feedSha2(x, msg, inputOff, blockSize, updateFn);
	finalFn();
	const mem = new Uint8Array(x.memory.buffer);
	return mem.slice(outOff, outOff + outLen);
}

// ── SHA-3 fixed-length driver ──────────────────────────────────────────────

function sha3HashFixed(
	sx: Sha3Exports,
	msg: Uint8Array,
	initFn: () => void,
	finalFn: () => void,
	outLen: number,
): Uint8Array {
	initFn();
	sha3Absorb(sx, msg);
	finalFn();
	const mem = new Uint8Array(sx.memory.buffer);
	const off = sx.getOutOffset();
	return mem.slice(off, off + outLen);
}

// ── SHAKE driver, fixed output length per FIPS 205 §10.2.2 ─────────────────

function shakeHashFixed(
	sx: Sha3Exports,
	msg: Uint8Array,
	initFn: () => void,
	rate: number,
	outLen: number,
): Uint8Array {
	initFn();
	sha3Absorb(sx, msg);
	sx.shakePad();
	const mem = new Uint8Array(sx.memory.buffer);
	const off = sx.getOutOffset();
	const out = new Uint8Array(outLen);
	let pos = 0;
	while (pos < outLen) {
		sx.shakeSqueezeBlock();
		const take = Math.min(outLen - pos, rate);
		out.set(mem.subarray(off, off + take), pos);
		pos += take;
	}
	return out;
}

/**
 * Pre-hash dispatcher, applies the FIPS 205 §10.2.2 hash function `algo`
 * to message `M` and returns PH_M (the bytes that go into M' alongside
 * the OID).
 *
 * `sx` is the sha3-wasm Sha3Exports, required for SHA-3 / SHAKE prehashes.
 * `sha2x` is the sha2-wasm Sha2Exports, required for SHA-2 prehashes.
 * Either argument may be `undefined` when the chosen `algo` does not need
 * that module; the dispatcher throws a clear error if a required module
 * is missing rather than NPE'ing on a member access. Pure-SLH-DSA users
 * call neither (slhdsa-wasm has its own embedded Keccak permutation), so
 * both modules are strictly optional.
 */
export function preHashMessage(
	sx:    Sha3Exports | undefined,
	sha2x: Sha2Exports | undefined,
	algo:  PreHashAlgorithm,
	M:     Uint8Array,
): Uint8Array {
	if (algoNeedsSha3(algo)) {
		if (sx === undefined)
			throw new Error('leviathan-crypto: HashSLH-DSA SHA-3 / SHAKE pre-hash requires the sha3 module to be initialized');
		switch (algo) {
		case 'SHA3-224':
			return sha3HashFixed(sx, M, sx.sha3_224Init, sx.sha3_224Final, 28);
		case 'SHA3-256':
			return sha3HashFixed(sx, M, sx.sha3_256Init, sx.sha3_256Final, 32);
		case 'SHA3-384':
			return sha3HashFixed(sx, M, sx.sha3_384Init, sx.sha3_384Final, 48);
		case 'SHA3-512':
			return sha3HashFixed(sx, M, sx.sha3_512Init, sx.sha3_512Final, 64);
		case 'SHAKE128':
			// FIPS 205 §10.2.2 Algorithm 23 line 17: PH_M = SHAKE128(M, 256).
			return shakeHashFixed(sx, M, sx.shake128Init, 168, 32);
		case 'SHAKE256':
			// FIPS 205 §10.2.2 Algorithm 23 line 20: PH_M = SHAKE256(M, 512).
			return shakeHashFixed(sx, M, sx.shake256Init, 136, 64);
		default: break;
		}
	}
	if (algoNeedsSha2(algo)) {
		if (sha2x === undefined)
			throw new Error('leviathan-crypto: HashSLH-DSA SHA-2 pre-hash requires the sha2 module to be initialized');
		const x = sha2x;
		switch (algo) {
		case 'SHA2-224':
			return sha2Hash(x, M,
				x.sha224Init, x.sha224Final,
				x.getSha256InputOffset(), x.getSha256OutOffset(),
				64, x.sha256Update, 28);
		case 'SHA2-256':
			return sha2Hash(x, M,
				x.sha256Init, x.sha256Final,
				x.getSha256InputOffset(), x.getSha256OutOffset(),
				64, x.sha256Update, 32);
		case 'SHA2-384':
			return sha2Hash(x, M,
				x.sha384Init, x.sha384Final,
				x.getSha512InputOffset(), x.getSha512OutOffset(),
				128, x.sha512Update, 48);
		case 'SHA2-512':
			return sha2Hash(x, M,
				x.sha512Init, x.sha512Final,
				x.getSha512InputOffset(), x.getSha512OutOffset(),
				128, x.sha512Update, 64);
		case 'SHA2-512/224':
			return sha2Hash(x, M,
				x.sha512_224Init, x.sha512_224Final,
				x.getSha512InputOffset(), x.getSha512OutOffset(),
				128, x.sha512Update, 28);
		case 'SHA2-512/256':
			return sha2Hash(x, M,
				x.sha512_256Init, x.sha512_256Final,
				x.getSha512InputOffset(), x.getSha512OutOffset(),
				128, x.sha512Update, 32);
		default: break;
		}
	}
	throw new RangeError(`leviathan-crypto: unsupported HashSLH-DSA pre-hash algorithm '${algo as string}'`);
}
