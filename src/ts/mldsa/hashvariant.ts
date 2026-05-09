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
// src/ts/mldsa/hashvariant.ts
//
// HashML-DSA pre-hash dispatcher and OID DER table.
// FIPS 204 §5.4 / §5.4.1 — Algorithm 4 (HashML-DSA.Sign) and Algorithm 5
// (HashML-DSA.Verify) build M' = 0x01 ‖ |ctx| ‖ ctx ‖ OID ‖ PH_M, where
//   • PH_M = H_PH(M) for the caller-selected approved pre-hash function PH
//   • OID  = the DER encoding of PH's NIST CSOR object identifier
//
// The 12 approved pre-hash functions (FIPS 204 §5.4.1) are SHA2-{224,256,
// 384,512,512/224,512/256}, SHA3-{224,256,384,512}, and the two XOFs
// SHAKE128 / SHAKE256 with fixed 256- / 512-bit outputs respectively.
//
// All OIDs share the 10-byte DER prefix `06 09 60 86 48 01 65 03 04 02`
// (joint-iso-itu-t.country(2).us(16).organization(840).gov(1).csor(101)
// .nistalgorithm(3).hashalgs(4).hashalg(2)) and are distinguished by the
// trailing arc byte. Spec authority: FIPS 204 Algorithm 4 lines 12, 15,
// 18 enumerates SHA-256 (.01), SHA-512 (.03), and SHAKE128 (.0B) by
// example; the remaining nine arcs are the NIST CSOR registrations
// (RFC 5754 / RFC 8702) on the same 2.16.840.1.101.3.4.2.x branch and
// must match the verifying-party expectation byte-for-byte.

import type { Sha3Exports } from './types.js';
import type { Sha2Exports } from '../sha2/types.js';
import { sha3Absorb } from './sha3-helpers.js';

/** FIPS 204 §5.4.1 — approved pre-hash functions. Names follow the spec
 *  spelling (no hyphens between SHAKE and the digit). The SHAKE entries
 *  are XOFs with fixed output lengths set by FIPS 204 §5.4.1:
 *  SHAKE128 → 256-bit (32-byte) output, SHAKE256 → 512-bit (64-byte). */
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

// ── OID DER table — FIPS 204 §5.4.1 ─────────────────────────────────────────
// Shared 10-byte DER prefix: tag 0x06 (OBJECT IDENTIFIER), length 0x09,
// then the encoded ancestor arcs 2.16.840.1.101.3.4.2:
//   2.16   → 0x60 0x86 0x48                  (joint-iso-itu-t.country)
//   .1     → 0x01                            (us)
//   .101   → 0x65                            (organization → gov)
//   .3.4.2 → 0x03 0x04 0x02                  (csor.nistalgorithm.hashalgs)
// The trailing byte is the per-algorithm arc.

const DER_PREFIX = Object.freeze<number[]>(
	[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02],
);

function oid(arc: number): Uint8Array {
	const out = new Uint8Array(11);
	for (let i = 0; i < 10; i++) out[i] = DER_PREFIX[i];
	out[10] = arc & 0xFF;
	return out;
}

// id-sha224 — 2.16.840.1.101.3.4.2.4
const OID_SHA2_224     = oid(0x04);
// id-sha256 — 2.16.840.1.101.3.4.2.1 (FIPS 204 §5.4.1 Algorithm 4 line 12)
const OID_SHA2_256     = oid(0x01);
// id-sha384 — 2.16.840.1.101.3.4.2.2
const OID_SHA2_384     = oid(0x02);
// id-sha512 — 2.16.840.1.101.3.4.2.3 (FIPS 204 §5.4.1 Algorithm 4 line 15)
const OID_SHA2_512     = oid(0x03);
// id-sha512-224 — 2.16.840.1.101.3.4.2.5
const OID_SHA2_512_224 = oid(0x05);
// id-sha512-256 — 2.16.840.1.101.3.4.2.6
const OID_SHA2_512_256 = oid(0x06);
// id-sha3-224 — 2.16.840.1.101.3.4.2.7
const OID_SHA3_224     = oid(0x07);
// id-sha3-256 — 2.16.840.1.101.3.4.2.8
const OID_SHA3_256     = oid(0x08);
// id-sha3-384 — 2.16.840.1.101.3.4.2.9
const OID_SHA3_384     = oid(0x09);
// id-sha3-512 — 2.16.840.1.101.3.4.2.10
const OID_SHA3_512     = oid(0x0A);
// id-shake128 — 2.16.840.1.101.3.4.2.11 (FIPS 204 §5.4.1 Algorithm 4 line 18)
const OID_SHAKE128     = oid(0x0B);
// id-shake256 — 2.16.840.1.101.3.4.2.12
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

/** Look up the FIPS 204 §5.4.1 OID DER bytes for `algo`. Returns a fresh
 *  Uint8Array each call so callers can wipe / mutate without aliasing the
 *  module-private constant. */
export function getOid(algo: PreHashAlgorithm): Uint8Array {
	const tab = OID_TABLE[algo];
	if (!tab)
		throw new RangeError(`leviathan-crypto: unsupported HashML-DSA pre-hash algorithm '${algo as string}'`);
	return tab.slice();
}

/** True iff `algo` is one of the SHA-2 family pre-hashes (and therefore
 *  requires `init({ sha2: ... })`). The SHA-3 family and SHAKE variants
 *  use the same `sha3` module mldsa already requires. */
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

// ── SHA-2 driver ────────────────────────────────────────────────────────────
// Mirrors the `feedHash` pattern in src/ts/sha2/index.ts, but kept inline
// here so hashvariant.ts is the only file that needs to know about HashML-DSA's
// SHA-2 dispatch table.

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

// ── SHA-3 fixed-length driver ───────────────────────────────────────────────
// `sha3Absorb` from sha3-helpers handles ≤168-byte chunks. Final functions
// land the digest at OUT_OFFSET; we slice it out into a fresh Uint8Array.

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

// ── SHAKE driver — fixed output length per FIPS 204 §5.4.1 ──────────────────

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
 * Pre-hash dispatcher — applies the FIPS 204 §5.4.1 hash function `algo`
 * to message `M` and returns PH_M (the bytes that go into M' alongside
 * the OID).
 *
 * `sha2x` may be `undefined` if `algo` does not need the sha2 module
 * (i.e. SHA3-* / SHAKE*). When `algo` is a SHA-2 variant, the dispatcher
 * throws if `sha2x` is missing rather than NPE'ing on a member access.
 * The arrangement keeps sha2 strictly optional for pure-ML-DSA users and
 * SHA3-prehash HashML-DSA users.
 */
export function preHashMessage(
	sx: Sha3Exports,
	sha2x: Sha2Exports | undefined,
	algo: PreHashAlgorithm,
	M: Uint8Array,
): Uint8Array {
	// SHA-3 / SHAKE branches don't touch sha2x — handle them first so
	// the SHA-2 cases below operate on a narrowed non-undefined sha2x.
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
		// FIPS 204 §5.4.1 — SHAKE128 fixed at 256-bit / 32-byte output.
		return shakeHashFixed(sx, M, sx.shake128Init, 168, 32);
	case 'SHAKE256':
		// FIPS 204 §5.4.1 — SHAKE256 fixed at 512-bit / 64-byte output.
		return shakeHashFixed(sx, M, sx.shake256Init, 136, 64);
	}
	if (sha2x === undefined)
		throw new Error('leviathan-crypto: HashML-DSA SHA-2 pre-hash requires the sha2 module to be initialized');
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
	default: {
		// Defensive: type system should rule this out, but a dynamic
		// dispatch (e.g. parsing a vector file) could widen the type.
		const exhaustive: never = algo;
		throw new RangeError(`leviathan-crypto: unsupported HashML-DSA pre-hash algorithm '${exhaustive as string}'`);
	}
	}
}
