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
/**
 * BLAKE3 tree-internals substrate tests, BLAKE3 §2.4 / §2.5.
 *
 * Drives the WASM `_testChunkCV` / `_testParentCV` / `_testDeriveContextCV`
 * exports through `helpers.ts` and verifies that hand-composed chunk +
 * parent CVs reproduce `BLAKE3.hash` / `BLAKE3KeyedHash.hash` /
 * `BLAKE3DeriveKey.derive` byte-for-byte across 1, 2, and 4-chunk inputs
 * for all three modes. This is the Phase 7 (blake3-log merkle substrate)
 * gate: if the test exports compose into BLAKE3, the Phase 7 log proofs
 * will be byte-identical to a BLAKE3 streaming reader's chunk / parent
 * intermediates.
 *
 * Expected values come from `test/vectors/blake3.ts` (upstream KAT
 * corpus, audit-status: VERIFIED) by routing the same inputs through
 * BLAKE3.hash and comparing the substrate result against the public
 * API result. The public API path is itself gated by the KAT corpus,
 * so an indirect KAT chain holds.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
	loadBlake3, exports_, toHex, BLAKE3_IV_BYTES,
	_chunkCV, _parentCV, _deriveContextCV,
} from './helpers.js';
import {
	BLAKE3, BLAKE3KeyedHash, BLAKE3DeriveKey,
} from '../../../src/ts/blake3/index.js';
import {
	blake3Vectors, blake3Key, blake3ContextString, expandBlake3Input,
} from '../../vectors/blake3.js';

const KEY_BYTES = new TextEncoder().encode(blake3Key);
const CTX_BYTES = new TextEncoder().encode(blake3ContextString);

beforeAll(async () => {
	await loadBlake3();
});

// ────────────────────────────────────────────────────────────────────────────
// Helpers: pull mode-flag constants from the WASM exports so the test
// stays in lockstep with `src/asm/blake3/flags.ts` without copying values.
// ────────────────────────────────────────────────────────────────────────────

function modeFlagHash():   number {
	return 0;
}
function modeFlagKeyed():  number {
	return exports_().FLAG_KEYED_HASH.value;
}
function modeFlagDerive(): number {
	return exports_().FLAG_DERIVE_KEY_MATERIAL.value;
}

interface ModeSpec {
	name:        string;
	startCv:     () => Uint8Array;
	modeFlags:   () => number;
	hash:        (input: Uint8Array) => Uint8Array;
}

const HASH_MODE: ModeSpec = {
	name: 'hash',
	startCv: () => BLAKE3_IV_BYTES,
	modeFlags: () => modeFlagHash(),
	hash: (input) => {
		const h = new BLAKE3();
		try        {
			return h.hash(input);
		} finally    {
			h.dispose();
		}
	},
};

const KEYED_MODE: ModeSpec = {
	name: 'keyed_hash',
	startCv: () => KEY_BYTES,
	modeFlags: () => modeFlagKeyed(),
	hash: (input) => {
		const h = new BLAKE3KeyedHash();
		try        {
			return h.hash(KEY_BYTES, input);
		} finally    {
			h.dispose();
		}
	},
};

// derive_key pass 2's starting CV is the context_chain_value from pass 1.
// We compute it once via `_deriveContextCV` at suite setup and reuse it
// across the three derive_key test cases (1 / 2 / 4 chunks).
let _ccv: Uint8Array | null = null;
function ccv(): Uint8Array {
	if (_ccv) return _ccv;
	_ccv = _deriveContextCV(CTX_BYTES);
	return _ccv;
}

const DERIVE_MODE: ModeSpec = {
	name: 'derive_key',
	startCv: () => ccv(),
	modeFlags: () => modeFlagDerive(),
	hash: (input) => {
		const dk = new BLAKE3DeriveKey();
		try        {
			return dk.derive(blake3ContextString, input);
		} finally    {
			dk.dispose();
		}
	},
};

// Slice the input into chunks of up to 1024 bytes per BLAKE3 §2.4.
function chunkSlices(input: Uint8Array): Uint8Array[] {
	const out: Uint8Array[] = [];
	for (let off = 0; off < input.length; off += 1024) {
		out.push(input.subarray(off, Math.min(off + 1024, input.length)));
	}
	return out;
}

// Hand-compose a tree's root output for `input` whose chunk count is
// `numChunks` (power of 2 only — 2 or 4 in this suite). Returns the
// 32-byte hash output for comparison with `mode.hash(input)`.
function composeTreeRoot(mode: ModeSpec, input: Uint8Array, numChunks: 2 | 4): Uint8Array {
	const slices  = chunkSlices(input);
	const startCv = mode.startCv();
	const flags   = mode.modeFlags();
	expect(slices.length).toBe(numChunks);

	const chunkCvs: Uint8Array[] = slices.map((slice, i) =>
		_chunkCV(slice, BigInt(i), startCv, flags),
	);

	if (numChunks === 2) {
		return _parentCV(chunkCvs[0], chunkCvs[1], startCv, flags, /* isRoot=*/ true);
	}

	// numChunks === 4: pair-wise non-root parents, then a root parent.
	const left  = _parentCV(chunkCvs[0], chunkCvs[1], startCv, flags, /* isRoot=*/ false);
	const right = _parentCV(chunkCvs[2], chunkCvs[3], startCv, flags, /* isRoot=*/ false);
	return _parentCV(left, right, startCv, flags, /* isRoot=*/ true);
}

// ────────────────────────────────────────────────────────────────────────────
// 1-chunk substrate check
// ────────────────────────────────────────────────────────────────────────────
//
// For a 1-chunk input, BLAKE3 §2.4 applies ROOT on the chunk's last
// compress; _chunkCV does NOT apply ROOT (its contract is "produce the
// value that would be pushed to the §2.5 tree assembly for a multi-
// chunk input"). The two values differ by the ROOT flag bit on the
// last compress, so they aren't directly equal.
//
// What we CAN verify cheaply: _chunkCV's chunk-pipeline output for a
// 1-block single-chunk input matches the public `compress` export
// driven with CHUNK_START|CHUNK_END (no ROOT) over the same input
// block, CV, and counter. This proves the chunk machine wiring inside
// _chunkCV matches the spec.

describe('BLAKE3 tree-internals substrate, §2.4 / §2.5', () => {
	it('_chunkCV: 1-block single-chunk input matches direct compress (CHUNK_START|CHUNK_END, no ROOT)', () => {
		// Use the 64-byte KAT record (vector index 11) as a 1-block 1-chunk
		// input. _chunkCV gives the chunk-pipeline output (chunk CV); a
		// direct `compress` with the same flags should agree.
		const v     = blake3Vectors.find(r => r.inputLen === 64);
		expect(v).toBeDefined();
		const input = expandBlake3Input(v!.inputLen);

		const x = exports_();
		const m = new Uint8Array(x.memory.buffer);

		// Stage IV (CV), input block (MSG), and the expected output landing
		// at the module's COMPRESS_OUT_OFFSET (read via getter for safety).
		const cvOff    = x.getCvOffset();
		const msgOff   = x.getMsgOffset();
		const outOff   = x.getCompressOutOffset();

		m.set(BLAKE3_IV_BYTES, cvOff);
		m.set(input,           msgOff);

		const flags = x.FLAG_CHUNK_START.value | x.FLAG_CHUNK_END.value;
		x.compress(cvOff, msgOff, 0, 0, 64, flags, outOff);

		const direct = m.slice(outOff, outOff + 32);
		const viaTest = _chunkCV(input, 0n, BLAKE3_IV_BYTES, 0);
		expect(toHex(viaTest)).toBe(toHex(direct));
	});

	// GATE: the simplest authoritative composition test for the Phase 7
	// substrate. For a 2-chunk input, the §2.5 tree assembly collapses
	// to a single parent compress (which is also the §2.5 root). Building
	// that parent by hand from two `_chunkCV` outputs must reproduce
	// BLAKE3.hash byte-for-byte.
	it('_chunkCV × 2 + _parentCV(isRoot=true) equals BLAKE3.hash for 2048B (GATE)', () => {
		// GATE
		const v     = blake3Vectors.find(r => r.inputLen === 2048);
		expect(v).toBeDefined();
		const input = expandBlake3Input(v!.inputLen);

		const composed = composeTreeRoot(HASH_MODE, input, 2);
		const direct   = HASH_MODE.hash(input);
		expect(toHex(composed)).toBe(toHex(direct));
		expect(toHex(composed)).toBe(v!.hashHex.slice(0, 64));
	});

	it('_chunkCV × 4 + 2 × _parentCV + _parentCV(isRoot=true) equals BLAKE3.hash for 4096B', () => {
		const v     = blake3Vectors.find(r => r.inputLen === 4096);
		expect(v).toBeDefined();
		const input = expandBlake3Input(v!.inputLen);

		const composed = composeTreeRoot(HASH_MODE, input, 4);
		const direct   = HASH_MODE.hash(input);
		expect(toHex(composed)).toBe(toHex(direct));
		expect(toHex(composed)).toBe(v!.hashHex.slice(0, 64));
	});

	// ─── keyed_hash (mode-flag plumbing) ───────────────────────────────────
	it('keyed: _chunkCV × 2 + _parentCV(isRoot=true) equals BLAKE3KeyedHash for 2048B', () => {
		const v     = blake3Vectors.find(r => r.inputLen === 2048);
		const input = expandBlake3Input(v!.inputLen);
		const composed = composeTreeRoot(KEYED_MODE, input, 2);
		const direct   = KEYED_MODE.hash(input);
		expect(toHex(composed)).toBe(toHex(direct));
		expect(toHex(composed)).toBe(v!.keyedHashHex.slice(0, 64));
	});

	it('keyed: _chunkCV × 4 + tree equals BLAKE3KeyedHash for 4096B', () => {
		const v     = blake3Vectors.find(r => r.inputLen === 4096);
		const input = expandBlake3Input(v!.inputLen);
		const composed = composeTreeRoot(KEYED_MODE, input, 4);
		const direct   = KEYED_MODE.hash(input);
		expect(toHex(composed)).toBe(toHex(direct));
		expect(toHex(composed)).toBe(v!.keyedHashHex.slice(0, 64));
	});

	// ─── derive_key pass 2 (CCV is starting CV) ────────────────────────────
	it('derive: _chunkCV × 2 + _parentCV(isRoot=true) equals BLAKE3DeriveKey for 2048B', () => {
		const v     = blake3Vectors.find(r => r.inputLen === 2048);
		const input = expandBlake3Input(v!.inputLen);
		const composed = composeTreeRoot(DERIVE_MODE, input, 2);
		const direct   = DERIVE_MODE.hash(input);
		expect(toHex(composed)).toBe(toHex(direct));
		expect(toHex(composed)).toBe(v!.deriveKeyHex.slice(0, 64));
	});

	it('derive: _chunkCV × 4 + tree equals BLAKE3DeriveKey for 4096B', () => {
		const v     = blake3Vectors.find(r => r.inputLen === 4096);
		const input = expandBlake3Input(v!.inputLen);
		const composed = composeTreeRoot(DERIVE_MODE, input, 4);
		const direct   = DERIVE_MODE.hash(input);
		expect(toHex(composed)).toBe(toHex(direct));
		expect(toHex(composed)).toBe(v!.deriveKeyHex.slice(0, 64));
	});
});
