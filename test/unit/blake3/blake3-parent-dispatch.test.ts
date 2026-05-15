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
 * BLAKE3 compress4 parent-level dispatch coverage, BLAKE3 §2.5 + §5.3.
 *
 * Proves the multi-chunk hash hot path drives parent merges through
 * the v128-external `compress4` kernel (via `parentBatch4` in
 * `src/asm/blake3/tree_simd.ts`) for inputs producing ≥ 8 chunks.
 * The queue-per-level discipline in `src/asm/blake3/tree.ts` defers
 * push-time merges: a chunk CV lands in level 0's queue, and when a
 * level's queue reaches 8 entries `parentBatch4` batches 4 parent
 * merges in parallel, the 4 outputs propagate to the next level's
 * queue, possibly cascading further batches at upper levels.
 *
 * The WASM module carries a test-only `parentBatch4` invocation
 * counter (held as a WASM global, not in linear memory, so
 * `wipeBuffers()` does not clear it). Each exact-count assertion
 * resets the counter, fires a hash, and verifies the counter equals
 * the predicted cascade depth for that input size.
 *
 * Predicted cascade per input size (chunks = inputLen / 1024 ceil):
 *  - 4096   B,  4 chunks: 0 batches (count[0] stays ≤ 7)
 *  - 7168   B,  7 chunks: 0 batches (count[0] stays ≤ 7)
 *  - 8192   B,  8 chunks: 1 batch at L=0 (push 8 cascades to count[1]=4)
 *  - 16384  B, 16 chunks: 3 batches (2 at L=0 from pushes 8 and 16;
 *                                    1 at L=1 when count[1] reaches 8)
 *  - 32768  B, 32 chunks: 7 batches (4 at L=0; 2 at L=1; 1 at L=2)
 *  - 65536  B, 64 chunks: 15 batches (8 at L=0; 4 at L=1; 2 at L=2;
 *                                     1 at L=3)
 *
 * Layered on top: a KAT regression over every upstream corpus record
 * with `inputLen >= 8192` confirms the queue-per-level discipline
 * produces byte-identical output to the prior ctz-stack implementation.
 * The §2.5 reorganization changes when merges happen, not what they
 * compute — so KAT regression is the bit-correctness gate.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
	loadBlake3,
	getParentBatch4CallCount, resetParentBatch4CallCount,
	toHex,
} from './helpers.js';
import {
	BLAKE3, BLAKE3KeyedHash, BLAKE3DeriveKey,
} from '../../../src/ts/blake3/index.js';
import {
	blake3Vectors, blake3Key, blake3ContextString, expandBlake3Input,
} from '../../vectors/blake3.js';

const KEY_BYTES = new TextEncoder().encode(blake3Key);

beforeAll(async () => {
	await loadBlake3();
});

// Run a one-shot BLAKE3.hash and return both the digest and the number
// of parentBatch4 invocations consumed by that hash. Reset is done
// inside so the counter reading is exact for this call.
function hashWithParentDispatchCount(input: Uint8Array): { digest: Uint8Array; batchCount: number } {
	resetParentBatch4CallCount();
	const h = new BLAKE3();
	let digest: Uint8Array;
	try {
		digest = h.hash(input);
	} finally {
		h.dispose();
	}
	return { digest, batchCount: getParentBatch4CallCount() };
}

describe('BLAKE3 compress4 parent-level dispatch coverage', () => {
	it('inputLen = 4096 dispatches zero parent batches (count[0] ≤ 7)', () => {
		const input = expandBlake3Input(4096);
		const { digest, batchCount } = hashWithParentDispatchCount(input);

		expect(batchCount).toBe(0);
		const expected = blake3Vectors.find(v => v.inputLen === 4096)!.hashHex.slice(0, 64);
		expect(toHex(digest)).toBe(expected);
	});

	it('inputLen = 7168 dispatches zero parent batches (7 chunks)', () => {
		const input = expandBlake3Input(7168);
		const { digest, batchCount } = hashWithParentDispatchCount(input);

		expect(batchCount).toBe(0);
		const expected = blake3Vectors.find(v => v.inputLen === 7168)!.hashHex.slice(0, 64);
		expect(toHex(digest)).toBe(expected);
	});

	// GATE: the smallest input that triggers parent-level dispatch. count[0]
	// reaches 8 on push 8 and fires one parentBatch4 emitting 4 CVs to
	// count[1]; finalize then drives the remaining merges through single-
	// pair `compress` only (no further batches).
	it('inputLen = 8192 dispatches exactly one parent batch', () => {
		// GATE
		const input = expandBlake3Input(8192);
		const { digest, batchCount } = hashWithParentDispatchCount(input);

		expect(batchCount).toBe(1);
		const expected = blake3Vectors.find(v => v.inputLen === 8192)!.hashHex.slice(0, 64);
		expect(toHex(digest)).toBe(expected);
	});

	it('inputLen = 16384 dispatches three parent batches', () => {
		// 16 chunks: count[0] reaches 8 twice (pushes 8 and 16 → 2 L=0
		// batches). The second L=0 batch brings count[1] from 4 to 8,
		// cascading one L=1 batch. Total: 2 + 1 = 3.
		const input = expandBlake3Input(16384);
		const { digest, batchCount } = hashWithParentDispatchCount(input);

		expect(batchCount).toBe(3);
		const expected = blake3Vectors.find(v => v.inputLen === 16384)!.hashHex.slice(0, 64);
		expect(toHex(digest)).toBe(expected);
	});

	it('inputLen = 32768 dispatches seven parent batches', () => {
		// 32 chunks: 4 L=0 batches; 2 L=1 batches; 1 L=2 batch.
		// 4 + 2 + 1 = 7.
		const input = expandBlake3Input(32768);
		const { batchCount } = hashWithParentDispatchCount(input);

		expect(batchCount).toBe(7);
	});

	it('inputLen = 65536 dispatches fifteen parent batches', () => {
		// 64 chunks: 8 L=0; 4 L=1; 2 L=2; 1 L=3. 8+4+2+1 = 15.
		const input = expandBlake3Input(65536);
		const { batchCount } = hashWithParentDispatchCount(input);

		expect(batchCount).toBe(15);
	});
});

describe('BLAKE3 compress4 parent dispatch fires across all three modes', () => {
	// 8192 bytes = 8 chunks; the smallest input that drives at least one
	// parentBatch4 dispatch.
	const MULTI_BATCH_LEN = 8192;

	it('hash mode dispatches parentBatch4 for ≥ 8-chunk input', () => {
		resetParentBatch4CallCount();
		const input = expandBlake3Input(MULTI_BATCH_LEN);
		const h = new BLAKE3();
		try {
			h.hash(input);
		} finally {
			h.dispose();
		}
		expect(getParentBatch4CallCount()).toBeGreaterThan(0);
	});

	it('keyed_hash mode dispatches parentBatch4 for ≥ 8-chunk input', () => {
		resetParentBatch4CallCount();
		const input = expandBlake3Input(MULTI_BATCH_LEN);
		const h = new BLAKE3KeyedHash();
		try {
			h.hash(KEY_BYTES, input);
		} finally {
			h.dispose();
		}
		expect(getParentBatch4CallCount()).toBeGreaterThan(0);
	});

	it('derive_key mode dispatches parentBatch4 for ≥ 8-chunk material (pass 2)', () => {
		// derive_key pass 1 hashes the short context string and never
		// reaches the multi-chunk batch threshold; pass 2 hashes
		// `material` through the same tree pipeline as ordinary input,
		// where an 8192-byte material exercises parentBatch4 with
		// MODE_FLAGS = FLAG_DERIVE_KEY_MATERIAL.
		resetParentBatch4CallCount();
		const material = expandBlake3Input(MULTI_BATCH_LEN);
		const h = new BLAKE3DeriveKey();
		try {
			h.derive(blake3ContextString, material);
		} finally {
			h.dispose();
		}
		expect(getParentBatch4CallCount()).toBeGreaterThan(0);
	});
});

describe('BLAKE3 KAT regression for dispatched-via-parentBatch4 cases', () => {
	// Every upstream corpus record with inputLen ≥ 8192 routes at least
	// one parent merge through parentBatch4. The queue-per-level
	// discipline is a tree-shape reorganization that must produce
	// byte-identical output to the prior ctz implementation. Bit-
	// identical agreement against the upstream KAT is the correctness
	// gate for the dispatch refactor.
	const dispatchedVectors = blake3Vectors.filter(v => v.inputLen >= 8192);

	for (const v of dispatchedVectors) {
		it(`hash inputLen = ${v.inputLen} matches upstream KAT`, () => {
			const input = expandBlake3Input(v.inputLen);
			const h = new BLAKE3();
			try {
				const digest = h.hash(input);
				expect(toHex(digest)).toBe(v.hashHex.slice(0, 64));
			} finally {
				h.dispose();
			}
		});
	}
});
