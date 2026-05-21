//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▒ █▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓▀▓ ▓ ▓
//      ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒  ▒ █ ▒ █
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
 * BLAKE3 chunk-level dispatch coverage (§2.4 + §5.3). See
 * docs/blake3.md#chunk-level-dispatch for the dispatch counter
 * contract and the KAT regression scope.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
	loadBlake3, getBatch4CallCount, resetBatch4CallCount, toHex,
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
// of chunkBatch4 invocations consumed by that hash. Reset is done inside
// so the counter reading is exact for this call.
function hashWithDispatchCount(input: Uint8Array): { digest: Uint8Array; batchCount: number } {
	resetBatch4CallCount();
	const h = new BLAKE3();
	let digest: Uint8Array;
	try {
		digest = h.hash(input);
	} finally {
		h.dispose();
	}
	return { digest, batchCount: getBatch4CallCount() };
}

describe('BLAKE3 compress4 chunk-level dispatch coverage', () => {
	// GATE: 4096B is the smallest input that fires compress4 (one chunkBatch4 call).
	it('inputLen = 4096 dispatches exactly one 4-chunk batch', () => {
		// GATE
		const input = expandBlake3Input(4096);
		const { digest, batchCount } = hashWithDispatchCount(input);

		expect(batchCount).toBe(1);
		// Sanity-check the digest against the upstream KAT to ensure the
		// dispatch produced correct output, not just any output.
		const expected = blake3Vectors.find(v => v.inputLen === 4096)!.hashHex.slice(0, 64);
		expect(toHex(digest)).toBe(expected);
	});

	it('inputLen = 16384 dispatches four 4-chunk batches', () => {
		// 16 chunks → 4 x compress4, no trailing single-chunk work.
		const input = expandBlake3Input(16384);
		const { digest, batchCount } = hashWithDispatchCount(input);

		expect(batchCount).toBe(4);
		const expected = blake3Vectors.find(v => v.inputLen === 16384)!.hashHex.slice(0, 64);
		expect(toHex(digest)).toBe(expected);
	});

	it('inputLen = 4095 does NOT dispatch (single-chunk path only)', () => {
		// 1025..4095: multi-chunk path, but batchableBytes=0, all chunks
		// fall through to single-chunk; chunkBatch4 never fires.
		const input = expandBlake3Input(4095);
		const { batchCount } = hashWithDispatchCount(input);

		expect(batchCount).toBe(0);
	});

	it('inputLen = 5120 dispatches one batch with a trailing full chunk', () => {
		// 5 full chunks: one compress4 + trailing full chunk via single-chunk path.
		const input = expandBlake3Input(5120);
		const { digest, batchCount } = hashWithDispatchCount(input);

		expect(batchCount).toBe(1);
		const expected = blake3Vectors.find(v => v.inputLen === 5120)!.hashHex.slice(0, 64);
		expect(toHex(digest)).toBe(expected);
	});

	it('inputLen = 1024 does NOT dispatch (single-chunk path)', () => {
		// Boundary: 1024B is one chunk per §2.4; no multi-chunk path.
		const input = expandBlake3Input(1024);
		const { batchCount } = hashWithDispatchCount(input);

		expect(batchCount).toBe(0);
	});
});

describe('BLAKE3 compress4 dispatch fires across all three modes', () => {
	const MULTI_CHUNK_LEN = 4096;  // smallest input that exercises chunkBatch4

	it('hash mode dispatches compress4 for multi-chunk input', () => {
		resetBatch4CallCount();
		const input = expandBlake3Input(MULTI_CHUNK_LEN);
		const h = new BLAKE3();
		try {
			h.hash(input);
		} finally {
			h.dispose();
		}
		expect(getBatch4CallCount()).toBeGreaterThan(0);
	});

	it('keyed_hash mode dispatches compress4 for multi-chunk input', () => {
		resetBatch4CallCount();
		const input = expandBlake3Input(MULTI_CHUNK_LEN);
		const h = new BLAKE3KeyedHash();
		try {
			h.hash(KEY_BYTES, input);
		} finally {
			h.dispose();
		}
		expect(getBatch4CallCount()).toBeGreaterThan(0);
	});

	it('derive_key mode dispatches compress4 for multi-chunk material', () => {
		// derive_key pass 2 hashes `material` through the same chunk
		// pipeline as ordinary input; a 4096-byte material exercises
		// chunkBatch4 with MODE_FLAGS = FLAG_DERIVE_KEY_MATERIAL.
		// (Pass 1 hashes the short context string and never reaches the
		// multi-chunk path; pass 2 is what we want to observe here.)
		resetBatch4CallCount();
		const material = expandBlake3Input(MULTI_CHUNK_LEN);
		const h = new BLAKE3DeriveKey();
		try {
			h.derive(blake3ContextString, material);
		} finally {
			h.dispose();
		}
		expect(getBatch4CallCount()).toBeGreaterThan(0);
	});
});

describe('BLAKE3 KAT regression for dispatched-via-compress4 cases', () => {
	// Every upstream corpus record with inputLen ≥ 4096 routes some or
	// all of its chunks through chunkBatch4. Asserting bit-identical
	// output against the upstream hash on these inputs is the
	// correctness gate for the dispatch change; the dispatch is a
	// performance restructuring and must produce byte-for-byte identical
	// digests to the previous single-chunk implementation.
	const dispatchedVectors = blake3Vectors.filter(v => v.inputLen >= 4096);

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
