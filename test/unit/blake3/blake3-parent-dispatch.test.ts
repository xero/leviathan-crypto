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
 * BLAKE3 parent-level dispatch coverage (§2.5 + §5.3). See
 * docs/blake3.md#tree-level-parent-merge-dispatch for the cascade
 * table and the queue-per-level discipline.
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
		// 16 chunks: 2 L=0 batches + 1 cascaded L=1.
		const input = expandBlake3Input(16384);
		const { digest, batchCount } = hashWithParentDispatchCount(input);

		expect(batchCount).toBe(3);
		const expected = blake3Vectors.find(v => v.inputLen === 16384)!.hashHex.slice(0, 64);
		expect(toHex(digest)).toBe(expected);
	});

	it('inputLen = 32768 dispatches seven parent batches', () => {
		// 32 chunks: 4 + 2 + 1 = 7 batches.
		const input = expandBlake3Input(32768);
		const { batchCount } = hashWithParentDispatchCount(input);

		expect(batchCount).toBe(7);
	});

	it('inputLen = 65536 dispatches fifteen parent batches', () => {
		// 64 chunks: 8 + 4 + 2 + 1 = 15 batches.
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
		// Pass 1 (short context) skips multi-chunk; pass 2 with FLAG_DERIVE_KEY_MATERIAL
		// exercises parentBatch4 on 8192B material.
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
	// Bit-identical agreement against upstream KAT is the correctness gate
	// for the queue-per-level dispatch refactor.
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
