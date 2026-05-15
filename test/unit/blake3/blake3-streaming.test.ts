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
 * BLAKE3 streaming vs one-shot equivalence, BLAKE3 §2.4 / §2.5 / §2.6.
 *
 * For each (mode, inputLen, split-pattern) tuple, the streaming class
 * fed update()/finalize() must produce the same bytes as the one-shot
 * call over the same input. The sizes deliberately cover every
 * chunk- and tree-boundary the v3 implementation touches:
 *
 *   0   - empty
 *   1   - smallest nontrivial
 *   63  - just under one block
 *   64  - exactly one block
 *   1023 - just under one chunk
 *   1024 - exactly one chunk (single-chunk §2.4 path)
 *   1025 - one chunk + 1 byte (forces tree)
 *   4096 - exactly four chunks (compress4-eligible)
 *   4097 - four chunks + 1 byte (imbalanced tree)
 *   65536 - many chunks, multi-level tree
 *
 * Split patterns per size mix "single shove" (one update) with various
 * byte-aligned and odd-aligned chunkings so the test surfaces
 * dispatch bugs in the streaming class's compress1 / compress4
 * fallback path.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
	BLAKE3, BLAKE3Stream,
	BLAKE3KeyedHash, BLAKE3KeyedHashStream,
	BLAKE3DeriveKey, BLAKE3DeriveKeyStream,
	blake3Init,
} from '../../../src/ts/blake3/index.js';
import { blake3Wasm } from '../../../src/ts/blake3/embedded.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { blake3Key, blake3ContextString } from '../../vectors/blake3.js';

const KEY_BYTES = new TextEncoder().encode(blake3Key);

function toHex(b: Uint8Array): string {
	return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

// Deterministic input pattern matching the upstream KAT convention
// (`expandBlake3Input`): byte i is (i mod 251). The same pattern is
// used here so the streamed and one-shot bytes are reproducible across
// runs and span the same algebraic input as the KAT corpus.
function makeInput(len: number): Uint8Array {
	const out = new Uint8Array(len);
	for (let i = 0; i < len; i++) out[i] = i % 251;
	return out;
}

beforeAll(async () => {
	_resetForTesting();
	await blake3Init(blake3Wasm);
});

// ────────────────────────────────────────────────────────────────────────────
// Size + split-pattern matrix
// ────────────────────────────────────────────────────────────────────────────

const SIZES = [0, 1, 63, 64, 1023, 1024, 1025, 4096, 4097, 65536] as const;

// `name` is the pattern label, `chunks(input)` returns the slice list to
// feed to update() in order. Single-byte chunking is restricted to
// inputs ≤ 1024 bytes so the test stays inside its CI timeout budget.
interface SplitPattern {
	name:   string;
	chunks: (input: Uint8Array) => Uint8Array[];
	maxLen: number;  // skip pattern if input.length exceeds this
}

function fixedSizeSplit(size: number): (input: Uint8Array) => Uint8Array[] {
	return (input) => {
		const out: Uint8Array[] = [];
		for (let off = 0; off < input.length; off += size) {
			out.push(input.subarray(off, Math.min(off + size, input.length)));
		}
		// Empty input still needs an empty slice run (no updates) — caller
		// loops over the result, which is the empty list for length 0.
		return out;
	};
}

const PATTERNS: SplitPattern[] = [
	{ name: 'whole-input',     chunks: (input) => input.length === 0 ? [] : [input], maxLen: Infinity },
	{ name: '1-byte chunks',   chunks: fixedSizeSplit(1),   maxLen: 1024 },
	{ name: '7-byte chunks',   chunks: fixedSizeSplit(7),   maxLen: 16384 },
	{ name: '64-byte chunks',  chunks: fixedSizeSplit(64),  maxLen: Infinity },
	{ name: '1024-byte chunks', chunks: fixedSizeSplit(1024), maxLen: Infinity },
];

// ────────────────────────────────────────────────────────────────────────────
// Per-mode driver pairs
// ────────────────────────────────────────────────────────────────────────────

interface ModeDriver {
	name:     string;
	oneShot:  (input: Uint8Array) => Uint8Array;
	streamed: (slices: Uint8Array[]) => Uint8Array;
}

const HASH_DRIVER: ModeDriver = {
	name: 'hash',
	oneShot: (input) => {
		const h = new BLAKE3();
		try        {
			return h.hash(input);
		} finally    {
			h.dispose();
		}
	},
	streamed: (slices) => {
		const s = new BLAKE3Stream();
		for (const c of slices) s.update(c);
		return s.finalize();
	},
};

const KEYED_DRIVER: ModeDriver = {
	name: 'keyed_hash',
	oneShot: (input) => {
		const h = new BLAKE3KeyedHash();
		try        {
			return h.hash(KEY_BYTES, input);
		} finally    {
			h.dispose();
		}
	},
	streamed: (slices) => {
		const s = new BLAKE3KeyedHashStream(KEY_BYTES);
		for (const c of slices) s.update(c);
		return s.finalize();
	},
};

const DERIVE_DRIVER: ModeDriver = {
	name: 'derive_key',
	oneShot: (input) => {
		const dk = new BLAKE3DeriveKey();
		try        {
			return dk.derive(blake3ContextString, input);
		} finally    {
			dk.dispose();
		}
	},
	streamed: (slices) => {
		const s = new BLAKE3DeriveKeyStream(blake3ContextString);
		for (const c of slices) s.update(c);
		return s.finalize();
	},
};

const DRIVERS = [HASH_DRIVER, KEYED_DRIVER, DERIVE_DRIVER];

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

describe('BLAKE3 streaming vs one-shot equivalence', () => {
	for (const driver of DRIVERS) {
		for (const inputLen of SIZES) {
			const input    = makeInput(inputLen);
			// One-shot bytes computed once per (mode, size) — the streamed
			// branches compare against this. One-shot itself is gated by
			// the KAT corpus tests in blake3-kat / keyed-hash / derive-key.
			let oneShotHex: string | null = null;

			for (const pattern of PATTERNS) {
				if (inputLen > pattern.maxLen) continue;
				it(`${driver.name}, inputLen=${inputLen}, split=${pattern.name}`, () => {
					if (oneShotHex === null) {
						oneShotHex = toHex(driver.oneShot(input));
					}
					const slices = pattern.chunks(input);
					const out    = driver.streamed(slices);
					expect(toHex(out)).toBe(oneShotHex);
				});
			}
		}
	}
});
