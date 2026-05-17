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
// MemoryStorage round-trip and edge-case coverage. Local API; no
// spec citation needed.

import { describe, it, expect } from 'vitest';
import { MemoryStorage } from '../../../src/ts/index.js';

function blob(byte: number): Uint8Array {
	return new Uint8Array(32).fill(byte);
}

describe('MemoryStorage', () => {
	it('size() starts at 0', () => {
		const s = new MemoryStorage();
		expect(s.size()).toBe(0);
	});

	it('appendLeaf is monotonic, getLeaf returns the stored value', () => {
		const s = new MemoryStorage();
		s.appendLeaf(0, blob(1));
		s.appendLeaf(1, blob(2));
		s.appendLeaf(2, blob(3));
		expect(s.size()).toBe(3);
		expect(s.getLeaf(0)).toEqual(blob(1));
		expect(s.getLeaf(1)).toEqual(blob(2));
		expect(s.getLeaf(2)).toEqual(blob(3));
	});

	it('appendLeaf rejects out-of-order indices', () => {
		const s = new MemoryStorage();
		s.appendLeaf(0, blob(1));
		expect(() => s.appendLeaf(2, blob(3))).toThrow(/out-of-order/);
		expect(() => s.appendLeaf(0, blob(0))).toThrow(/out-of-order/);
		expect(s.size()).toBe(1);
	});

	it('putNode and getNode round-trip; hasNode probes without throwing', () => {
		const s = new MemoryStorage();
		expect(s.hasNode(1, 0)).toBe(false);
		s.putNode(1, 0, blob(5));
		expect(s.hasNode(1, 0)).toBe(true);
		expect(s.getNode(1, 0)).toEqual(blob(5));
		expect(s.hasNode(1, 1)).toBe(false);
	});

	it('getLeaf throws when the slot is empty', () => {
		const s = new MemoryStorage();
		expect(() => s.getLeaf(0)).toThrow(/no leaf at index/);
	});

	it('getNode throws when the slot is empty', () => {
		const s = new MemoryStorage();
		expect(() => s.getNode(3, 7)).toThrow(/no node at \(3, 7\)/);
	});

	it('overwriting putNode at the same key is permitted (last write wins)', () => {
		const s = new MemoryStorage();
		s.putNode(2, 5, blob(1));
		s.putNode(2, 5, blob(2));
		expect(s.getNode(2, 5)).toEqual(blob(2));
	});

	it('level-0 leaf slots and level-0 node slots are aliased', () => {
		// appendLeaf(0, ...) and a subsequent getNode(0, 0) read the
		// same entry. The single Map keyed on "level:index" makes leaf
		// access and proof-builder access drive the same code path.
		const s = new MemoryStorage();
		s.appendLeaf(0, blob(7));
		expect(s.getNode(0, 0)).toEqual(blob(7));
		expect(s.hasNode(0, 0)).toBe(true);
	});

	it('size() does not advance when appendLeaf throws', () => {
		const s = new MemoryStorage();
		expect(() => s.appendLeaf(1, blob(0))).toThrow();
		expect(s.size()).toBe(0);
	});
});
