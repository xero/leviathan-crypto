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
import { describe, test, expect, beforeAll, afterAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { ratchetInit, KDFChain, ratchetReady } from '../../../src/ts/ratchet/index.js';
import { wipe } from '../../../src/ts/utils.js';
import {
	ratchetInitVectors,
	kdfChainVectors,
} from '../../vectors/ratchet_kat.js';

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return bytes;
}

beforeAll(async () => {
	await init({ sha2: sha2Wasm });
});

// ── ratchetInit — KAT vectors ────────────────────────────────────────────────

// GATE — ratchetInit KDF_SCKA_INIT: HKDF-SHA-256 self-generated, Python-verified
// Vector: ratchet_kat.ts[ratchetInitVectors[0]]
test('ratchetInit — gate: all-zero sk', () => {
	const v   = ratchetInitVectors[0];
	const res = ratchetInit(fromHex(v.sk));
	expect(toHex(res.nextRootKey)).toBe(v.nextRootKey);
	expect(toHex(res.sendChainKey)).toBe(v.sendChainKey);
	expect(toHex(res.recvChainKey)).toBe(v.recvChainKey);
	wipe(res.nextRootKey); wipe(res.sendChainKey); wipe(res.recvChainKey);
});

describe('ratchetInit — all KAT vectors', () => {
	for (const v of ratchetInitVectors) {
		test(`vector ${v.id}: sk=${v.sk.slice(0, 8)}… context=${v.context || '(none)'}`, () => {
			const context = v.context !== '' ? fromHex(v.context) : undefined;
			const res = ratchetInit(fromHex(v.sk), context);
			expect(toHex(res.nextRootKey)).toBe(v.nextRootKey);
			expect(toHex(res.sendChainKey)).toBe(v.sendChainKey);
			expect(toHex(res.recvChainKey)).toBe(v.recvChainKey);
			wipe(res.nextRootKey); wipe(res.sendChainKey); wipe(res.recvChainKey);
		});
	}
});

// ── KDFChain — KAT vectors ───────────────────────────────────────────────────

describe('KDFChain — KAT vectors', () => {
	for (const v of kdfChainVectors) {
		test(`chain ${v.id}: initialCk=${v.initialCk.slice(0, 8)}…`, () => {
			const chain      = new KDFChain(fromHex(v.initialCk));
			const chainState = chain as unknown as { _ck: Uint8Array };
			for (const step of v.steps) {
				const msgKey = chain.step();
				expect(chain.n).toBe(step.n);
				expect(toHex(msgKey)).toBe(step.messageKey);
				expect(toHex(chainState._ck)).toBe(step.nextChainKey);
			}
			chain.dispose();
		});
	}
});

// ── KDFChain — nextChainKey propagation ─────────────────────────────────────

describe('KDFChain — nextChainKey propagation', () => {
	test('chain 0: each step n matches vector step.n', () => {
		const v     = kdfChainVectors[0];
		const chain = new KDFChain(fromHex(v.initialCk));
		for (const step of v.steps) {
			chain.step();
			expect(chain.n).toBe(step.n);
		}
		chain.dispose();
	});

	test('chain 0: step 1 messageKey matches', () => {
		const v     = kdfChainVectors[0];
		const chain = new KDFChain(fromHex(v.initialCk));
		const mk    = chain.step();
		expect(toHex(mk)).toBe(v.steps[0].messageKey);
		chain.dispose();
	});

	test('chain 1: step 1 messageKey matches', () => {
		const v     = kdfChainVectors[1];
		const chain = new KDFChain(fromHex(v.initialCk));
		const mk    = chain.step();
		expect(toHex(mk)).toBe(v.steps[0].messageKey);
		chain.dispose();
	});

	test('chain 0: n starts at 0 before first step', () => {
		const v     = kdfChainVectors[0];
		const chain = new KDFChain(fromHex(v.initialCk));
		expect(chain.n).toBe(0);
		chain.dispose();
	});
});

// ── Guards ───────────────────────────────────────────────────────────────────

describe('dispose guard', () => {
	test('chain.step() throws after dispose()', () => {
		const chain = new KDFChain(new Uint8Array(32));
		chain.dispose();
		expect(() => chain.step()).toThrow(Error);
	});
});

describe('ratchetInit — input guards', () => {
	test('throws RangeError for sk of wrong length', () => {
		expect(() => ratchetInit(new Uint8Array(16))).toThrow(RangeError);
	});

	test('throws RangeError for sk of length 0', () => {
		expect(() => ratchetInit(new Uint8Array(0))).toThrow(RangeError);
	});

	test('empty context produces same output as no context', () => {
		const sk  = new Uint8Array(32);
		const a   = ratchetInit(sk);
		const b   = ratchetInit(sk, new Uint8Array(0));
		expect(toHex(a.nextRootKey)).toBe(toHex(b.nextRootKey));
		expect(toHex(a.sendChainKey)).toBe(toHex(b.sendChainKey));
		expect(toHex(a.recvChainKey)).toBe(toHex(b.recvChainKey));
		wipe(a.nextRootKey); wipe(a.sendChainKey); wipe(a.recvChainKey);
		wipe(b.nextRootKey); wipe(b.sendChainKey); wipe(b.recvChainKey);
	});
});

describe('KDFChain — input guards', () => {
	test('throws RangeError for ck of wrong length', () => {
		expect(() => new KDFChain(new Uint8Array(16))).toThrow(RangeError);
	});

	test('step() throws RangeError when counter is at MAX_SAFE_INTEGER', () => {
		const chain = new KDFChain(new Uint8Array(32));
		(chain as unknown as { _n: number })._n = Number.MAX_SAFE_INTEGER;
		expect(() => chain.step()).toThrow(RangeError);
		chain.dispose();
	});
});

// ── ratchetReady ─────────────────────────────────────────────────────────────

test('ratchetReady() returns true after init({ sha2 })', () => {
	expect(ratchetReady()).toBe(true);
});

// ── Init guard — isolated describe, resets and restores sha2 ─────────────────

describe('init guard — sha2 not initialized', () => {
	beforeAll(() => {
		_resetForTesting();
	});
	afterAll(async () => {
		await init({ sha2: sha2Wasm });
	});

	test('ratchetInit throws if sha2 not initialized', () => {
		expect(() => ratchetInit(new Uint8Array(32))).toThrow(Error);
	});

	test('new KDFChain throws if sha2 not initialized', () => {
		expect(() => new KDFChain(new Uint8Array(32))).toThrow(Error);
	});

	test('ratchetReady() returns false when sha2 not initialized', () => {
		expect(ratchetReady()).toBe(false);
	});
});
