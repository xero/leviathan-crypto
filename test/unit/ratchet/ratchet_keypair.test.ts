//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓▀▓ ▓▄▓ ▓ ▓
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
import { describe, test, expect, beforeAll } from 'vitest';
import { init, MlKem512, constantTimeEqual, wipe } from '../../../src/ts/index.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { kyberWasm } from '../../../src/ts/kyber/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { kemRatchetEncap, RatchetKeypair } from '../../../src/ts/ratchet/index.js';
import { utf8ToBytes } from '../../../src/ts/utils.js';

beforeAll(async () => {
	await init({ sha2: sha2Wasm, kyber: kyberWasm, sha3: sha3Wasm });
});

function makeRk(): Uint8Array {
	const rk = new Uint8Array(32);
	for (let i = 0; i < 32; i++) rk[i] = i;
	return rk;
}

// ── Round-trip ───────────────────────────────────────────────────────────────

describe('round-trip', () => {
	test('nextRootKey matches across encap/decap', () => {
		const kem  = new MlKem512();
		const rk   = makeRk();
		const kp   = new RatchetKeypair(kem);
		const enc  = kemRatchetEncap(kem, rk, kp.ek);
		const dec  = kp.decap(kem, rk, enc.kemCt);

		expect(constantTimeEqual(enc.nextRootKey, dec.nextRootKey)).toBe(true);

		wipe(enc.nextRootKey); wipe(enc.sendChainKey); wipe(enc.recvChainKey);
		wipe(dec.nextRootKey); wipe(dec.sendChainKey); wipe(dec.recvChainKey);
		kp.dispose();
		kem.dispose();
	});

	test('recvChainKey === encap sendChainKey (direction cross-match)', () => {
		const kem  = new MlKem512();
		const rk   = makeRk();
		const kp   = new RatchetKeypair(kem);
		const enc  = kemRatchetEncap(kem, rk, kp.ek);
		const dec  = kp.decap(kem, rk, enc.kemCt);

		// Decap side's recvChainKey equals encap side's sendChainKey
		expect(constantTimeEqual(dec.recvChainKey, enc.sendChainKey)).toBe(true);

		wipe(enc.nextRootKey); wipe(enc.sendChainKey); wipe(enc.recvChainKey);
		wipe(dec.nextRootKey); wipe(dec.sendChainKey); wipe(dec.recvChainKey);
		kp.dispose();
		kem.dispose();
	});
});

// ── Single-use guard ─────────────────────────────────────────────────────────

test('single-use guard: second decap throws', () => {
	const kem = new MlKem512();
	const rk  = makeRk();
	const kp  = new RatchetKeypair(kem);
	const enc = kemRatchetEncap(kem, rk, kp.ek);

	const dec = kp.decap(kem, rk, enc.kemCt);
	wipe(dec.nextRootKey); wipe(dec.sendChainKey); wipe(dec.recvChainKey);
	wipe(enc.nextRootKey); wipe(enc.sendChainKey); wipe(enc.recvChainKey);

	expect(() => kp.decap(kem, rk, enc.kemCt)).toThrow(Error);
	kp.dispose();
	kem.dispose();
});

// ── dispose guards ───────────────────────────────────────────────────────────

describe('dispose guards', () => {
	test('dispose after decap does not throw (idempotent)', () => {
		const kem = new MlKem512();
		const rk  = makeRk();
		const kp  = new RatchetKeypair(kem);
		const enc = kemRatchetEncap(kem, rk, kp.ek);
		const dec = kp.decap(kem, rk, enc.kemCt);
		wipe(enc.nextRootKey); wipe(enc.sendChainKey); wipe(enc.recvChainKey);
		wipe(dec.nextRootKey); wipe(dec.sendChainKey); wipe(dec.recvChainKey);

		expect(() => kp.dispose()).not.toThrow();
		kem.dispose();
	});

	test('dispose on never-used instance does not throw', () => {
		const kem = new MlKem512();
		const kp  = new RatchetKeypair(kem);
		expect(() => kp.dispose()).not.toThrow();
		kem.dispose();
	});

	test('dk wiped even when decap throws (bad rk length)', () => {
		const kem   = new MlKem512();
		const kp    = new RatchetKeypair(kem);
		const badRk = new Uint8Array(0); // RangeError: rk must be 32 bytes
		const enc   = kemRatchetEncap(kem, makeRk(), kp.ek);

		expect(() => kp.decap(kem, badRk, enc.kemCt)).toThrow(RangeError);
		// dispose() must not throw — dk was wiped in the finally block
		expect(() => kp.dispose()).not.toThrow();
		wipe(enc.nextRootKey); wipe(enc.sendChainKey); wipe(enc.recvChainKey);
		kem.dispose();
	});
});

// ── Context round-trip ───────────────────────────────────────────────────────

describe('context round-trip', () => {
	test('decap with matching context produces matching nextRootKey', () => {
		const kem = new MlKem512();
		const rk  = makeRk();
		const ctx = utf8ToBytes('test-session-a');
		const kp  = new RatchetKeypair(kem);
		const enc = kemRatchetEncap(kem, rk, kp.ek, ctx);
		const dec = kp.decap(kem, rk, enc.kemCt, ctx);

		expect(constantTimeEqual(enc.nextRootKey, dec.nextRootKey)).toBe(true);

		wipe(enc.nextRootKey); wipe(enc.sendChainKey); wipe(enc.recvChainKey);
		wipe(dec.nextRootKey); wipe(dec.sendChainKey); wipe(dec.recvChainKey);
		kp.dispose();
		kem.dispose();
	});

	test('decap with different context produces different nextRootKey', () => {
		const kem  = new MlKem512();
		const rk   = makeRk();
		const ctxA = utf8ToBytes('context-a');
		const ctxB = utf8ToBytes('context-b');

		// Encap with ctxA, decap with ctxB — context mismatch → different keys
		const kp  = new RatchetKeypair(kem);
		const enc = kemRatchetEncap(kem, rk, kp.ek, ctxA);
		const dec = kp.decap(kem, rk, enc.kemCt, ctxB);

		expect(constantTimeEqual(enc.nextRootKey, dec.nextRootKey)).toBe(false);

		wipe(enc.nextRootKey); wipe(enc.sendChainKey); wipe(enc.recvChainKey);
		wipe(dec.nextRootKey); wipe(dec.sendChainKey); wipe(dec.recvChainKey);
		kp.dispose();
		kem.dispose();
	});
});
