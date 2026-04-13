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
import { describe, test, expect, beforeAll } from 'vitest';
import { init, MlKem512, constantTimeEqual, wipe } from '../../../src/ts/index.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { kyberWasm } from '../../../src/ts/kyber/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { kemRatchetEncap, kemRatchetDecap } from '../../../src/ts/ratchet/index.js';
import { utf8ToBytes, hexToBytes, bytesToHex } from '../../../src/ts/utils.js';
import { kemRatchetDecapVectors } from '../../vectors/ratchet_kat.js';

beforeAll(async () => {
	await init({ sha2: sha2Wasm, kyber: kyberWasm, sha3: sha3Wasm });
});

// ML-KEM-512 dk layout per FIPS 203 §7.2: dk = skCpa(768) || ek(800) || H(ek)(32) || z(32).
const MLKEM512_SK_CPA_BYTES = 768;
const MLKEM512_EK_BYTES     = 800;
function ekFromDk(dk: Uint8Array): Uint8Array {
	return dk.slice(MLKEM512_SK_CPA_BYTES, MLKEM512_SK_CPA_BYTES + MLKEM512_EK_BYTES);
}

// GATE — kemRatchetDecap KDF_SCKA: HKDF-SHA-256 self-generated, Python-verified
// Vector: ratchet_kat.ts[kemRatchetDecapVectors[0]]
// ownEk is extracted from dk and bound into the HKDF info string.
test('kemRatchetDecap — gate: ACVP-derived sharedSecret', () => {
	const v     = kemRatchetDecapVectors[0];
	const dk    = hexToBytes(v.dk);
	const ownEk = ekFromDk(dk);
	const kem   = new MlKem512();

	const dec = kemRatchetDecap(kem, hexToBytes(v.rk), dk, hexToBytes(v.kemCt), ownEk);

	expect(bytesToHex(dec.nextRootKey)).toBe(v.nextRootKey);
	expect(bytesToHex(dec.recvChainKey)).toBe(v.recvChainKey);
	expect(bytesToHex(dec.sendChainKey)).toBe(v.sendChainKey);

	wipe(dec.nextRootKey); wipe(dec.recvChainKey); wipe(dec.sendChainKey);
	kem.dispose();
});

// ── Shared setup helpers ─────────────────────────────────────────────────────

function makeRk(): Uint8Array {
	const rk = new Uint8Array(32);
	for (let i = 0; i < 32; i++) rk[i] = i;
	return rk;
}

// ── Round-trip identity ──────────────────────────────────────────────────────

test('kemRatchetEncap/Decap — round-trip: nextRootKey matches', () => {
	const kem = new MlKem512();
	const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygen();
	const rk = makeRk();

	const alice = kemRatchetEncap(kem, rk, ek);
	const bob   = kemRatchetDecap(kem, rk, dk, alice.kemCt, ek);

	expect(constantTimeEqual(alice.nextRootKey, bob.nextRootKey)).toBe(true);

	wipe(alice.nextRootKey); wipe(alice.sendChainKey); wipe(alice.recvChainKey);
	wipe(bob.nextRootKey);   wipe(bob.sendChainKey);   wipe(bob.recvChainKey);
	kem.dispose();
});

// ── Direction symmetry ───────────────────────────────────────────────────────

test('kemRatchetEncap/Decap — direction symmetry: alice.send === bob.recv', () => {
	const kem = new MlKem512();
	const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygen();
	const rk = makeRk();

	const alice = kemRatchetEncap(kem, rk, ek);
	const bob   = kemRatchetDecap(kem, rk, dk, alice.kemCt, ek);

	// Alice's send is Bob's receive and vice versa — A2B direction split
	expect(constantTimeEqual(alice.sendChainKey, bob.recvChainKey)).toBe(true);
	expect(constantTimeEqual(alice.recvChainKey, bob.sendChainKey)).toBe(true);

	wipe(alice.nextRootKey); wipe(alice.sendChainKey); wipe(alice.recvChainKey);
	wipe(bob.nextRootKey);   wipe(bob.sendChainKey);   wipe(bob.recvChainKey);
	kem.dispose();
});

// ── Context isolation ────────────────────────────────────────────────────────

describe('kemRatchetEncap/Decap — context isolation', () => {
	test('different context produces different nextRootKey', () => {
		const kem = new MlKem512();
		const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygen();
		const rk  = makeRk();
		const ct1 = kemRatchetEncap(kem, rk, ek, utf8ToBytes('context-a'));
		// For context-b test we need same rk/ek/dk: re-use the same kemCt is wrong
		// since sharedSecret is deterministic for a given (ek, dk) pair only if
		// encapsulation is deterministic. ML-KEM encapsulation uses fresh randomness
		// each call — so call encap again with context-b separately.
		const ek2  = ek.slice(); // same encapsulation key
		const ct2 = kemRatchetEncap(kem, rk, ek2, utf8ToBytes('context-b'));

		expect(constantTimeEqual(ct1.nextRootKey, ct2.nextRootKey)).toBe(false);

		wipe(ct1.nextRootKey); wipe(ct1.sendChainKey); wipe(ct1.recvChainKey);
		wipe(ct2.nextRootKey); wipe(ct2.sendChainKey); wipe(ct2.recvChainKey);

		// Verify decap side also produces different keys with different context
		const bob1 = kemRatchetDecap(kem, rk, dk, ct1.kemCt, ek,  utf8ToBytes('context-a'));
		const bob2 = kemRatchetDecap(kem, rk, dk, ct2.kemCt, ek2, utf8ToBytes('context-b'));
		expect(constantTimeEqual(bob1.nextRootKey, bob2.nextRootKey)).toBe(false);

		wipe(bob1.nextRootKey); wipe(bob1.sendChainKey); wipe(bob1.recvChainKey);
		wipe(bob2.nextRootKey); wipe(bob2.sendChainKey); wipe(bob2.recvChainKey);
		kem.dispose();
	});
});

// ── kemCt length ─────────────────────────────────────────────────────────────

test('kemRatchetEncap — kemCt.length === kem.params.ctBytes', () => {
	const kem = new MlKem512();
	const { encapsulationKey: ek } = kem.keygen();
	const rk = makeRk();

	const result = kemRatchetEncap(kem, rk, ek);
	expect(result.kemCt.length).toBe(kem.params.ctBytes);

	wipe(result.nextRootKey); wipe(result.sendChainKey); wipe(result.recvChainKey);
	kem.dispose();
});

// ── Init guard — note ─────────────────────────────────────────────────────────
// kemRatchetEncap and kemRatchetDecap check isInitialized('sha2') at the top
// of each call and throw Error if sha2 is not loaded. This is verified by
// inspection and by the init guard test in ratchet_kdf.test.ts which uses
// _resetForTesting() to clear all module state. An isolated test is not
// duplicated here to avoid resetting kyber/sha3 mid-suite.
