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
 * KEM ratchet info binding.
 *
 * `kemRatchetEncap` / `kemRatchetDecap` bind peerEk, kemCt, and (optional)
 * context into the HKDF info string with u32be length prefixes:
 *
 *   info = INFO_ROOT
 *        || u32be(|peerEk|)  || peerEk
 *        || u32be(|kemCt|)   || kemCt
 *        || u32be(|context|) || context
 *
 * Defense-in-depth: the KEM's FO transform already binds ct to the shared
 * secret, but binding these transcript fields into HKDF info means an
 * adversary who substitutes peerEk/kemCt/context in the protocol header
 * cannot induce a working chain-key trio even if the KEM somehow produced
 * a matching shared secret via re-encryption or similar.
 *
 * Test scope:
 *   1. Round-trip with new construction: encap then decap agrees.
 *   2. Wrong ownEk on decap → different nextRootKey (binding is active).
 *   3. Tampered kemCt → KEM rejects outright (FO transform catches it).
 *   4. Context still honoured (matched → agree, mismatched → differ).
 *   5. Regenerated vectors round-trip against the new construction.
 */

import { describe, test, expect, beforeAll } from 'vitest';
import { init, MlKem512, constantTimeEqual, wipe } from '../../../src/ts/index.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { kyberWasm } from '../../../src/ts/kyber/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { kemRatchetEncap, kemRatchetDecap } from '../../../src/ts/ratchet/index.js';
import { utf8ToBytes, hexToBytes, bytesToHex } from '../../../src/ts/utils.js';
import { kemRatchetDecapVectors } from '../../vectors/ratchet_kat.js';

const MLKEM512_SK_CPA_BYTES = 768;
const MLKEM512_EK_BYTES     = 800;
function ekFromDk(dk: Uint8Array): Uint8Array {
	return dk.slice(MLKEM512_SK_CPA_BYTES, MLKEM512_SK_CPA_BYTES + MLKEM512_EK_BYTES);
}

function rk(seed: number): Uint8Array {
	const r = new Uint8Array(32);
	for (let i = 0; i < 32; i++) r[i] = (seed + i) & 0xff;
	return r;
}

function wipeDecap(x: { nextRootKey: Uint8Array; sendChainKey: Uint8Array; recvChainKey: Uint8Array }): void {
	wipe(x.nextRootKey); wipe(x.sendChainKey); wipe(x.recvChainKey);
}

beforeAll(async () => {
	await init({ sha2: sha2Wasm, kyber: kyberWasm, sha3: sha3Wasm });
});

describe('kemRatchet info binding', () => {
	test('1. round-trip with new construction: identical chain keys', () => {
		const kem = new MlKem512();
		const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygen();
		const rootKey = rk(0x10);

		const alice = kemRatchetEncap(kem, rootKey, ek);
		const bob   = kemRatchetDecap(kem, rootKey, dk, alice.kemCt, ek);

		expect(constantTimeEqual(alice.nextRootKey, bob.nextRootKey)).toBe(true);
		// Alice.send === Bob.recv, Alice.recv === Bob.send (direction split)
		expect(constantTimeEqual(alice.sendChainKey, bob.recvChainKey)).toBe(true);
		expect(constantTimeEqual(alice.recvChainKey, bob.sendChainKey)).toBe(true);

		wipeDecap(alice); wipe(alice.kemCt);
		wipeDecap(bob);
		kem.dispose();
	});

	test('2. wrong ownEk on decap → different nextRootKey', () => {
		const kem = new MlKem512();

		// Generate two distinct keypairs — same dk/kemCt transcript from party A,
		// but feed party B's ek as ownEk on the decap side.
		const { encapsulationKey: ekA, decapsulationKey: dkA } = kem.keygen();
		const { encapsulationKey: ekB } = kem.keygen();
		const rootKey = rk(0x20);

		const alice = kemRatchetEncap(kem, rootKey, ekA);

		// Correct: bind alice's target ek (ekA) — round-trip agrees.
		const bobOk = kemRatchetDecap(kem, rootKey, dkA, alice.kemCt, ekA);
		expect(constantTimeEqual(alice.nextRootKey, bobOk.nextRootKey)).toBe(true);

		// Wrong: bind a different ek (ekB) — info string differs, chain keys differ.
		const bobWrong = kemRatchetDecap(kem, rootKey, dkA, alice.kemCt, ekB);
		expect(constantTimeEqual(alice.nextRootKey, bobWrong.nextRootKey)).toBe(false);
		expect(constantTimeEqual(bobOk.nextRootKey, bobWrong.nextRootKey)).toBe(false);

		wipeDecap(alice); wipe(alice.kemCt);
		wipeDecap(bobOk); wipeDecap(bobWrong);
		wipe(ekB);
		kem.dispose();
	});

	test('3. tampered kemCt → caught by KEM FO transform (implicit rejection gives different shared secret)', () => {
		const kem = new MlKem512();
		const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygen();
		const rootKey = rk(0x30);

		const alice = kemRatchetEncap(kem, rootKey, ek);
		const tampered = new Uint8Array(alice.kemCt);
		tampered[0] ^= 0x01; // flip one bit

		// ML-KEM's FO transform: a tampered ct produces an implicit-rejection
		// shared secret derived from dk's z seed — guaranteed not to match
		// Alice's sharedSecret. Result: different nextRootKey.
		const bob = kemRatchetDecap(kem, rootKey, dk, tampered, ek);
		expect(constantTimeEqual(alice.nextRootKey, bob.nextRootKey)).toBe(false);

		wipeDecap(alice); wipe(alice.kemCt);
		wipeDecap(bob);
		kem.dispose();
	});

	test('4. context is still honoured — match → agree, mismatch → differ', () => {
		const kem = new MlKem512();
		const { encapsulationKey: ek, decapsulationKey: dk } = kem.keygen();
		const rootKey = rk(0x40);
		const ctxA = utf8ToBytes('session-a');
		const ctxB = utf8ToBytes('session-b');

		const alice = kemRatchetEncap(kem, rootKey, ek, ctxA);

		const bobMatch = kemRatchetDecap(kem, rootKey, dk, alice.kemCt, ek, ctxA);
		expect(constantTimeEqual(alice.nextRootKey, bobMatch.nextRootKey)).toBe(true);

		const bobMismatch = kemRatchetDecap(kem, rootKey, dk, alice.kemCt, ek, ctxB);
		expect(constantTimeEqual(alice.nextRootKey, bobMismatch.nextRootKey)).toBe(false);

		wipeDecap(alice); wipe(alice.kemCt);
		wipeDecap(bobMatch); wipeDecap(bobMismatch);
		kem.dispose();
	});

	test('5. regenerated ratchet vectors round-trip against the new construction', () => {
		const kem = new MlKem512();
		for (const v of kemRatchetDecapVectors) {
			const dk    = hexToBytes(v.dk);
			const ownEk = ekFromDk(dk);
			const dec = kemRatchetDecap(kem, hexToBytes(v.rk), dk, hexToBytes(v.kemCt), ownEk);
			expect(bytesToHex(dec.nextRootKey)).toBe(v.nextRootKey);
			expect(bytesToHex(dec.sendChainKey)).toBe(v.sendChainKey);
			expect(bytesToHex(dec.recvChainKey)).toBe(v.recvChainKey);
			wipeDecap(dec);
		}
		kem.dispose();
	});
});
