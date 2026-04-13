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
import { test, expect } from '@playwright/test';

const BASE = 'http://localhost:1337';

test.beforeEach(async ({ page }) => {
	await page.goto(BASE);
});

test.describe('SPQR ratchet — e2e (MlKem768 + SerpentCipher + Seal)', () => {
	// T1 — Same-realm two-party 10-message round-trip. Validates the full
	// KEM-ratchet → KDFChain → Seal pipeline under real-browser SIMD.
	test('same-realm two-party 10-message round-trip', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			const { sha3Wasm }    = await import(`${base}/dist/sha3/embedded.js`);
			const { kyberWasm }   = await import(`${base}/dist/kyber/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm, sha3: sha3Wasm, kyber: kyberWasm });

			const kem = new lib.MlKem768();
			const { encapsulationKey: bobEk, decapsulationKey: bobDk } = kem.keygen();

			const sk    = new Uint8Array(32).fill(0x42);
			const alice = lib.ratchetInit(sk);
			const bob   = lib.ratchetInit(sk);

			const aliceEpoch = lib.kemRatchetEncap(kem, alice.nextRootKey, bobEk);
			// kemRatchetDecap signature: (kem, rk, dk, kemCt, ownEk, context?)
			// ownEk is Bob's own encapsulation key — both sides must bind the
			// identical (peerEk, kemCt) pair into the HKDF info string.
			const bobEpoch = lib.kemRatchetDecap(kem, bob.nextRootKey, bobDk, aliceEpoch.kemCt, bobEk);

			const aliceSend = new lib.KDFChain(aliceEpoch.sendChainKey);
			const bobRecv   = new lib.KDFChain(bobEpoch.recvChainKey);

			let allMatch = true;
			for (let i = 0; i < 10; i++) {
				const mkA = aliceSend.step() as Uint8Array;
				const pt  = lib.randomBytes(64) as Uint8Array;
				const ct  = lib.Seal.encrypt(lib.SerpentCipher, mkA, pt) as Uint8Array;
				const mkB = bobRecv.step() as Uint8Array;
				const dec = lib.Seal.decrypt(lib.SerpentCipher, mkB, ct) as Uint8Array;
				if (dec.length !== pt.length) {
					allMatch = false; break;
				}
				for (let j = 0; j < pt.length; j++) {
					if (dec[j] !== pt[j]) {
						allMatch = false; break;
					}
				}
				if (!allMatch) break;
			}

			aliceSend.dispose();
			bobRecv.dispose();
			kem.dispose();
			return allMatch;
		}, BASE);

		expect(result).toBe(true);
	});

	// T2 — Out-of-order delivery via SkippedKeyStore. Alice sends 5
	// messages with counters 1..5; Bob receives them as [1, 3, 2, 5, 4].
	// This exercises in-order, skip-ahead, and past-retrieve paths.
	test('out-of-order delivery via SkippedKeyStore', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			const { sha3Wasm }    = await import(`${base}/dist/sha3/embedded.js`);
			const { kyberWasm }   = await import(`${base}/dist/kyber/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm, sha3: sha3Wasm, kyber: kyberWasm });

			const kem = new lib.MlKem768();
			const { encapsulationKey: bobEk, decapsulationKey: bobDk } = kem.keygen();
			const sk    = new Uint8Array(32).fill(0x99);
			const alice = lib.ratchetInit(sk);
			const bob   = lib.ratchetInit(sk);
			const aliceEpoch = lib.kemRatchetEncap(kem, alice.nextRootKey, bobEk);
			const bobEpoch   = lib.kemRatchetDecap(kem, bob.nextRootKey, bobDk, aliceEpoch.kemCt, bobEk);
			const aliceSend  = new lib.KDFChain(aliceEpoch.sendChainKey);
			const bobRecv    = new lib.KDFChain(bobEpoch.recvChainKey);
			const bobStore   = new lib.SkippedKeyStore();

			const sent: { counter: number; pt: Uint8Array; ct: Uint8Array }[] = [];
			for (let i = 0; i < 5; i++) {
				const { key, counter } = aliceSend.stepWithCounter();
				const pt = lib.randomBytes(32) as Uint8Array;
				const ct = lib.Seal.encrypt(lib.SerpentCipher, key, pt) as Uint8Array;
				sent.push({ counter, pt, ct });
			}

			// Receive order by index into `sent`: [0, 2, 1, 4, 3] → counters [1, 3, 2, 5, 4]
			const order = [0, 2, 1, 4, 3];
			let allMatch = true;
			for (const idx of order) {
				const { counter, pt, ct } = sent[idx];
				const handle = bobStore.resolve(bobRecv, counter);
				try {
					const dec = lib.Seal.decrypt(lib.SerpentCipher, handle.key, ct) as Uint8Array;
					handle.commit();
					if (dec.length !== pt.length) {
						allMatch = false; break;
					}
					for (let j = 0; j < pt.length; j++) {
						if (dec[j] !== pt[j]) {
							allMatch = false; break;
						}
					}
					if (!allMatch) break;
				} catch (e) {
					handle.rollback();
					throw e;
				}
			}

			bobStore.wipeAll();
			aliceSend.dispose();
			bobRecv.dispose();
			kem.dispose();
			return { allMatch, storeSize: bobStore.size };
		}, BASE);

		expect(result.allMatch).toBe(true);
		expect(result.storeSize).toBe(0);
	});

	// T3 — Tamper + rollback preserves the key for legitimate retry.
	// Exercises the DoS-mitigation path documented in
	// docs/ratchet.md: rollback() returns the key to the store under the
	// same counter so a later legitimate delivery can still decrypt.
	test('tamper + rollback preserves the key for legitimate retry', async ({ page }) => {
		const result = await page.evaluate(async (base) => {
			const lib = await import(`${base}/dist/index.js`);
			const { serpentWasm } = await import(`${base}/dist/serpent/embedded.js`);
			const { sha2Wasm }    = await import(`${base}/dist/sha2/embedded.js`);
			const { sha3Wasm }    = await import(`${base}/dist/sha3/embedded.js`);
			const { kyberWasm }   = await import(`${base}/dist/kyber/embedded.js`);
			(await import(`${base}/dist/init.js`))._resetForTesting();
			await lib.init({ serpent: serpentWasm, sha2: sha2Wasm, sha3: sha3Wasm, kyber: kyberWasm });

			const kem = new lib.MlKem768();
			const { encapsulationKey: bobEk, decapsulationKey: bobDk } = kem.keygen();
			const sk    = new Uint8Array(32).fill(0x55);
			const alice = lib.ratchetInit(sk);
			const bob   = lib.ratchetInit(sk);
			const aliceEpoch = lib.kemRatchetEncap(kem, alice.nextRootKey, bobEk);
			const bobEpoch   = lib.kemRatchetDecap(kem, bob.nextRootKey, bobDk, aliceEpoch.kemCt, bobEk);
			const aliceSend  = new lib.KDFChain(aliceEpoch.sendChainKey);
			const bobRecv    = new lib.KDFChain(bobEpoch.recvChainKey);
			const bobStore   = new lib.SkippedKeyStore();

			const { key: mk, counter } = aliceSend.stepWithCounter();
			const pt = lib.randomBytes(64) as Uint8Array;
			const ct = lib.Seal.encrypt(lib.SerpentCipher, mk, pt) as Uint8Array;

			// Tamper: flip a byte inside the tag region (last 16 bytes) →
			// guaranteed auth failure.
			const tampered = ct.slice();
			tampered[tampered.length - 5] ^= 0xff;

			// First attempt — in-order resolve (chain.n = 0 → 1, key wrapped).
			const h1 = bobStore.resolve(bobRecv, counter);
			let firstThrew = false;
			try {
				lib.Seal.decrypt(lib.SerpentCipher, h1.key, tampered);
			} catch {
				firstThrew = true;
				h1.rollback();
			}
			const sizeAfterRollback = bobStore.size;

			// Legitimate retry — past-path (counter <= chain.n), pulls key
			// back out of the store.
			const h2 = bobStore.resolve(bobRecv, counter);
			const dec = lib.Seal.decrypt(lib.SerpentCipher, h2.key, ct) as Uint8Array;
			h2.commit();

			let match = dec.length === pt.length;
			if (match) {
				for (let j = 0; j < pt.length; j++) {
					if (dec[j] !== pt[j]) {
						match = false; break;
					}
				}
			}

			bobStore.wipeAll();
			aliceSend.dispose();
			bobRecv.dispose();
			kem.dispose();
			return { firstThrew, sizeAfterRollback, match, storeSizeFinal: bobStore.size };
		}, BASE);

		expect(result.firstThrew).toBe(true);
		expect(result.sizeAfterRollback).toBe(1);
		expect(result.match).toBe(true);
		expect(result.storeSizeFinal).toBe(0);
	});
});
