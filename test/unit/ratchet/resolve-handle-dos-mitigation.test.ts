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
// test/unit/ratchet/resolve-handle-dos-mitigation.test.ts
//
// Delete-on-retrieval DoS mitigation via ResolveHandle.
//
// Scenario:
//   1. Alice seals messages 1..10. Bob receives message 5 first (skip-ahead).
//   2. Attacker injects garbage for counter 3. Bob calls resolve(3), tries to
//      decrypt, auth fails → Bob calls rollback(). The store restores counter 3.
//   3. The legitimate message 3 arrives. Bob calls resolve(3) again → succeeds.
//
// A raw-key-plus-delete-on-retrieval contract would leave the legitimate
// counter-3 message unrecoverable after the attacker's forged one consumed
// the key. The handle's rollback path closes that DoS.

import { describe, test, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { KDFChain, SkippedKeyStore } from '../../../src/ts/ratchet/index.js';
import { ChaCha20Poly1305 } from '../../../src/ts/chacha20/index.js';
import { randomBytes, utf8ToBytes, bytesToUtf8 } from '../../../src/ts/utils.js';

beforeAll(async () => {
	await init({ sha2: sha2Wasm, chacha20: chacha20Wasm });
});

describe('resolve-handle DoS mitigation', () => {
	test('rollback on auth failure preserves the legitimate message key', () => {
		// ── Alice side — derive 10 message keys and encrypt 10 messages ──────
		const sharedChainKey = new Uint8Array(32);
		sharedChainKey.fill(0x5A);

		const aliceChain = new KDFChain(sharedChainKey.slice());
		const messages:  Uint8Array[] = [];
		const keysTaped: Uint8Array[] = []; // kept copies so we can verify later

		for (let i = 1; i <= 10; i++) {
			const key = aliceChain.step();
			keysTaped.push(key.slice());
			const nonce = new Uint8Array(12);
			// Bind nonce to counter i (deterministic: i in last 4 bytes BE)
			new DataView(nonce.buffer).setUint32(8, i, false);
			const aead = new ChaCha20Poly1305();
			const pt  = utf8ToBytes(`msg-${i}`);
			const ct  = aead.encrypt(key, nonce, pt);
			messages.push(ct);
			aead.dispose();
		}
		aliceChain.dispose();

		// ── Bob side — reconstruct chain, use SkippedKeyStore for OOO ────────
		const bobChain = new KDFChain(sharedChainKey.slice());
		const bobStore = new SkippedKeyStore();

		// 1. Bob receives message 5 first — skip-ahead, commit on success.
		const h5 = bobStore.resolve(bobChain, 5);
		const nonce5 = new Uint8Array(12);
		new DataView(nonce5.buffer).setUint32(8, 5, false);
		{
			const aead = new ChaCha20Poly1305();
			const pt   = aead.decrypt(h5.key, nonce5, messages[4]);
			expect(bytesToUtf8(pt)).toBe('msg-5');
			aead.dispose();
		}
		h5.commit();
		expect(bobStore.size).toBe(4); // counters 1..4 stored

		// 2. Attacker injects garbage ciphertext for counter 3.
		//    Bob calls resolve(3), tries to decrypt, auth fails, rollback.
		const nonce3 = new Uint8Array(12);
		new DataView(nonce3.buffer).setUint32(8, 3, false);
		const garbage = new Uint8Array(messages[2].length);
		crypto.getRandomValues(garbage);

		const hBad = bobStore.resolve(bobChain, 3);
		expect(bobStore.size).toBe(3); // counter 3 pulled out
		let decryptThrew = false;
		try {
			const aead = new ChaCha20Poly1305();
			try {
				aead.decrypt(hBad.key, nonce3, garbage);
			} finally {
				aead.dispose();
			}
		} catch {
			decryptThrew = true;
		}
		expect(decryptThrew).toBe(true);
		hBad.rollback();
		expect(bobStore.size).toBe(4); // counter 3 restored

		// 3. The legitimate message 3 arrives. Bob resolves again and decrypts.
		const hGood = bobStore.resolve(bobChain, 3);
		{
			const aead = new ChaCha20Poly1305();
			const pt   = aead.decrypt(hGood.key, nonce3, messages[2]);
			expect(bytesToUtf8(pt)).toBe('msg-3');
			aead.dispose();
		}
		hGood.commit();
		expect(bobStore.size).toBe(3); // counter 3 consumed for real this time

		bobStore.wipeAll();
		bobChain.dispose();
		for (const k of keysTaped) k.fill(0);
	});

	test('rollback permits arbitrarily many auth failures without consuming the key', () => {
		// Harder version — the attacker sends N garbage ciphertexts at counter 3.
		// Every one triggers resolve + rollback. The real message still decrypts.
		const sharedChainKey = new Uint8Array(32).fill(0xC3);

		const aliceChain = new KDFChain(sharedChainKey.slice());
		for (let i = 0; i < 4; i++) aliceChain.step(); // burn 1..4
		const realKey = aliceChain.step(); // counter 5
		const nonce = new Uint8Array(12);
		new DataView(nonce.buffer).setUint32(8, 5, false);

		const aead = new ChaCha20Poly1305();
		const realCt = aead.encrypt(realKey, nonce, utf8ToBytes('the-real-one'));
		aead.dispose();

		const bobChain = new KDFChain(sharedChainKey.slice());
		const bobStore = new SkippedKeyStore();

		// Bob receives message 10 first to push counter 5 into the store.
		const h10 = bobStore.resolve(bobChain, 10);
		h10.rollback();           // we don't care about 10 — put it back
		expect(bobStore.size).toBe(10); // counters 1..10

		// Attacker floods Bob with 20 garbage ciphertexts at counter 5.
		for (let i = 0; i < 20; i++) {
			const garbage = randomBytes(realCt.length);
			const h = bobStore.resolve(bobChain, 5);
			let threw = false;
			try {
				const a = new ChaCha20Poly1305();
				try {
					a.decrypt(h.key, nonce, garbage);
				} finally {
					a.dispose();
				}
			} catch {
				threw = true;
			}
			expect(threw).toBe(true);
			h.rollback();
		}
		expect(bobStore.size).toBe(10);

		// Real message arrives.
		const hReal = bobStore.resolve(bobChain, 5);
		const aReal = new ChaCha20Poly1305();
		const pt    = aReal.decrypt(hReal.key, nonce, realCt);
		aReal.dispose();
		expect(bytesToUtf8(pt)).toBe('the-real-one');
		hReal.commit();

		bobStore.wipeAll();
		bobChain.dispose();
		aliceChain.dispose();
	});
});
