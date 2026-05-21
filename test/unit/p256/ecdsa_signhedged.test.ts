//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//
/**
 * Hedged-deterministic ECDSA sign smoke test.
 *
 * The current ACVP P-256 + SHA-256 corpus transcribed at
 * test/vectors/ecdsa_p256_siggen.ts contains only componentTest=false
 * records, so there is NO hedged-path KAT we can byte-match against
 * for ecdsaSign(rnd != 0). When ACVP-Server publishes
 * componentTest=true P-256 + SHA-256 records (the hedged-with-extra-
 * entropy variant), they should be transcribed and this file should
 * gate against them.
 *
 * Until then this file confirms two looser invariants:
 *   1. Hedged sign produces a verifiable signature.
 *   2. Distinct rnd inputs produce distinct signatures (the whole
 *      point of the hedged construction is that the per-call entropy
 *      breaks the deterministic-K shape).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { loadP256, testSlot, writeBytes, hexToBytes, type P256Exports } from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

describe('p256 ecdsaSign hedged path', () => {
	it('hedged signature verifies', () => {
		wasm.wipeBuffers();
		const sk = testSlot(0);
		const pk = testSlot(32);
		const msgHash = testSlot(96);
		const rnd = testSlot(128);
		const sig = testSlot(160);

		writeBytes(wasm.memory, sk, hexToBytes(
			'00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
		));
		wasm.ecdsaKeygen(sk, pk);

		const digest = createHash('sha256').update('hedged sign test').digest();
		writeBytes(wasm.memory, msgHash, new Uint8Array(digest));
		// Non-zero rnd: routes through the hedged path.
		writeBytes(wasm.memory, rnd, new Uint8Array(32).fill(0xab));

		wasm.ecdsaSign(sk, pk, msgHash, rnd, sig);
		expect(wasm.ecdsaVerify(pk, msgHash, sig)).toBe(1);
	}, 30000);

	it('distinct rnd inputs produce distinct signatures', () => {
		wasm.wipeBuffers();
		const sk = testSlot(0);
		const pk = testSlot(32);
		const msgHash = testSlot(96);
		const rnd1 = testSlot(128);
		const rnd2 = testSlot(160);
		const sig1 = testSlot(192);
		const sig2 = testSlot(256);

		writeBytes(wasm.memory, sk, new Uint8Array(32).fill(0x99));
		wasm.ecdsaKeygen(sk, pk);

		const digest = createHash('sha256').update('msg').digest();
		writeBytes(wasm.memory, msgHash, new Uint8Array(digest));

		writeBytes(wasm.memory, rnd1, new Uint8Array(32).fill(0x11));
		writeBytes(wasm.memory, rnd2, new Uint8Array(32).fill(0x22));

		wasm.ecdsaSign(sk, pk, msgHash, rnd1, sig1);
		wasm.ecdsaSign(sk, pk, msgHash, rnd2, sig2);

		const s1 = new Uint8Array(wasm.memory.buffer, sig1, 64);
		const s2 = new Uint8Array(wasm.memory.buffer, sig2, 64);
		let diff = 0;
		for (let i = 0; i < 64; i++) diff |= s1[i] ^ s2[i];
		expect(diff).not.toBe(0);

		// Both must still verify under the same pk.
		expect(wasm.ecdsaVerify(pk, msgHash, sig1)).toBe(1);
		expect(wasm.ecdsaVerify(pk, msgHash, sig2)).toBe(1);
	}, 30000);
});
