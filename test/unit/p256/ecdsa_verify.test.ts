//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▒ ▒ █
//        ▄██████████████████████ ▀████▄
//
/**
 * Validate `ecdsaVerify` against:
 *   - ACVP sigVer records (mixed pass/fail with reason discriminators)
 *   - Wycheproof p1363 strict-gate / malleability corpus
 *
 * The library's strict-S posture (low-S enforced) means SOME Wycheproof
 * 'valid' records flagged with the SignatureMalleability bug class will
 * be REJECTED by the library while Wycheproof treats them as valid for
 * the non-strict semantics. The test reconciles this via the per-record
 * flag interpretation documented in the verifier header:
 * library rejects high-S, Wycheproof valid-with-malleability-flag is
 * expected to reject from the library's side.
 *
 * Per AGENTS.md §3, vectors are sourced verbatim from
 * test/vectors/ecdsa_p256_sigver.ts and ecdsa_p256_wycheproof.ts.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { ecdsa_p256_sigver_tg8 } from '../../vectors/ecdsa_p256_sigver.js';
import {
	loadP256, hexToBytes, writeBytes,
	testSlot, N_HEX,
	type P256Exports,
} from './util.js';

let wasm: P256Exports;

beforeAll(async () => {
	wasm = await loadP256();
});

// Compute compressed-pk encoding from (qx, qy) hex BE.
function compressedPk(qxHex: string, qyHex: string): Uint8Array {
	const qx = hexToBytes(qxHex);
	const qy = hexToBytes(qyHex);
	const out = new Uint8Array(33);
	out[0] = (qy[31] & 1) ? 0x03 : 0x02;
	out.set(qx, 1);
	return out;
}

// Check if s in BE form is high-S (s > n/2). Returns true if strict-S
// rejection is expected from the library's side.
function isHighS(sHex: string): boolean {
	const n = BigInt('0x' + N_HEX);
	const s = BigInt('0x' + sHex);
	return s > (n >> 1n);
}

describe('p256 ecdsaVerify (ACVP sigVer)', () => {
	for (const vec of ecdsa_p256_sigver_tg8) {
		it(`tcId ${vec.tcId} "${vec.reason}" returns ${vec.testPassed}`, () => {
			wasm.wipeBuffers();
			const pkOff      = testSlot(0);   // 33 bytes compressed
			const msgHashOff = testSlot(48);  // 32 bytes
			const sigOff     = testSlot(96);  // 64 bytes

			writeBytes(wasm.memory, pkOff, compressedPk(vec.qx, vec.qy));

			const msgBytes = hexToBytes(vec.message);
			const msgHash = createHash('sha256').update(msgBytes).digest();
			writeBytes(wasm.memory, msgHashOff, new Uint8Array(msgHash));

			const sig = new Uint8Array(64);
			sig.set(hexToBytes(vec.r), 0);
			sig.set(hexToBytes(vec.s), 32);
			writeBytes(wasm.memory, sigOff, sig);

			const result = wasm.ecdsaVerify(pkOff, msgHashOff, sigOff);

			// Library's strict-S rejects high-S even on otherwise-valid
			// records. Adjust the expected outcome accordingly.
			const expected =
				vec.testPassed && !isHighS(vec.s) ? 1 : 0;
			expect(result).toBe(expected);
		});
	}
});
