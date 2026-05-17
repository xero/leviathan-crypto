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
 * X25519 iterated test (RFC 7748 §5), iter=1000.
 *
 * RFC 7748 §5 iterated procedure:
 *   k = 0x09 || 31 zero bytes        (initial)
 *   u = 0x09 || 31 zero bytes        (initial)
 *   for _ in 0..iter:
 *     next_k = X25519(k, u)          // clamp(k) happens inside X25519
 *     u = k                          // u becomes the RAW (pre-clamp) k
 *     k = next_k
 *   assert k == expected_k_iter
 *
 * Important: the `u = k` step uses the raw k from the previous iteration,
 * NOT the clamped form X25519 consumed internally. The high-level
 * `x25519DH` wrapper clamps a fresh copy each call and leaves skOff
 * intact, so the test loop simply passes the raw k into the sk slot and
 * lets the wrapper handle clamping.
 *
 * iter=1 is covered by `montgomery.test.ts` against the same vector
 * record and implicitly by `x25519_keygen.test.ts` (X25519(sk, 9) at the
 * basepoint); not re-tested here.
 *
 * iter=1000000 is deliberately not exercised; per the
 * docs/vector_audit.md note, the marginal correctness coverage at
 * ~5000x the iter=1000 runtime budget is too low.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { x25519Vectors } from '../../vectors/x25519.js';
import {
	loadCurve25519, bytesToHex, readBytes, writeBytes, testSlot,
	type Curve25519Exports,
} from './util.js';

let wasm: Curve25519Exports;

beforeAll(async () => {
	wasm = await loadCurve25519();
});

const SK_OFF     = testSlot(0);
const PEER_OFF   = testSlot(64);
const SHARED_OFF = testSlot(128);

describe('x25519 iterated (RFC 7748 §5)', () => {
	it('iter=1000', () => {
		const vec = x25519Vectors.find(v => v.kind === 'iterated' && v.iter === 1000);
		expect(vec).toBeDefined();
		if (vec === undefined || vec.kind !== 'iterated') return;

		wasm.wipeBuffers();

		// Initial k = u = 0x09 || 31 zero bytes (the encoded u-coord of
		// the Curve25519 basepoint per RFC 7748 §4.1).
		const init = new Uint8Array(32); init[0] = 9;
		let k: Uint8Array = init.slice();
		let u: Uint8Array = init.slice();

		for (let i = 0; i < 1000; i++) {
			writeBytes(wasm.memory, SK_OFF,   k);
			writeBytes(wasm.memory, PEER_OFF, u);
			wasm.x25519DH(SK_OFF, PEER_OFF, SHARED_OFF);
			const next = readBytes(wasm.memory, SHARED_OFF, 32);
			u = k;        // u becomes the RAW (pre-clamp) k
			k = next;
		}

		expect(bytesToHex(k)).toBe(vec.kHex);
	}, 60_000);
});
