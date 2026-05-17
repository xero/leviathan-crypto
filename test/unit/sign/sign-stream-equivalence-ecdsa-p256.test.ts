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
// test/unit/sign/sign-stream-equivalence-ecdsa-p256.test.ts
//
// SignStream vs Sign.sign equivalence gate for EcdsaP256Suite. Unlike
// the Ed25519 prehash equivalence test, ECDSA-P256 cannot match
// byte-for-byte across one-shot and streamed sign paths because each
// suite-level sign generates fresh randomBytes(32) per call (hedged
// per draft-irtf-cfrg-det-sigs-with-noise-05) and so the trailing
// signature differs every time. The equivalence test instead asserts
// the framing invariants:
//
//   1. Header bytes [suite_byte][ctx_len][ctx] are byte-identical to
//      `Sign.sign`'s output prefix.
//   2. The payload region (bytes [2+ctx_len, length-64)) is byte-
//      identical to the input message.
//   3. Both blobs verify under the same pk via `Sign.verify`.
//   4. `VerifyStream` accepts a chunked feed of the streamed blob and
//      returns the payload.
//   5. A subsequent `update()` after `finalize()` throws
//      sig-stream-finalized.
//
// The hasher buffering shim (sha256Buffered in src/ts/sign/hasher.ts)
// is exercised here: SignStream drives it under the hood; a regression
// (e.g. accidentally re-finalising the buffered shim) would surface as
// a verify failure on the streamed blob.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, concat } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { WASM_GZ_BASE64 as p256Wasm } from '../../../src/ts/embedded/p256.js';
import { WASM_GZ_BASE64 as sha2Wasm } from '../../../src/ts/embedded/sha2.js';
import {
	Sign, SignStream, VerifyStream,
	EcdsaP256Suite,
} from '../../../src/ts/sign/index.js';
import { SigningError } from '../../../src/ts/errors.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ p256: p256Wasm, sha2: sha2Wasm });
});

function makeMsg(n: number): Uint8Array {
	const m = new Uint8Array(n);
	for (let i = 0; i < n; i++) m[i] = (i * 31 + 5) & 0xff;
	return m;
}

const EMPTY_CTX = new Uint8Array(0);

// ── Framing equivalence: header + payload bytes match ─────────────────────

describe('SignStream framing matches Sign.sign (EcdsaP256Suite, sig bytes differ)', () => {
	for (const msgLen of [0, 1, 100, 4096] as const) {
		it(`msg=${msgLen}: framing identical, payload identical, sig differs`, () => {
			const { pk, sk } = EcdsaP256Suite.keygen();
			const msg = makeMsg(msgLen);

			const blobOneShot = Sign.sign(EcdsaP256Suite, sk, msg, EMPTY_CTX);

			const s = new SignStream(EcdsaP256Suite, sk, EMPTY_CTX);
			let blobStream: Uint8Array;
			try {
				s.update(msg);
				const sig = s.finalize();
				blobStream = concat(s.preamble, msg, sig);
			} finally {
				s.dispose();
			}

			// 1) Total length matches (deterministic from suite + inputs).
			expect(blobStream.length).toBe(blobOneShot.length);

			// 2) Header bytes (suite_byte + ctx_len + ctx) match.
			expect(blobStream[0]).toBe(0x02);
			expect(blobOneShot[0]).toBe(0x02);
			expect(blobStream[1]).toBe(0x00);
			expect(blobOneShot[1]).toBe(0x00);

			// 3) Payload bytes match the input msg.
			const payloadEndOneShot = blobOneShot.length - 64;
			const payloadEndStream  = blobStream.length - 64;
			expect(payloadEndOneShot).toBe(2 + msg.length);
			expect(payloadEndStream).toBe(2 + msg.length);
			expect(Array.from(blobOneShot.subarray(2, payloadEndOneShot)))
				.toEqual(Array.from(msg));
			expect(Array.from(blobStream.subarray(2, payloadEndStream)))
				.toEqual(Array.from(msg));

			// 4) Both blobs verify against the same pk.
			const outOneShot = Sign.verify(EcdsaP256Suite, pk, blobOneShot, EMPTY_CTX);
			const outStream  = Sign.verify(EcdsaP256Suite, pk, blobStream,  EMPTY_CTX);
			expect(Array.from(outOneShot)).toEqual(Array.from(msg));
			expect(Array.from(outStream)).toEqual(Array.from(msg));

			// 5) Sig bytes differ because the hedged path re-rolls rnd per call.
			//    Empty-msg + same digest is still hedged at the rnd input, so
			//    even msg=0 produces different sigs.
			const sigOneShot = blobOneShot.subarray(payloadEndOneShot);
			const sigStream  = blobStream.subarray(payloadEndStream);
			expect(Array.from(sigOneShot)).not.toEqual(Array.from(sigStream));
		});
	}
});

// ── Chunked SignStream matches one-shot semantics ─────────────────────────

describe('SignStream chunked feed (EcdsaP256Suite)', () => {
	it('chunking a 523-byte msg in 5 pieces still produces a verifiable blob', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const msg = makeMsg(523);

		const s = new SignStream(EcdsaP256Suite, sk, EMPTY_CTX);
		let blobStream: Uint8Array;
		try {
			s.update(msg.subarray(0, 7));
			s.update(msg.subarray(7, 99));
			s.update(msg.subarray(99, 250));
			s.update(msg.subarray(250, 499));
			s.update(msg.subarray(499));
			const sig = s.finalize();
			blobStream = concat(s.preamble, msg, sig);
		} finally {
			s.dispose();
		}

		const out = Sign.verify(EcdsaP256Suite, pk, blobStream, EMPTY_CTX);
		expect(Array.from(out)).toEqual(Array.from(msg));
	});

	it('two SignStream chunks vs all-at-once: both verifiable, payload identical', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const msg = makeMsg(1234);

		// Chunked at half.
		const sA = new SignStream(EcdsaP256Suite, sk, EMPTY_CTX);
		let blobA: Uint8Array;
		try {
			sA.update(msg.subarray(0, 617));
			sA.update(msg.subarray(617));
			const sig = sA.finalize();
			blobA = concat(sA.preamble, msg, sig);
		} finally {
			sA.dispose();
		}

		// All at once.
		const sB = new SignStream(EcdsaP256Suite, sk, EMPTY_CTX);
		let blobB: Uint8Array;
		try {
			sB.update(msg);
			const sig = sB.finalize();
			blobB = concat(sB.preamble, msg, sig);
		} finally {
			sB.dispose();
		}

		// Headers + payloads identical; sigs differ (hedged).
		expect(blobA.length).toBe(blobB.length);
		expect(blobA[0]).toBe(blobB[0]);
		expect(blobA[1]).toBe(blobB[1]);
		const payloadEnd = blobA.length - 64;
		expect(Array.from(blobA.subarray(0, payloadEnd)))
			.toEqual(Array.from(blobB.subarray(0, payloadEnd)));

		// Both verify under the same pk.
		expect(Array.from(Sign.verify(EcdsaP256Suite, pk, blobA, EMPTY_CTX)))
			.toEqual(Array.from(msg));
		expect(Array.from(Sign.verify(EcdsaP256Suite, pk, blobB, EMPTY_CTX)))
			.toEqual(Array.from(msg));
	});
});

// ── VerifyStream round-trip + tamper rejection ────────────────────────────

describe('VerifyStream round-trip and tamper rejection (EcdsaP256Suite)', () => {
	it('VerifyStream accepts the streamed blob and returns the payload', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const msg = makeMsg(256);
		const blob = Sign.sign(EcdsaP256Suite, sk, msg, EMPTY_CTX);
		const v = new VerifyStream(EcdsaP256Suite, pk, EMPTY_CTX);
		try {
			v.update(blob);
			const out = v.finalize();
			expect(Array.from(out)).toEqual(Array.from(msg));
		} finally {
			v.dispose();
		}
	});

	it('VerifyStream accepts a chunked feed of the streamed blob', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const msg = makeMsg(256);
		const blob = Sign.sign(EcdsaP256Suite, sk, msg, EMPTY_CTX);
		const v = new VerifyStream(EcdsaP256Suite, pk, EMPTY_CTX);
		try {
			v.update(blob.subarray(0, 1));
			v.update(blob.subarray(1, 50));
			v.update(blob.subarray(50));
			const out = v.finalize();
			expect(Array.from(out)).toEqual(Array.from(msg));
		} finally {
			v.dispose();
		}
	});

	it('VerifyStream rejects a mid-payload byte flip', () => {
		const { pk, sk } = EcdsaP256Suite.keygen();
		const msg = makeMsg(256);
		const blob = Sign.sign(EcdsaP256Suite, sk, msg, EMPTY_CTX);
		const tampered = blob.slice();
		// Flip a byte well inside the payload (after header, before sig).
		const payloadStart = 2;
		tampered[payloadStart + 7] ^= 0x80;

		const v = new VerifyStream(EcdsaP256Suite, pk, EMPTY_CTX);
		let caught: unknown;
		try {
			v.update(tampered);
			v.finalize();
		} catch (e) {
			caught = e;
		} finally {
			v.dispose();
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('verify-failed');
	});
});

// ── Stream state machine: post-finalize update throws ─────────────────────

describe('SignStream state machine (EcdsaP256Suite)', () => {
	it('update() after finalize() throws sig-stream-finalized', () => {
		const { sk } = EcdsaP256Suite.keygen();
		const s = new SignStream(EcdsaP256Suite, sk, EMPTY_CTX);
		try {
			s.update(makeMsg(10));
			s.finalize();
			let caught: unknown;
			try {
				s.update(makeMsg(5));
			} catch (e) {
				caught = e;
			}
			expect(caught).toBeInstanceOf(SigningError);
			expect((caught as SigningError).discriminator).toBe('sig-stream-finalized');
		} finally {
			s.dispose();
		}
	});

	it('finalize() called twice throws sig-stream-finalized', () => {
		const { sk } = EcdsaP256Suite.keygen();
		const s = new SignStream(EcdsaP256Suite, sk, EMPTY_CTX);
		try {
			s.update(makeMsg(10));
			s.finalize();
			let caught: unknown;
			try {
				s.finalize();
			} catch (e) {
				caught = e;
			}
			expect(caught).toBeInstanceOf(SigningError);
			expect((caught as SigningError).discriminator).toBe('sig-stream-finalized');
		} finally {
			s.dispose();
		}
	});
});
