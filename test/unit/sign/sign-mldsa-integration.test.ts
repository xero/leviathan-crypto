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
// test/unit/sign/sign-mldsa-integration.test.ts
//
// Envelope + stream integration for ML-DSA suites. See
// docs/mldsa.md#suite-integration.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm } from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm }  from '../../../src/ts/sha3/embedded.js';
import {
	Sign, SignStream, VerifyStream,
	MlDsa65Suite, MlDsa65PreHashSuite,
} from '../../../src/ts/sign/index.js';
import { concat } from '../../../src/ts/utils.js';

beforeAll(async () => {
	_resetForTesting();
	await init({ mldsa: mldsaWasm, sha3: sha3Wasm });
});

const CTX = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
const MSG = new Uint8Array(128).map((_, i) => (i * 37 + 9) & 0xff);

describe('Sign envelope, pure suite (MlDsa65Suite)', () => {
	it('round-trips msg through real ML-DSA-65 sign/verify', () => {
		const { pk, sk } = MlDsa65Suite.keygen();
		const blob = Sign.sign(MlDsa65Suite, sk, MSG, CTX);
		const out  = Sign.verify(MlDsa65Suite, pk, blob, CTX);
		expect(out).toEqual(MSG);
	});

	it('peek matches envelope structure', () => {
		const { pk: _pk, sk } = MlDsa65Suite.keygen();
		const blob = Sign.sign(MlDsa65Suite, sk, MSG, CTX);
		const peek = Sign.peek(blob, MlDsa65Suite);
		expect(peek.suiteByte).toBe(MlDsa65Suite.formatEnum);
		expect(peek.payloadLength).toBe(MSG.length);
		expect(Array.from(peek.ctx)).toEqual(Array.from(CTX));
	});
});

describe('Sign envelope, prehash suite (MlDsa65PreHashSuite)', () => {
	it('round-trips msg through real ML-DSA-65 + SHA3-256 prehash', () => {
		const { pk, sk } = MlDsa65PreHashSuite.keygen();
		const blob = Sign.sign(MlDsa65PreHashSuite, sk, MSG, CTX);
		const out  = Sign.verify(MlDsa65PreHashSuite, pk, blob, CTX);
		expect(out).toEqual(MSG);
	});
});

describe('SignStream + VerifyStream, prehash suite (MlDsa65PreHashSuite)', () => {
	it('streaming sign output verifies via Sign.verify', () => {
		const { pk, sk } = MlDsa65PreHashSuite.keygen();
		const s = new SignStream(MlDsa65PreHashSuite, sk, CTX);
		try {
			// chunk the message so we exercise the running hash
			s.update(MSG.subarray(0, 32));
			s.update(MSG.subarray(32, 96));
			s.update(MSG.subarray(96));
			const sig = s.finalize();
			const blob = concat(s.buildPreamble(MSG.length), MSG, sig);
			const out  = Sign.verify(MlDsa65PreHashSuite, pk, blob, CTX);
			expect(out).toEqual(MSG);
		} finally {
			s.dispose();
		}
	});

	it('VerifyStream consumes the same byte stream and returns the msg', () => {
		const { pk, sk } = MlDsa65PreHashSuite.keygen();
		const s = new SignStream(MlDsa65PreHashSuite, sk, CTX);
		let blob: Uint8Array;
		try {
			s.update(MSG);
			const sig = s.finalize();
			blob = concat(s.buildPreamble(MSG.length), MSG, sig);
		} finally {
			s.dispose();
		}

		const v = new VerifyStream(MlDsa65PreHashSuite, pk, CTX);
		try {
			// feed bytes in two pieces so header + payload parsing both run
			v.update(blob.subarray(0, 1));
			v.update(blob.subarray(1));
			const out = v.finalize();
			expect(out).toEqual(MSG);
		} finally {
			v.dispose();
		}
	});
});
