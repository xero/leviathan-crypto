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
// test/unit/sign/sign-hybrid-classical-vectors.test.ts
//
// KAT replay against test/vectors/sign_hybrid_classical.ts. Loads the
// eight composite-sigs Appendix E vectors (4 suites × 2 ctx variants) and
// asserts that Sign.verify accepts the spec's `s` / `sWithContext` bytes
// under the spec's pk. composite-sigs Appendix E's reference implementation
// uses hedged ML-DSA (and for the ECDSA suites, hedged ECDSA too); only the
// verify-against-spec direction is byte-stable. The KAT path here is
// verify-against-spec, not sign-and-reproduce.

import { describe, it, expect, beforeAll } from 'vitest';
import { init, hexToBytes } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { mldsaWasm }      from '../../../src/ts/mldsa/embedded.js';
import { sha3Wasm }       from '../../../src/ts/sha3/embedded.js';
import { sha2Wasm }       from '../../../src/ts/sha2/embedded.js';
import { ed25519Wasm }    from '../../../src/ts/ed25519/embedded.js';
import { p256Wasm }       from '../../../src/ts/ecdsa/embedded.js';
import { Sign } from '../../../src/ts/sign/index.js';
import type { SignatureSuite } from '../../../src/ts/sign/index.js';
import {
	MlDsa44Ed25519Suite,
	MlDsa65Ed25519Suite,
	MlDsa44EcdsaP256Suite,
	MlDsa65EcdsaP256Suite,
} from '../../../src/ts/sign/suites/hybrid-classical.js';
import { signHybridClassicalVectors } from '../../vectors/sign_hybrid_classical.js';

beforeAll(async () => {
	_resetForTesting();
	await init({
		mldsa: mldsaWasm,
		sha3: sha3Wasm,
		sha2: sha2Wasm,
		ed25519: ed25519Wasm,
		p256: p256Wasm,
	});
});

const SUITE_BY_FORMAT: Record<number, SignatureSuite> = {
	0x20: MlDsa44Ed25519Suite,
	0x21: MlDsa65Ed25519Suite,
	0x22: MlDsa44EcdsaP256Suite,
	0x23: MlDsa65EcdsaP256Suite,
};

describe('sign_hybrid_classical KAT replay', () => {
	it('has eight vectors covering four suites × two ctx variants', () => {
		expect(signHybridClassicalVectors.length).toBe(8);
		const formats = signHybridClassicalVectors
			.map((v) => v.formatEnum)
			.sort((a, b) => a - b);
		expect(formats).toEqual([0x20, 0x20, 0x21, 0x21, 0x22, 0x22, 0x23, 0x23]);
	});

	// GATE: verify the spec's `s` / `sWithContext` bytes under the spec's
	// pk for every Appendix E entry. composite-sigs Appendix E is the
	// authoritative source; a green here means the suite's M' construction,
	// PQ-first wire ordering, mldsa_ctx=Label propagation, and ECDSA-half
	// SHA-256(M') hashing all match the spec byte-for-byte.
	it.each(signHybridClassicalVectors)(
		'$id: Sign.verify returns the expected payload',
		(v) => {
			const suite = SUITE_BY_FORMAT[v.formatEnum];
			expect(suite).toBeDefined();
			const pk   = hexToBytes(v.pkHex);
			const blob = hexToBytes(v.blobHex);
			const ctx  = hexToBytes(v.ctxHex);
			const msg  = hexToBytes(v.msgHex);
			const out  = Sign.verify(suite, pk, blob, ctx);
			expect(out).toEqual(msg);
		},
	);

	it.each(signHybridClassicalVectors)(
		'$id: Sign.peek matches v3 wire offsets',
		(v) => {
			const suite = SUITE_BY_FORMAT[v.formatEnum];
			const blob  = hexToBytes(v.blobHex);
			const ctx   = hexToBytes(v.ctxHex);
			const msg   = hexToBytes(v.msgHex);
			const sig   = hexToBytes(v.sigHex);
			const peek  = Sign.peek(blob, suite);
			expect(peek.suiteByte).toBe(v.formatEnum);
			expect(peek.payloadLength).toBe(msg.length);
			expect(Array.from(peek.ctx)).toEqual(Array.from(ctx));
			// v3 envelope head: 1 (suite) + 1 (ctx_len) + ctx + 4 (payload_len BE).
			expect(peek.payloadOffset).toBe(2 + ctx.length + 4);
			// Trailing sig fills the tail; offset depends on sig length
			// (variable for ECDSA suites under composite-sigs Appendix A
			// Table 4 *).
			expect(peek.sigOffset).toBe(blob.length - sig.length);
		},
	);

	it.each(signHybridClassicalVectors)(
		'$id: catalog sizes match the recorded pk/sk/sig',
		(v) => {
			const suite = SUITE_BY_FORMAT[v.formatEnum];
			const pk   = hexToBytes(v.pkHex);
			const sk   = hexToBytes(v.skHex);
			const sig  = hexToBytes(v.sigHex);
			const blob = hexToBytes(v.blobHex);
			const msg  = hexToBytes(v.msgHex);
			const ctx  = hexToBytes(v.ctxHex);
			expect(pk.length).toBe(suite.pkSize);
			expect(sk.length).toBe(suite.skSize);
			// Fixed-length suites: sig length is exact. Variable-length
			// (ECDSA composite): sig length is bounded above by sigMaxSize.
			if (v.tradSigVariable) {
				expect(sig.length).toBeLessThanOrEqual(suite.sigMaxSize);
				expect(sig.length).toBeGreaterThanOrEqual(v.mldsaSigBytes + 8);
			} else {
				expect(sig.length).toBe(suite.sigMaxSize);
			}
			expect(blob.length).toBe(2 + ctx.length + 4 + msg.length + sig.length);
		},
	);
});
