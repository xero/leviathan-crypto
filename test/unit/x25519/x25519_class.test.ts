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
 * X25519 TypeScript-class smoke tests.
 *
 * Validates the public surface of `X25519` against the RFC 7748 §6.1
 * Alice / Bob exchange plus API-edge tests (length / type validation,
 * the all-zero shared-secret rejection on small-order peer pks, the
 * concurrency assertion). The iterated §5 corpus and the full ACVP
 * record set run at the WASM layer in
 * `test/unit/curve25519/x25519_*.test.ts`; this file gates only the
 * wrapper API and the alias init plumbing.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init, X25519, isInitialized, KeyAgreementError,
	hexToBytes, bytesToHex,
} from '../../../src/ts/index.js';
import { _resetForTesting, _acquireModule, _releaseModule } from '../../../src/ts/init.js';
import { x25519Vectors } from '../../vectors/x25519.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const exchange = x25519Vectors.find(v => v.kind === 'exchange')!;
if (exchange.kind !== 'exchange') throw new Error('x25519 vectors missing exchange record');

beforeAll(async () => {
	_resetForTesting();
	// Pre-init guard: with no module loaded, the X25519 constructor must
	// throw a clear init-required error mentioning the x25519 alias.
	expect(() => new X25519()).toThrow(/init\(\{ x25519:/);
	const wasmBytes = readFileSync(join(__dirname, '../../../build/curve25519.wasm'));
	await init({ x25519: wasmBytes });
});

describe('X25519 init plumbing', () => {
	it('x25519Init alias initialises the curve25519 module', () => {
		expect(isInitialized('curve25519')).toBe(true);
	});

	it('X25519 constructor succeeds after init', () => {
		const x = new X25519();
		expect(x).toBeInstanceOf(X25519);
		x.dispose();
	});
});

describe('X25519 keygen', () => {
	// GATE: deterministic keygen reproduces RFC 7748 §6.1 Alice public key.
	it('keygenDerand matches RFC 7748 §6.1 Alice public key', () => {
		const x = new X25519();
		try {
			const { publicKey } = x.keygenDerand(hexToBytes(exchange.aliceSkHex));
			expect(bytesToHex(publicKey)).toBe(exchange.alicePkHex);
		} finally {
			x.dispose();
		}
	});

	it('keygenDerand matches RFC 7748 §6.1 Bob public key', () => {
		const x = new X25519();
		try {
			const { publicKey } = x.keygenDerand(hexToBytes(exchange.bobSkHex));
			expect(bytesToHex(publicKey)).toBe(exchange.bobPkHex);
		} finally {
			x.dispose();
		}
	});

	it('keygen returns 32-byte pk + sk, with sk independent across calls', () => {
		const x = new X25519();
		try {
			const a = x.keygen();
			const b = x.keygen();
			expect(a.publicKey).toBeInstanceOf(Uint8Array);
			expect(a.secretKey).toBeInstanceOf(Uint8Array);
			expect(a.publicKey.length).toBe(32);
			expect(a.secretKey.length).toBe(32);
			expect(bytesToHex(a.secretKey)).not.toBe(bytesToHex(b.secretKey));
		} finally {
			x.dispose();
		}
	});
});

describe('X25519 dh', () => {
	it('dh(aliceSk, bobPk) matches RFC 7748 §6.1 shared secret', () => {
		const x = new X25519();
		try {
			const shared = x.dh(hexToBytes(exchange.aliceSkHex), hexToBytes(exchange.bobPkHex));
			expect(bytesToHex(shared)).toBe(exchange.sharedHex);
		} finally {
			x.dispose();
		}
	});

	it('dh(bobSk, alicePk) matches the same shared secret (symmetry)', () => {
		const x = new X25519();
		try {
			const shared = x.dh(hexToBytes(exchange.bobSkHex), hexToBytes(exchange.alicePkHex));
			expect(bytesToHex(shared)).toBe(exchange.sharedHex);
		} finally {
			x.dispose();
		}
	});

	it('dh throws KeyAgreementError on the all-zero u-coord peer pk', () => {
		const x = new X25519();
		try {
			const sk     = hexToBytes(exchange.aliceSkHex);
			const peerPk = new Uint8Array(32);   // u = 0
			expect(() => x.dh(sk, peerPk)).toThrow(KeyAgreementError);
		} finally {
			x.dispose();
		}
	});

	it('dh throws KeyAgreementError on the u=1 small-order peer pk', () => {
		const x = new X25519();
		try {
			const sk     = hexToBytes(exchange.aliceSkHex);
			const peerPk = new Uint8Array(32);
			peerPk[0] = 1;                       // u = 1 (small-order point)
			expect(() => x.dh(sk, peerPk)).toThrow(KeyAgreementError);
		} finally {
			x.dispose();
		}
	});
});

describe('X25519 input validation', () => {
	it('dh throws RangeError on a 31-byte sk', () => {
		const x = new X25519();
		try {
			expect(() => x.dh(new Uint8Array(31), new Uint8Array(32))).toThrow(RangeError);
		} finally {
			x.dispose();
		}
	});

	it('dh throws RangeError on a 33-byte peer pk', () => {
		const x = new X25519();
		try {
			expect(() => x.dh(new Uint8Array(32), new Uint8Array(33))).toThrow(RangeError);
		} finally {
			x.dispose();
		}
	});

	it('dh throws TypeError on a non-Uint8Array sk', () => {
		const x = new X25519();
		try {
			expect(() => x.dh('not bytes' as unknown as Uint8Array, new Uint8Array(32)))
				.toThrow(TypeError);
		} finally {
			x.dispose();
		}
	});
});

describe('X25519 concurrency assertion', () => {
	it('dh throws when the curve25519 module is held by another stateful instance', () => {
		const x = new X25519();
		const tok = _acquireModule('curve25519');
		try {
			expect(() => x.dh(new Uint8Array(32), new Uint8Array(32)))
				.toThrow(/another stateful instance/);
		} finally {
			_releaseModule('curve25519', tok);
			x.dispose();
		}
	});
});
