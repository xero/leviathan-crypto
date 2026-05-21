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
 * Ed25519 TypeScript-class smoke tests.
 *
 * Validates the public surface of `Ed25519` against a subset of the
 * RFC 8032 §7 KAT corpus plus API-edge tests (length / type validation,
 * the fault-injection pk-mismatch trap, concurrency assertion). The full
 * RFC + ACVP corpus runs at the WASM layer in
 * `test/unit/curve25519/ed25519_*.test.ts`; this file gates only the
 * wrapper API and the alias init plumbing.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init, Ed25519, isInitialized, SigningError,
	hexToBytes, bytesToHex,
} from '../../../src/ts/index.js';
import { _resetForTesting, _acquireModule, _releaseModule } from '../../../src/ts/init.js';
import { ed25519Vectors } from '../../vectors/ed25519.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const pureVecs = ed25519Vectors.filter(v => v.mode === 'pure');
const phVec    = ed25519Vectors.find(v => v.mode === 'ph')!;

beforeAll(async () => {
	_resetForTesting();
	// Pre-init guard: with no module loaded, the Ed25519 constructor must
	// throw a clear init-required error mentioning the ed25519 alias.
	expect(() => new Ed25519()).toThrow(/init\(\{ ed25519:/);
	const wasmBytes = readFileSync(join(__dirname, '../../../build/curve25519.wasm'));
	await init({ ed25519: wasmBytes });
});

describe('Ed25519 init plumbing', () => {
	it('ed25519Init alias initialises the curve25519 module', () => {
		expect(isInitialized('curve25519')).toBe(true);
	});

	it('Ed25519 constructor succeeds after init', () => {
		const ed = new Ed25519();
		expect(ed).toBeInstanceOf(Ed25519);
		ed.dispose();
	});
});

describe('Ed25519 keygen', () => {
	// GATE: deterministic keygen reproduces RFC 8032 §7.1 TEST 1 verifying key.
	for (let i = 0; i < 3; i++) {
		it(`keygenDerand matches RFC 8032 §7.1 TEST ${i + 1} verifying key`, () => {
			const ed = new Ed25519();
			try {
				const { publicKey, secretKey } = ed.keygenDerand(hexToBytes(pureVecs[i].skHex));
				expect(bytesToHex(publicKey)).toBe(pureVecs[i].pkHex);
				expect(bytesToHex(secretKey)).toBe(pureVecs[i].skHex);
			} finally {
				ed.dispose();
			}
		});
	}

	it('keygen returns a fresh 32-byte pk and 32-byte sk', () => {
		const ed = new Ed25519();
		try {
			const a = ed.keygen();
			const b = ed.keygen();
			expect(a.publicKey).toBeInstanceOf(Uint8Array);
			expect(a.secretKey).toBeInstanceOf(Uint8Array);
			expect(a.publicKey.length).toBe(32);
			expect(a.secretKey.length).toBe(32);
			// Two random keygens almost certainly differ; this catches a
			// keygen that mistakenly returns a constant seed.
			expect(bytesToHex(a.secretKey)).not.toBe(bytesToHex(b.secretKey));
		} finally {
			ed.dispose();
		}
	});
});

describe('Ed25519 sign / verify', () => {
	it('sign reproduces RFC 8032 §7.1 TEST 1 signature byte-for-byte', () => {
		const ed = new Ed25519();
		try {
			const sk  = hexToBytes(pureVecs[0].skHex);
			const pk  = hexToBytes(pureVecs[0].pkHex);
			const msg = hexToBytes(pureVecs[0].msgHex);
			const sig = ed.sign(sk, pk, msg);
			expect(bytesToHex(sig)).toBe(pureVecs[0].sigHex);
		} finally {
			ed.dispose();
		}
	});

	it('sign self-verify round-trip on a random key', () => {
		const ed = new Ed25519();
		try {
			const { publicKey, secretKey } = ed.keygen();
			const msg = new TextEncoder().encode('round-trip');
			const sig = ed.sign(secretKey, publicKey, msg);
			expect(ed.verify(publicKey, msg, sig)).toBe(true);
		} finally {
			ed.dispose();
		}
	});

	it('sign with a mismatched pk throws SigningError (fault-injection trap)', () => {
		const ed = new Ed25519();
		try {
			const sk     = hexToBytes(pureVecs[0].skHex);
			// Use TEST 2's pk against TEST 1's sk so the WASM-side derived
			// pk does not match, triggering the unreachable abort.
			const wrong  = hexToBytes(pureVecs[1].pkHex);
			const msg    = hexToBytes(pureVecs[0].msgHex);
			expect(() => ed.sign(sk, wrong, msg)).toThrow(SigningError);
		} finally {
			ed.dispose();
		}
	});

	it('verify returns true on the RFC §7.1 TEST 1 record', () => {
		const ed = new Ed25519();
		try {
			const pk  = hexToBytes(pureVecs[0].pkHex);
			const msg = hexToBytes(pureVecs[0].msgHex);
			const sig = hexToBytes(pureVecs[0].sigHex);
			expect(ed.verify(pk, msg, sig)).toBe(true);
		} finally {
			ed.dispose();
		}
	});

	it('verify returns false on a tampered message, never throws', () => {
		const ed = new Ed25519();
		try {
			const pk  = hexToBytes(pureVecs[1].pkHex);
			const msg = hexToBytes(pureVecs[1].msgHex);
			const sig = hexToBytes(pureVecs[1].sigHex);
			const tampered = new Uint8Array(msg);
			tampered[0] ^= 0x01;
			expect(ed.verify(pk, tampered, sig)).toBe(false);
		} finally {
			ed.dispose();
		}
	});

	it('verify returns false on a tampered signature, never throws', () => {
		const ed = new Ed25519();
		try {
			const pk  = hexToBytes(pureVecs[2].pkHex);
			const msg = hexToBytes(pureVecs[2].msgHex);
			const sig = hexToBytes(pureVecs[2].sigHex);
			const tampered = new Uint8Array(sig);
			tampered[0] ^= 0x01;
			expect(ed.verify(pk, msg, tampered)).toBe(false);
		} finally {
			ed.dispose();
		}
	});
});

describe('Ed25519ph prehash', () => {
	it('signPrehashed reproduces RFC 8032 §7.3 TEST abc signature', () => {
		const ed = new Ed25519();
		try {
			const sk     = hexToBytes(phVec.skHex);
			const pk     = hexToBytes(phVec.pkHex);
			const msg    = hexToBytes(phVec.msgHex);
			const digest = createHash('sha512').update(msg).digest();
			const sig    = ed.signPrehashed(sk, pk, new Uint8Array(digest), new Uint8Array(0));
			expect(bytesToHex(sig)).toBe(phVec.sigHex);
		} finally {
			ed.dispose();
		}
	});

	it('verifyPrehashed returns true on the RFC §7.3 TEST abc record', () => {
		const ed = new Ed25519();
		try {
			const pk     = hexToBytes(phVec.pkHex);
			const msg    = hexToBytes(phVec.msgHex);
			const sig    = hexToBytes(phVec.sigHex);
			const digest = new Uint8Array(createHash('sha512').update(msg).digest());
			expect(ed.verifyPrehashed(pk, digest, new Uint8Array(0), sig)).toBe(true);
		} finally {
			ed.dispose();
		}
	});
});

describe('Ed25519 input validation', () => {
	it('sign throws RangeError on a 31-byte seed', () => {
		const ed = new Ed25519();
		try {
			expect(() => ed.sign(new Uint8Array(31), new Uint8Array(32), new Uint8Array(0)))
				.toThrow(RangeError);
		} finally {
			ed.dispose();
		}
	});

	it('verify throws RangeError on a 33-byte pk', () => {
		const ed = new Ed25519();
		try {
			expect(() => ed.verify(new Uint8Array(33), new Uint8Array(0), new Uint8Array(64)))
				.toThrow(RangeError);
		} finally {
			ed.dispose();
		}
	});

	it('sign throws TypeError on a non-Uint8Array sk', () => {
		const ed = new Ed25519();
		try {
			expect(() => ed.sign('not bytes' as unknown as Uint8Array, new Uint8Array(32), new Uint8Array(0)))
				.toThrow(TypeError);
		} finally {
			ed.dispose();
		}
	});
});

describe('Ed25519 _signInternalPk / _signPrehashedInternalPk (suite helpers)', () => {
	it('_signInternalPk reproduces RFC 8032 §7.1 TEST 1 byte-for-byte', () => {
		const ed = new Ed25519();
		try {
			const sk  = hexToBytes(pureVecs[0].skHex);
			const msg = hexToBytes(pureVecs[0].msgHex);
			const sig = ed._signInternalPk(sk, msg);
			expect(bytesToHex(sig)).toBe(pureVecs[0].sigHex);
		} finally {
			ed.dispose();
		}
	});

	it('_signInternalPk output equals sign(sk, derivedPk, msg) for fresh keypairs', () => {
		const ed = new Ed25519();
		try {
			const { publicKey, secretKey } = ed.keygen();
			const msg = new TextEncoder().encode('internal-pk equivalence');
			const sigInternal = ed._signInternalPk(secretKey, msg);
			const sigExternal = ed.sign(secretKey, publicKey, msg);
			expect(bytesToHex(sigInternal)).toBe(bytesToHex(sigExternal));
		} finally {
			ed.dispose();
		}
	});

	it('_signPrehashedInternalPk reproduces RFC 8032 §7.3 TEST abc byte-for-byte', () => {
		const ed = new Ed25519();
		try {
			const sk     = hexToBytes(phVec.skHex);
			const msg    = hexToBytes(phVec.msgHex);
			const digest = new Uint8Array(createHash('sha512').update(msg).digest());
			const sig    = ed._signPrehashedInternalPk(sk, digest, new Uint8Array(0));
			expect(bytesToHex(sig)).toBe(phVec.sigHex);
		} finally {
			ed.dispose();
		}
	});

	it('_signPrehashedInternalPk output equals signPrehashed(sk, derivedPk, digest, ctx)', () => {
		const ed = new Ed25519();
		try {
			const { publicKey, secretKey } = ed.keygen();
			const digest = new Uint8Array(64).map((_, i) => (i * 31 + 7) & 0xff);
			const ctx    = new TextEncoder().encode('ph-equivalence');
			const sigInternal = ed._signPrehashedInternalPk(secretKey, digest, ctx);
			const sigExternal = ed.signPrehashed(secretKey, publicKey, digest, ctx);
			expect(bytesToHex(sigInternal)).toBe(bytesToHex(sigExternal));
		} finally {
			ed.dispose();
		}
	});
});

describe('Ed25519 concurrency assertion', () => {
	it('sign throws when the curve25519 module is held by another stateful instance', () => {
		const ed = new Ed25519();
		const tok = _acquireModule('curve25519');
		try {
			expect(() => ed.sign(new Uint8Array(32), new Uint8Array(32), new Uint8Array(0)))
				.toThrow(/another stateful instance/);
		} finally {
			_releaseModule('curve25519', tok);
			ed.dispose();
		}
	});
});
