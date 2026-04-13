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
// test/unit/init/exclusivity.test.ts
//
// Stateful classes (SHAKE128/256, ChaCha20, SerpentCtr, SerpentCbc) must hold
// exclusive access to their WASM module, and any second construction (stateful
// or atomic) on the same module must throw loudly instead of silently
// clobbering shared WASM state.

import { describe, test, expect, beforeAll } from 'vitest';
import {
	init,
	SHAKE128, SHAKE256, SHA3_256,
	ChaCha20, Poly1305, ChaCha20Poly1305, XChaCha20Poly1305,
	Serpent, SerpentCtr, SerpentCbc, SerpentCipher, Seal,
	MlKem768, bytesToHex,
} from '../../../src/ts/index.js';
import { _isModuleBusy } from '../../../src/ts/init.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { kyberWasm } from '../../../src/ts/kyber/embedded.js';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

beforeAll(async () => {
	await init({
		serpent: serpentWasm,
		chacha20: chacha20Wasm,
		sha2: sha2Wasm,
		sha3: sha3Wasm,
		kyber: kyberWasm,
	});
});

// ── sha3 module ─────────────────────────────────────────────────────────────

describe('exclusivity — sha3', () => {
	test('two sequential SHAKE128 with dispose between — succeeds', () => {
		const a = new SHAKE128();
		a.dispose();
		const b = new SHAKE128();
		b.dispose();
		expect(_isModuleBusy('sha3')).toBe(false);
	});

	test('two SHAKE128 without dispose — second throws mentioning sha3', () => {
		const a = new SHAKE128();
		expect(() => new SHAKE128()).toThrow(/sha3/);
		a.dispose();
	});

	test('SHAKE128 + SHAKE256 without dispose — second throws', () => {
		const a = new SHAKE128();
		expect(() => new SHAKE256()).toThrow(/sha3/);
		a.dispose();
	});

	test('SHAKE128 + atomic SHA3_256 — atomic construction throws', () => {
		const a = new SHAKE128();
		expect(() => new SHA3_256()).toThrow(/sha3/);
		a.dispose();
	});

	test('reset() does not release the token', () => {
		const a = new SHAKE128();
		a.absorb(new Uint8Array([0x61]));
		a.squeeze(4);
		a.reset();
		expect(_isModuleBusy('sha3')).toBe(true);
		expect(() => new SHAKE128()).toThrow(/sha3/);
		a.dispose();
	});

	test('idempotent dispose — second dispose does not throw', () => {
		const a = new SHAKE128();
		a.dispose();
		expect(() => a.dispose()).not.toThrow();
		expect(_isModuleBusy('sha3')).toBe(false);
	});
});

// ── chacha20 module ─────────────────────────────────────────────────────────

describe('exclusivity — chacha20', () => {
	test('two sequential ChaCha20 with dispose between — succeeds', () => {
		const a = new ChaCha20();
		a.dispose();
		const b = new ChaCha20();
		b.dispose();
		expect(_isModuleBusy('chacha20')).toBe(false);
	});

	test('two ChaCha20 without dispose — second throws mentioning chacha20', () => {
		const a = new ChaCha20();
		expect(() => new ChaCha20()).toThrow(/chacha20/);
		a.dispose();
	});

	test('ChaCha20 + atomic Poly1305 — atomic construction throws', () => {
		const a = new ChaCha20();
		expect(() => new Poly1305()).toThrow(/chacha20/);
		a.dispose();
	});

	test('ChaCha20 + atomic ChaCha20Poly1305 — atomic construction throws', () => {
		const a = new ChaCha20();
		expect(() => new ChaCha20Poly1305()).toThrow(/chacha20/);
		a.dispose();
	});

	test('ChaCha20 + atomic XChaCha20Poly1305 — atomic construction throws', () => {
		const a = new ChaCha20();
		expect(() => new XChaCha20Poly1305()).toThrow(/chacha20/);
		a.dispose();
	});

	test('idempotent dispose — second dispose does not throw', () => {
		const a = new ChaCha20();
		a.dispose();
		expect(() => a.dispose()).not.toThrow();
		expect(_isModuleBusy('chacha20')).toBe(false);
	});
});

// ── serpent module ──────────────────────────────────────────────────────────

describe('exclusivity — serpent', () => {
	test('two sequential SerpentCtr with dispose between — succeeds', () => {
		const a = new SerpentCtr({ dangerUnauthenticated: true });
		a.dispose();
		const b = new SerpentCtr({ dangerUnauthenticated: true });
		b.dispose();
		expect(_isModuleBusy('serpent')).toBe(false);
	});

	test('two SerpentCtr without dispose — second throws mentioning serpent', () => {
		const a = new SerpentCtr({ dangerUnauthenticated: true });
		expect(() => new SerpentCtr({ dangerUnauthenticated: true })).toThrow(/serpent/);
		a.dispose();
	});

	test('two SerpentCbc without dispose — second throws mentioning serpent', () => {
		const a = new SerpentCbc({ dangerUnauthenticated: true });
		expect(() => new SerpentCbc({ dangerUnauthenticated: true })).toThrow(/serpent/);
		a.dispose();
	});

	test('SerpentCtr + SerpentCbc — second throws mentioning serpent', () => {
		const a = new SerpentCtr({ dangerUnauthenticated: true });
		expect(() => new SerpentCbc({ dangerUnauthenticated: true })).toThrow(/serpent/);
		a.dispose();
	});

	test('SerpentCtr + atomic Serpent (block) — atomic construction throws', () => {
		const a = new SerpentCtr({ dangerUnauthenticated: true });
		expect(() => new Serpent()).toThrow(/serpent/);
		a.dispose();
	});

	test('SerpentCtr blocks SerpentCipher usage (via Seal)', () => {
		const a = new SerpentCtr({ dangerUnauthenticated: true });
		const key = SerpentCipher.keygen();
		// SerpentCipher.sealChunk constructs SerpentCbc, which must acquire serpent
		expect(() => Seal.encrypt(SerpentCipher, key, new Uint8Array([1, 2, 3])))
			.toThrow(/serpent/);
		a.dispose();
	});

	test('idempotent dispose — second dispose does not throw', () => {
		const a = new SerpentCtr({ dangerUnauthenticated: true });
		a.dispose();
		expect(() => a.dispose()).not.toThrow();
		expect(_isModuleBusy('serpent')).toBe(false);
	});
});

// ── cross-module independence ───────────────────────────────────────────────

describe('exclusivity — cross-module independence', () => {
	test('SHAKE128 does not block ChaCha20', () => {
		const s = new SHAKE128();
		const c = new ChaCha20();
		expect(_isModuleBusy('sha3')).toBe(true);
		expect(_isModuleBusy('chacha20')).toBe(true);
		expect(_isModuleBusy('serpent')).toBe(false);
		c.dispose();
		s.dispose();
	});

	test('SHAKE128 does not block SerpentCtr', () => {
		const s = new SHAKE128();
		const ctr = new SerpentCtr({ dangerUnauthenticated: true });
		expect(() => new SHAKE128()).toThrow(/sha3/);
		expect(() => new SerpentCtr({ dangerUnauthenticated: true })).toThrow(/serpent/);
		ctr.dispose();
		s.dispose();
	});

	test('three stateful instances on three modules coexist', () => {
		const s = new SHAKE128();
		const c = new ChaCha20();
		const ctr = new SerpentCtr({ dangerUnauthenticated: true });
		expect(_isModuleBusy('sha3')).toBe(true);
		expect(_isModuleBusy('chacha20')).toBe(true);
		expect(_isModuleBusy('serpent')).toBe(true);
		ctr.dispose();
		c.dispose();
		s.dispose();
		expect(_isModuleBusy('sha3')).toBe(false);
		expect(_isModuleBusy('chacha20')).toBe(false);
		expect(_isModuleBusy('serpent')).toBe(false);
	});
});

// ── shared-state clobber reproducer ─────────────────────────────────────────

describe('shared-state clobber reproducer', () => {
	test('interleaved SHAKE128 now throws instead of silently clobbering', () => {
		const a = new SHAKE128();
		a.absorb(new TextEncoder().encode('alice'));
		expect(() => new SHAKE128()).toThrow(/sha3/);
		a.dispose();
	});
});

// ── post-dispose guards ─────────────────────────────────────────────────────

describe('post-dispose — SHAKE128', () => {
	test('absorb after dispose throws', () => {
		const s = new SHAKE128();
		s.dispose();
		expect(() => s.absorb(enc('x'))).toThrow(/disposed/);
	});

	test('squeeze after dispose throws', () => {
		const s = new SHAKE128();
		s.dispose();
		expect(() => s.squeeze(32)).toThrow(/disposed/);
	});

	test('reset after dispose throws', () => {
		const s = new SHAKE128();
		s.dispose();
		expect(() => s.reset()).toThrow(/disposed/);
	});

	test('hash after dispose throws', () => {
		const s = new SHAKE128();
		s.dispose();
		expect(() => s.hash(enc('x'), 32)).toThrow(/disposed/);
	});
});

describe('post-dispose — SHAKE256', () => {
	test('absorb after dispose throws', () => {
		const s = new SHAKE256();
		s.dispose();
		expect(() => s.absorb(enc('x'))).toThrow(/disposed/);
	});

	test('squeeze after dispose throws', () => {
		const s = new SHAKE256();
		s.dispose();
		expect(() => s.squeeze(32)).toThrow(/disposed/);
	});

	test('reset after dispose throws', () => {
		const s = new SHAKE256();
		s.dispose();
		expect(() => s.reset()).toThrow(/disposed/);
	});

	test('hash after dispose throws', () => {
		const s = new SHAKE256();
		s.dispose();
		expect(() => s.hash(enc('x'), 32)).toThrow(/disposed/);
	});
});

describe('post-dispose — ChaCha20', () => {
	test('beginEncrypt after dispose throws', () => {
		const c = new ChaCha20();
		c.dispose();
		expect(() => c.beginEncrypt(new Uint8Array(32), new Uint8Array(12)))
			.toThrow(/disposed/);
	});

	test('encryptChunk after dispose throws', () => {
		const c = new ChaCha20();
		c.beginEncrypt(new Uint8Array(32), new Uint8Array(12));
		c.dispose();
		expect(() => c.encryptChunk(new Uint8Array(4))).toThrow(/disposed/);
	});
});

describe('post-dispose — SerpentCtr', () => {
	test('beginEncrypt after dispose throws', () => {
		const s = new SerpentCtr({ dangerUnauthenticated: true });
		s.dispose();
		expect(() => s.beginEncrypt(new Uint8Array(32), new Uint8Array(16)))
			.toThrow(/disposed/);
	});

	test('encryptChunk after dispose throws', () => {
		const s = new SerpentCtr({ dangerUnauthenticated: true });
		s.beginEncrypt(new Uint8Array(32), new Uint8Array(16));
		s.dispose();
		expect(() => s.encryptChunk(new Uint8Array(4))).toThrow(/disposed/);
	});
});

describe('post-dispose — SerpentCbc', () => {
	test('encrypt after dispose throws', () => {
		const s = new SerpentCbc({ dangerUnauthenticated: true });
		s.dispose();
		expect(() => s.encrypt(new Uint8Array(32), new Uint8Array(16), enc('msg')))
			.toThrow(/disposed/);
	});

	test('decrypt after dispose throws', () => {
		const s = new SerpentCbc({ dangerUnauthenticated: true });
		s.dispose();
		expect(() => s.decrypt(new Uint8Array(32), new Uint8Array(16), new Uint8Array(16)))
			.toThrow(/disposed/);
	});
});

describe('post-dispose — regression: disposed call does not clobber new instance', () => {
	test('SHAKE128 disposed+new+old-call: old throws, new output uncorrupted', () => {
		const a = new SHAKE128();
		a.absorb(enc('A'));
		a.dispose();
		const b = new SHAKE128();
		b.absorb(enc('B'));
		expect(() => a.squeeze(32)).toThrow(/disposed/);
		// b's output must match a fresh instance that only absorbed 'B'
		const bOut = b.squeeze(32);
		b.dispose();
		const ref = new SHAKE128();
		ref.absorb(enc('B'));
		const refOut = ref.squeeze(32);
		ref.dispose();
		expect(bytesToHex(bOut)).toBe(bytesToHex(refOut));
	});
});

// ── kyber exclusivity — SHAKE ↔ MlKem interleave ────────────────────────────

describe('exclusivity — kyber ↔ sha3', () => {
	test('SHAKE128 live blocks MlKem768.keygen() — assertNotOwned(sha3)', () => {
		const s = new SHAKE128();
		const m = new MlKem768();
		try {
			expect(() => m.keygen()).toThrow(/sha3/);
		} finally {
			s.dispose();
		}
	});

	test('SHAKE128 live blocks MlKem768.encapsulate(ek)', () => {
		const m = new MlKem768();
		const { encapsulationKey: ek } = m.keygen();
		const s = new SHAKE128();
		try {
			expect(() => m.encapsulate(ek)).toThrow(/sha3/);
		} finally {
			s.dispose();
		}
	});

	test('SHAKE128 live blocks MlKem768.decapsulate(dk, ct)', () => {
		const m = new MlKem768();
		const { encapsulationKey: ek, decapsulationKey: dk } = m.keygen();
		const { ciphertext } = m.encapsulate(ek);
		const s = new SHAKE128();
		try {
			expect(() => m.decapsulate(dk, ciphertext)).toThrow(/sha3/);
		} finally {
			s.dispose();
		}
	});

	test('SHAKE128 live blocks MlKem768.checkEncapsulationKey(ek)', () => {
		const m = new MlKem768();
		const { encapsulationKey: ek } = m.keygen();
		const s = new SHAKE128();
		try {
			expect(() => m.checkEncapsulationKey(ek)).toThrow(/sha3/);
		} finally {
			s.dispose();
		}
	});

	test('SHAKE128 dispose + MlKem768 ops succeed (cross-module cleanup works)', () => {
		const s = new SHAKE128();
		s.absorb(enc('priming'));
		s.dispose();
		const m = new MlKem768();
		const { encapsulationKey: ek, decapsulationKey: dk } = m.keygen();
		const { ciphertext, sharedSecret: K1 } = m.encapsulate(ek);
		const K2 = m.decapsulate(dk, ciphertext);
		expect(bytesToHex(K1)).toBe(bytesToHex(K2));
	});

	test('MlKem768 atomic ops do not hold the sha3 token across calls', () => {
		const m = new MlKem768();
		m.keygen();
		// After the atomic call returns, sha3 must be unowned — a fresh SHAKE128
		// must construct without throwing.
		expect(_isModuleBusy('sha3')).toBe(false);
		const s = new SHAKE128();
		s.absorb(enc('after-kyber'));
		s.dispose();
	});

	test('MlKemBase.dispose() does NOT clobber live SHAKE128 state', () => {
		const s = new SHAKE128();
		s.absorb(enc('sensitive'));
		const m = new MlKem768();
		m.dispose();
		const out = s.squeeze(32);
		s.dispose();

		const ref = new SHAKE128();
		ref.absorb(enc('sensitive'));
		const refOut = ref.squeeze(32);
		ref.dispose();

		expect(bytesToHex(out)).toBe(bytesToHex(refOut));
	});
});
