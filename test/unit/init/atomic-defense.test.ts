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
// test/unit/init/atomic-defense.test.ts
//
// Every atomic WASM-touching method on a module with stateful users must fire
// `_assertNotOwned` before touching memory, so pre-existing atomic instances
// whose cached exports were captured BEFORE a stateful acquire cannot silently
// clobber the live stateful state.
//
// Structural note: each test constructs the atomic BEFORE the stateful user,
// so the construction-time `getInstance` check passes (no owner yet). The
// method-time `_assertNotOwned` check is the sole defense that fires on the
// call.

import { describe, test, expect, beforeAll } from 'vitest';
import {
	init,
	SHA256, SHA512, SHA384, HMAC_SHA256, HMAC_SHA512, HMAC_SHA384, HKDF_SHA256,
	SHA3_256, SHA3_512, SHA3_384, SHA3_224, SHAKE128,
	ChaCha20, Poly1305, ChaCha20Poly1305, XChaCha20Poly1305, XChaCha20Cipher,
	Serpent, SerpentCtr,
	Seal,
} from '../../../src/ts/index.js';
import { _acquireModule, _releaseModule } from '../../../src/ts/init.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm, chacha20: chacha20Wasm, sha2: sha2Wasm, sha3: sha3Wasm });
});

// ── sha3 module (stateful user: SHAKE128) ───────────────────────────────────

describe('atomic defense — sha3', () => {
	test('SHA3_256.hash throws when SHAKE128 owns the module', () => {
		const atomic = new SHA3_256();
		const shake  = new SHAKE128();
		expect(() => atomic.hash(new Uint8Array([1]))).toThrow(/stateful instance is using/);
		shake.dispose();
		expect(atomic.hash(new Uint8Array([1]))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});

	test('SHA3_512.hash throws when SHAKE128 owns the module', () => {
		const atomic = new SHA3_512();
		const shake  = new SHAKE128();
		expect(() => atomic.hash(new Uint8Array([1]))).toThrow(/stateful instance is using/);
		shake.dispose();
		expect(atomic.hash(new Uint8Array([1]))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});

	test('SHA3_384.hash throws when SHAKE128 owns the module', () => {
		const atomic = new SHA3_384();
		const shake  = new SHAKE128();
		expect(() => atomic.hash(new Uint8Array([1]))).toThrow(/stateful instance is using/);
		shake.dispose();
		expect(atomic.hash(new Uint8Array([1]))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});

	test('SHA3_224.hash throws when SHAKE128 owns the module', () => {
		const atomic = new SHA3_224();
		const shake  = new SHAKE128();
		expect(() => atomic.hash(new Uint8Array([1]))).toThrow(/stateful instance is using/);
		shake.dispose();
		expect(atomic.hash(new Uint8Array([1]))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});
});

// ── chacha20 module (stateful user: ChaCha20) ───────────────────────────────

describe('atomic defense — chacha20', () => {
	test('Poly1305.mac throws when ChaCha20 owns the module', () => {
		const atomic = new Poly1305();
		const stream = new ChaCha20();
		expect(() => atomic.mac(new Uint8Array(32), new Uint8Array([1])))
			.toThrow(/stateful instance is using/);
		stream.dispose();
		expect(atomic.mac(new Uint8Array(32), new Uint8Array([1]))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});

	test('ChaCha20Poly1305.encrypt throws when ChaCha20 owns the module', () => {
		const atomic = new ChaCha20Poly1305();
		const stream = new ChaCha20();
		expect(() => atomic.encrypt(new Uint8Array(32), new Uint8Array(12), new Uint8Array([1])))
			.toThrow(/stateful instance is using/);
		stream.dispose();
		atomic.dispose();
		// Strict single-use: the ownership-throw locked `atomic`. A fresh
		// instance succeeds after dispose of the stateful owner.
		const fresh = new ChaCha20Poly1305();
		expect(fresh.encrypt(new Uint8Array(32), new Uint8Array(12), new Uint8Array([1])))
			.toBeInstanceOf(Uint8Array);
		fresh.dispose();
	});

	test('ChaCha20Poly1305.decrypt throws when ChaCha20 owns the module', () => {
		// Build a valid ciphertext pre-acquire so decrypt has something to chew on.
		const ctBuilder = new ChaCha20Poly1305();
		const key       = new Uint8Array(32);
		const nonce     = new Uint8Array(12);
		const blob      = ctBuilder.encrypt(key, nonce, new Uint8Array([1, 2, 3]));
		ctBuilder.dispose();

		const atomic = new ChaCha20Poly1305();
		const stream = new ChaCha20();
		expect(() => atomic.decrypt(key, nonce, blob)).toThrow(/stateful instance is using/);
		stream.dispose();
		expect(atomic.decrypt(key, nonce, blob)).toEqual(new Uint8Array([1, 2, 3]));
		atomic.dispose();
	});

	test('XChaCha20Poly1305.encrypt throws when ChaCha20 owns the module', () => {
		const atomic = new XChaCha20Poly1305();
		const stream = new ChaCha20();
		expect(() => atomic.encrypt(new Uint8Array(32), new Uint8Array(24), new Uint8Array([1])))
			.toThrow(/stateful instance is using/);
		stream.dispose();
		atomic.dispose();
		// Strict single-use: the ownership-throw locked `atomic`. A fresh
		// instance succeeds after dispose of the stateful owner.
		const fresh = new XChaCha20Poly1305();
		expect(fresh.encrypt(new Uint8Array(32), new Uint8Array(24), new Uint8Array([1])))
			.toBeInstanceOf(Uint8Array);
		fresh.dispose();
	});

	test('XChaCha20Poly1305.decrypt throws when ChaCha20 owns the module', () => {
		const ctBuilder = new XChaCha20Poly1305();
		const key       = new Uint8Array(32);
		const nonce     = new Uint8Array(24);
		const blob      = ctBuilder.encrypt(key, nonce, new Uint8Array([1, 2, 3]));
		ctBuilder.dispose();

		const atomic = new XChaCha20Poly1305();
		const stream = new ChaCha20();
		expect(() => atomic.decrypt(key, nonce, blob)).toThrow(/stateful instance is using/);
		stream.dispose();
		expect(atomic.decrypt(key, nonce, blob)).toEqual(new Uint8Array([1, 2, 3]));
		atomic.dispose();
	});

	test('XChaCha20Cipher.sealChunk (via Seal.encrypt) throws when ChaCha20 owns the module', () => {
		const key    = XChaCha20Cipher.keygen();
		const stream = new ChaCha20();
		// Seal.encrypt → SealStream.finalize → XChaCha20Cipher.deriveKeys + sealChunk.
		// Any of these chacha20-touching entrypoints must throw.
		expect(() => Seal.encrypt(XChaCha20Cipher, key, new Uint8Array([1, 2, 3])))
			.toThrow(/stateful instance is using/);
		stream.dispose();
		// After dispose, the same call succeeds.
		expect(Seal.encrypt(XChaCha20Cipher, key, new Uint8Array([1, 2, 3])))
			.toBeInstanceOf(Uint8Array);
	});
});

// ── serpent module (stateful user: SerpentCtr) ──────────────────────────────

describe('atomic defense — serpent', () => {
	test('Serpent.loadKey throws when SerpentCtr owns the module', () => {
		const atomic = new Serpent();
		const ctr    = new SerpentCtr({ dangerUnauthenticated: true });
		expect(() => atomic.loadKey(new Uint8Array(32))).toThrow(/stateful instance is using/);
		ctr.dispose();
		expect(() => atomic.loadKey(new Uint8Array(32))).not.toThrow();
		atomic.dispose();
	});

	test('Serpent.encryptBlock throws when SerpentCtr owns the module', () => {
		const atomic = new Serpent();
		atomic.loadKey(new Uint8Array(32));
		const ctr    = new SerpentCtr({ dangerUnauthenticated: true });
		expect(() => atomic.encryptBlock(new Uint8Array(16))).toThrow(/stateful instance is using/);
		ctr.dispose();
		expect(atomic.encryptBlock(new Uint8Array(16))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});

	test('Serpent.decryptBlock throws when SerpentCtr owns the module', () => {
		const atomic = new Serpent();
		atomic.loadKey(new Uint8Array(32));
		const ct     = atomic.encryptBlock(new Uint8Array(16));
		const ctr    = new SerpentCtr({ dangerUnauthenticated: true });
		expect(() => atomic.decryptBlock(ct)).toThrow(/stateful instance is using/);
		ctr.dispose();
		// Reload key — SerpentCtr's loadKey clobbered the schedule on acquire.
		atomic.loadKey(new Uint8Array(32));
		expect(atomic.decryptBlock(ct)).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});
});

// ── sha2 module (no stateful user today — simulate via _acquireModule) ──────

describe('atomic defense — sha2 (simulated stateful)', () => {
	test('SHA256.hash throws when sha2 is acquired by a hypothetical stateful user', () => {
		const atomic = new SHA256();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.hash(new Uint8Array([1]))).toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		expect(atomic.hash(new Uint8Array([1]))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});

	test('SHA512.hash throws when sha2 is acquired', () => {
		const atomic = new SHA512();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.hash(new Uint8Array([1]))).toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		expect(atomic.hash(new Uint8Array([1]))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});

	test('SHA384.hash throws when sha2 is acquired', () => {
		const atomic = new SHA384();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.hash(new Uint8Array([1]))).toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		expect(atomic.hash(new Uint8Array([1]))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});

	test('HMAC_SHA256.hash throws when sha2 is acquired', () => {
		const atomic = new HMAC_SHA256();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.hash(new Uint8Array(32), new Uint8Array([1])))
				.toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		expect(atomic.hash(new Uint8Array(32), new Uint8Array([1]))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});

	test('HMAC_SHA512.hash throws when sha2 is acquired', () => {
		const atomic = new HMAC_SHA512();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.hash(new Uint8Array(64), new Uint8Array([1])))
				.toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		expect(atomic.hash(new Uint8Array(64), new Uint8Array([1]))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});

	test('HMAC_SHA384.hash throws when sha2 is acquired', () => {
		const atomic = new HMAC_SHA384();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.hash(new Uint8Array(64), new Uint8Array([1])))
				.toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		expect(atomic.hash(new Uint8Array(64), new Uint8Array([1]))).toBeInstanceOf(Uint8Array);
		atomic.dispose();
	});

	test('SHA256.dispose throws when sha2 is acquired by a hypothetical stateful user', () => {
		const atomic = new SHA256();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.dispose()).toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		atomic.dispose();
	});

	test('SHA512.dispose throws when sha2 is acquired', () => {
		const atomic = new SHA512();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.dispose()).toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		atomic.dispose();
	});

	test('SHA384.dispose throws when sha2 is acquired', () => {
		const atomic = new SHA384();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.dispose()).toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		atomic.dispose();
	});

	test('HMAC_SHA256.dispose throws when sha2 is acquired', () => {
		const atomic = new HMAC_SHA256();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.dispose()).toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		atomic.dispose();
	});

	test('HMAC_SHA512.dispose throws when sha2 is acquired', () => {
		const atomic = new HMAC_SHA512();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.dispose()).toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		atomic.dispose();
	});

	test('HMAC_SHA384.dispose throws when sha2 is acquired', () => {
		const atomic = new HMAC_SHA384();
		const tok    = _acquireModule('sha2');
		try {
			expect(() => atomic.dispose()).toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		atomic.dispose();
	});
});

// ── HKDF indirection — defended via underlying HMAC ─────────────────────────

describe('atomic defense — HKDF indirection', () => {
	test('HKDF_SHA256.derive throws via its underlying HMAC_SHA256.hash when sha2 is owned', () => {
		const hkdf = new HKDF_SHA256();
		const tok  = _acquireModule('sha2');
		try {
			expect(() => hkdf.derive(new Uint8Array(32), null, new Uint8Array(8), 32))
				.toThrow(/stateful instance is using/);
		} finally {
			_releaseModule('sha2', tok);
		}
		hkdf.dispose();
	});
});
