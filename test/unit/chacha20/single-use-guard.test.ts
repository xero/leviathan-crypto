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
 * Strict single-use guard on ChaCha20Poly1305 / XChaCha20Poly1305 encrypt().
 *
 * Contract:
 *   - `_used = true` is set FIRST inside encrypt(), before any validation or
 *     WASM-touching code runs.
 *   - Any subsequent throw — validation, crypto path, anything — locks the
 *     instance. A retry will always get the single-use guard error, never a
 *     fresh length-validation error.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, ChaCha20Poly1305, XChaCha20Poly1305 } from '../../../src/ts/index.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm });
});

// ── ChaCha20Poly1305 ─────────────────────────────────────────────────────────

describe('ChaCha20Poly1305 — strict single-use guard', () => {
	it('happy path: one encrypt succeeds, a second throws the single-use error', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		aead.encrypt(key, nonce, new Uint8Array(8));

		let caught: unknown;
		try {
			aead.encrypt(key, nonce, new Uint8Array(8));
		} catch (e) {
			caught = e;
		}
		expect((caught as Error).message).toContain('encrypt() already called');
		aead.dispose();
	});

	it('crypto-path throw locks the instance — second encrypt is the single-use error, not a length error', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		// 70000 > CHUNK_SIZE (65536) → aeadEncrypt throws RangeError AFTER key/nonce length validation.
		const oversized = new Uint8Array(70_000);

		let first: unknown;
		try {
			aead.encrypt(key, nonce, oversized);
		} catch (e) {
			first = e;
		}
		expect(first).toBeInstanceOf(RangeError);
		expect((first as Error).message).toContain('exceeds');

		// Second call must be the single-use guard, proving _used was set before the failing op.
		let second: unknown;
		try {
			aead.encrypt(key, nonce, new Uint8Array(8));
		} catch (e) {
			second = e;
		}
		expect(second).toBeInstanceOf(Error);
		expect((second as Error).message).toContain('encrypt() already called');
		aead.dispose();
	});

	it('validation throw ALSO locks the instance — retry after bad key length still throws single-use', () => {
		const aead  = new ChaCha20Poly1305();
		const nonce = crypto.getRandomValues(new Uint8Array(12));

		let caught: unknown;
		try {
			aead.encrypt(new Uint8Array(31), nonce, new Uint8Array(8));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(RangeError);
		expect((caught as Error).message).toContain('key must be 32 bytes');

		// Retry with a valid key: must STILL throw single-use, not a fresh length error.
		const key = crypto.getRandomValues(new Uint8Array(32));
		let second: unknown;
		try {
			aead.encrypt(key, nonce, new Uint8Array(8));
		} catch (e) {
			second = e;
		}
		expect(second).toBeInstanceOf(Error);
		expect((second as Error).message).toContain('encrypt() already called');
		aead.dispose();
	});

	it('validation throw on nonce length ALSO locks the instance', () => {
		const aead = new ChaCha20Poly1305();
		const key  = crypto.getRandomValues(new Uint8Array(32));

		let caught: unknown;
		try {
			aead.encrypt(key, new Uint8Array(8), new Uint8Array(8));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(RangeError);
		expect((caught as Error).message).toContain('nonce must be 12 bytes');

		const nonce = crypto.getRandomValues(new Uint8Array(12));
		let second: unknown;
		try {
			aead.encrypt(key, nonce, new Uint8Array(8));
		} catch (e) {
			second = e;
		}
		expect(second).toBeInstanceOf(Error);
		expect((second as Error).message).toContain('encrypt() already called');
		aead.dispose();
	});
});

// ── XChaCha20Poly1305 ────────────────────────────────────────────────────────

describe('XChaCha20Poly1305 — strict single-use guard', () => {
	it('happy path: one encrypt succeeds, a second throws the single-use error', () => {
		const aead  = new XChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		aead.encrypt(key, nonce, new Uint8Array(8));

		let caught: unknown;
		try {
			aead.encrypt(key, nonce, new Uint8Array(8));
		} catch (e) {
			caught = e;
		}
		expect((caught as Error).message).toContain('encrypt() already called');
		aead.dispose();
	});

	it('crypto-path throw locks the instance — second encrypt is the single-use error, not a length error', () => {
		const aead  = new XChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const oversized = new Uint8Array(70_000);

		let first: unknown;
		try {
			aead.encrypt(key, nonce, oversized);
		} catch (e) {
			first = e;
		}
		expect(first).toBeInstanceOf(RangeError);
		expect((first as Error).message).toContain('exceeds');

		let second: unknown;
		try {
			aead.encrypt(key, nonce, new Uint8Array(8));
		} catch (e) {
			second = e;
		}
		expect(second).toBeInstanceOf(Error);
		expect((second as Error).message).toContain('encrypt() already called');
		aead.dispose();
	});

	it('validation throw ALSO locks the instance — retry after bad key length still throws single-use', () => {
		const aead  = new XChaCha20Poly1305();
		const nonce = crypto.getRandomValues(new Uint8Array(24));

		let caught: unknown;
		try {
			aead.encrypt(new Uint8Array(31), nonce, new Uint8Array(8));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(RangeError);
		expect((caught as Error).message).toContain('key must be 32 bytes');

		const key = crypto.getRandomValues(new Uint8Array(32));
		let second: unknown;
		try {
			aead.encrypt(key, nonce, new Uint8Array(8));
		} catch (e) {
			second = e;
		}
		expect(second).toBeInstanceOf(Error);
		expect((second as Error).message).toContain('encrypt() already called');
		aead.dispose();
	});

	it('validation throw on nonce length ALSO locks the instance', () => {
		const aead = new XChaCha20Poly1305();
		const key  = crypto.getRandomValues(new Uint8Array(32));

		let caught: unknown;
		try {
			aead.encrypt(key, new Uint8Array(12), new Uint8Array(8));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(RangeError);
		expect((caught as Error).message).toContain('XChaCha20 nonce must be 24 bytes');

		const nonce = crypto.getRandomValues(new Uint8Array(24));
		let second: unknown;
		try {
			aead.encrypt(key, nonce, new Uint8Array(8));
		} catch (e) {
			second = e;
		}
		expect(second).toBeInstanceOf(Error);
		expect((second as Error).message).toContain('encrypt() already called');
		aead.dispose();
	});
});
