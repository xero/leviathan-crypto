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
 * ChaCha20-Poly1305 AEAD test vectors + phase 2 behavioral tests.
 *
 * Source: RFC 8439, "ChaCha20 and Poly1305 for IETF Protocols", May 2018
 * URL: https://www.rfc-editor.org/rfc/rfc8439
 * Sections: §2.8 (AEAD construction), §2.8.2 (sunscreen example)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, ChaCha20Poly1305, AuthenticationError } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import type { ChaChaExports } from '../../../src/ts/chacha20/types.js';
import { chacha20Poly1305Vectors } from '../../vectors/chacha20.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { aeadEncrypt } from '../../../src/ts/chacha20/ops.js';

const toHex = (b: Uint8Array): string =>
	Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

const fromHex = (hex: string): Uint8Array =>
	Uint8Array.from(hex.match(/.{2}/g)!.map(b => parseInt(b, 16)));

function getWasm() {
	return getInstance('chacha20').exports as unknown as ChaChaExports;
}

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm });
});

// RFC 8439 §2.8.2 test vector
const TV       = chacha20Poly1305Vectors[0];
const RFC_KEY   = fromHex(TV.key);
const RFC_NONCE = fromHex(TV.nonce);
const RFC_AAD   = fromHex(TV.aad);
const RFC_PT    = new TextEncoder().encode(TV.ptText!);
const RFC_CT    = fromHex(TV.ct);
const RFC_TAG   = fromHex(TV.tag);

describe('ChaCha20-Poly1305 AEAD — RFC 8439', () => {

	// GATE — ChaCha20-Poly1305 AEAD: RFC 8439 §2.8.2
	// Vector: chacha20.ts[chacha20Poly1305Vectors[0]]
	it('encrypt — RFC 8439 §2.8.2 sunscreen vector', () => {
		const aead   = new ChaCha20Poly1305();
		const sealed = aead.encrypt(RFC_KEY, RFC_NONCE, RFC_PT, RFC_AAD);
		expect(toHex(sealed.slice(0, -16))).toBe(toHex(RFC_CT));
		expect(toHex(sealed.slice(-16))).toBe(toHex(RFC_TAG));
		aead.dispose();
	});

	it('decrypt — RFC 8439 §2.8.2 sunscreen vector recovers plaintext', () => {
		const aead = new ChaCha20Poly1305();
		const combined = new Uint8Array(RFC_CT.length + 16);
		combined.set(RFC_CT);
		combined.set(RFC_TAG, RFC_CT.length);
		const pt = aead.decrypt(RFC_KEY, RFC_NONCE, combined, RFC_AAD);
		expect(new TextDecoder().decode(pt)).toBe(TV.ptText);
		aead.dispose();
	});

	// Round-trips
	it('round-trip: 64-byte plaintext with AAD', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const aad   = crypto.getRandomValues(new Uint8Array(20));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		const sealed    = aead.encrypt(key, nonce, pt, aad);
		const aead2     = new ChaCha20Poly1305();
		const recovered = aead2.decrypt(key, nonce, sealed, aad);
		expect(toHex(recovered)).toBe(toHex(pt));
		aead.dispose();
		aead2.dispose();
	});

	it('round-trip: 100-byte plaintext (non-block-aligned)', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(100));

		const sealed    = aead.encrypt(key, nonce, pt);
		const aead2     = new ChaCha20Poly1305();
		const recovered = aead2.decrypt(key, nonce, sealed);
		expect(toHex(recovered)).toBe(toHex(pt));
		aead.dispose();
		aead2.dispose();
	});

	it('round-trip: 128-byte plaintext (2 ChaCha20 blocks)', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(128));

		const sealed    = aead.encrypt(key, nonce, pt);
		const aead2     = new ChaCha20Poly1305();
		const recovered = aead2.decrypt(key, nonce, sealed);
		expect(toHex(recovered)).toBe(toHex(pt));
		aead.dispose();
		aead2.dispose();
	});

	it('round-trip: empty plaintext with AAD', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const aad   = fromHex('deadbeef');
		const pt    = new Uint8Array(0);

		const sealed = aead.encrypt(key, nonce, pt, aad);
		expect(sealed.length).toBe(16);  // tag only
		const aead2     = new ChaCha20Poly1305();
		const recovered = aead2.decrypt(key, nonce, sealed, aad);
		expect(recovered.length).toBe(0);
		aead.dispose();
		aead2.dispose();
	});

	it('round-trip: plaintext with empty AAD', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(32));

		const sealed    = aead.encrypt(key, nonce, pt);
		const aead2     = new ChaCha20Poly1305();
		const recovered = aead2.decrypt(key, nonce, sealed);
		expect(toHex(recovered)).toBe(toHex(pt));
		aead.dispose();
		aead2.dispose();
	});

	// Tamper detection
	it('rejects tampered ciphertext body', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		const sealed  = aead.encrypt(key, nonce, pt);
		const tampered = sealed.slice();
		tampered[0] ^= 0x01;

		const aead2 = new ChaCha20Poly1305();
		expect(() => aead2.decrypt(key, nonce, tampered)).toThrow(
			'chacha20-poly1305: authentication failed',
		);
		aead.dispose();
		aead2.dispose();
	});

	it('rejects tampered tag', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		const sealed  = aead.encrypt(key, nonce, pt);
		const tampered = sealed.slice();
		tampered[tampered.length - 1] ^= 0xff;

		const aead2 = new ChaCha20Poly1305();
		expect(() => aead2.decrypt(key, nonce, tampered)).toThrow(
			'chacha20-poly1305: authentication failed',
		);
		aead.dispose();
		aead2.dispose();
	});

	it('rejects tampered AAD', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const aad   = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		const sealed = aead.encrypt(key, nonce, pt, aad);
		const badAad = aad.slice();
		badAad[0] ^= 0x01;

		const aead2 = new ChaCha20Poly1305();
		expect(() => aead2.decrypt(key, nonce, sealed, badAad)).toThrow(
			'chacha20-poly1305: authentication failed',
		);
		aead.dispose();
		aead2.dispose();
	});

	it('rejects wrong key on decrypt', () => {
		const aead   = new ChaCha20Poly1305();
		const key    = crypto.getRandomValues(new Uint8Array(32));
		const key2   = crypto.getRandomValues(new Uint8Array(32));
		const nonce  = crypto.getRandomValues(new Uint8Array(12));
		const pt     = crypto.getRandomValues(new Uint8Array(64));

		const sealed = aead.encrypt(key, nonce, pt);
		const aead2  = new ChaCha20Poly1305();
		expect(() => aead2.decrypt(key2, nonce, sealed)).toThrow(
			'chacha20-poly1305: authentication failed',
		);
		aead.dispose();
		aead2.dispose();
	});

	it('rejects wrong nonce on decrypt', () => {
		const aead   = new ChaCha20Poly1305();
		const key    = crypto.getRandomValues(new Uint8Array(32));
		const nonce  = crypto.getRandomValues(new Uint8Array(12));
		const nonce2 = crypto.getRandomValues(new Uint8Array(12));
		const pt     = crypto.getRandomValues(new Uint8Array(64));

		const sealed = aead.encrypt(key, nonce, pt);
		const aead2  = new ChaCha20Poly1305();
		expect(() => aead2.decrypt(key, nonce2, sealed)).toThrow(
			'chacha20-poly1305: authentication failed',
		);
		aead.dispose();
		aead2.dispose();
	});

	// Input validation — strict single-use: each encrypt() attempt locks the
	// instance, so each length probe needs a fresh AEAD.
	it('throws RangeError for non-32-byte key', () => {
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		for (const keyLen of [16, 31]) {
			const aead = new ChaCha20Poly1305();
			expect(() => aead.encrypt(new Uint8Array(keyLen), nonce, new Uint8Array(1))).toThrow(RangeError);
			aead.dispose();
		}
	});

	it('throws RangeError for non-12-byte nonce', () => {
		const key = crypto.getRandomValues(new Uint8Array(32));
		for (const nonceLen of [8, 24]) {
			const aead = new ChaCha20Poly1305();
			expect(() => aead.encrypt(key, new Uint8Array(nonceLen), new Uint8Array(1))).toThrow(RangeError);
			aead.dispose();
		}
	});

	it('throws RangeError if ciphertext too short to contain tag', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		expect(() => aead.decrypt(key, nonce, new Uint8Array(15))).toThrow(RangeError);
		expect(() => aead.decrypt(key, nonce, new Uint8Array(0))).toThrow(RangeError);
		aead.dispose();
	});

	// dispose
	it('dispose() then re-create works', () => {
		const aead = new ChaCha20Poly1305();
		aead.encrypt(RFC_KEY, RFC_NONCE, RFC_PT, RFC_AAD);
		aead.dispose();

		const aead2  = new ChaCha20Poly1305();
		const sealed = aead2.encrypt(RFC_KEY, RFC_NONCE, RFC_PT, RFC_AAD);
		expect(toHex(sealed.slice(0, -16))).toBe(toHex(RFC_CT));
		expect(toHex(sealed.slice(-16))).toBe(toHex(RFC_TAG));
		aead2.dispose();
	});
});

// ── Return type unification ───────────────────────────────────────────────────

describe('ChaCha20Poly1305 — return type', () => {
	it('encrypt() returns Uint8Array', () => {
		const aead   = new ChaCha20Poly1305();
		const key    = crypto.getRandomValues(new Uint8Array(32));
		const nonce  = crypto.getRandomValues(new Uint8Array(12));
		const sealed = aead.encrypt(key, nonce, new Uint8Array(32));
		expect(sealed).toBeInstanceOf(Uint8Array);
		aead.dispose();
	});

	it('encrypt() length equals plaintext.length + 16', () => {
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		for (const len of [0, 1, 16, 64, 100]) {
			const aead   = new ChaCha20Poly1305();
			const sealed = aead.encrypt(key, nonce, new Uint8Array(len));
			expect(sealed.length).toBe(len + 16);
			aead.dispose();
		}
	});

	it('decrypt() accepts single Uint8Array and returns plaintext', () => {
		const aead  = new ChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(48));
		const sealed  = aead.encrypt(key, nonce, pt);
		const aead2   = new ChaCha20Poly1305();
		const recovered = aead2.decrypt(key, nonce, sealed);
		expect(toHex(recovered)).toBe(toHex(pt));
		aead.dispose();
		aead2.dispose();
	});

	it('output layout is ciphertext || tag (not tag || ciphertext)', () => {
		// Encrypt with ChaCha20Poly1305, manually verify the last 16 bytes are tag
		// by also computing via raw ops — the RFC vector has known ct and tag
		const aead   = new ChaCha20Poly1305();
		const sealed = aead.encrypt(RFC_KEY, RFC_NONCE, RFC_PT, RFC_AAD);
		// sealed = RFC_CT(114 bytes) || RFC_TAG(16 bytes)
		expect(sealed.length).toBe(RFC_CT.length + 16);
		expect(toHex(sealed.slice(0, RFC_CT.length))).toBe(toHex(RFC_CT));
		expect(toHex(sealed.slice(RFC_CT.length))).toBe(toHex(RFC_TAG));
		aead.dispose();
	});
});

// ── Single-use encrypt guard ──────────────────────────────────────────────────

describe('ChaCha20Poly1305 — single-use encrypt guard', () => {
	it('encrypt() once succeeds and returns Uint8Array', () => {
		const aead   = new ChaCha20Poly1305();
		const key    = crypto.getRandomValues(new Uint8Array(32));
		const nonce  = crypto.getRandomValues(new Uint8Array(12));
		const sealed = aead.encrypt(key, nonce, new Uint8Array(8));
		expect(sealed).toBeInstanceOf(Uint8Array);
		aead.dispose();
	});

	it('encrypt() twice on same instance throws plain Error (not AuthenticationError)', () => {
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
		expect(caught).toBeInstanceOf(Error);
		expect(caught).not.toBeInstanceOf(AuthenticationError);
		expect((caught as Error).message).toContain('encrypt() already called');
		aead.dispose();
	});

	it('decrypt() still works after encrypt() was called', () => {
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(32));
		const aead  = new ChaCha20Poly1305();
		const sealed = aead.encrypt(key, nonce, pt);
		// decrypt on the SAME instance (guard does not block decrypt)
		const recovered = aead.decrypt(key, nonce, sealed);
		expect(toHex(recovered)).toBe(toHex(pt));
		aead.dispose();
	});

	it('decrypt() can be called multiple times on same instance', () => {
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(32));
		const encryptor = new ChaCha20Poly1305();
		const sealed    = encryptor.encrypt(key, nonce, pt);
		encryptor.dispose();

		const aead      = new ChaCha20Poly1305();
		const first     = aead.decrypt(key, nonce, sealed);
		const second    = aead.decrypt(key, nonce, sealed);
		expect(toHex(first)).toBe(toHex(pt));
		expect(toHex(second)).toBe(toHex(pt));
		aead.dispose();
	});
});

// ── ops.ts behavioural check ────────────────────────────────────────────────

describe('aeadEncrypt — behavioural regression after chachaLoadKey dedup', () => {
	// Direct call to the raw `aeadEncrypt` function from ops.ts — bypasses the
	// class wrapper's single-use guard and exercises the exact call sequence
	// that drops the redundant second `chachaLoadKey()` after
	// `chachaSetCounter(1)`. Byte-exact match against RFC 8439 §2.8.2 proves
	// the dedup is equivalent — `chachaGenPolyKey` only mutates the counter
	// word of CHACHA_STATE, so `chachaSetCounter(1)` alone restores state
	// for encryption without re-loading the key.
	it('produces RFC 8439 §2.8.2 ciphertext || tag after the redundant chachaLoadKey removal', () => {
		const x = getWasm();
		const { ciphertext, tag } = aeadEncrypt(x, RFC_KEY, RFC_NONCE, RFC_PT, RFC_AAD);
		expect(toHex(ciphertext)).toBe(toHex(RFC_CT));
		expect(toHex(tag)).toBe(toHex(RFC_TAG));
	});
});

// ── Wipe-before-throw ─────────────────────────────────────────────────────────

describe('ChaCha20Poly1305 — wipe-before-throw', () => {
	it('WASM chunk output buffer is zeroed after auth failure', () => {
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		const encryptor = new ChaCha20Poly1305();
		const sealed    = encryptor.encrypt(key, nonce, pt);
		encryptor.dispose();

		// Tamper with the tag
		const tampered = sealed.slice();
		tampered[tampered.length - 1] ^= 0xff;

		const aead = new ChaCha20Poly1305();
		let caught: unknown;
		try {
			aead.decrypt(key, nonce, tampered);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(AuthenticationError);

		// Verify WASM chunk ct buffer is zeroed after wipe
		const x      = getWasm();
		const ctOff  = x.getChunkCtOffset();
		const region = new Uint8Array(x.memory.buffer).slice(ctOff, ctOff + pt.length);
		expect(Array.from(region).every(b => b === 0)).toBe(true);
		aead.dispose();
	});
});
