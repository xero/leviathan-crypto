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
 * XChaCha20-Poly1305 test vectors
 *
 * Sources:
 *   IETF draft-irtf-cfrg-xchacha (draft-irtf-cfrg-xchacha-03)
 *   URL: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
 *   §A.3.1 — HChaCha20 test vector (key derivation)
 *   §A.3.2 — XChaCha20-Poly1305 AEAD vector
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, XChaCha20Poly1305, AuthenticationError } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import type { ChaChaExports } from '../../../src/ts/chacha20/types.js';
import { hchacha20Vectors, xchacha20Poly1305Vectors } from '../../vectors/chacha20.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';

const toHex = (b: Uint8Array): string =>
	Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

const fromHex = (h: string): Uint8Array =>
	Uint8Array.from(h.match(/.{2}/g)!.map(b => parseInt(b, 16)));

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm });
});

function getWasm() {
	return getInstance('chacha20').exports as unknown as ChaChaExports;
}

describe('HChaCha20 — draft-irtf-cfrg-xchacha §A.3.1', () => {

	// GATE — HChaCha20/XChaCha20: draft-irtf-cfrg-xchacha §A.3.1
	// Vector: chacha20.ts[hchacha20Vectors[0]]
	it('HChaCha20 subkey derivation matches draft vector', () => {
		const v = hchacha20Vectors[0];
		const x = getWasm();
		const mem = new Uint8Array(x.memory.buffer);
		const key   = fromHex(v.key);
		const nonce = fromHex(v.nonce16);  // 16 bytes

		mem.set(key,   x.getKeyOffset());
		mem.set(nonce, x.getXChaChaNonceOffset());
		x.hchacha20();

		const subkey = toHex(new Uint8Array(x.memory.buffer).slice(
			x.getXChaChaSubkeyOffset(), x.getXChaChaSubkeyOffset() + 32
		));

		expect(subkey).toBe(v.subkey);
	});
});

// ── XChaCha20-Poly1305 AEAD ───────────────────────────────────────────────────

// IETF draft §A.3.2 test vector
const TV          = xchacha20Poly1305Vectors[0];
const DRAFT_KEY   = fromHex(TV.key);
const DRAFT_NONCE = fromHex(TV.nonce);  // 24 bytes
const DRAFT_AAD   = fromHex(TV.aad);
const DRAFT_PT    = new TextEncoder().encode(TV.ptText!);
const DRAFT_CT    = fromHex(TV.ct);
const DRAFT_TAG   = fromHex(TV.tag);

describe('XChaCha20-Poly1305 — draft-irtf-cfrg-xchacha §A.3.2', () => {

	// Draft vector
	it('draft §A.3.2 — encrypt produces correct ciphertext and tag', () => {
		const xchacha = new XChaCha20Poly1305();
		const ct = xchacha.encrypt(DRAFT_KEY, DRAFT_NONCE, DRAFT_PT, DRAFT_AAD);
		expect(toHex(ct.slice(0, -16))).toBe(toHex(DRAFT_CT));
		expect(toHex(ct.slice(-16))).toBe(toHex(DRAFT_TAG));
		xchacha.dispose();
	});

	it('draft §A.3.2 — decrypt recovers plaintext', () => {
		const xchacha = new XChaCha20Poly1305();
		const combined = new Uint8Array(DRAFT_CT.length + 16);
		combined.set(DRAFT_CT);
		combined.set(DRAFT_TAG, DRAFT_CT.length);
		const pt = xchacha.decrypt(DRAFT_KEY, DRAFT_NONCE, combined, DRAFT_AAD);
		expect(new TextDecoder().decode(pt)).toBe(TV.ptText);
		xchacha.dispose();
	});

	// Round-trips
	it('5 round-trips with random key/nonce/plaintext/aad', () => {
		for (let i = 0; i < 5; i++) {
			const xchacha = new XChaCha20Poly1305();
			const key   = crypto.getRandomValues(new Uint8Array(32));
			const nonce = crypto.getRandomValues(new Uint8Array(24));
			const pt    = crypto.getRandomValues(new Uint8Array(64 * i + 7));
			const aad   = crypto.getRandomValues(new Uint8Array(i * 3));

			const ct        = xchacha.encrypt(key, nonce, pt, aad);
			const recovered = xchacha.decrypt(key, nonce, ct, aad);
			expect(toHex(recovered)).toBe(toHex(pt));
			xchacha.dispose();
		}
	});

	it('empty plaintext round-trips (result is tag only)', () => {
		const xchacha = new XChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const ct    = xchacha.encrypt(key, nonce, new Uint8Array(0));
		expect(ct.length).toBe(16);  // tag only
		const pt = xchacha.decrypt(key, nonce, ct);
		expect(pt.length).toBe(0);
		xchacha.dispose();
	});

	it('128-byte plaintext (2 ChaCha20 blocks)', () => {
		const xchacha = new XChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const pt    = crypto.getRandomValues(new Uint8Array(128));
		const ct    = xchacha.encrypt(key, nonce, pt);
		expect(toHex(xchacha.decrypt(key, nonce, ct))).toBe(toHex(pt));
		xchacha.dispose();
	});

	// Tamper detection
	it('tampered ciphertext throws', () => {
		const xchacha = new XChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const ct    = xchacha.encrypt(key, nonce, new Uint8Array(32));
		const bad   = ct.slice();
		bad[0] ^= 0x01;
		expect(() => xchacha.decrypt(key, nonce, bad)).toThrow('authentication failed');
		xchacha.dispose();
	});

	it('tampered tag throws', () => {
		const xchacha = new XChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const ct    = xchacha.encrypt(key, nonce, new Uint8Array(32));
		const bad   = ct.slice();
		bad[bad.length - 1] ^= 0x01;
		expect(() => xchacha.decrypt(key, nonce, bad)).toThrow('authentication failed');
		xchacha.dispose();
	});

	it('wrong nonce throws', () => {
		const xchacha = new XChaCha20Poly1305();
		const key    = crypto.getRandomValues(new Uint8Array(32));
		const nonce  = crypto.getRandomValues(new Uint8Array(24));
		const nonce2 = crypto.getRandomValues(new Uint8Array(24));
		const ct     = xchacha.encrypt(key, nonce, new Uint8Array(32));
		expect(() => xchacha.decrypt(key, nonce2, ct)).toThrow('authentication failed');
		xchacha.dispose();
	});

	it('wrong key throws', () => {
		const xchacha = new XChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const key2  = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const ct    = xchacha.encrypt(key, nonce, new Uint8Array(32));
		expect(() => xchacha.decrypt(key2, nonce, ct)).toThrow('authentication failed');
		xchacha.dispose();
	});

	it('wrong AAD throws', () => {
		const xchacha = new XChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const aad   = new Uint8Array([1, 2, 3]);
		const aad2  = new Uint8Array([1, 2, 4]);
		const ct    = xchacha.encrypt(key, nonce, new Uint8Array(32), aad);
		expect(() => xchacha.decrypt(key, nonce, ct, aad2)).toThrow('authentication failed');
		xchacha.dispose();
	});

	// Input validation
	it('RangeError for 12-byte nonce (must be 24)', () => {
		const xchacha = new XChaCha20Poly1305();
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(12));
		expect(() => xchacha.encrypt(key, nonce, new Uint8Array(1))).toThrow(RangeError);
		xchacha.dispose();
	});

	it('RangeError for non-32-byte key', () => {
		// Strict single-use: each encrypt() attempt locks the instance, so
		// each length probe needs a fresh AEAD.
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		for (const keyLen of [16, 31]) {
			const xchacha = new XChaCha20Poly1305();
			expect(() => xchacha.encrypt(new Uint8Array(keyLen), nonce, new Uint8Array(1))).toThrow(RangeError);
			xchacha.dispose();
		}
	});

	// wipeBuffers
	it('wipeBuffers() zeroes XCHACHA_NONCE and XCHACHA_SUBKEY buffers', () => {
		const x = getWasm();
		const mem = () => new Uint8Array(x.memory.buffer);
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		mem().set(key,                    x.getKeyOffset());
		mem().set(nonce.subarray(0, 16),  x.getXChaChaNonceOffset());
		x.hchacha20();

		const noncePre  = mem().slice(x.getXChaChaNonceOffset(), x.getXChaChaNonceOffset() + 24);
		const subkeyPre = mem().slice(x.getXChaChaSubkeyOffset(), x.getXChaChaSubkeyOffset() + 32);
		expect(noncePre.some((b: number)  => b !== 0)).toBe(true);
		expect(subkeyPre.some((b: number) => b !== 0)).toBe(true);

		x.wipeBuffers();
		const noncePost  = mem().slice(x.getXChaChaNonceOffset(), x.getXChaChaNonceOffset() + 24);
		const subkeyPost = mem().slice(x.getXChaChaSubkeyOffset(), x.getXChaChaSubkeyOffset() + 32);
		expect(noncePost.every((b: number)  => b === 0)).toBe(true);
		expect(subkeyPost.every((b: number) => b === 0)).toBe(true);
	});
});

// ── Single-use encrypt guard ──────────────────────────────────────────────────

describe('XChaCha20Poly1305 — single-use encrypt guard', () => {
	it('encrypt() once succeeds', () => {
		const xchacha = new XChaCha20Poly1305();
		const key     = crypto.getRandomValues(new Uint8Array(32));
		const nonce   = crypto.getRandomValues(new Uint8Array(24));
		const result  = xchacha.encrypt(key, nonce, new Uint8Array(8));
		expect(result).toBeInstanceOf(Uint8Array);
		xchacha.dispose();
	});

	it('encrypt() twice on same instance throws plain Error (not AuthenticationError)', () => {
		const xchacha = new XChaCha20Poly1305();
		const key     = crypto.getRandomValues(new Uint8Array(32));
		const nonce   = crypto.getRandomValues(new Uint8Array(24));
		xchacha.encrypt(key, nonce, new Uint8Array(8));
		let caught: unknown;
		try {
			xchacha.encrypt(key, nonce, new Uint8Array(8));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(Error);
		expect(caught).not.toBeInstanceOf(AuthenticationError);
		expect((caught as Error).message).toContain('encrypt() already called');
		xchacha.dispose();
	});

	it('decrypt() still works after encrypt() was called', () => {
		const key     = crypto.getRandomValues(new Uint8Array(32));
		const nonce   = crypto.getRandomValues(new Uint8Array(24));
		const pt      = crypto.getRandomValues(new Uint8Array(32));
		const xchacha = new XChaCha20Poly1305();
		const ct      = xchacha.encrypt(key, nonce, pt);
		const recovered = xchacha.decrypt(key, nonce, ct);
		expect(toHex(recovered)).toBe(toHex(pt));
		xchacha.dispose();
	});

	it('decrypt() can be called multiple times on same instance', () => {
		const key        = crypto.getRandomValues(new Uint8Array(32));
		const nonce      = crypto.getRandomValues(new Uint8Array(24));
		const pt         = crypto.getRandomValues(new Uint8Array(32));
		const encryptor  = new XChaCha20Poly1305();
		const ct         = encryptor.encrypt(key, nonce, pt);
		encryptor.dispose();

		const xchacha    = new XChaCha20Poly1305();
		const first      = xchacha.decrypt(key, nonce, ct);
		const second     = xchacha.decrypt(key, nonce, ct);
		expect(toHex(first)).toBe(toHex(pt));
		expect(toHex(second)).toBe(toHex(pt));
		xchacha.dispose();
	});
});

// ── Wipe-before-throw ─────────────────────────────────────────────────────────

describe('XChaCha20Poly1305 — wipe-before-throw', () => {
	it('WASM chunk output buffer is zeroed after auth failure', () => {
		const key   = crypto.getRandomValues(new Uint8Array(32));
		const nonce = crypto.getRandomValues(new Uint8Array(24));
		const pt    = crypto.getRandomValues(new Uint8Array(64));

		const encryptor = new XChaCha20Poly1305();
		const sealed    = encryptor.encrypt(key, nonce, pt);
		encryptor.dispose();

		// Tamper with the tag
		const tampered = sealed.slice();
		tampered[tampered.length - 1] ^= 0xff;

		const xchacha = new XChaCha20Poly1305();
		let caught: unknown;
		try {
			xchacha.decrypt(key, nonce, tampered);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(AuthenticationError);

		// Verify WASM chunk ct buffer is zeroed after wipe
		const x      = getWasm();
		const ctOff  = x.getChunkCtOffset();
		// ciphertext portion is pt.length = 64 bytes (tag is excluded before aeadDecrypt)
		const region = new Uint8Array(x.memory.buffer).slice(ctOff, ctOff + pt.length);
		expect(Array.from(region).every(b => b === 0)).toBe(true);
		xchacha.dispose();
	});
});
