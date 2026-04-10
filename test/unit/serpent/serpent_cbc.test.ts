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
 * Serpent-256 CBC mode unit tests
 *
 * Tests the SerpentCbc wrapper: PKCS7 padding, round-trips, IV sensitivity,
 * CBC chaining verification, and parameter validation.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, SerpentCbc } from '../../../src/ts/index.js';
import { getWasm } from '../helpers';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';

function toHex(b: Uint8Array): string {
	return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

let cbc: SerpentCbc;

beforeAll(async () => {
	await init({ serpent: serpentWasm });
	cbc = new SerpentCbc({ dangerUnauthenticated: true });
});

// ── PKCS7 padding output length ───────────────────────────────────────────

describe('SerpentCbc — PKCS7 padding lengths', () => {
	const key = new Uint8Array(32).fill(0x01);
	const iv  = new Uint8Array(16).fill(0x02);

	it('0-byte input → 16-byte output (full pad block)', () => {
		const ct = cbc.encrypt(key, iv, new Uint8Array(0));
		expect(ct.length).toBe(16);
	});

	it('1-byte input → 16-byte output', () => {
		const ct = cbc.encrypt(key, iv, new Uint8Array(1).fill(0xAA));
		expect(ct.length).toBe(16);
	});

	it('15-byte input → 16-byte output', () => {
		const ct = cbc.encrypt(key, iv, new Uint8Array(15).fill(0xBB));
		expect(ct.length).toBe(16);
	});

	it('16-byte input → 32-byte output (full pad block appended)', () => {
		const ct = cbc.encrypt(key, iv, new Uint8Array(16).fill(0xCC));
		expect(ct.length).toBe(32);
	});

	it('17-byte input → 32-byte output', () => {
		const ct = cbc.encrypt(key, iv, new Uint8Array(17).fill(0xDD));
		expect(ct.length).toBe(32);
	});
});

// ── Round-trip tests ──────────────────────────────────────────────────────

describe('SerpentCbc — round-trips', () => {
	const key = new Uint8Array(32);
	for (let i = 0; i < 32; i++) key[i] = i;
	const iv = new Uint8Array(16);
	for (let i = 0; i < 16; i++) iv[i] = (i + 10) & 0xFF;

	function roundTrip(pt: Uint8Array): void {
		const ct = cbc.encrypt(key, iv, pt);
		const recovered = cbc.decrypt(key, iv, ct);
		expect(toHex(recovered)).toBe(toHex(pt));
	}

	it('16-byte plaintext (one block)', () => {
		roundTrip(new Uint8Array(16).fill(0x42));
	});

	it('31-byte plaintext (partial block)', () => {
		const pt = new Uint8Array(31);
		for (let i = 0; i < 31; i++) pt[i] = i & 0xFF;
		roundTrip(pt);
	});

	it('64-byte plaintext (four blocks)', () => {
		const pt = new Uint8Array(64);
		for (let i = 0; i < 64; i++) pt[i] = (i * 7) & 0xFF;
		roundTrip(pt);
	});

	it('65536-byte plaintext (exactly one chunk)', () => {
		const pt = new Uint8Array(65536);
		for (let i = 0; i < 65536; i++) pt[i] = i & 0xFF;
		roundTrip(pt);
	}, 30_000);

	it('65537-byte plaintext (crosses chunk boundary)', () => {
		const pt = new Uint8Array(65537);
		for (let i = 0; i < 65537; i++) pt[i] = (i * 3) & 0xFF;
		roundTrip(pt);
	}, 30_000);

	it('0-byte plaintext (empty → pad block only → decrypt gives empty)', () => {
		const ct = cbc.encrypt(key, iv, new Uint8Array(0));
		const recovered = cbc.decrypt(key, iv, ct);
		expect(recovered.length).toBe(0);
	});
});

// ── Invalid padding rejection ─────────────────────────────────────────────

describe('SerpentCbc — invalid PKCS7 padding rejection', () => {
	const key = new Uint8Array(32).fill(0x33);
	const iv  = new Uint8Array(16).fill(0x44);

	it('tampered last ciphertext byte throws', () => {
		const pt = new Uint8Array(16).fill(0x55);
		const ct = cbc.encrypt(key, iv, pt).slice();
		ct[ct.length - 1] ^= 0x01;
		expect(() => cbc.decrypt(key, iv, ct)).toThrow(RangeError);
	});

	it('ciphertext length not multiple of 16 throws', () => {
		expect(() => cbc.decrypt(key, iv, new Uint8Array(17))).toThrow(RangeError);
	});

	it('empty ciphertext throws', () => {
		expect(() => cbc.decrypt(key, iv, new Uint8Array(0))).toThrow(RangeError);
	});

	it('ciphertext with zero padding byte throws', () => {
		const ct = new Uint8Array(16).fill(0x00);
		expect(() => cbc.decrypt(key, iv, ct)).toThrow(RangeError);
	});
});

// ── IV sensitivity ────────────────────────────────────────────────────────

describe('SerpentCbc — IV sensitivity', () => {
	const key = new Uint8Array(32).fill(0x77);
	const pt  = new Uint8Array(32).fill(0x88);
	const iv1 = new Uint8Array(16).fill(0x11);
	const iv2 = new Uint8Array(16).fill(0x22);

	it('same key+plaintext, different IV → different ciphertext', () => {
		const ct1 = cbc.encrypt(key, iv1, pt);
		const ct2 = cbc.encrypt(key, iv2, pt);
		expect(toHex(ct1)).not.toBe(toHex(ct2));
	});

	it('CBC chaining: second block depends on first', () => {
		const combined = new Uint8Array(32);
		combined.fill(0xAA, 0, 16);
		combined.fill(0xBB, 16, 32);

		const ct = cbc.encrypt(key, iv1, combined);

		// Verify chaining manually via raw WASM
		const wasm = getWasm();
		const mem = new Uint8Array(wasm.memory.buffer);
		const ptOff = wasm.getChunkPtOffset();
		const ctOff = wasm.getChunkCtOffset();
		const ivOff = wasm.getCbcIvOffset();
		const keyOff = wasm.getKeyOffset();

		mem.set(key, keyOff);
		wasm.loadKey(32);

		mem.set(iv1, ivOff);
		mem.set(combined.subarray(0, 16), ptOff);
		wasm.cbcEncryptChunk(16);
		const ct0 = new Uint8Array(mem.subarray(ctOff, ctOff + 16));

		mem.set(ct0, ivOff);
		mem.set(combined.subarray(16, 32), ptOff);
		wasm.cbcEncryptChunk(16);
		const ct1 = new Uint8Array(mem.subarray(ctOff, ctOff + 16));

		expect(toHex(ct.subarray(0, 16))).toBe(toHex(ct0));
		expect(toHex(ct.subarray(16, 32))).toBe(toHex(ct1));
	});
});

// ── WASM chunk boundary ───────────────────────────────────────────────────

describe('SerpentCbc — WASM chunk boundary', () => {
	const key = new Uint8Array(32).fill(0x55);
	const iv  = new Uint8Array(16).fill(0xAA);

	function setupWasm() {
		const wasm = getWasm();
		const m = new Uint8Array(wasm.memory.buffer);
		m.set(key, wasm.getKeyOffset());
		wasm.loadKey(key.length);
		m.set(iv, wasm.getCbcIvOffset());
		return wasm;
	}

	it('cbcEncryptChunk succeeds at CHUNK_SIZE', () => {
		const wasm = setupWasm();
		const cs = wasm.getChunkSize(); // 65552 after fix
		const m = new Uint8Array(wasm.memory.buffer);
		for (let i = 0; i < cs; i++) m[wasm.getChunkPtOffset() + i] = i & 0xFF;
		const ret = wasm.cbcEncryptChunk(cs);
		expect(ret).toBe(cs);
		// Real ciphertext — not all zeros, not plaintext
		const ct0 = m.slice(wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + 16);
		expect(ct0.some(b => b !== 0)).toBe(true);
		expect(ct0.every((b, i) => b === (i & 0xFF))).toBe(false);
	}, 30_000);

	it('cbcEncryptChunk rejects CHUNK_SIZE + 1', () => {
		const wasm = setupWasm();
		const cs = wasm.getChunkSize();
		const m = new Uint8Array(wasm.memory.buffer);
		// Fill the full CHUNK_PT_BUFFER; last 16 bytes are 0x10 (simulated PKCS7 padding)
		for (let i = 0; i < cs - 16; i++) m[wasm.getChunkPtOffset() + i] = i & 0xFF;
		for (let i = cs - 16; i < cs; i++) m[wasm.getChunkPtOffset() + i] = 0x10;
		const ctBefore = m.slice(wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + 16);
		const ret = wasm.cbcEncryptChunk(cs + 1);
		expect(ret).toBe(-1);
		// Guard must return early — CHUNK_CT must be unchanged
		const ctAfter = new Uint8Array(wasm.memory.buffer).slice(wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + 16);
		expect(Array.from(ctAfter)).toEqual(Array.from(ctBefore));
	});

	it('cbcDecryptChunk roundtrip at CHUNK_SIZE', () => {
		const wasm = setupWasm();
		const cs = wasm.getChunkSize();
		const m = new Uint8Array(wasm.memory.buffer);
		const original = new Uint8Array(cs);
		for (let i = 0; i < cs; i++) original[i] = (i * 3) & 0xFF;
		m.set(original, wasm.getChunkPtOffset());
		const encRet = wasm.cbcEncryptChunk(cs);
		expect(encRet).toBe(cs);
		const ct = new Uint8Array(wasm.memory.buffer).slice(wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + cs);
		// Reset IV and decrypt
		new Uint8Array(wasm.memory.buffer).set(iv, wasm.getCbcIvOffset());
		new Uint8Array(wasm.memory.buffer).set(ct, wasm.getChunkCtOffset());
		const decRet = wasm.cbcDecryptChunk(cs);
		expect(decRet).toBe(cs);
		const recovered = new Uint8Array(wasm.memory.buffer).slice(wasm.getChunkPtOffset(), wasm.getChunkPtOffset() + cs);
		expect(Array.from(recovered)).toEqual(Array.from(original));
	}, 30_000);

	it('overflow guard: cbcEncryptChunk(CHUNK_SIZE) outputs real ciphertext, not [0x10]*16', () => {
		// Regression guard for the pre-fix corruption mode:
		// old CHUNK_SIZE=65536, old CHUNK_CT_OFFSET=66160. A 65552-byte write to
		// CHUNK_PT_OFFSET(624) overflowed 16 bytes (66160..66175) into CHUNK_CT[0:16]
		// with 0x10*16. cbcEncryptChunk(65552) returned -1 (rejected), leaving the
		// overflow bytes in place as the "ciphertext". After fix: CHUNK_SIZE=65552,
		// CHUNK_CT_OFFSET=66176 — no overlap; the call succeeds with real ciphertext.
		const wasm = setupWasm();
		const cs = wasm.getChunkSize();
		const m = new Uint8Array(wasm.memory.buffer);
		// Simulate a PKCS7-padded 65536-byte plaintext: last 16 bytes are 0x10
		for (let i = 0; i < cs - 16; i++) m[wasm.getChunkPtOffset() + i] = i & 0xFF;
		for (let i = cs - 16; i < cs; i++) m[wasm.getChunkPtOffset() + i] = 0x10;
		const ret = wasm.cbcEncryptChunk(cs);
		expect(ret).toBe(cs);
		const ct0 = new Uint8Array(wasm.memory.buffer).slice(wasm.getChunkCtOffset(), wasm.getChunkCtOffset() + 16);
		// Must be real ciphertext, not the PKCS7 overflow bytes
		expect(ct0.every(b => b === 0x10)).toBe(false);
	}, 30_000);
});

// ── RangeError for invalid key/IV sizes ──────────────────────────────────

describe('SerpentCbc — parameter validation', () => {
	const key = new Uint8Array(32).fill(0x01);
	const iv  = new Uint8Array(16).fill(0x02);
	const pt  = new Uint8Array(16).fill(0x03);

	it('key length 15 throws', () => {
		expect(() => cbc.encrypt(new Uint8Array(15), iv, pt)).toThrow(RangeError);
	});

	it('key length 33 throws', () => {
		expect(() => cbc.encrypt(new Uint8Array(33), iv, pt)).toThrow(RangeError);
	});

	it('IV length 15 throws', () => {
		expect(() => cbc.encrypt(key, new Uint8Array(15), pt)).toThrow(RangeError);
	});

	it('IV length 17 throws', () => {
		expect(() => cbc.encrypt(key, new Uint8Array(17), pt)).toThrow(RangeError);
	});

	it('16-byte key accepted', () => {
		expect(() => cbc.encrypt(new Uint8Array(16).fill(0x01), iv, pt)).not.toThrow();
	});

	it('24-byte key accepted', () => {
		expect(() => cbc.encrypt(new Uint8Array(24).fill(0x01), iv, pt)).not.toThrow();
	});

	it('32-byte key accepted', () => {
		expect(() => cbc.encrypt(key, iv, pt)).not.toThrow();
	});
});
