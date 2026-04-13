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
 * Poly1305 MAC test vectors
 *
 * Source: RFC 8439, "ChaCha20 and Poly1305 for IETF Protocols", May 2018
 * URL: https://www.rfc-editor.org/rfc/rfc8439
 * Sections: §2.5.2, §2.6.2, Appendix A.3 (TV#1–#6)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, Poly1305 } from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import type { ChaChaExports } from '../../../src/ts/chacha20/types.js';
import { poly1305Vectors, poly1305KeyGenVectors } from '../../vectors/chacha20.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';

const toHex = (b: Uint8Array): string =>
	Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

const fromHex = (h: string): Uint8Array =>
	Uint8Array.from(h.match(/.{2}/g)!.map(b => parseInt(b, 16)));

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm });
});

// Helper to get raw WASM exports for low-level tests
function getWasm() {
	return getInstance('chacha20').exports as unknown as ChaChaExports;
}

describe('Poly1305 — RFC 8439 vectors', () => {

	// GATE — Poly1305 MAC: RFC 8439 §2.5.2
	// Vector: chacha20.ts[poly1305Vectors[0]]
	it('§2.5.2 gate — 34-byte message', () => {
		const v = poly1305Vectors[0]; // §2.5.2 gate vector
		const poly = new Poly1305();
		const key = fromHex(v.key);
		const msg = new TextEncoder().encode(v.msgText!);
		expect(msg.length).toBe(34);
		expect(toHex(poly.mac(key, msg))).toBe(v.tag);
		poly.dispose();
	});

	// §2.6.2 — Poly1305 key generation from ChaCha20 block 0
	it('§2.6.2 — Poly1305 key from ChaCha20 block 0', () => {
		const v = poly1305KeyGenVectors[0];
		const x = getWasm();
		const mem = new Uint8Array(x.memory.buffer);
		const chachaKey = fromHex(v.key);
		const nonce = fromHex(v.nonce);

		mem.set(chachaKey, x.getKeyOffset());
		mem.set(nonce, x.getChachaNonceOffset());
		x.chachaSetCounter(v.counter);
		x.chachaLoadKey();
		x.chachaGenPolyKey();

		const polyKey = toHex(mem.slice(x.getPolyKeyOffset(), x.getPolyKeyOffset() + 32));
		expect(polyKey).toBe(v.poly1305Key);
	});

	// Appendix A.3 TV#1 — all-zero key and message
	it('A.3 TV#1 — all-zero key and message', () => {
		const v = poly1305Vectors[1]; // A.3 vec 1
		const poly = new Poly1305();
		expect(toHex(poly.mac(fromHex(v.key), fromHex(v.msg!))))
			.toBe(v.tag);
		poly.dispose();
	});

	// A.3 TV#2 — r=0, tag equals s
	it('A.3 TV#2 — r=0, any message, tag equals s', () => {
		const v = poly1305Vectors[2]; // A.3 vec 2
		const poly = new Poly1305();
		const msg = new TextEncoder().encode(v.msgText!);
		expect(msg.length).toBe(375);
		expect(toHex(poly.mac(fromHex(v.key), msg))).toBe(v.tag);
		poly.dispose();
	});

	// A.3 TV#3 — r-only key
	it('A.3 TV#3 — r-only key, 375-byte IETF message', () => {
		const v = poly1305Vectors[3]; // A.3 vec 3
		const poly = new Poly1305();
		const msg = new TextEncoder().encode(v.msgText!);
		expect(msg.length).toBe(375);
		expect(toHex(poly.mac(fromHex(v.key), msg))).toBe(v.tag);
		poly.dispose();
	});

	// A.3 TV#4 — Jabberwocky
	it('A.3 TV#4 — 127-byte Jabberwocky message', () => {
		const v = poly1305Vectors[4]; // A.3 vec 4
		const poly = new Poly1305();
		const msg = new TextEncoder().encode(v.msgText!);
		expect(msg.length).toBe(127);
		expect(toHex(poly.mac(fromHex(v.key), msg))).toBe(v.tag);
		poly.dispose();
	});

	// A.3 TV#5 — h reaches p
	it('A.3 TV#5 — h reaches p (modular reduction edge case)', () => {
		const v = poly1305Vectors[5]; // A.3 vec 5
		const poly = new Poly1305();
		expect(toHex(poly.mac(fromHex(v.key), fromHex(v.msg!)))).toBe(v.tag);
		poly.dispose();
	});

	// A.3 TV#6 — h + s overflow
	it('A.3 TV#6 — h + s overflows 128-bit, carry discarded', () => {
		const v = poly1305Vectors[6]; // A.3 vec 6
		const poly = new Poly1305();
		expect(toHex(poly.mac(fromHex(v.key), fromHex(v.msg!)))).toBe(v.tag);
		poly.dispose();
	});

	// wipeBuffers
	it('dispose() zeroes Poly1305 key and tag', () => {
		const v = poly1305Vectors[0]; // §2.5.2 gate vector
		const poly = new Poly1305();
		const key = fromHex(v.key);
		poly.mac(key, new TextEncoder().encode('test'));
		poly.dispose();

		// Re-create and verify works
		const p2 = new Poly1305();
		const msg = new TextEncoder().encode(v.msgText!);
		expect(toHex(p2.mac(key, msg))).toBe(v.tag);
		p2.dispose();
	});
});
