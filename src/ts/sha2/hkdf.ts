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
// src/ts/sha2/hkdf.ts
//
// RFC 5869 — HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
// Pure TS composition over HMAC_SHA256 and HMAC_SHA512.

import { HMAC_SHA256, HMAC_SHA512 } from './index.js';

// ── HKDF_SHA256 ─────────────────────────────────────────────────────────────

export class HKDF_SHA256 {
	private readonly hmac: HMAC_SHA256;

	constructor() {
		this.hmac = new HMAC_SHA256();
	}

	// RFC 5869 §2.2 — Extract
	extract(salt: Uint8Array | null, ikm: Uint8Array): Uint8Array {
		const s = (!salt || salt.length === 0) ? new Uint8Array(32) : salt;
		return this.hmac.hash(s, ikm);
	}

	// RFC 5869 §2.3 — Expand
	expand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
		if (prk.length !== 32) throw new RangeError('HKDF expand: PRK must be 32 bytes');
		if (length < 1) throw new RangeError('HKDF expand: length must be at least 1');
		if (length > 255 * 32) throw new RangeError(`HKDF expand: length exceeds maximum (${255 * 32} bytes)`);

		const N = Math.ceil(length / 32);
		const okm = new Uint8Array(N * 32);
		let prev = new Uint8Array(0);

		for (let i = 1; i <= N; i++) {
			const buf = new Uint8Array(prev.length + info.length + 1);
			buf.set(prev, 0);
			buf.set(info, prev.length);
			buf[prev.length + info.length] = i;
			prev = this.hmac.hash(prk, buf);
			okm.set(prev, (i - 1) * 32);
		}

		return okm.slice(0, length);
	}

	// One-shot: extract then expand
	derive(ikm: Uint8Array, salt: Uint8Array | null, info: Uint8Array, length: number): Uint8Array {
		const prk = this.extract(salt, ikm);
		return this.expand(prk, info, length);
	}

	dispose(): void {
		this.hmac.dispose();
	}
}

// ── HKDF_SHA512 ─────────────────────────────────────────────────────────────

export class HKDF_SHA512 {
	private readonly hmac: HMAC_SHA512;

	constructor() {
		this.hmac = new HMAC_SHA512();
	}

	// RFC 5869 §2.2 — Extract
	extract(salt: Uint8Array | null, ikm: Uint8Array): Uint8Array {
		const s = (!salt || salt.length === 0) ? new Uint8Array(64) : salt;
		return this.hmac.hash(s, ikm);
	}

	// RFC 5869 §2.3 — Expand
	expand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
		if (prk.length !== 64) throw new RangeError('HKDF expand: PRK must be 64 bytes');
		if (length < 1) throw new RangeError('HKDF expand: length must be at least 1');
		if (length > 255 * 64) throw new RangeError(`HKDF expand: length exceeds maximum (${255 * 64} bytes)`);

		const N = Math.ceil(length / 64);
		const okm = new Uint8Array(N * 64);
		let prev = new Uint8Array(0);

		for (let i = 1; i <= N; i++) {
			const buf = new Uint8Array(prev.length + info.length + 1);
			buf.set(prev, 0);
			buf.set(info, prev.length);
			buf[prev.length + info.length] = i;
			prev = this.hmac.hash(prk, buf);
			okm.set(prev, (i - 1) * 64);
		}

		return okm.slice(0, length);
	}

	// One-shot: extract then expand
	derive(ikm: Uint8Array, salt: Uint8Array | null, info: Uint8Array, length: number): Uint8Array {
		const prk = this.extract(salt, ikm);
		return this.expand(prk, info, length);
	}

	dispose(): void {
		this.hmac.dispose();
	}
}
