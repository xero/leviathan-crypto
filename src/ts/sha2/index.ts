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
// src/ts/sha2/index.ts
//
// Public API classes for the SHA-2 WASM module.
// Uses the init() module cache — call init('sha2') before constructing.

import { getInstance, initModule } from '../init.js';
import type { Mode, InitOpts } from '../init.js';

const _embedded = () => import('../embedded/sha2.js').then(m => m.WASM_BASE64);

export async function sha2Init(
	mode: Mode = 'embedded',
	opts?: InitOpts,
): Promise<void> {
	return initModule('sha2', _embedded, mode, opts);
}

interface Sha2Exports {
	memory:              WebAssembly.Memory;
	getSha256InputOffset:  () => number;
	getSha256OutOffset:    () => number;
	getSha256HOffset:      () => number;
	getSha512InputOffset:  () => number;
	getSha512OutOffset:    () => number;
	getSha512HOffset:      () => number;
	getHmac256IpadOffset:  () => number;
	getHmac256OpadOffset:  () => number;
	getHmac256InnerOffset: () => number;
	getHmac512IpadOffset:  () => number;
	getHmac512OpadOffset:  () => number;
	getHmac512InnerOffset: () => number;
	sha256Init:    () => void;
	sha256Update:  (len: number) => void;
	sha256Final:   () => void;
	sha512Init:    () => void;
	sha384Init:    () => void;
	sha512Update:  (len: number) => void;
	sha512Final:   () => void;
	sha384Final:   () => void;
	hmac256Init:   (keyLen: number) => void;
	hmac256Update: (len: number) => void;
	hmac256Final:  () => void;
	hmac512Init:   (keyLen: number) => void;
	hmac512Update: (len: number) => void;
	hmac512Final:  () => void;
	hmac384Init:   (keyLen: number) => void;
	hmac384Update: (len: number) => void;
	hmac384Final:  () => void;
	wipeBuffers:   () => void;
}

function getExports(): Sha2Exports {
	return getInstance('sha2').exports as unknown as Sha2Exports;
}

export function _sha2Ready(): boolean {
	try {
		getInstance('sha2'); return true;
	} catch {
		return false;
	}
}

// Write msg into input buffer in chunks, calling update for each chunk.
function feedHash(x: Sha2Exports, msg: Uint8Array, inputOff: number, chunkSize: number,
	updateFn: (len: number) => void): void {
	const mem = new Uint8Array(x.memory.buffer);
	let pos = 0;
	while (pos < msg.length) {
		const n = Math.min(msg.length - pos, chunkSize);
		mem.set(msg.subarray(pos, pos + n), inputOff);
		updateFn(n);
		pos += n;
	}
}

// ── SHA256 ──────────────────────────────────────────────────────────────────

export class SHA256 {
	private readonly x: Sha2Exports;
	constructor() {
		this.x = getExports();
	}

	hash(msg: Uint8Array): Uint8Array {
		this.x.sha256Init();
		feedHash(this.x, msg, this.x.getSha256InputOffset(), 64, this.x.sha256Update);
		this.x.sha256Final();
		const mem = new Uint8Array(this.x.memory.buffer);
		return mem.slice(this.x.getSha256OutOffset(), this.x.getSha256OutOffset() + 32);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── SHA512 ──────────────────────────────────────────────────────────────────

export class SHA512 {
	private readonly x: Sha2Exports;
	constructor() {
		this.x = getExports();
	}

	hash(msg: Uint8Array): Uint8Array {
		this.x.sha512Init();
		feedHash(this.x, msg, this.x.getSha512InputOffset(), 128, this.x.sha512Update);
		this.x.sha512Final();
		const mem = new Uint8Array(this.x.memory.buffer);
		return mem.slice(this.x.getSha512OutOffset(), this.x.getSha512OutOffset() + 64);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── SHA384 ──────────────────────────────────────────────────────────────────

export class SHA384 {
	private readonly x: Sha2Exports;
	constructor() {
		this.x = getExports();
	}

	hash(msg: Uint8Array): Uint8Array {
		this.x.sha384Init();
		feedHash(this.x, msg, this.x.getSha512InputOffset(), 128, this.x.sha512Update);
		this.x.sha384Final();
		const mem = new Uint8Array(this.x.memory.buffer);
		return mem.slice(this.x.getSha512OutOffset(), this.x.getSha512OutOffset() + 48);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── HMAC_SHA256 ─────────────────────────────────────────────────────────────

export class HMAC_SHA256 {
	private readonly x: Sha2Exports;
	constructor() {
		this.x = getExports();
	}

	hash(key: Uint8Array, msg: Uint8Array): Uint8Array {
		let k = key;
		// RFC 2104 §3: keys longer than block size are pre-hashed
		if (k.length > 64) {
			this.x.sha256Init();
			feedHash(this.x, k, this.x.getSha256InputOffset(), 64, this.x.sha256Update);
			this.x.sha256Final();
			const mem = new Uint8Array(this.x.memory.buffer);
			k = mem.slice(this.x.getSha256OutOffset(), this.x.getSha256OutOffset() + 32);
		}
		const mem = new Uint8Array(this.x.memory.buffer);
		mem.set(k, this.x.getSha256InputOffset());
		this.x.hmac256Init(k.length);
		feedHash(this.x, msg, this.x.getSha256InputOffset(), 64, this.x.hmac256Update);
		this.x.hmac256Final();
		const out = new Uint8Array(this.x.memory.buffer);
		return out.slice(this.x.getSha256OutOffset(), this.x.getSha256OutOffset() + 32);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── HMAC_SHA512 ─────────────────────────────────────────────────────────────

export class HMAC_SHA512 {
	private readonly x: Sha2Exports;
	constructor() {
		this.x = getExports();
	}

	hash(key: Uint8Array, msg: Uint8Array): Uint8Array {
		let k = key;
		// RFC 2104 §3: keys longer than block size (128) are pre-hashed
		if (k.length > 128) {
			this.x.sha512Init();
			feedHash(this.x, k, this.x.getSha512InputOffset(), 128, this.x.sha512Update);
			this.x.sha512Final();
			const mem = new Uint8Array(this.x.memory.buffer);
			k = mem.slice(this.x.getSha512OutOffset(), this.x.getSha512OutOffset() + 64);
		}
		const mem = new Uint8Array(this.x.memory.buffer);
		mem.set(k, this.x.getSha512InputOffset());
		this.x.hmac512Init(k.length);
		feedHash(this.x, msg, this.x.getSha512InputOffset(), 128, this.x.hmac512Update);
		this.x.hmac512Final();
		const out = new Uint8Array(this.x.memory.buffer);
		return out.slice(this.x.getSha512OutOffset(), this.x.getSha512OutOffset() + 64);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── HMAC_SHA384 ─────────────────────────────────────────────────────────────

export class HMAC_SHA384 {
	private readonly x: Sha2Exports;
	constructor() {
		this.x = getExports();
	}

	hash(key: Uint8Array, msg: Uint8Array): Uint8Array {
		let k = key;
		// RFC 2104 §3: keys longer than block size (128) are pre-hashed with SHA-384
		if (k.length > 128) {
			this.x.sha384Init();
			feedHash(this.x, k, this.x.getSha512InputOffset(), 128, this.x.sha512Update);
			this.x.sha384Final();
			const mem = new Uint8Array(this.x.memory.buffer);
			k = mem.slice(this.x.getSha512OutOffset(), this.x.getSha512OutOffset() + 48);
		}
		const mem = new Uint8Array(this.x.memory.buffer);
		mem.set(k, this.x.getSha512InputOffset());
		this.x.hmac384Init(k.length);
		feedHash(this.x, msg, this.x.getSha512InputOffset(), 128, this.x.hmac384Update);
		this.x.hmac384Final();
		const out = new Uint8Array(this.x.memory.buffer);
		return out.slice(this.x.getSha512OutOffset(), this.x.getSha512OutOffset() + 48);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── HKDF ────────────────────────────────────────────────────────────────────

export { HKDF_SHA256, HKDF_SHA512 } from './hkdf.js';
