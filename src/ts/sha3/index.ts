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
// src/ts/sha3/index.ts
//
// Public API classes for the SHA-3 WASM module.
// Uses the init() module cache — call init('sha3') before constructing.

import { getInstance, initModule } from '../init.js';
import type { Mode, InitOpts } from '../init.js';

const _embedded = () => import('../embedded/sha3.js').then(m => m.WASM_BASE64);

export async function init(
	mode: Mode = 'embedded',
	opts?: InitOpts,
): Promise<void> {
	return initModule('sha3', _embedded, mode, opts);
}

interface Sha3Exports {
	memory:          WebAssembly.Memory;
	getInputOffset:  () => number;
	getOutOffset:    () => number;
	getStateOffset:  () => number;
	sha3_224Init:    () => void;
	sha3_256Init:    () => void;
	sha3_384Init:    () => void;
	sha3_512Init:    () => void;
	shake128Init:    () => void;
	shake256Init:    () => void;
	keccakAbsorb:    (len: number) => void;
	sha3_224Final:   () => void;
	sha3_256Final:   () => void;
	sha3_384Final:   () => void;
	sha3_512Final:   () => void;
	shakeFinal:      (outLen: number) => void;
	wipeBuffers:     () => void;
}

function getExports(): Sha3Exports {
	return getInstance('sha3').exports as unknown as Sha3Exports;
}

export function _sha3Ready(): boolean {
	try {
		getInstance('sha3'); return true;
	} catch {
		return false;
	}
}

// Write msg into INPUT_OFFSET in chunks of 168 bytes (max rate)
function absorb(x: Sha3Exports, msg: Uint8Array): void {
	const mem = new Uint8Array(x.memory.buffer);
	const inputOff = x.getInputOffset();
	let pos = 0;
	while (pos < msg.length) {
		const chunk = Math.min(msg.length - pos, 168);
		mem.set(msg.subarray(pos, pos + chunk), inputOff);
		x.keccakAbsorb(chunk);
		pos += chunk;
	}
}

// ── SHA3_256 ────────────────────────────────────────────────────────────────

export class SHA3_256 {
	private readonly x: Sha3Exports;
	constructor() {
		this.x = getExports();
	}

	hash(msg: Uint8Array): Uint8Array {
		this.x.sha3_256Init();
		absorb(this.x, msg);
		this.x.sha3_256Final();
		const mem = new Uint8Array(this.x.memory.buffer);
		return mem.slice(this.x.getOutOffset(), this.x.getOutOffset() + 32);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── SHA3_512 ────────────────────────────────────────────────────────────────

export class SHA3_512 {
	private readonly x: Sha3Exports;
	constructor() {
		this.x = getExports();
	}

	hash(msg: Uint8Array): Uint8Array {
		this.x.sha3_512Init();
		absorb(this.x, msg);
		this.x.sha3_512Final();
		const mem = new Uint8Array(this.x.memory.buffer);
		return mem.slice(this.x.getOutOffset(), this.x.getOutOffset() + 64);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── SHA3_384 ────────────────────────────────────────────────────────────────

export class SHA3_384 {
	private readonly x: Sha3Exports;
	constructor() {
		this.x = getExports();
	}

	hash(msg: Uint8Array): Uint8Array {
		this.x.sha3_384Init();
		absorb(this.x, msg);
		this.x.sha3_384Final();
		const mem = new Uint8Array(this.x.memory.buffer);
		return mem.slice(this.x.getOutOffset(), this.x.getOutOffset() + 48);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── SHA3_224 ────────────────────────────────────────────────────────────────

export class SHA3_224 {
	private readonly x: Sha3Exports;
	constructor() {
		this.x = getExports();
	}

	hash(msg: Uint8Array): Uint8Array {
		this.x.sha3_224Init();
		absorb(this.x, msg);
		this.x.sha3_224Final();
		const mem = new Uint8Array(this.x.memory.buffer);
		return mem.slice(this.x.getOutOffset(), this.x.getOutOffset() + 28);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── SHAKE128 ────────────────────────────────────────────────────────────────

/** SHAKE128 XOF. Output capped at 168 bytes (one squeeze block). */
export class SHAKE128 {
	private readonly x: Sha3Exports;
	constructor() {
		this.x = getExports();
	}

	hash(msg: Uint8Array, outputLength: number): Uint8Array {
		if (outputLength < 1 || outputLength > 168)
			throw new RangeError(
				`SHAKE128 outputLength must be 1–168 bytes (got ${outputLength}). ` +
				'Multi-squeeze is not supported in v1.0.'
			);
		this.x.shake128Init();
		absorb(this.x, msg);
		this.x.shakeFinal(outputLength);
		const mem = new Uint8Array(this.x.memory.buffer);
		return mem.slice(this.x.getOutOffset(), this.x.getOutOffset() + outputLength);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}

// ── SHAKE256 ────────────────────────────────────────────────────────────────

/** SHAKE256 XOF. Output capped at 136 bytes (one squeeze block). */
export class SHAKE256 {
	private readonly x: Sha3Exports;
	constructor() {
		this.x = getExports();
	}

	hash(msg: Uint8Array, outputLength: number): Uint8Array {
		if (outputLength < 1 || outputLength > 136)
			throw new RangeError(
				`SHAKE256 outputLength must be 1–136 bytes (got ${outputLength}). ` +
				'Multi-squeeze is not supported in v1.0.'
			);
		this.x.shake256Init();
		absorb(this.x, msg);
		this.x.shakeFinal(outputLength);
		const mem = new Uint8Array(this.x.memory.buffer);
		return mem.slice(this.x.getOutOffset(), this.x.getOutOffset() + outputLength);
	}

	dispose(): void {
		this.x.wipeBuffers();
	}
}
