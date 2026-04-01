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

const _embedded = () => import('../embedded/sha3.js').then(m => m.WASM_GZ_BASE64);

export async function sha3Init(
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
	shakeFinal:         (outLen: number) => void;
	shakePad:           () => void;
	shakeSqueezeBlock:  () => void;
	wipeBuffers:        () => void;
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

/** SHAKE128 XOF — extendable output, multi-squeeze capable. */
export class SHAKE128 {
	private readonly x: Sha3Exports;
	private readonly _rate = 168;
	private _squeezing = false;
	private _block = new Uint8Array(168);
	private _blockPos = 168;

	constructor() {
		this.x = getExports();
		this.x.shake128Init();
	}

	reset(): this {
		this.x.shake128Init();
		this._squeezing = false;
		this._block.fill(0);
		this._blockPos = this._rate;
		return this;
	}

	absorb(msg: Uint8Array): this {
		if (this._squeezing)
			throw new Error(
				'SHAKE128: cannot absorb after squeeze — call reset() first'
			);
		absorb(this.x, msg);
		return this;
	}

	squeeze(n: number): Uint8Array {
		if (n < 1) throw new RangeError(`squeeze length must be >= 1 (got ${n})`);

		if (!this._squeezing) {
			this.x.shakePad();
			this._squeezing = true;
			this._blockPos = this._rate;
		}

		const out = new Uint8Array(n);
		let pos = 0;

		while (pos < n) {
			if (this._blockPos >= this._rate) {
				this.x.shakeSqueezeBlock();
				const mem = new Uint8Array(this.x.memory.buffer);
				const off = this.x.getOutOffset();
				this._block.set(mem.subarray(off, off + this._rate));
				this._blockPos = 0;
			}
			const take = Math.min(n - pos, this._rate - this._blockPos);
			out.set(this._block.subarray(this._blockPos, this._blockPos + take), pos);
			this._blockPos += take;
			pos += take;
		}

		return out;
	}

	hash(msg: Uint8Array, outputLength: number): Uint8Array {
		if (outputLength < 1)
			throw new RangeError(`outputLength must be >= 1 (got ${outputLength})`);
		this.reset();
		this.absorb(msg);
		return this.squeeze(outputLength);
	}

	dispose(): void {
		this._block.fill(0);
		this.x.wipeBuffers();
	}
}

// ── SHAKE256 ────────────────────────────────────────────────────────────────

/** SHAKE256 XOF — extendable output, multi-squeeze capable. */
export class SHAKE256 {
	private readonly x: Sha3Exports;
	private readonly _rate = 136;
	private _squeezing = false;
	private _block = new Uint8Array(136);
	private _blockPos = 136;

	constructor() {
		this.x = getExports();
		this.x.shake256Init();
	}

	reset(): this {
		this.x.shake256Init();
		this._squeezing = false;
		this._block.fill(0);
		this._blockPos = this._rate;
		return this;
	}

	absorb(msg: Uint8Array): this {
		if (this._squeezing)
			throw new Error(
				'SHAKE256: cannot absorb after squeeze — call reset() first'
			);
		absorb(this.x, msg);
		return this;
	}

	squeeze(n: number): Uint8Array {
		if (n < 1) throw new RangeError(`squeeze length must be >= 1 (got ${n})`);

		if (!this._squeezing) {
			this.x.shakePad();
			this._squeezing = true;
			this._blockPos = this._rate;
		}

		const out = new Uint8Array(n);
		let pos = 0;

		while (pos < n) {
			if (this._blockPos >= this._rate) {
				this.x.shakeSqueezeBlock();
				const mem = new Uint8Array(this.x.memory.buffer);
				const off = this.x.getOutOffset();
				this._block.set(mem.subarray(off, off + this._rate));
				this._blockPos = 0;
			}
			const take = Math.min(n - pos, this._rate - this._blockPos);
			out.set(this._block.subarray(this._blockPos, this._blockPos + take), pos);
			this._blockPos += take;
			pos += take;
		}

		return out;
	}

	hash(msg: Uint8Array, outputLength: number): Uint8Array {
		if (outputLength < 1)
			throw new RangeError(`outputLength must be >= 1 (got ${outputLength})`);
		this.reset();
		this.absorb(msg);
		return this.squeeze(outputLength);
	}

	dispose(): void {
		this._block.fill(0);
		this.x.wipeBuffers();
	}
}
