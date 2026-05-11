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
// src/ts/sha3/kmac.ts
//
// cSHAKE and KMAC public classes — SP 800-185.
// Built on the existing sha3 WASM sponge primitives plus two new init
// exports (cshake128Init / cshake256Init). All SP 800-185 §2.3 encoding
// helpers live in TypeScript per the established mldsa/sha3-helpers.ts
// precedent for non-trivial input framing.

import { getInstance, _acquireModule, _releaseModule, _assertNotOwned } from '../init.js';
import { AuthenticationError } from '../errors.js';
import { constantTimeEqual, wipe } from '../utils.js';

interface Sha3KmacExports {
	memory:            WebAssembly.Memory;
	getInputOffset:    () => number;
	getOutOffset:      () => number;
	cshake128Init:     () => void;
	cshake256Init:     () => void;
	keccakAbsorb:      (len: number) => void;
	shakePad:          () => void;
	shakeSqueezeBlock: () => void;
	wipeBuffers:       () => void;
}

function getExports(): Sha3KmacExports {
	return getInstance('sha3').exports as unknown as Sha3KmacExports;
}

// ── SP 800-185 §2.3 encoding helpers ────────────────────────────────────────

// SP 800-185 §2.3.1 — left_encode(x). Encodes x as n base-256 bytes (big-endian)
// preceded by the byte n. Cap on the input range is conservative — all
// realistic uses (rate ≤ 168, output bit-lengths, key bit-lengths) fit in a
// 32-bit signed integer.
function leftEncode(x: number): Uint8Array {
	if (!Number.isInteger(x) || x < 0 || x > 0x7fffffff)
		throw new RangeError(`leftEncode: x out of range (got ${x})`);
	if (x === 0) return new Uint8Array([0x01, 0x00]);
	const bytes: number[] = [];
	let v = x;
	while (v > 0) {
		bytes.unshift(v & 0xff); v >>>= 8;
	}
	const out = new Uint8Array(bytes.length + 1);
	out[0] = bytes.length;
	for (let i = 0; i < bytes.length; i++) out[i + 1] = bytes[i];
	return out;
}

// SP 800-185 §2.3.1 — right_encode(x). Same digit sequence as left_encode but
// with the n byte appended.
function rightEncode(x: number): Uint8Array {
	if (!Number.isInteger(x) || x < 0 || x > 0x7fffffff)
		throw new RangeError(`rightEncode: x out of range (got ${x})`);
	if (x === 0) return new Uint8Array([0x00, 0x01]);
	const bytes: number[] = [];
	let v = x;
	while (v > 0) {
		bytes.unshift(v & 0xff); v >>>= 8;
	}
	const out = new Uint8Array(bytes.length + 1);
	for (let i = 0; i < bytes.length; i++) out[i] = bytes[i];
	out[bytes.length] = bytes.length;
	return out;
}

// SP 800-185 §2.3.2 — encode_string(S). left_encode of the BIT length of S
// followed by S itself. For byte-aligned inputs len(S) = 8 * bytes.length.
function encodeString(s: Uint8Array): Uint8Array {
	const prefix = leftEncode(s.length * 8);
	const out = new Uint8Array(prefix.length + s.length);
	out.set(prefix, 0);
	out.set(s, prefix.length);
	return out;
}

// SP 800-185 §2.3.3 — bytepad(x, w). Prepend left_encode(w), then zero-pad
// until total length is a multiple of w.
function bytepad(x: Uint8Array, w: number): Uint8Array {
	const prefix = leftEncode(w);
	const baseLen = prefix.length + x.length;
	const padded = Math.ceil(baseLen / w) * w;
	const out = new Uint8Array(padded);
	out.set(prefix, 0);
	out.set(x, prefix.length);
	return out;
}

// Stream msg into INPUT_OFFSET in ≤168-byte chunks. Mirrors the local helper
// in src/ts/sha3/index.ts; duplicated here to keep that file's @internal
// surface unchanged. See also mldsa/sha3-helpers.ts sha3Absorb.
function absorb(x: Sha3KmacExports, msg: Uint8Array): void {
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

// SP 800-185 §4 — function name "KMAC" used by KMAC{128,256} and the XOF
// variants when calling cSHAKE internally. ASCII 'K','M','A','C'.
const KMAC_N = new Uint8Array([0x4b, 0x4d, 0x41, 0x43]);
const EMPTY = new Uint8Array(0);

// ── CSHAKE128 ───────────────────────────────────────────────────────────────

/**
 * cSHAKE128 — customizable SHAKE128 (SP 800-185 §3).
 *
 * Holds exclusive access to the `sha3` WASM module from construction until
 * `dispose()`. Constructing any other sha3 user (SHAKE128/256, SHA3_*,
 * KMAC*, CSHAKE*) while this instance is live throws.
 */
export class CSHAKE128 {
	private readonly x: Sha3KmacExports;
	private readonly _rate = 168;
	private readonly _prefix: Uint8Array;
	private _squeezing = false;
	private _block = new Uint8Array(168);
	private _blockPos = 168;
	private _tok: symbol | undefined;

	constructor(customization: Uint8Array) {
		// SP 800-185 §3.3 — if N and S are both empty cSHAKE collapses to
		// SHAKE. The public API hides N (always empty); the both-empty case
		// is therefore "customization is empty" — reject and direct the
		// caller to SHAKE128.
		if (customization.length === 0)
			throw new Error('CSHAKE128: customization is empty — use SHAKE128 instead');
		// SP 800-185 §3.3 — cSHAKE128 prefix:
		//   bytepad(encode_string(N) || encode_string(S), 168)
		const en = encodeString(EMPTY);
		const es = encodeString(customization);
		const cat = new Uint8Array(en.length + es.length);
		cat.set(en, 0); cat.set(es, en.length);
		this._prefix = bytepad(cat, this._rate);

		this.x = getExports();
		this._tok = _acquireModule('sha3');
		try {
			this.x.cshake128Init();
			absorb(this.x, this._prefix);
		} catch (e) {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
			throw e;
		}
	}

	reset(): this {
		if (this._tok === undefined)
			throw new Error('CSHAKE128: instance has been disposed');
		this.x.cshake128Init();
		absorb(this.x, this._prefix);
		this._squeezing = false;
		this._block.fill(0);
		this._blockPos = this._rate;
		return this;
	}

	absorb(msg: Uint8Array): this {
		if (this._tok === undefined)
			throw new Error('CSHAKE128: instance has been disposed');
		if (this._squeezing)
			throw new Error('CSHAKE128: cannot absorb after squeeze — call reset() first');
		absorb(this.x, msg);
		return this;
	}

	squeeze(n: number): Uint8Array {
		if (this._tok === undefined)
			throw new Error('CSHAKE128: instance has been disposed');
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
		if (this._tok === undefined)
			throw new Error('CSHAKE128: instance has been disposed');
		if (outputLength < 1)
			throw new RangeError(`outputLength must be >= 1 (got ${outputLength})`);
		this.reset();
		this.absorb(msg);
		return this.squeeze(outputLength);
	}

	dispose(): void {
		if (this._tok === undefined) return;
		this._block.fill(0);
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
		}
	}
}

// ── CSHAKE256 ───────────────────────────────────────────────────────────────

/**
 * cSHAKE256 — customizable SHAKE256 (SP 800-185 §3).
 *
 * Holds exclusive access to the `sha3` WASM module from construction until
 * `dispose()`.
 */
export class CSHAKE256 {
	private readonly x: Sha3KmacExports;
	private readonly _rate = 136;
	private readonly _prefix: Uint8Array;
	private _squeezing = false;
	private _block = new Uint8Array(136);
	private _blockPos = 136;
	private _tok: symbol | undefined;

	constructor(customization: Uint8Array) {
		if (customization.length === 0)
			throw new Error('CSHAKE256: customization is empty — use SHAKE256 instead');
		const en = encodeString(EMPTY);
		const es = encodeString(customization);
		const cat = new Uint8Array(en.length + es.length);
		cat.set(en, 0); cat.set(es, en.length);
		this._prefix = bytepad(cat, this._rate);

		this.x = getExports();
		this._tok = _acquireModule('sha3');
		try {
			this.x.cshake256Init();
			absorb(this.x, this._prefix);
		} catch (e) {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
			throw e;
		}
	}

	reset(): this {
		if (this._tok === undefined)
			throw new Error('CSHAKE256: instance has been disposed');
		this.x.cshake256Init();
		absorb(this.x, this._prefix);
		this._squeezing = false;
		this._block.fill(0);
		this._blockPos = this._rate;
		return this;
	}

	absorb(msg: Uint8Array): this {
		if (this._tok === undefined)
			throw new Error('CSHAKE256: instance has been disposed');
		if (this._squeezing)
			throw new Error('CSHAKE256: cannot absorb after squeeze — call reset() first');
		absorb(this.x, msg);
		return this;
	}

	squeeze(n: number): Uint8Array {
		if (this._tok === undefined)
			throw new Error('CSHAKE256: instance has been disposed');
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
		if (this._tok === undefined)
			throw new Error('CSHAKE256: instance has been disposed');
		if (outputLength < 1)
			throw new RangeError(`outputLength must be >= 1 (got ${outputLength})`);
		this.reset();
		this.absorb(msg);
		return this.squeeze(outputLength);
	}

	dispose(): void {
		if (this._tok === undefined) return;
		this._block.fill(0);
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
		}
	}
}

// ── KMAC128 ─────────────────────────────────────────────────────────────────

/**
 * KMAC128 — keyed Keccak MAC, fixed-output (SP 800-185 §4).
 *
 * Bound to a specific output length at construction (the spec's right_encode(L)
 * suffix is a function of L). Use `KMACXOF128` for arbitrary-length output.
 *
 * Holds exclusive access to the `sha3` WASM module from construction until
 * `dispose()`.
 */
export class KMAC128 {
	private readonly x: Sha3KmacExports;
	private readonly _rate = 168;
	private readonly _outLen: number;
	private _finalized = false;
	private _tok: symbol | undefined;

	constructor(key: Uint8Array, outLen: number, customization: Uint8Array) {
		if (key.length === 0)
			throw new Error('KMAC128: empty key — use CSHAKE128 instead');
		if (!Number.isInteger(outLen) || outLen < 1)
			throw new RangeError(`KMAC128: outLen must be a positive integer (got ${outLen})`);
		this._outLen = outLen;

		// SP 800-185 §4 — cSHAKE128 prefix with N = "KMAC", S = customization.
		const en = encodeString(KMAC_N);
		const es = encodeString(customization);
		const csPrefix = new Uint8Array(en.length + es.length);
		csPrefix.set(en, 0); csPrefix.set(es, en.length);
		const cshakePad = bytepad(csPrefix, this._rate);
		// SP 800-185 §4 — KMAC newX = bytepad(encode_string(K), rate) || X || right_encode(L).
		// The key bytepad is absorbed at construction; X is absorbed via update();
		// right_encode(L*8) is appended in finalize().
		const keyPad = bytepad(encodeString(key), this._rate);

		this.x = getExports();
		this._tok = _acquireModule('sha3');
		try {
			this.x.cshake128Init();
			absorb(this.x, cshakePad);
			absorb(this.x, keyPad);
		} catch (e) {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
			throw e;
		}
	}

	update(chunk: Uint8Array): this {
		if (this._tok === undefined)
			throw new Error('KMAC128: instance has been disposed');
		if (this._finalized)
			throw new Error('KMAC128: cannot update after finalize');
		absorb(this.x, chunk);
		return this;
	}

	finalize(): Uint8Array {
		if (this._tok === undefined)
			throw new Error('KMAC128: instance has been disposed');
		if (this._finalized)
			throw new Error('KMAC128: already finalized');
		absorb(this.x, rightEncode(this._outLen * 8));
		this.x.shakePad();
		const out = new Uint8Array(this._outLen);
		let pos = 0;
		while (pos < this._outLen) {
			this.x.shakeSqueezeBlock();
			const mem = new Uint8Array(this.x.memory.buffer);
			const off = this.x.getOutOffset();
			const take = Math.min(this._outLen - pos, this._rate);
			out.set(mem.subarray(off, off + take), pos);
			pos += take;
		}
		this._finalized = true;
		return out;
	}

	mac(msg: Uint8Array): Uint8Array {
		this.update(msg);
		return this.finalize();
	}

	dispose(): void {
		if (this._tok === undefined) return;
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
		}
	}

	/**
	 * Constant-time tag verification. Throws `AuthenticationError('kmac128')`
	 * on mismatch (matches the lib's AEAD pattern). Returns `true` on success.
	 *
	 * Atomic — does not hold the sha3 module beyond the internal compute.
	 */
	static verify(
		tag: Uint8Array,
		key: Uint8Array,
		msg: Uint8Array,
		customization: Uint8Array,
	): true {
		_assertNotOwned('sha3');
		const m = new KMAC128(key, tag.length, customization);
		let exp: Uint8Array | undefined;
		try {
			m.update(msg);
			exp = m.finalize();
			if (!constantTimeEqual(exp, tag))
				throw new AuthenticationError('kmac128');
			return true;
		} finally {
			if (exp !== undefined) wipe(exp);
			m.dispose();
		}
	}
}

// ── KMAC256 ─────────────────────────────────────────────────────────────────

/**
 * KMAC256 — 256-bit-strength keyed Keccak MAC, fixed-output (SP 800-185 §4).
 */
export class KMAC256 {
	private readonly x: Sha3KmacExports;
	private readonly _rate = 136;
	private readonly _outLen: number;
	private _finalized = false;
	private _tok: symbol | undefined;

	constructor(key: Uint8Array, outLen: number, customization: Uint8Array) {
		if (key.length === 0)
			throw new Error('KMAC256: empty key — use CSHAKE256 instead');
		if (!Number.isInteger(outLen) || outLen < 1)
			throw new RangeError(`KMAC256: outLen must be a positive integer (got ${outLen})`);
		this._outLen = outLen;

		const en = encodeString(KMAC_N);
		const es = encodeString(customization);
		const csPrefix = new Uint8Array(en.length + es.length);
		csPrefix.set(en, 0); csPrefix.set(es, en.length);
		const cshakePad = bytepad(csPrefix, this._rate);
		const keyPad = bytepad(encodeString(key), this._rate);

		this.x = getExports();
		this._tok = _acquireModule('sha3');
		try {
			this.x.cshake256Init();
			absorb(this.x, cshakePad);
			absorb(this.x, keyPad);
		} catch (e) {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
			throw e;
		}
	}

	update(chunk: Uint8Array): this {
		if (this._tok === undefined)
			throw new Error('KMAC256: instance has been disposed');
		if (this._finalized)
			throw new Error('KMAC256: cannot update after finalize');
		absorb(this.x, chunk);
		return this;
	}

	finalize(): Uint8Array {
		if (this._tok === undefined)
			throw new Error('KMAC256: instance has been disposed');
		if (this._finalized)
			throw new Error('KMAC256: already finalized');
		absorb(this.x, rightEncode(this._outLen * 8));
		this.x.shakePad();
		const out = new Uint8Array(this._outLen);
		let pos = 0;
		while (pos < this._outLen) {
			this.x.shakeSqueezeBlock();
			const mem = new Uint8Array(this.x.memory.buffer);
			const off = this.x.getOutOffset();
			const take = Math.min(this._outLen - pos, this._rate);
			out.set(mem.subarray(off, off + take), pos);
			pos += take;
		}
		this._finalized = true;
		return out;
	}

	mac(msg: Uint8Array): Uint8Array {
		this.update(msg);
		return this.finalize();
	}

	dispose(): void {
		if (this._tok === undefined) return;
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
		}
	}

	static verify(
		tag: Uint8Array,
		key: Uint8Array,
		msg: Uint8Array,
		customization: Uint8Array,
	): true {
		_assertNotOwned('sha3');
		const m = new KMAC256(key, tag.length, customization);
		let exp: Uint8Array | undefined;
		try {
			m.update(msg);
			exp = m.finalize();
			if (!constantTimeEqual(exp, tag))
				throw new AuthenticationError('kmac256');
			return true;
		} finally {
			if (exp !== undefined) wipe(exp);
			m.dispose();
		}
	}
}

// ── KMACXOF128 ──────────────────────────────────────────────────────────────

/**
 * KMACXOF128 — XOF variant of KMAC128 (SP 800-185 §4.3.1). Output length
 * is caller-chosen per squeeze; the spec's right_encode(0) suffix marks the
 * XOF mode.
 */
export class KMACXOF128 {
	private readonly x: Sha3KmacExports;
	private readonly _rate = 168;
	private _squeezing = false;
	private _block = new Uint8Array(168);
	private _blockPos = 168;
	private _tok: symbol | undefined;

	constructor(key: Uint8Array, customization: Uint8Array) {
		if (key.length === 0)
			throw new Error('KMACXOF128: empty key — use CSHAKE128 instead');

		const en = encodeString(KMAC_N);
		const es = encodeString(customization);
		const csPrefix = new Uint8Array(en.length + es.length);
		csPrefix.set(en, 0); csPrefix.set(es, en.length);
		const cshakePad = bytepad(csPrefix, this._rate);
		const keyPad = bytepad(encodeString(key), this._rate);

		this.x = getExports();
		this._tok = _acquireModule('sha3');
		try {
			this.x.cshake128Init();
			absorb(this.x, cshakePad);
			absorb(this.x, keyPad);
		} catch (e) {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
			throw e;
		}
	}

	update(chunk: Uint8Array): this {
		if (this._tok === undefined)
			throw new Error('KMACXOF128: instance has been disposed');
		if (this._squeezing)
			throw new Error('KMACXOF128: cannot update after squeeze');
		absorb(this.x, chunk);
		return this;
	}

	squeeze(n: number): Uint8Array {
		if (this._tok === undefined)
			throw new Error('KMACXOF128: instance has been disposed');
		if (n < 1) throw new RangeError(`squeeze length must be >= 1 (got ${n})`);

		if (!this._squeezing) {
			// SP 800-185 §4.3.1 — right_encode(0) terminates the absorb phase.
			absorb(this.x, rightEncode(0));
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

	mac(msg: Uint8Array, outLen: number): Uint8Array {
		this.update(msg);
		return this.squeeze(outLen);
	}

	dispose(): void {
		if (this._tok === undefined) return;
		this._block.fill(0);
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
		}
	}
}

// ── @internal — test-only cSHAKE-with-N helpers ─────────────────────────────

/**
 * cSHAKE128(X, L, N, S) — direct primitive with explicit function-name N.
 *
 * The public CSHAKE128 class hard-wires N to empty per SP 800-185 §3.4
 * ("Users of cSHAKE should not make up their own names"). This helper
 * exists so that ACVP cSHAKE corpora — whose records carry NIST-reserved
 * function names ("KMAC", "TupleHash", "ParallelHash") — can be exercised
 * against the WASM sponge. Acquires and releases the sha3 module token
 * around the computation; not safe to call concurrently with any stateful
 * sha3 user.
 *
 * @internal
 */
export function _cshake128Raw(
	functionName: Uint8Array,
	customization: Uint8Array,
	msg: Uint8Array,
	outLen: number,
): Uint8Array {
	if (functionName.length === 0 && customization.length === 0)
		throw new Error('_cshake128Raw: N and S both empty — use SHAKE128 instead');
	const rate = 168;
	const en = encodeString(functionName);
	const es = encodeString(customization);
	const cat = new Uint8Array(en.length + es.length);
	cat.set(en, 0); cat.set(es, en.length);
	const prefix = bytepad(cat, rate);

	const x = getExports();
	const tok = _acquireModule('sha3');
	try {
		x.cshake128Init();
		absorb(x, prefix);
		absorb(x, msg);
		x.shakePad();
		const out = new Uint8Array(outLen);
		let pos = 0;
		while (pos < outLen) {
			x.shakeSqueezeBlock();
			const mem = new Uint8Array(x.memory.buffer);
			const off = x.getOutOffset();
			const take = Math.min(outLen - pos, rate);
			out.set(mem.subarray(off, off + take), pos);
			pos += take;
		}
		return out;
	} finally {
		x.wipeBuffers();
		_releaseModule('sha3', tok);
	}
}

/**
 * cSHAKE256(X, L, N, S) — direct primitive with explicit function-name N.
 * See `_cshake128Raw` for usage notes.
 * @internal
 */
export function _cshake256Raw(
	functionName: Uint8Array,
	customization: Uint8Array,
	msg: Uint8Array,
	outLen: number,
): Uint8Array {
	if (functionName.length === 0 && customization.length === 0)
		throw new Error('_cshake256Raw: N and S both empty — use SHAKE256 instead');
	const rate = 136;
	const en = encodeString(functionName);
	const es = encodeString(customization);
	const cat = new Uint8Array(en.length + es.length);
	cat.set(en, 0); cat.set(es, en.length);
	const prefix = bytepad(cat, rate);

	const x = getExports();
	const tok = _acquireModule('sha3');
	try {
		x.cshake256Init();
		absorb(x, prefix);
		absorb(x, msg);
		x.shakePad();
		const out = new Uint8Array(outLen);
		let pos = 0;
		while (pos < outLen) {
			x.shakeSqueezeBlock();
			const mem = new Uint8Array(x.memory.buffer);
			const off = x.getOutOffset();
			const take = Math.min(outLen - pos, rate);
			out.set(mem.subarray(off, off + take), pos);
			pos += take;
		}
		return out;
	} finally {
		x.wipeBuffers();
		_releaseModule('sha3', tok);
	}
}

// ── KMACXOF256 ──────────────────────────────────────────────────────────────

/**
 * KMACXOF256 — XOF variant of KMAC256 (SP 800-185 §4.3.1).
 */
export class KMACXOF256 {
	private readonly x: Sha3KmacExports;
	private readonly _rate = 136;
	private _squeezing = false;
	private _block = new Uint8Array(136);
	private _blockPos = 136;
	private _tok: symbol | undefined;

	constructor(key: Uint8Array, customization: Uint8Array) {
		if (key.length === 0)
			throw new Error('KMACXOF256: empty key — use CSHAKE256 instead');

		const en = encodeString(KMAC_N);
		const es = encodeString(customization);
		const csPrefix = new Uint8Array(en.length + es.length);
		csPrefix.set(en, 0); csPrefix.set(es, en.length);
		const cshakePad = bytepad(csPrefix, this._rate);
		const keyPad = bytepad(encodeString(key), this._rate);

		this.x = getExports();
		this._tok = _acquireModule('sha3');
		try {
			this.x.cshake256Init();
			absorb(this.x, cshakePad);
			absorb(this.x, keyPad);
		} catch (e) {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
			throw e;
		}
	}

	update(chunk: Uint8Array): this {
		if (this._tok === undefined)
			throw new Error('KMACXOF256: instance has been disposed');
		if (this._squeezing)
			throw new Error('KMACXOF256: cannot update after squeeze');
		absorb(this.x, chunk);
		return this;
	}

	squeeze(n: number): Uint8Array {
		if (this._tok === undefined)
			throw new Error('KMACXOF256: instance has been disposed');
		if (n < 1) throw new RangeError(`squeeze length must be >= 1 (got ${n})`);

		if (!this._squeezing) {
			absorb(this.x, rightEncode(0));
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

	mac(msg: Uint8Array, outLen: number): Uint8Array {
		this.update(msg);
		return this.squeeze(outLen);
	}

	dispose(): void {
		if (this._tok === undefined) return;
		this._block.fill(0);
		try {
			this.x.wipeBuffers();
		} finally {
			_releaseModule('sha3', this._tok);
			this._tok = undefined;
		}
	}
}
