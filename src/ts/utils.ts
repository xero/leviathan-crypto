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
// src/ts/utils.ts
//
// Pure TypeScript utilities — no init() dependency.
// Ported from leviathan/src/base.ts (Convert namespace, Util namespace, constantTimeEqual).

// ── Encoding ────────────────────────────────────────────────────────────────

/** Hex string to Uint8Array. Accepts lowercase/uppercase, optional 0x prefix. Throws RangeError on odd-length or non-hex input. */
export const hexToBytes = (hex: string): Uint8Array => {
	if (hex.startsWith('0x') || hex.startsWith('0X')) hex = hex.slice(2);
	if (hex.length % 2)
		throw new RangeError(`hexToBytes: odd-length string (${hex.length} chars) — input must be an even-length hex string`);
	// parseInt('0g', 16) returns 0 (not NaN) because it stops at the first
	// invalid char — silent wrong-answer. Reject non-hex chars up front.
	if (hex.length > 0 && !/^[0-9a-fA-F]*$/.test(hex))
		throw new RangeError('hexToBytes: input contains non-hex characters');
	const bin = new Uint8Array(hex.length >>> 1);
	for (let i = 0, len = hex.length >>> 1; i < len; i++)
		bin[i] = parseInt(hex.slice(i << 1, (i << 1) + 2), 16);
	return bin;
};

/** Uint8Array to lowercase hex string. */
export const bytesToHex = (bytes: Uint8Array): string => {
	const lut = '0123456789abcdef';
	let str = '';
	for (const b of bytes)
		str += lut.charAt((b >>> 4) & 0x0f) + lut.charAt(b & 0x0f);
	return str;
};

/** UTF-8 string to Uint8Array. */
export const utf8ToBytes = (str: string): Uint8Array => {
	return new TextEncoder().encode(str);
};

/** Uint8Array to UTF-8 string. */
export const bytesToUtf8 = (bytes: Uint8Array): string => {
	return new TextDecoder().decode(bytes);
};

/** Base64 or base64url string to Uint8Array. Handles padded, unpadded, and legacy %3d padding. Throws RangeError on invalid input. */
export const base64ToBytes = (b64: string): Uint8Array => {
	// Normalise base64url → base64
	b64 = b64.replace(/-/g, '+').replace(/_/g, '/').replace(/%3d/gi, '=');
	// Re-pad if unpadded (RFC 4648 §5 base64url omits '=')
	const rem = b64.length % 4;
	if (rem === 1) throw new RangeError('base64ToBytes: invalid base64 input'); // no valid b64 produces this
	if (rem === 2) b64 += '==';
	if (rem === 3) b64 += '=';
	if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new RangeError('base64ToBytes: invalid base64 input');

	let strlen = b64.length / 4 * 3;
	if (b64.charAt(b64.length - 1) === '=') strlen--;
	if (b64.charAt(b64.length - 2) === '=') strlen--;

	if (typeof atob !== 'undefined') {
		try {
			return new Uint8Array(atob(b64).split('').map(c => c.charCodeAt(0)));
		} catch {
			throw new RangeError('base64ToBytes: invalid base64 input');
		}
	}

	// Fallback: manual decode
	const decodingTable = new Int8Array([
		-1, -1, -1, -1, -1, -1, -1, -1,   -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1,   -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1,   -1, -1, -1, 62, -1, 62, -1, 63,
		52, 53, 54, 55, 56, 57, 58, 59,   60, 61, -1, -1, -1, -2, -1, -1,
		-1,  0,  1,  2,  3,  4,  5,  6,    7,  8,  9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22,   23, 24, 25, -1, -1, -1, -1, 63,
		-1, 26, 27, 28, 29, 30, 31, 32,   33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48,   49, 50, 51, -1, -1, -1, -1, -1,
	]);
	let p = 0;
	const bin = new Uint8Array(strlen);
	for (let i = 0; i < b64.length;) {
		const a = b64.charAt(i) === '=' || b64.charCodeAt(i) > 122 ? 0 : decodingTable[b64.charCodeAt(i)]; i++;
		const b = b64.charAt(i) === '=' || b64.charCodeAt(i) > 122 ? 0 : decodingTable[b64.charCodeAt(i)]; i++;
		const c = b64.charAt(i) === '=' || b64.charCodeAt(i) > 122 ? 0 : decodingTable[b64.charCodeAt(i)]; i++;
		const d = b64.charAt(i) === '=' || b64.charCodeAt(i) > 122 ? 0 : decodingTable[b64.charCodeAt(i)]; i++;
		const triple = (a << 18) + (b << 12) + (c << 6) + d;
		if (b64.charAt(i - 3) !== '=') bin[p++] = (triple >>> 16) & 0xff;
		if (b64.charAt(i - 2) !== '=') bin[p++] = (triple >>> 8) & 0xff;
		if (b64.charAt(i - 1) !== '=') bin[p++] = triple & 0xff;
	}
	return bin;
};

/** Uint8Array to base64 string. Pass url=true for base64url (RFC 4648 §5 — no padding characters). */
export const bytesToBase64 = (bytes: Uint8Array, url = false): string => {
	if (typeof btoa !== 'undefined') {
		const raw = btoa(String.fromCharCode.apply(null, Array.from(bytes)));
		return url ? raw.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '') : raw;
	}

	// Fallback: manual encode
	const table = url
		? 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
		: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	let base64 = '';
	for (let i = 0; i < bytes.length;) {
		const a = i < bytes.length ? bytes[i] : 0; i++;
		const b = i < bytes.length ? bytes[i] : 0; i++;
		const c = i < bytes.length ? bytes[i] : 0; i++;
		const triple = (a << 0x10) + (b << 0x08) + c;
		base64 += table.charAt((triple >>> 18) & 0x3F);
		base64 += table.charAt((triple >>> 12) & 0x3F);
		base64 += (i < bytes.length + 2) ? table.charAt((triple >>> 6) & 0x3F) : (url ? '' : '=');
		base64 += (i < bytes.length + 1) ? table.charAt(triple & 0x3F) : (url ? '' : '=');
	}
	return base64;
};

// ── Constant-time comparison ────────────────────────────────────────────────

import { CT_WASM } from './ct-wasm.js';

let _ctCompare: ((a: number, b: number, len: number) => number) | null = null;
let _ctMem: WebAssembly.Memory | null = null;
let _ctInit = false;
let _ctInitError: Error | null = null;

// CT WASM module uses 1 page (64KB) of linear memory with both buffers
// laid out side-by-side: a at offset 0, b at offset a.length.
// Max per-side = _ctMem.buffer.byteLength >>> 1 = 32768 bytes.
// In practice the largest comparison is a 32-byte HMAC-SHA-256 tag.
export const CT_MAX_BYTES = 32768;

/**
 * Compile and instantiate the SIMD WASM ct module. On failure, caches the
 * branded error and re-throws on every subsequent call; no retries, no
 * fallback. Throws on runtimes without WebAssembly SIMD and on any
 * instantiation error.
 */
function _initCt(): void {
	if (_ctInit) {
		if (_ctInitError) throw _ctInitError;
		return;
	}
	_ctInit = true;
	if (!hasSIMD()) {
		_ctInitError = new Error(
			'leviathan-crypto: constantTimeEqual requires WebAssembly SIMD — '
			+ 'this runtime does not support it',
		);
		throw _ctInitError;
	}
	try {
		const buf = CT_WASM.buffer.slice(CT_WASM.byteOffset, CT_WASM.byteOffset + CT_WASM.byteLength);
		const mod = new WebAssembly.Module(buf as ArrayBuffer);
		const inst = new WebAssembly.Instance(mod);
		const exports = inst.exports as {
			memory:  WebAssembly.Memory;
			compare: (a: number, b: number, len: number) => number;
		};
		_ctMem     = exports.memory;
		_ctCompare = exports.compare;
	} catch (cause) {
		_ctInitError = new Error(
			`leviathan-crypto: ct WASM module failed to instantiate: ${(cause as Error).message}`,
		);
		throw _ctInitError;
	}
}

/**
 * Constant-time byte-array equality.
 * Runs entirely inside a WASM SIMD module (v128 XOR accumulate with
 * branch-free reduction). Throws on runtimes without SIMD support —
 * no JS fallback. Length check is not constant-time (length is
 * non-secret in all protocols). Max input size: 32768 bytes per side.
 */
export const constantTimeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
	if (a.length !== b.length) return false;
	if (a.length > CT_MAX_BYTES)
		throw new RangeError(`constantTimeEqual: max ${CT_MAX_BYTES} bytes (got ${a.length})`);
	_initCt();
	// Copy module-level refs to locals. _initCt() either populates both
	// _ctMem and _ctCompare or throws; the null check below is a defensive
	// invariant guard that is unreachable on a correctly-initialized module.
	const memObj  = _ctMem;
	const compare = _ctCompare;
	if (!memObj || !compare)
		throw new Error('leviathan-crypto: ct init invariant violated');
	const mem = new Uint8Array(memObj.buffer);
	mem.set(a, 0);
	mem.set(b, a.length);
	try {
		return compare(0, a.length, a.length) === 1;
	} finally {
		mem.fill(0, 0, a.length * 2);
	}
};

/**
 * Reset the internal CT WASM cache, including any cached initialization
 * error. Exists so the test suite can force re-instantiation across
 * describe blocks.
 * @internal
 */
export function _ctResetForTesting(): void {
	_ctInit = false;
	_ctCompare = null;
	_ctMem = null;
	_ctInitError = null;
}

/** Zero a typed array in place. */
export const wipe = (data: Uint8Array | Uint16Array | Uint32Array): void => {
	data.fill(0);
};

/** XOR two equal-length Uint8Arrays, returns new array. */
export const xor = (a: Uint8Array, b: Uint8Array): Uint8Array => {
	if (a.length !== b.length)
		throw new RangeError(`xor: length mismatch (${a.length} vs ${b.length})`);
	return a.map((val, i) => val ^ b[i]);
};

/** Concatenate one or more Uint8Arrays into a new array. */
export const concat = (...arrays: Uint8Array[]): Uint8Array => {
	const len = arrays.reduce((s, a) => s + a.length, 0);
	const out = new Uint8Array(len);
	let off = 0;
	for (const a of arrays) {
		out.set(a, off); off += a.length;
	}
	return out;
};

/** Cryptographically secure random bytes via Web Crypto API. */
export const randomBytes = (n: number): Uint8Array => {
	if (typeof globalThis.crypto === 'undefined'
		|| typeof globalThis.crypto.getRandomValues !== 'function')
		throw new Error(
			'leviathan-crypto: crypto.getRandomValues is required — '
			+ 'this runtime does not expose the Web Crypto API',
		);
	const buf = new Uint8Array(n);
	globalThis.crypto.getRandomValues(buf);
	return buf;
};

// ── SIMD detection ──────────────────────────────────────────────────────────

let _simd: boolean | null = null;

/**
 * Detects WASM SIMD support once and caches the result.
 * Used by init() to preflight-check before loading serpent/chacha20 modules.
 * Exported for consumers who want to feature-detect before calling init().
 */
export function hasSIMD(): boolean {
	if (_simd !== null) return _simd;
	if (typeof WebAssembly === 'undefined' || typeof WebAssembly.validate !== 'function') {
		_simd = false;
		return _simd;
	}
	// Minimal WASM module using v128 — validates iff SIMD is supported
	try {
		_simd = WebAssembly.validate(new Uint8Array([
			0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 123,
			3, 2, 1, 0, 10, 10, 1, 8, 0, 65, 0, 253, 15, 253, 98, 11,
		]));
	} catch {
		_simd = false;
	}
	return _simd;
}
