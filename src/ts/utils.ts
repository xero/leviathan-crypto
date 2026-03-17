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

// ── Encoding ─────────────────────────────────────────────────────────────────

/** Hex string to Uint8Array. Accepts lowercase/uppercase, optional 0x prefix. */
export const hexToBytes = (hex: string): Uint8Array => {
	if (hex.startsWith('0x') || hex.startsWith('0X')) hex = hex.slice(2);
	if (hex.length % 2) hex += '0';
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

/** Base64 or base64url string to Uint8Array. Returns undefined on invalid input. */
export const base64ToBytes = (b64: string): Uint8Array | undefined => {
	// Normalise base64url → base64
	b64 = b64.replace(/-/g, '+').replace(/_/g, '/').replace(/%3d/g, '=');
	if (b64.length % 4 !== 0) return undefined;
	if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) return undefined;

	let strlen = b64.length / 4 * 3;
	if (b64.charAt(b64.length - 1) === '=') strlen--;
	if (b64.charAt(b64.length - 2) === '=') strlen--;

	if (typeof atob !== 'undefined') {
		try {
			return new Uint8Array(atob(b64).split('').map(c => c.charCodeAt(0)));
		} catch {
			return undefined;
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

/** Uint8Array to base64 string. Pass url=true for base64url encoding. */
export const bytesToBase64 = (bytes: Uint8Array, url = false): string => {
	if (typeof btoa !== 'undefined') {
		const raw = btoa(String.fromCharCode.apply(null, Array.from(bytes)));
		return url ? raw.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '%3d') : raw;
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
		base64 += (i < bytes.length + 2) ? table.charAt((triple >>> 6) & 0x3F) : (url ? '%3d' : '=');
		base64 += (i < bytes.length + 1) ? table.charAt(triple & 0x3F) : (url ? '%3d' : '=');
	}
	return base64;
};

// ── Crypto utilities ─────────────────────────────────────────────────────────

/**
 * Constant-time byte-array equality.
 * XOR-accumulate pattern — no early return on mismatch.
 * Length check is not constant-time (length is non-secret in all protocols).
 */
export const constantTimeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
	return diff === 0;
};

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

/** Concatenate two Uint8Arrays, returns new array. */
export const concat = (a: Uint8Array, b: Uint8Array): Uint8Array => {
	const result = new Uint8Array(a.length + b.length);
	result.set(a, 0);
	result.set(b, a.length);
	return result;
};

/** Cryptographically secure random bytes via Web Crypto API. */
export const randomBytes = (n: number): Uint8Array => {
	const buf = new Uint8Array(n);
	crypto.getRandomValues(buf);
	return buf;
};
