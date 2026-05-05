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
// src/ts/shared/pkcs7.ts
//
// Cipher-agnostic PKCS7 padding helpers (RFC 5652 §6.3). Used by every
// CBC mode wrapper in the library — `SerpentCbc`, `AESCbc`, the Serpent
// pool worker, and any future CBC-based suite. A single source of truth
// keeps the branch-free, Vaudenay-2002-closed padding check identical
// across all call sites; divergence between paths would reintroduce a
// padding-oracle.

// Generic error string used by every failure mode of `pkcs7Strip` and the
// length/alignment gates in CBC `decrypt` paths. No numeric leaks, no
// structural disclosure — a caller cannot distinguish "bad length" from
// "bad padding" by message or by timing.
export const PKCS7_INVALID = 'invalid ciphertext';

/**
 * Apply PKCS7 padding to `data` so the result length is a multiple of 16.
 * Padding length is always 1–16 bytes so a full pad block is appended when
 * `data.length` is already block-aligned.
 * @param data  Input bytes of any length
 * @returns     New Uint8Array padded to the next 16-byte boundary
 */
export function pkcs7Pad(data: Uint8Array): Uint8Array {
	const padLen = 16 - (data.length % 16);  // 1..16
	const out    = new Uint8Array(data.length + padLen);
	out.set(data);
	out.fill(padLen, data.length);
	return out;
}

/**
 * Remove PKCS7 padding from a block-aligned buffer in constant time.
 *
 * Branch-free over all secret bits — padding length and per-byte comparisons
 * are accumulated into a single `bad` flag with no early exit. Closes the
 * Vaudenay 2002 padding-oracle surface. Throws a single generic
 * `RangeError('invalid ciphertext')` for every failure mode: empty input,
 * non-block-aligned length, padding byte out of range 1–16, and any per-byte
 * mismatch in the padding region.
 * @param data  Block-aligned ciphertext (length must be a multiple of 16)
 * @returns     Plaintext with padding removed
 */
export function pkcs7Strip(data: Uint8Array): Uint8Array {
	if (data.length === 0 || data.length % 16 !== 0)
		throw new RangeError(PKCS7_INVALID);

	const padLen = data[data.length - 1];

	let bad = 0;
	bad |= ((padLen - 1) >>> 31);       // 1 if padLen == 0
	bad |= ((16 - padLen) >>> 31);      // 1 if padLen > 16

	// Per-byte pad-region mask without branches on secret bits.
	//   inPadRegion = 0xff when i >= 16 - padLen
	//               = 0x00 otherwise
	//
	// (16 - padLen - i - 1) is negative iff i >= 16 - padLen. A signed
	// arithmetic shift by 31 yields -1 for negative, 0 for non-negative;
	// ANDing with 0xff collapses those to 0xff and 0x00.
	for (let i = 0; i < 16; i++) {
		const idx  = data.length - 16 + i;
		const mask = ((16 - padLen - i - 1) >> 31) & 0xff;
		bad |= (data[idx] ^ padLen) & mask;
	}

	const invalid = ((bad - 1) >>> 31) ^ 1;
	if (invalid) throw new RangeError(PKCS7_INVALID);

	return data.subarray(0, data.length - padLen);
}
