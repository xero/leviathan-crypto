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
// src/ts/stream/header.ts
//
// Wire format header encoding/decoding and counter nonce construction.

import { FLAG_FRAMED, HEADER_SIZE, TAG_DATA, TAG_FINAL } from './constants.js';

// The 16-byte nonce is a HKDF salt — not a direct cipher nonce.
// Both XChaCha20Cipher and SerpentCipher derive their actual key material
// and nonces from this value via HKDF-SHA-256. The 16-byte size is chosen
// to satisfy HChaCha20's 16-byte input requirement while also serving as a
// sufficient HKDF salt for the Serpent construction.
export function writeHeader(
	formatEnum: number,
	framed: boolean,
	nonce: Uint8Array,
	chunkSize: number,
): Uint8Array {
	if (!Number.isInteger(formatEnum) || formatEnum < 0 || formatEnum > 0x3f)
		throw new RangeError(`formatEnum must be an integer in [0, 0x3f] (got ${formatEnum})`);
	if (nonce.length !== 16)
		throw new RangeError(`nonce must be 16 bytes (got ${nonce.length})`);
	if (!Number.isInteger(chunkSize) || chunkSize < 0 || chunkSize > 0xffffff)
		throw new RangeError(`chunkSize must be an integer in [0, 0xFFFFFF] (got ${chunkSize})`);
	const h = new Uint8Array(HEADER_SIZE);
	h[0] = (framed ? FLAG_FRAMED : 0) | formatEnum;
	h.set(nonce, 1);
	// u24 big-endian chunk size
	h[17] = (chunkSize >> 16) & 0xff;
	h[18] = (chunkSize >>  8) & 0xff;
	h[19] =  chunkSize        & 0xff;
	return h;
}

export function readHeader(header: Uint8Array): {
	formatEnum: number;
	framed: boolean;
	nonce: Uint8Array;
	chunkSize: number;
} {
	if (header.length !== HEADER_SIZE)
		throw new RangeError(`header must be exactly ${HEADER_SIZE} bytes (got ${header.length})`);
	const byte0 = header[0];
	if (byte0 & 0x40)
		throw new RangeError(
			`header has reserved bit 6 set (byte0=0x${byte0.toString(16).padStart(2, '0')}) — unknown or malformed wire format`,
		);
	return {
		formatEnum: byte0 & 0x3f,
		framed: !!(byte0 & FLAG_FRAMED),
		nonce: header.slice(1, 17),
		chunkSize: (header[17] << 16) | (header[18] << 8) | header[19],
	};
}

/** 12-byte counter nonce: 11-byte BE counter + 1-byte final flag. */
export function makeCounterNonce(counter: number, finalFlag: number): Uint8Array {
	if (!Number.isInteger(counter) || counter < 0 || counter > Number.MAX_SAFE_INTEGER)
		throw new RangeError(`counter must be an integer in [0, ${Number.MAX_SAFE_INTEGER}]`);
	if (finalFlag !== TAG_DATA && finalFlag !== TAG_FINAL)
		throw new RangeError(`finalFlag must be TAG_DATA (0x00) or TAG_FINAL (0x01) (got 0x${finalFlag.toString(16).padStart(2, '0')})`);
	const n = new Uint8Array(12);
	// Write counter as 11-byte big-endian.
	// JS safe integers fit in 53 bits — we only need the lower 53 bits.
	// Pack from the right (byte 10 down to byte 0).
	let c = counter;
	for (let i = 10; i >= 0; i--) {
		n[i] = c & 0xff;
		c = Math.floor(c / 256);
	}
	n[11] = finalFlag;
	return n;
}
