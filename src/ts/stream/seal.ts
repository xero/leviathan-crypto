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
// src/ts/stream/seal.ts
//
// Seal — unified single-shot encrypt/decrypt using the STREAM construction.
// Seal blobs are valid SealStream blobs with a single final chunk.
// OpenStream can decrypt a Seal blob without modification.

import { concat } from '../utils.js';
import type { CipherSuite } from './types.js';
import { SealStream } from './seal-stream.js';
import { OpenStream } from './open-stream.js';
import { HEADER_SIZE, CHUNK_MAX, CHUNK_MIN } from './constants.js';

// eslint-disable-next-line @typescript-eslint/no-extraneous-class -- static-only class required for stripInternal to strip _fromNonce from .d.ts
export class Seal {
	static encrypt(
		suite: CipherSuite,
		key: Uint8Array,
		pt: Uint8Array,
		opts?: { aad?: Uint8Array },
	): Uint8Array {
		if (pt.length > CHUNK_MAX)
			throw new RangeError(`Seal.encrypt: plaintext exceeds maximum (${CHUNK_MAX} bytes) — use SealStream for large data`);
		const sealer = new SealStream(suite, key, { chunkSize: Math.max(pt.length, CHUNK_MIN) });
		try {
			const ct = sealer.finalize(pt, opts);
			return concat(sealer.preamble, ct);
		} finally {
			sealer.dispose();
		}
	}

	static decrypt(
		suite: CipherSuite,
		key: Uint8Array,
		blob: Uint8Array,
		opts?: { aad?: Uint8Array },
	): Uint8Array {
		const preambleLen = HEADER_SIZE + suite.kemCtSize;
		if (blob.length < preambleLen)
			throw new RangeError(`Seal.decrypt: blob too short — need at least ${preambleLen} bytes (got ${blob.length})`);
		const preamble = blob.subarray(0, preambleLen);
		const opener = new OpenStream(suite, key, preamble);
		try {
			return opener.finalize(blob.subarray(preambleLen), opts);
		} finally {
			opener.dispose();
		}
	}

	/**
	 * @internal
	 * KAT-only — injects a fixed nonce so output is deterministic.
	 * Stripped from published `.d.ts` by `stripInternal`. Do not use in production.
	 */
	static _fromNonce(
		suite: CipherSuite,
		key: Uint8Array,
		pt: Uint8Array,
		nonce: Uint8Array,
		opts?: { aad?: Uint8Array },
	): Uint8Array {
		if (pt.length > CHUNK_MAX)
			throw new RangeError(`Seal._fromNonce: plaintext exceeds maximum (${CHUNK_MAX} bytes) — use SealStream for large data`);
		const sealer = SealStream._fromNonce(suite, key, { chunkSize: Math.max(pt.length, CHUNK_MIN) }, nonce);
		try {
			const ct = sealer.finalize(pt, opts);
			return concat(sealer.preamble, ct);
		} finally {
			sealer.dispose();
		}
	}
}
