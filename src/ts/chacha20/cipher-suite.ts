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
// src/ts/chacha20/cipher-suite.ts
//
// XChaCha20Cipher — CipherSuite implementation for the STREAM construction.
// HKDF-SHA-256 key derivation → HChaCha20 subkey → ChaCha20-Poly1305 per chunk.

import { getInstance, _assertNotOwned } from '../init.js';
import { HKDF_SHA256 } from '../sha2/index.js';
import { aeadEncrypt, aeadDecrypt, deriveSubkey } from './ops.js';
import { wipe, randomBytes } from '../utils.js';
import { WORKER_SOURCE } from '../embedded/chacha20-pool-worker.js';
import type { ChaChaExports } from './types.js';
import type { CipherSuite, DerivedKeys } from '../stream/types.js';

const INFO = new TextEncoder().encode('xchacha20-sealstream-v2');

function getExports(): ChaChaExports {
	return getInstance('chacha20').exports as unknown as ChaChaExports;
}

export const XChaCha20Cipher: CipherSuite & { keygen(): Uint8Array } = {
	formatEnum: 0x01,
	formatName: 'xchacha20',
	hkdfInfo: 'xchacha20-sealstream-v2',
	keySize: 32,
	kemCtSize: 0,
	tagSize: 16,
	padded: false,
	wasmChunkSize: 65536,  // src/asm/chacha20/buffers.ts CHUNK_SIZE
	wasmModules: ['chacha20'],

	keygen(): Uint8Array {
		return randomBytes(32);
	},

	deriveKeys(masterKey: Uint8Array, nonce: Uint8Array, _kemCt?: Uint8Array): DerivedKeys {
		_assertNotOwned('chacha20');
		const hkdf = new HKDF_SHA256();
		const streamKey = hkdf.derive(masterKey, nonce, INFO, 32);
		hkdf.dispose();

		// HChaCha20 subkey derivation — nonce[0:16] as XChaCha input
		const x = getExports();
		const subkey = deriveSubkey(x, streamKey, nonce);
		wipe(streamKey);
		return { bytes: subkey };
	},

	sealChunk(
		keys: DerivedKeys,
		counterNonce: Uint8Array,
		chunk: Uint8Array,
		aad?: Uint8Array,
	): Uint8Array {
		_assertNotOwned('chacha20');
		const x = getExports();
		const { ciphertext, tag } = aeadEncrypt(
			x, keys.bytes, counterNonce, chunk, aad ?? new Uint8Array(0),
		);
		const out = new Uint8Array(ciphertext.length + 16);
		out.set(ciphertext);
		out.set(tag, ciphertext.length);
		return out;
	},

	openChunk(
		keys: DerivedKeys,
		counterNonce: Uint8Array,
		chunk: Uint8Array,
		aad?: Uint8Array,
	): Uint8Array {
		_assertNotOwned('chacha20');
		if (chunk.length < 16)
			throw new RangeError(`chunk too short for 16-byte tag (got ${chunk.length})`);
		const x = getExports();
		const ct  = chunk.subarray(0, chunk.length - 16);
		const tag = chunk.subarray(chunk.length - 16);
		return aeadDecrypt(
			x, keys.bytes, counterNonce, ct, tag,
			aad ?? new Uint8Array(0), 'xchacha20-poly1305',
		);
	},

	wipeKeys(keys: DerivedKeys): void {
		wipe(keys.bytes);
	},

	createPoolWorker(): Worker {
		// IIFE source is bundled at lib build time (scripts/embed-workers.ts).
		// Avoids the syntactic `new Worker(new URL(..., import.meta.url))`
		// pattern that triggers eager worker-chunk emission in Vite's
		// transform hook (issue.md). Classic worker via blob URL —
		// module workers fail on file:// in Chromium (issue2.md).
		const blob = new Blob([WORKER_SOURCE], { type: 'application/javascript' });
		const url  = URL.createObjectURL(blob);
		const w    = new Worker(url);
		// Worker spec fetches the URL synchronously at construction. Revoke
		// in a macrotask so the spawn completes first; releases the Blob
		// (~5 KB per spawn × N workers) instead of leaking it for the
		// document's lifetime.
		setTimeout(() => URL.revokeObjectURL(url), 0);
		return w;
	},
};
