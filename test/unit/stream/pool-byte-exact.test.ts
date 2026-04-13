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
/**
 * Byte-exact cross-check: `SealStreamPool.seal(pt)` must produce the same
 * bytes as a main-thread `SealStream` driven over the same chunks with the
 * same nonce. Both paths route through `shared-ops.ts`; any drift here
 * fails loudly.
 *
 * The pool generates its own random nonce internally; we extract that nonce
 * from the pool header and feed it to `SealStream._fromNonce` (the KAT-only
 * factory) so the main-thread bytes are derived from the same 16-byte
 * header nonce the pool used.
 *
 * Size buckets are chosen at chunk-boundary cases: 0, 1, chunkSize-1,
 * chunkSize, chunkSize+1, 2*chunkSize, and a multi-MB payload.
 */
import '@vitest/web-worker';
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes } from '../../../src/ts/index.js';
import { SealStream, SealStreamPool } from '../../../src/ts/stream/index.js';
import {
	TestXChaCha20Cipher as XChaCha20Cipher,
	TestSerpentCipher   as SerpentCipher,
} from './_test-ciphers.js';
import { readHeader } from '../../../src/ts/stream/header.js';
import { HEADER_SIZE } from '../../../src/ts/stream/constants.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import type { CipherSuite } from '../../../src/ts/stream/types.js';
import type { WasmSource } from '../../../src/ts/wasm-source.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm, serpent: serpentWasm, sha2: sha2Wasm });
});

// chunkSize — the pool default for these tests. Keep small enough that the
// 5MB bucket exercises multiple chunks without multi-second CPU burn.
const CHUNK_SIZE = 65536;

const buckets: number[] = [
	0,
	1,
	CHUNK_SIZE - 1,
	CHUNK_SIZE,
	CHUNK_SIZE + 1,
	2 * CHUNK_SIZE,
	5 * 1024 * 1024,
];

interface CipherConfig {
	name: string;
	cipher: CipherSuite;
	wasm:   WasmSource | Record<string, WasmSource>;
}

const configs: CipherConfig[] = [
	{ name: 'XChaCha20', cipher: XChaCha20Cipher, wasm: chacha20Wasm },
	{ name: 'Serpent',   cipher: SerpentCipher,   wasm: { serpent: serpentWasm, sha2: sha2Wasm } },
];

// Drive a SealStream byte-for-byte identically to how SealStreamPool.seal
// slices the plaintext: floor(N / chunkSize) data chunks then one final
// chunk with the remainder. Empty input gets exactly one final chunk of
// length 0.
function sealViaMainThread(
	cipher: CipherSuite,
	key: Uint8Array,
	nonce: Uint8Array,
	plaintext: Uint8Array,
	chunkSize: number,
): Uint8Array {
	const ss = SealStream._fromNonce(cipher, key, { chunkSize }, nonce);
	const parts: Uint8Array[] = [ss.preamble];

	if (plaintext.length === 0) {
		parts.push(ss.finalize(new Uint8Array(0)));
	} else {
		const full = Math.floor(plaintext.length / chunkSize);
		const remainder = plaintext.length - full * chunkSize;
		for (let i = 0; i < full; i++) {
			const slice = plaintext.subarray(i * chunkSize, (i + 1) * chunkSize);
			if (remainder === 0 && i === full - 1) {
				parts.push(ss.finalize(slice));
			} else {
				parts.push(ss.push(slice));
			}
		}
		if (remainder > 0) {
			parts.push(ss.finalize(plaintext.subarray(full * chunkSize)));
		}
	}

	let totalLen = 0;
	for (const p of parts) totalLen += p.length;
	const out = new Uint8Array(totalLen);
	let pos = 0;
	for (const p of parts) {
		out.set(p, pos);
		pos += p.length;
	}
	return out;
}

// Deterministic filler for payload sizes that exceed the 65,536-byte
// crypto.getRandomValues cap. Content irrelevant to the cross-check — we
// just need two call sites to produce the same bytes.
function fillPattern(n: number): Uint8Array {
	const out = new Uint8Array(n);
	for (let i = 0; i < n; i++) out[i] = (i * 131 + 7) & 0xff;
	return out;
}

for (const cfg of configs) {
	describe(`pool-byte-exact — ${cfg.name}`, () => {
		// Cache the master key per-cipher so we don't regenerate it per bucket.
		const key = randomBytes(cfg.cipher.keySize);

		for (const n of buckets) {
			it(`SealStream output === SealStreamPool output for N=${n}`, async () => {
				const pt = n === 0 ? new Uint8Array(0) : fillPattern(n);

				const pool = await SealStreamPool.create(cfg.cipher, key, {
					wasm: cfg.wasm, workers: 1, chunkSize: CHUNK_SIZE,
				});
				let poolBytes: Uint8Array;
				try {
					poolBytes = await pool.seal(pt);
				} finally {
					pool.destroy();
				}

				// Extract the header nonce that the pool generated randomly.
				const h = readHeader(poolBytes.subarray(0, HEADER_SIZE));
				expect(h.chunkSize).toBe(CHUNK_SIZE);

				const mainBytes = sealViaMainThread(cfg.cipher, key, h.nonce, pt, CHUNK_SIZE);

				expect(mainBytes.length).toBe(poolBytes.length);
				// Compare byte-for-byte. Convert via Array first: vitest's deep
				// equality on Uint8Array of multi-MB size is slow.
				expect(mainBytes.length).toBe(poolBytes.length);
				let firstDiff = -1;
				for (let i = 0; i < mainBytes.length; i++) {
					if (mainBytes[i] !== poolBytes[i]) {
						firstDiff = i; break;
					}
				}
				if (firstDiff !== -1) {
					throw new Error(
						`main-thread vs pool bytes differ at offset ${firstDiff} `
						+ `(N=${n}, main[${firstDiff}]=0x${mainBytes[firstDiff].toString(16)}, `
						+ `pool[${firstDiff}]=0x${poolBytes[firstDiff].toString(16)})`,
					);
				}
			}, 60_000);
		}
	});
}
