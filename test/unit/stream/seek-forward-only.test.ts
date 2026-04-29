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
 * `OpenStream.seek(index)` is forward-only.
 *
 * Backward seeks would re-use a per-chunk counter nonce against a new
 * ciphertext, permitting plaintext replay against a stale opener. The
 * cryptographic properties are unchanged; we're just refusing a surprising
 * semantic with a clear `RangeError`. Construct a new `OpenStream` if you
 * need to restart from an earlier chunk.
 *
 * Cases:
 *   1. Forward seek succeeds.
 *   2. Backward seek throws with 'forward-only' in the message.
 *   3. Seek to current counter is a no-op (allowed).
 *   4. Seek after finalize throws with 'finalized' (state check fires first).
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes } from '../../../src/ts/index.js';
import { SealStream, OpenStream } from '../../../src/ts/stream/index.js';
import { XChaCha20Cipher } from '../../../src/ts/chacha20/cipher-suite.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
});

function sealThree(key: Uint8Array): { preamble: Uint8Array; chunks: Uint8Array[]; encrypted: Uint8Array[] } {
	const sealer = new SealStream(XChaCha20Cipher, key, { chunkSize: 1024 });
	const chunks = [randomBytes(100), randomBytes(100), randomBytes(100), randomBytes(50)];
	const encrypted = [
		sealer.push(chunks[0]),
		sealer.push(chunks[1]),
		sealer.push(chunks[2]),
		sealer.finalize(chunks[3]),
	];
	return { preamble: sealer.preamble, chunks, encrypted };
}

describe('OpenStream.seek forward-only', () => {
	it('1. forward seek succeeds: counter=0 → seek(2) decrypts chunk 2', () => {
		const key = randomBytes(32);
		const { preamble, chunks, encrypted } = sealThree(key);

		const opener = new OpenStream(XChaCha20Cipher, key, preamble);
		opener.seek(2);
		const pt = opener.pull(encrypted[2]);
		expect(pt).toEqual(chunks[2]);
		opener.dispose();
	});

	it('2. backward seek throws RangeError with "forward-only" in message', () => {
		const key = randomBytes(32);
		const { preamble, encrypted } = sealThree(key);

		const opener = new OpenStream(XChaCha20Cipher, key, preamble);
		// Advance counter by pulling three data chunks (0, 1, 2).
		opener.pull(encrypted[0]);
		opener.pull(encrypted[1]);
		opener.pull(encrypted[2]);
		// Now counter === 3. Ask to go back to 1.
		expect(() => opener.seek(1)).toThrow(RangeError);
		expect(() => opener.seek(1)).toThrow(/forward-only/);
		// Zero is also backward.
		expect(() => opener.seek(0)).toThrow(/forward-only/);
		opener.dispose();
	});

	it('3. seek to current counter is a no-op (allowed)', () => {
		const key = randomBytes(32);
		const { preamble, chunks, encrypted } = sealThree(key);

		const opener = new OpenStream(XChaCha20Cipher, key, preamble);
		opener.pull(encrypted[0]);
		opener.pull(encrypted[1]);
		// counter === 2 now
		expect(() => opener.seek(2)).not.toThrow();
		// The opener should still be able to pull chunk 2 next.
		const pt = opener.pull(encrypted[2]);
		expect(pt).toEqual(chunks[2]);
		opener.dispose();
	});

	it('4. seek after finalize throws with "finalized" (state check fires before range check)', () => {
		const key = randomBytes(32);
		const { preamble, encrypted } = sealThree(key);

		const opener = new OpenStream(XChaCha20Cipher, key, preamble);
		opener.pull(encrypted[0]);
		opener.pull(encrypted[1]);
		opener.pull(encrypted[2]);
		opener.finalize(encrypted[3]);

		// State is 'finalized' — state guard fires first regardless of direction.
		expect(() => opener.seek(100)).toThrow(/finalized/);
		expect(() => opener.seek(0)).toThrow(/finalized/);
	});

	it('5. seek > Number.MAX_SAFE_INTEGER throws without mutating state', () => {
		// IEEE 754 represents 2^53 as an exact integer, so Number.isInteger passes.
		// Number.isSafeInteger rejects it directly, closing the gap that the
		// previous Number.isInteger + > MAX_SAFE_INTEGER pair tried to span.
		const key = randomBytes(32);
		const { preamble, chunks, encrypted } = sealThree(key);

		const opener = new OpenStream(XChaCha20Cipher, key, preamble);
		expect(() => opener.seek(Number.MAX_SAFE_INTEGER + 1)).toThrow(RangeError);
		expect(() => opener.seek(Number.MAX_SAFE_INTEGER + 1)).toThrow(/MAX_SAFE_INTEGER/);

		// Stream remains usable — counter was never mutated, keys never wiped.
		const pt = opener.pull(encrypted[0]);
		expect(pt).toEqual(chunks[0]);
		opener.dispose();
	});

	it('6. negative seek throws without mutating state', () => {
		const key = randomBytes(32);
		const { preamble, chunks, encrypted } = sealThree(key);

		const opener = new OpenStream(XChaCha20Cipher, key, preamble);
		expect(() => opener.seek(-1)).toThrow(RangeError);
		// Stream remains usable.
		const pt = opener.pull(encrypted[0]);
		expect(pt).toEqual(chunks[0]);
		opener.dispose();
	});

	it('7. fractional seek throws without mutating state', () => {
		const key = randomBytes(32);
		const { preamble, chunks, encrypted } = sealThree(key);

		const opener = new OpenStream(XChaCha20Cipher, key, preamble);
		expect(() => opener.seek(1.5)).toThrow(RangeError);
		const pt = opener.pull(encrypted[0]);
		expect(pt).toEqual(chunks[0]);
		opener.dispose();
	});

	it('8. NaN seek throws without mutating state', () => {
		const key = randomBytes(32);
		const { preamble, chunks, encrypted } = sealThree(key);

		const opener = new OpenStream(XChaCha20Cipher, key, preamble);
		expect(() => opener.seek(NaN)).toThrow(RangeError);
		const pt = opener.pull(encrypted[0]);
		expect(pt).toEqual(chunks[0]);
		opener.dispose();
	});

	it('9. Infinity seek throws without mutating state', () => {
		const key = randomBytes(32);
		const { preamble, chunks, encrypted } = sealThree(key);

		const opener = new OpenStream(XChaCha20Cipher, key, preamble);
		expect(() => opener.seek(Infinity)).toThrow(RangeError);
		const pt = opener.pull(encrypted[0]);
		expect(pt).toEqual(chunks[0]);
		opener.dispose();
	});
});
