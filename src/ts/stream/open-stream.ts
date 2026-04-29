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
// src/ts/stream/open-stream.ts
//
// OpenStream — cipher-agnostic streaming decryption using the STREAM
// construction (Hoang/Reyhanitabar/Rogaway/Vizár, CRYPTO 2015).

import { isInitialized } from '../init.js';
import type { CipherSuite, DerivedKeys } from './types.js';
import { TAG_DATA, TAG_FINAL, CHUNK_MIN, CHUNK_MAX, HEADER_SIZE } from './constants.js';
import { readHeader, makeCounterNonce } from './header.js';

export class OpenStream {
	readonly chunkSize: number;
	readonly framed: boolean;

	private readonly cipher: CipherSuite;
	private readonly keys: DerivedKeys;
	private readonly maxWireChunk: number;
	private counter = 0;
	private state: 'ready' | 'finalized' | 'failed' = 'ready';

	constructor(cipher: CipherSuite, key: Uint8Array, preamble: Uint8Array) {
		this.cipher = cipher;

		if (!isInitialized('sha2'))
			throw new Error(
				'leviathan-crypto: stream layer requires sha2 for key derivation — '
				+ 'call init({ sha2: ... }) before creating an OpenStream',
			);
		const decKeySize = cipher.decKeySize ?? cipher.keySize;
		if (key.length !== decKeySize)
			throw new RangeError(`key must be ${decKeySize} bytes (got ${key.length})`);

		const expectedPreambleLen = HEADER_SIZE + cipher.kemCtSize;
		if (preamble.length !== expectedPreambleLen)
			throw new RangeError(
				`preamble must be exactly ${expectedPreambleLen} bytes (got ${preamble.length})`,
			);
		const h = readHeader(preamble.subarray(0, HEADER_SIZE));
		if (h.formatEnum !== cipher.formatEnum)
			throw new Error(
				`expected format 0x${cipher.formatEnum.toString(16).padStart(2, '0')} (${cipher.formatName}), `
				+ `got 0x${h.formatEnum.toString(16).padStart(2, '0')}`,
			);
		if (h.chunkSize < CHUNK_MIN || h.chunkSize > CHUNK_MAX)
			throw new RangeError(`header chunkSize must be in [${CHUNK_MIN}, ${CHUNK_MAX}] (got ${h.chunkSize})`);

		const kemCt = cipher.kemCtSize > 0
			? preamble.subarray(HEADER_SIZE, HEADER_SIZE + cipher.kemCtSize)
			: undefined;

		this.keys = cipher.deriveKeys(key, h.nonce, kemCt);
		this.chunkSize = h.chunkSize;
		this.framed = h.framed;
		// Max ciphertext chunk: padded plaintext + tag
		const paddedSize = cipher.padded
			? h.chunkSize + 16 - (h.chunkSize % 16)
			: h.chunkSize;
		this.maxWireChunk = paddedSize + cipher.tagSize;
	}

	pull(chunk: Uint8Array, opts?: { aad?: Uint8Array }): Uint8Array {
		if (this.state !== 'ready')
			throw new Error(`OpenStream: cannot pull in state '${this.state}'`);
		// Argument and wire-format validation runs before the crypto-failure
		// try/catch so a malformed chunk throws without wiping keys or
		// transitioning to 'failed'. The caller can retry with a corrected
		// chunk. Symmetric with SealStream.push.
		const data = this.framed ? this._stripFrame(chunk) : chunk;
		if (data.length < this.cipher.tagSize)
			throw new RangeError(
				`chunk too short to contain ${this.cipher.tagSize}-byte tag (got ${data.length} bytes)`,
			);
		if (data.length > this.maxWireChunk)
			throw new RangeError(
				`chunk exceeds max wire size (${data.length} > ${this.maxWireChunk})`,
			);
		try {
			const nonce = makeCounterNonce(this.counter, TAG_DATA);
			const plaintext = this.cipher.openChunk(this.keys, nonce, data, opts?.aad);
			this.counter++;
			return plaintext;
		} catch (err) {
			this.cipher.wipeKeys(this.keys);
			this.state = 'failed';
			throw err;
		}
	}

	finalize(chunk: Uint8Array, opts?: { aad?: Uint8Array }): Uint8Array {
		if (this.state !== 'ready')
			throw new Error(`OpenStream: cannot finalize in state '${this.state}'`);
		const data = this.framed ? this._stripFrame(chunk) : chunk;
		if (data.length < this.cipher.tagSize)
			throw new RangeError(
				`chunk too short to contain ${this.cipher.tagSize}-byte tag (got ${data.length} bytes)`,
			);
		if (data.length > this.maxWireChunk)
			throw new RangeError(
				`chunk exceeds max wire size (${data.length} > ${this.maxWireChunk})`,
			);
		try {
			const nonce = makeCounterNonce(this.counter, TAG_FINAL);
			const plaintext = this.cipher.openChunk(this.keys, nonce, data, opts?.aad);
			this.cipher.wipeKeys(this.keys);
			this.state = 'finalized';
			return plaintext;
		} catch (err) {
			this.cipher.wipeKeys(this.keys);
			this.state = 'failed';
			throw err;
		}
	}

	dispose(): void {
		if (this.state === 'ready') {
			this.cipher.wipeKeys(this.keys);
			this.state = 'finalized';
		}
		// 'failed' already wiped keys; 'finalized' already wiped keys — no-op.
	}

	seek(index: number): void {
		if (this.state !== 'ready')
			throw new Error(`OpenStream: cannot seek in state '${this.state}'`);
		if (!Number.isSafeInteger(index) || index < 0)
			throw new RangeError(
				`seek index must be a non-negative safe integer ≤ Number.MAX_SAFE_INTEGER (got ${index})`,
			);
		if (index < this.counter)
			throw new RangeError(
				`OpenStream: seek is forward-only — current counter ${this.counter}, requested ${index}. `
				+ 'Backward seeks would permit plaintext replay; construct a new OpenStream to restart.',
			);
		this.counter = index;
	}

	private _stripFrame(chunk: Uint8Array): Uint8Array {
		if (chunk.length < 4)
			throw new RangeError(`framed chunk too short — need at least 4 bytes (got ${chunk.length})`);
		const dv = new DataView(chunk.buffer, chunk.byteOffset);
		const payloadLen = dv.getUint32(0, false);
		if (payloadLen !== chunk.length - 4)
			throw new RangeError(
				`framed chunk length mismatch — prefix says ${payloadLen}, actual payload is ${chunk.length - 4}`,
			);
		return chunk.subarray(4);
	}

	toTransformStream(): TransformStream<Uint8Array, Uint8Array> {
		let buffered: Uint8Array | null = null;
		return new TransformStream<Uint8Array, Uint8Array>({
			transform: (chunk, controller) => {
				try {
					if (buffered !== null) {
						controller.enqueue(this.pull(buffered));
					}
					buffered = chunk;
				} catch (err) {
					this.dispose();
					throw err;
				}
			},
			flush: (controller) => {
				try {
					if (buffered !== null) {
						controller.enqueue(this.finalize(buffered));
					} else {
						this.dispose(); // no chunks piped — wipe keys, emit nothing
					}
				} catch (err) {
					this.dispose();
					throw err;
				}
			},
		});
	}
}
