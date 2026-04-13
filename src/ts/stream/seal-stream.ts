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
// src/ts/stream/seal-stream.ts
//
// SealStream — cipher-agnostic streaming encryption using the STREAM
// construction (Hoang/Reyhanitabar/Rogaway/Vizár, CRYPTO 2015).

import { randomBytes, concat } from '../utils.js';
import { isInitialized } from '../init.js';
import type { CipherSuite, DerivedKeys, SealStreamOpts } from './types.js';
import { CHUNK_MIN, CHUNK_MAX, TAG_DATA, TAG_FINAL } from './constants.js';
import { writeHeader, makeCounterNonce } from './header.js';


function u32beFrame(n: number): Uint8Array {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n, false);
	return b;
}

// Module-level nonce injection slot — used only by _fromNonce for KAT tests.
// Set immediately before constructing, cleared inside the constructor.
let _injectNonce: Uint8Array | undefined;

export class SealStream {
	/** Preamble sent before the first chunk: header [|| kemCiphertext]. */
	readonly preamble: Uint8Array;

	private readonly cipher: CipherSuite;
	private readonly keys: DerivedKeys;
	private readonly chunkSize: number;
	private readonly framed: boolean;
	private counter = 0;
	private state: 'ready' | 'finalized' | 'failed' = 'ready';

	constructor(cipher: CipherSuite, key: Uint8Array, opts?: SealStreamOpts) {
		this.cipher = cipher;
		this.chunkSize = opts?.chunkSize ?? 65536;
		this.framed = opts?.framed ?? false;

		if (!isInitialized('sha2'))
			throw new Error(
				'leviathan-crypto: stream layer requires sha2 for key derivation — '
				+ 'call init({ sha2: ... }) before creating a SealStream',
			);
		if (key.length !== cipher.keySize)
			throw new RangeError(`key must be ${cipher.keySize} bytes (got ${key.length})`);
		if (this.chunkSize < CHUNK_MIN || this.chunkSize > CHUNK_MAX)
			throw new RangeError(`chunkSize must be in [${CHUNK_MIN}, ${CHUNK_MAX}] (got ${this.chunkSize})`);

		const nonce = _injectNonce ?? randomBytes(16);
		_injectNonce = undefined;
		this.keys = cipher.deriveKeys(key, nonce);
		const kemCt = this.keys.kemCiphertext;
		const header = writeHeader(cipher.formatEnum, this.framed, nonce, this.chunkSize);
		this.preamble = kemCt ? concat(header, kemCt) : header;
	}

	/**
	 * @internal
	 * KAT-only factory — injects a fixed nonce so seal output is deterministic.
	 * Stripped from published `.d.ts` by `stripInternal`. Do not use in production.
	 */
	static _fromNonce(cipher: CipherSuite, key: Uint8Array, opts: SealStreamOpts, nonce: Uint8Array): SealStream {
		if (nonce.length !== 16)
			throw new RangeError(`_nonce must be 16 bytes (got ${nonce.length})`);
		_injectNonce = nonce;
		try {
			return new SealStream(cipher, key, opts);
		} finally {
			_injectNonce = undefined;
		}
	}

	push(chunk: Uint8Array, opts?: { aad?: Uint8Array }): Uint8Array {
		if (this.state !== 'ready')
			throw new Error(`SealStream: cannot push in state '${this.state}'`);
		// Argument validation runs before the crypto-failure try/catch so a
		// too-big chunk throws without wiping keys or transitioning to 'failed'.
		// The caller can retry with a correctly-sized chunk.
		if (chunk.length > this.chunkSize)
			throw new RangeError(`chunk exceeds chunkSize (${chunk.length} > ${this.chunkSize})`);
		try {
			const nonce = makeCounterNonce(this.counter, TAG_DATA);
			const result = this.cipher.sealChunk(this.keys, nonce, chunk, opts?.aad);
			this.counter++;
			return this.framed ? concat(u32beFrame(result.length), result) : result;
		} catch (err) {
			this.cipher.wipeKeys(this.keys);
			this.state = 'failed';
			throw err;
		}
	}

	finalize(chunk: Uint8Array, opts?: { aad?: Uint8Array }): Uint8Array {
		if (this.state !== 'ready')
			throw new Error(`SealStream: cannot finalize in state '${this.state}'`);
		if (chunk.length > this.chunkSize)
			throw new RangeError(`chunk exceeds chunkSize (${chunk.length} > ${this.chunkSize})`);
		try {
			const nonce = makeCounterNonce(this.counter, TAG_FINAL);
			const result = this.cipher.sealChunk(this.keys, nonce, chunk, opts?.aad);
			this.cipher.wipeKeys(this.keys);
			this.state = 'finalized';
			return this.framed ? concat(u32beFrame(result.length), result) : result;
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

	toTransformStream(): TransformStream<Uint8Array, Uint8Array> {
		let headerSent = false;
		let buffered: Uint8Array | null = null;
		return new TransformStream<Uint8Array, Uint8Array>({
			transform: (chunk, controller) => {
				try {
					if (!headerSent) {
						controller.enqueue(this.preamble);
						headerSent = true;
					}
					if (buffered !== null) {
						controller.enqueue(this.push(buffered));
					}
					buffered = chunk;
				} catch (err) {
					this.dispose();
					throw err;
				}
			},
			flush: (controller) => {
				try {
					if (!headerSent) {
						controller.enqueue(this.preamble);
					}
					controller.enqueue(this.finalize(buffered ?? new Uint8Array(0)));
				} catch (err) {
					this.dispose();
					throw err;
				}
			},
		});
	}
}
