//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▒ ▄▀▄ █▀▄
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
 * SealStream / OpenStream 'failed' terminal state.
 *
 * Contract:
 *   - A throw from the *crypto path* inside push / pull / finalize (auth
 *     failure, WASM error, cipher exception) wipes the derived keys and
 *     transitions the stream to state 'failed'.
 *   - An *argument-validation* throw (e.g. chunk larger than chunkSize) does
 *     NOT enter the failed state: keys are preserved, state stays 'ready',
 *     and the caller may retry with a corrected argument.
 *   - Subsequent method calls on a failed instance throw with 'failed' in
 *     the message — never "already finalized".
 *   - dispose() on a failed instance is a no-op (keys already wiped).
 *   - OpenStream.seek() throws on a failed instance.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, SealStream, OpenStream, XChaCha20Cipher, randomBytes } from '../../../src/ts/index.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import type { CipherSuite, DerivedKeys } from '../../../src/ts/stream/types.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
});

function isZero(b: Uint8Array): boolean {
	for (const x of b) if (x !== 0) return false;
	return true;
}

// Access the private keys.bytes buffer for wipe verification.

function getKeyBytes(stream: SealStream | OpenStream): Uint8Array {
	return ((stream as unknown) as { keys: { bytes: Uint8Array } }).keys.bytes;
}

function getState(stream: SealStream | OpenStream): string {
	return ((stream as unknown) as { state: string }).state;
}

// Mock cipher suite that delegates everything to XChaCha20Cipher but lets the
// test force a synthetic crypto-path throw from `sealChunk`. Used to exercise
// the 'failed' state transitions on the SealStream side without needing to
// induce real WASM failures.
function makeThrowingSealer(): CipherSuite {
	let throwNext = false;
	const suite: CipherSuite & { _trip(): void } = {
		formatEnum: XChaCha20Cipher.formatEnum,
		formatName: XChaCha20Cipher.formatName,
		hkdfInfo: XChaCha20Cipher.hkdfInfo,
		keySize: XChaCha20Cipher.keySize,
		kemCtSize: XChaCha20Cipher.kemCtSize,
		tagSize: XChaCha20Cipher.tagSize,
		padded: XChaCha20Cipher.padded,
		wasmChunkSize: XChaCha20Cipher.wasmChunkSize,
		wasmModules: XChaCha20Cipher.wasmModules,
		deriveKeys: XChaCha20Cipher.deriveKeys.bind(XChaCha20Cipher),
		openChunk: XChaCha20Cipher.openChunk.bind(XChaCha20Cipher),
		wipeKeys: XChaCha20Cipher.wipeKeys.bind(XChaCha20Cipher),
		createPoolWorker: XChaCha20Cipher.createPoolWorker.bind(XChaCha20Cipher),
		sealChunk(keys: DerivedKeys, nonce: Uint8Array, chunk: Uint8Array, aad?: Uint8Array): Uint8Array {
			if (throwNext) {
				throwNext = false;
				throw new Error('synthetic crypto-path failure');
			}
			return XChaCha20Cipher.sealChunk(keys, nonce, chunk, aad);
		},
		_trip() {
			throwNext = true;
		},
	};
	return suite;
}

describe('SealStream — argument-validation errors are non-terminal', () => {
	it('oversize chunk throws without wiping keys or entering failed state', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(XChaCha20Cipher, key, { chunkSize: 1024 });
		const keyView = getKeyBytes(sealer);
		expect(isZero(keyView)).toBe(false);

		expect(() => sealer.push(new Uint8Array(2048))).toThrow(/chunkSize/);
		expect(getState(sealer)).toBe('ready');
		expect(isZero(keyView)).toBe(false);

		// Stream is still usable — a correctly-sized retry succeeds.
		const ct = sealer.push(new Uint8Array(500));
		expect(ct).toBeInstanceOf(Uint8Array);
		sealer.finalize(new Uint8Array(0));
	});

	it('oversize final chunk throws without wiping keys or entering failed state', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(XChaCha20Cipher, key, { chunkSize: 1024 });
		const keyView = getKeyBytes(sealer);

		expect(() => sealer.finalize(new Uint8Array(2048))).toThrow(/chunkSize/);
		expect(getState(sealer)).toBe('ready');
		expect(isZero(keyView)).toBe(false);

		// finalize with a correctly-sized chunk succeeds and transitions cleanly.
		const ct = sealer.finalize(new Uint8Array(100));
		expect(ct).toBeInstanceOf(Uint8Array);
		expect(getState(sealer)).toBe('finalized');
	});
});

describe('SealStream — crypto-path throws trigger failed state', () => {
	it('synthetic sealChunk throw wipes keys and sets state=failed', () => {
		const key = randomBytes(32);
		const mock = makeThrowingSealer();
		const sealer = new SealStream(mock, key, { chunkSize: 1024 });
		const keyView = getKeyBytes(sealer);
		expect(isZero(keyView)).toBe(false);

		(mock as unknown as { _trip(): void })._trip();
		expect(() => sealer.push(new Uint8Array(100))).toThrow(/synthetic crypto-path/);
		expect(getState(sealer)).toBe('failed');
		expect(isZero(keyView)).toBe(true);
	});

	it('subsequent push() after failed state mentions "failed"', () => {
		const key = randomBytes(32);
		const mock = makeThrowingSealer();
		const sealer = new SealStream(mock, key, { chunkSize: 1024 });

		(mock as unknown as { _trip(): void })._trip();
		try {
			sealer.push(new Uint8Array(100));
		} catch { /* swallow */ }
		expect(() => sealer.push(new Uint8Array(100))).toThrow(/failed/);
	});

	it('subsequent finalize() after failed state mentions "failed"', () => {
		const key = randomBytes(32);
		const mock = makeThrowingSealer();
		const sealer = new SealStream(mock, key, { chunkSize: 1024 });

		(mock as unknown as { _trip(): void })._trip();
		try {
			sealer.push(new Uint8Array(100));
		} catch { /* swallow */ }
		expect(() => sealer.finalize(new Uint8Array(100))).toThrow(/failed/);
	});

	it('synthetic finalize() throw wipes keys and sets state=failed', () => {
		const key = randomBytes(32);
		const mock = makeThrowingSealer();
		const sealer = new SealStream(mock, key, { chunkSize: 1024 });
		const keyView = getKeyBytes(sealer);

		(mock as unknown as { _trip(): void })._trip();
		expect(() => sealer.finalize(new Uint8Array(100))).toThrow(/synthetic crypto-path/);
		expect(getState(sealer)).toBe('failed');
		expect(isZero(keyView)).toBe(true);
	});
});

describe('OpenStream — argument-validation errors are non-terminal', () => {
	it('too-short chunk throws without wiping keys or entering failed state', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(XChaCha20Cipher, key, { chunkSize: 1024 });
		const ct1 = sealer.push(randomBytes(100));
		const ctFinal = sealer.finalize(new Uint8Array(0));

		const opener = new OpenStream(XChaCha20Cipher, key, sealer.preamble);
		const keyView = getKeyBytes(opener);
		expect(isZero(keyView)).toBe(false);

		// A chunk smaller than the tag size cannot possibly contain a tag.
		// Should throw non-terminally.
		expect(() => opener.pull(new Uint8Array(8))).toThrow(/chunk too short/);
		expect(getState(opener)).toBe('ready');
		expect(isZero(keyView)).toBe(false);

		// Legitimate retry succeeds — stream was not failed by the validation throw.
		const pt1 = opener.pull(ct1);
		expect(pt1).toBeInstanceOf(Uint8Array);
		opener.finalize(ctFinal);
	});

	it('oversize chunk throws without wiping keys or entering failed state', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(XChaCha20Cipher, key, { chunkSize: 1024 });
		const ct1 = sealer.push(randomBytes(100));
		const ctFinal = sealer.finalize(new Uint8Array(0));

		const opener = new OpenStream(XChaCha20Cipher, key, sealer.preamble);
		const keyView = getKeyBytes(opener);

		// A chunk far larger than maxWireChunk cannot be a valid stream chunk.
		expect(() => opener.pull(new Uint8Array(100_000))).toThrow(/exceeds max wire size/);
		expect(getState(opener)).toBe('ready');
		expect(isZero(keyView)).toBe(false);

		// Legitimate retry succeeds.
		const pt1 = opener.pull(ct1);
		expect(pt1).toBeInstanceOf(Uint8Array);
		opener.finalize(ctFinal);
	});

	it('framed chunk length mismatch throws without wiping keys or entering failed state', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(XChaCha20Cipher, key, { chunkSize: 1024, framed: true });
		const ct1 = sealer.push(randomBytes(100));
		const ctFinal = sealer.finalize(new Uint8Array(0));

		const opener = new OpenStream(XChaCha20Cipher, key, sealer.preamble);
		const keyView = getKeyBytes(opener);

		// Corrupt the u32be length prefix so the declared length doesn't match
		// the actual payload length. _stripFrame should reject non-terminally.
		const corrupted = new Uint8Array(ct1);
		corrupted[0] = 0xff;
		corrupted[1] = 0xff;

		expect(() => opener.pull(corrupted)).toThrow(/length mismatch/);
		expect(getState(opener)).toBe('ready');
		expect(isZero(keyView)).toBe(false);

		// Legitimate retry on the un-corrupted chunk succeeds.
		const pt1 = opener.pull(ct1);
		expect(pt1).toBeInstanceOf(Uint8Array);
		opener.finalize(ctFinal);
	});

	it('oversize final chunk throws without wiping keys or entering failed state', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(XChaCha20Cipher, key, { chunkSize: 1024 });
		const ct1 = sealer.push(randomBytes(100));
		const ctFinal = sealer.finalize(new Uint8Array(0));

		const opener = new OpenStream(XChaCha20Cipher, key, sealer.preamble);
		const keyView = getKeyBytes(opener);

		opener.pull(ct1);

		expect(() => opener.finalize(new Uint8Array(100_000))).toThrow(/exceeds max wire size/);
		expect(getState(opener)).toBe('ready');
		expect(isZero(keyView)).toBe(false);

		// finalize with the correct chunk succeeds.
		opener.finalize(ctFinal);
		expect(getState(opener)).toBe('finalized');
	});
});

describe('OpenStream — auth failure triggers failed state', () => {
	it('tampered chunk wipes keys, transitions to failed, further pull throws with "failed"', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(XChaCha20Cipher, key, { chunkSize: 1024 });
		const ct1 = sealer.push(randomBytes(100));
		const ctFinal = sealer.finalize(new Uint8Array(0));

		// Tamper with the first chunk — flip the last byte of the tag.
		const tampered = new Uint8Array(ct1);
		tampered[tampered.length - 1] ^= 0x01;

		const opener = new OpenStream(XChaCha20Cipher, key, sealer.preamble);
		const keyView = getKeyBytes(opener);
		expect(isZero(keyView)).toBe(false); // pre-state sanity

		expect(() => opener.pull(tampered)).toThrow(/xchacha20-poly1305/);
		expect(getState(opener)).toBe('failed');
		expect(isZero(keyView)).toBe(true);

		// Re-use after failure — messages must say 'failed', not 'finalize'.
		expect(() => opener.pull(ctFinal)).toThrow(/failed/);
		expect(() => opener.finalize(ctFinal)).toThrow(/failed/);
	});
});

describe('SealStream / OpenStream — dispose() on failed is a no-op', () => {
	it('SealStream.dispose() after failed does not throw and keys remain zero', () => {
		const key = randomBytes(32);
		const mock = makeThrowingSealer();
		const sealer = new SealStream(mock, key, { chunkSize: 1024 });

		(mock as unknown as { _trip(): void })._trip();
		try {
			sealer.push(new Uint8Array(100));
		} catch { /* swallow */ }
		const keyView = getKeyBytes(sealer);
		expect(isZero(keyView)).toBe(true);

		expect(() => sealer.dispose()).not.toThrow();
		expect(getState(sealer)).toBe('failed');
		expect(isZero(keyView)).toBe(true);
	});

	it('OpenStream.dispose() after failed does not throw', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(XChaCha20Cipher, key, { chunkSize: 1024 });
		const ct1 = sealer.push(randomBytes(100));
		sealer.finalize(new Uint8Array(0));

		const tampered = new Uint8Array(ct1);
		tampered[tampered.length - 1] ^= 0x01;

		const opener = new OpenStream(XChaCha20Cipher, key, sealer.preamble);
		try {
			opener.pull(tampered);
		} catch { /* swallow */ }

		expect(getState(opener)).toBe('failed');
		expect(() => opener.dispose()).not.toThrow();
	});
});

describe('OpenStream.seek — throws on failed state', () => {
	it('seek after failed throws with "failed"', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(XChaCha20Cipher, key, { chunkSize: 1024 });
		const ct1 = sealer.push(randomBytes(100));
		sealer.finalize(new Uint8Array(0));

		const tampered = new Uint8Array(ct1);
		tampered[tampered.length - 1] ^= 0x01;

		const opener = new OpenStream(XChaCha20Cipher, key, sealer.preamble);
		try {
			opener.pull(tampered);
		} catch { /* swallow */ }

		expect(() => opener.seek(0)).toThrow(/failed/);
	});
});
