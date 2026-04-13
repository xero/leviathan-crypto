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
 * SealStream / OpenStream — STREAM construction tests for both cipher suites.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, randomBytes, AuthenticationError } from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { SealStream, OpenStream, CHUNK_MIN, CHUNK_MAX, HEADER_SIZE } from '../../../src/ts/stream/index.js';
import { writeHeader } from '../../../src/ts/stream/header.js';
import { XChaCha20Cipher } from '../../../src/ts/chacha20/cipher-suite.js';
import { SerpentCipher } from '../../../src/ts/serpent/cipher-suite.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import type { CipherSuite } from '../../../src/ts/stream/types.js';

beforeAll(async () => {
	await init({ chacha20: chacha20Wasm, serpent: serpentWasm, sha2: sha2Wasm });
});

// ── Helpers ─────────────────────────────────────────────────────────────────

function sealAndCollect(
	cipher: CipherSuite,
	key: Uint8Array,
	chunks: Uint8Array[],
	opts?: { chunkSize?: number; framed?: boolean; aads?: (Uint8Array | undefined)[] },
): { preamble: Uint8Array; encrypted: Uint8Array[] } {
	const sealer = new SealStream(cipher, key, {
		chunkSize: opts?.chunkSize,
		framed: opts?.framed,
	});
	const preamble = sealer.preamble;
	const encrypted: Uint8Array[] = [];
	for (let i = 0; i < chunks.length - 1; i++) {
		encrypted.push(sealer.push(chunks[i], { aad: opts?.aads?.[i] }));
	}
	encrypted.push(sealer.finalize(chunks[chunks.length - 1], { aad: opts?.aads?.[chunks.length - 1] }));
	return { preamble, encrypted };
}

function openAll(
	cipher: CipherSuite,
	key: Uint8Array,
	preamble: Uint8Array,
	encrypted: Uint8Array[],
	opts?: { aads?: (Uint8Array | undefined)[] },
): Uint8Array[] {
	const opener = new OpenStream(cipher, key, preamble);
	const plaintexts: Uint8Array[] = [];
	for (let i = 0; i < encrypted.length - 1; i++) {
		plaintexts.push(opener.pull(encrypted[i], { aad: opts?.aads?.[i] }));
	}
	plaintexts.push(opener.finalize(encrypted[encrypted.length - 1], { aad: opts?.aads?.[encrypted.length - 1] }));
	return plaintexts;
}

// ── Tests for both cipher suites ────────────────────────────────────────────

const suites: [string, CipherSuite, number][] = [
	['XChaCha20', XChaCha20Cipher, 32],
	['Serpent', SerpentCipher, 32],
];

for (const [name, cipher, keyLen] of suites) {
	describe(`SealStream / OpenStream — ${name}`, () => {
		const key = randomBytes(keyLen);

		// ── Round-trip ──────────────────────────────────────────────────

		describe('round-trip', () => {
			it('single chunk', () => {
				const pt = randomBytes(100);
				const { preamble, encrypted } = sealAndCollect(cipher, key, [pt]);
				expect(preamble.length).toBe(HEADER_SIZE);
				const result = openAll(cipher, key, preamble, encrypted);
				expect(result).toHaveLength(1);
				expect(result[0]).toEqual(pt);
			});

			it('multi-chunk (5 varying sizes)', () => {
				const chunks = [
					randomBytes(1024),
					randomBytes(500),
					randomBytes(2048),
					randomBytes(100),
					randomBytes(4000),
				];
				const { preamble, encrypted } = sealAndCollect(cipher, key, chunks, { chunkSize: 4096 });
				const result = openAll(cipher, key, preamble, encrypted);
				expect(result).toHaveLength(5);
				for (let i = 0; i < 5; i++) expect(result[i]).toEqual(chunks[i]);
			});

			it('empty final chunk', () => {
				const chunks = [randomBytes(2048), randomBytes(1500), new Uint8Array(0)];
				const { preamble, encrypted } = sealAndCollect(cipher, key, chunks, { chunkSize: 4096 });
				const result = openAll(cipher, key, preamble, encrypted);
				expect(result).toHaveLength(3);
				expect(result[0]).toEqual(chunks[0]);
				expect(result[1]).toEqual(chunks[1]);
				expect(result[2]).toEqual(new Uint8Array(0));
			});

			it('minimum chunk size (1024)', () => {
				const pt = randomBytes(1024);
				const { preamble, encrypted } = sealAndCollect(cipher, key, [pt], { chunkSize: CHUNK_MIN });
				const result = openAll(cipher, key, preamble, encrypted);
				expect(result[0]).toEqual(pt);
			});

			it('max configured chunk size', () => {
				const pt = randomBytes(8192);
				const { preamble, encrypted } = sealAndCollect(cipher, key, [pt], { chunkSize: 8192 });
				const result = openAll(cipher, key, preamble, encrypted);
				expect(result[0]).toEqual(pt);
			});
		});

		// ── Per-chunk AAD ───────────────────────────────────────────────

		describe('per-chunk AAD', () => {
			it('seal with AAD, open with same AAD', () => {
				const pt = randomBytes(100);
				const aad = new TextEncoder().encode('test-aad');
				const { preamble, encrypted } = sealAndCollect(cipher, key, [pt], { aads: [aad] });
				const result = openAll(cipher, key, preamble, encrypted, { aads: [aad] });
				expect(result[0]).toEqual(pt);
			});

			it('AAD mismatch → AuthenticationError', () => {
				const pt = randomBytes(100);
				const aad1 = new TextEncoder().encode('aad-1');
				const aad2 = new TextEncoder().encode('aad-2');
				const { preamble, encrypted } = sealAndCollect(cipher, key, [pt], { aads: [aad1] });
				expect(() => openAll(cipher, key, preamble, encrypted, { aads: [aad2] }))
					.toThrow(AuthenticationError);
			});
		});

		// ── Framed mode ─────────────────────────────────────────────────

		describe('framed mode', () => {
			it('round-trip with framed=true', () => {
				const chunks = [randomBytes(1024), randomBytes(512), randomBytes(256)];
				const { preamble, encrypted } = sealAndCollect(cipher, key, chunks, {
					chunkSize: 2048,
					framed: true,
				});
				const result = openAll(cipher, key, preamble, encrypted);
				expect(result).toHaveLength(3);
				for (let i = 0; i < 3; i++) expect(result[i]).toEqual(chunks[i]);
			});

			it('framed chunks have u32be length prefix', () => {
				const pt = randomBytes(100);
				const { encrypted } = sealAndCollect(cipher, key, [pt], {
					chunkSize: 1024,
					framed: true,
				});
				// First 4 bytes should be u32be of the payload length
				const dv = new DataView(encrypted[0].buffer, encrypted[0].byteOffset);
				const prefixLen = dv.getUint32(0, false);
				expect(prefixLen).toBe(encrypted[0].length - 4);
			});
		});

		// ── Authentication ──────────────────────────────────────────────

		describe('authentication', () => {
			it('tampered chunk body → AuthenticationError', () => {
				const pt = randomBytes(200);
				const { preamble, encrypted } = sealAndCollect(cipher, key, [pt]);
				encrypted[0][5] ^= 0xff;
				expect(() => openAll(cipher, key, preamble, encrypted))
					.toThrow(AuthenticationError);
			});

			it('tampered tag → AuthenticationError', () => {
				const pt = randomBytes(200);
				const { preamble, encrypted } = sealAndCollect(cipher, key, [pt]);
				encrypted[0][encrypted[0].length - 1] ^= 0xff;
				expect(() => openAll(cipher, key, preamble, encrypted))
					.toThrow(AuthenticationError);
			});

			it('chunk reorder → AuthenticationError', () => {
				const chunks = Array.from({ length: 6 }, () => randomBytes(1024));
				const { preamble, encrypted } = sealAndCollect(cipher, key, chunks, { chunkSize: 2048 });
				// Swap chunks 2 and 4 (middle data chunks)
				const tmp = encrypted[2];
				encrypted[2] = encrypted[4];
				encrypted[4] = tmp;
				const opener = new OpenStream(cipher, key, preamble);
				opener.pull(encrypted[0]);
				opener.pull(encrypted[1]);
				expect(() => opener.pull(encrypted[2])).toThrow(AuthenticationError);
			});

			it('replay chunk from different stream → AuthenticationError', () => {
				const pt = randomBytes(200);
				const key2 = randomBytes(keyLen);
				const { encrypted: encrypted1 } = sealAndCollect(cipher, key, [pt]);
				const { preamble: preamble2 } = sealAndCollect(cipher, key2, [pt]);
				expect(() => openAll(cipher, key2, preamble2, encrypted1))
					.toThrow(AuthenticationError);
			});

			it('chunk shorter than tagSize → RangeError', () => {
				const pt = randomBytes(100);
				const { preamble } = sealAndCollect(cipher, key, [pt]);
				const opener = new OpenStream(cipher, key, preamble);
				const tooShort = new Uint8Array(cipher.tagSize - 1);
				expect(() => opener.pull(tooShort)).toThrow(/too short/);
			});
		});

		// ── Seek ────────────────────────────────────────────────────────

		describe('seek', () => {
			it('seek to specific chunk', () => {
				const chunks = Array.from({ length: 10 }, (_, i) => {
					const b = new Uint8Array(100);
					b.fill(i);
					return b;
				});
				chunks.push(new Uint8Array(0)); // empty final
				const { preamble, encrypted } = sealAndCollect(cipher, key, chunks, { chunkSize: 1024 });
				const opener = new OpenStream(cipher, key, preamble);
				opener.seek(5);
				const result = opener.pull(encrypted[5]);
				expect(result).toEqual(chunks[5]);
			});

			it('seek to 0, read all sequentially', () => {
				const chunks = [randomBytes(200), randomBytes(300), randomBytes(100)];
				const { preamble, encrypted } = sealAndCollect(cipher, key, chunks, { chunkSize: 1024 });
				const opener = new OpenStream(cipher, key, preamble);
				opener.seek(0);
				const results: Uint8Array[] = [];
				for (let i = 0; i < encrypted.length - 1; i++) {
					results.push(opener.pull(encrypted[i]));
				}
				results.push(opener.finalize(encrypted[encrypted.length - 1]));
				for (let i = 0; i < chunks.length; i++) expect(results[i]).toEqual(chunks[i]);
			});

			it('seek beyond stream → AuthenticationError when pulling wrong chunk', () => {
				const chunks = [randomBytes(100), randomBytes(100)];
				const { preamble, encrypted } = sealAndCollect(cipher, key, chunks, { chunkSize: 1024 });
				const opener = new OpenStream(cipher, key, preamble);
				opener.seek(99);
				expect(() => opener.pull(encrypted[0])).toThrow(AuthenticationError);
			});

			it('seek with negative index → throws', () => {
				const pt = randomBytes(100);
				const { preamble } = sealAndCollect(cipher, key, [pt]);
				const opener = new OpenStream(cipher, key, preamble);
				expect(() => opener.seek(-1)).toThrow(/non-negative safe integer/);
			});

			it('seek with NaN → throws', () => {
				const pt = randomBytes(100);
				const { preamble } = sealAndCollect(cipher, key, [pt]);
				const opener = new OpenStream(cipher, key, preamble);
				expect(() => opener.seek(NaN)).toThrow(/non-negative safe integer/);
			});

			it('seek with fraction → throws', () => {
				const pt = randomBytes(100);
				const { preamble } = sealAndCollect(cipher, key, [pt]);
				const opener = new OpenStream(cipher, key, preamble);
				expect(() => opener.seek(3.5)).toThrow(/non-negative safe integer/);
			});
		});

		// ── TransformStream ─────────────────────────────────────────────

		describe('TransformStream', () => {
			it('toTransformStream returns a TransformStream', () => {
				const sealer = new SealStream(cipher, key, { chunkSize: 2048 });
				const ts = sealer.toTransformStream();
				expect(ts).toBeInstanceOf(TransformStream);
				expect(ts.readable).toBeDefined();
				expect(ts.writable).toBeDefined();
			});

			it('toTransformStream on opener returns a TransformStream', () => {
				const pt = randomBytes(100);
				const { preamble } = sealAndCollect(cipher, key, [pt]);
				const opener = new OpenStream(cipher, key, preamble);
				const ts = opener.toTransformStream();
				expect(ts).toBeInstanceOf(TransformStream);
			});

			it('round-trip through TransformStream pipes', async () => {
				const chunks = [randomBytes(200), randomBytes(300), randomBytes(100)];
				const sealer = new SealStream(cipher, key, { chunkSize: 2048 });

				// Seal side: write and read concurrently — sequential write-then-read
				// deadlocks because close() waits for flush, which backpressures on an
				// unconsumed readable.
				const sealTs = sealer.toTransformStream();
				const sealReader = sealTs.readable.getReader();
				const sealWriter = sealTs.writable.getWriter();

				const sealOutput: Uint8Array[] = [];
				await Promise.all([
					(async () => {
						for (const c of chunks) await sealWriter.write(c);
						await sealWriter.close();
					})(),
					(async () => {
						let done = false;
						while (!done) {
							const r = await sealReader.read();
							done = r.done;
							if (r.value) sealOutput.push(r.value);
						}
					})(),
				]);

				// First output is the preamble
				expect(sealOutput[0].length).toBe(HEADER_SIZE);
				const preamble = sealOutput[0];
				const encrypted = sealOutput.slice(1);

				// Open side: same concurrent pattern
				const opener = new OpenStream(cipher, key, preamble);
				const openTs = opener.toTransformStream();
				const openReader = openTs.readable.getReader();
				const openWriter = openTs.writable.getWriter();

				const decrypted: Uint8Array[] = [];
				await Promise.all([
					(async () => {
						for (const c of encrypted) await openWriter.write(c);
						await openWriter.close();
					})(),
					(async () => {
						let done = false;
						while (!done) {
							const r = await openReader.read();
							done = r.done;
							if (r.value) decrypted.push(r.value);
						}
					})(),
				]);

				// Verify round-trip
				expect(decrypted.length).toBe(chunks.length);
				for (let i = 0; i < chunks.length; i++) {
					expect(Buffer.from(decrypted[i])).toEqual(Buffer.from(chunks[i]));
				}
			});

			it('SealStream: keys wiped even when no chunks piped', async () => {
				const sealer = new SealStream(cipher, key, { chunkSize: 2048 });

				const ts = sealer.toTransformStream();
				const reader = ts.readable.getReader();
				const writer = ts.writable.getWriter();

				// Close writer immediately without writing any chunks
				await Promise.all([
					writer.close(),
					(async () => {
						let done = false;
						while (!done) {
							const r = await reader.read();
							done = r.done;
						}
					})(),
				]);

				// After the stream closes, the sealer should be in finalized state.
				// Attempting to push should throw.
				expect(() => sealer.push(new Uint8Array(32))).toThrow();
			});

			it('OpenStream: keys wiped even when no chunks piped', async () => {
				const pt = randomBytes(100);
				const { preamble } = sealAndCollect(cipher, key, [pt]);
				const opener = new OpenStream(cipher, key, preamble);

				const ts = opener.toTransformStream();
				const reader = ts.readable.getReader();
				const writer = ts.writable.getWriter();

				// Close writer immediately without writing any chunks
				await Promise.all([
					writer.close(),
					(async () => {
						let done = false;
						while (!done) {
							const r = await reader.read();
							done = r.done;
						}
					})(),
				]);

				// After the stream closes, the opener should be in finalized state
				// (dispose was called). Attempting to pull should throw.
				expect(() => opener.pull(new Uint8Array(32))).toThrow();
			});

			it('last chunk gets TAG_FINAL — no extra empty chunk', async () => {
				const sealer = new SealStream(cipher, key, { chunkSize: 2048 });
				const sealTs = sealer.toTransformStream();
				const reader = sealTs.readable.getReader();
				const writer = sealTs.writable.getWriter();
				const output: Uint8Array[] = [];
				await Promise.all([
					(async () => {
						await writer.write(randomBytes(100));
						await writer.write(randomBytes(200));
						await writer.close();
					})(),
					(async () => {
						let done = false;
						while (!done) {
							const r = await reader.read();
							done = r.done;
							if (r.value) output.push(r.value);
						}
					})(),
				]);
				// preamble + 2 encrypted chunks (NOT preamble + 2 + empty final)
				expect(output.length).toBe(3);
			});
		});

		// ── State machine ───────────────────────────────────────────────

		describe('state machine', () => {
			it('push after finalize → throws', () => {
				const sealer = new SealStream(cipher, key, { chunkSize: 1024 });
				sealer.finalize(new Uint8Array(0));
				expect(() => sealer.push(new Uint8Array(10))).toThrow(/finalize/);
			});

			it('finalize twice → throws', () => {
				const sealer = new SealStream(cipher, key, { chunkSize: 1024 });
				sealer.finalize(new Uint8Array(0));
				expect(() => sealer.finalize(new Uint8Array(0))).toThrow(/finalize/);
			});

			it('pull after finalize on opener → throws', () => {
				const pt = randomBytes(100);
				const { preamble, encrypted } = sealAndCollect(cipher, key, [pt]);
				const opener = new OpenStream(cipher, key, preamble);
				opener.finalize(encrypted[0]);
				expect(() => opener.pull(new Uint8Array(100))).toThrow(/finalize/);
			});

			it('seek after finalize → throws', () => {
				const pt = randomBytes(100);
				const { preamble, encrypted } = sealAndCollect(cipher, key, [pt]);
				const opener = new OpenStream(cipher, key, preamble);
				opener.finalize(encrypted[0]);
				expect(() => opener.seek(0)).toThrow(/finalize/);
			});

			it('separate streams with same key but different nonces', () => {
				const pt1 = randomBytes(100);
				const pt2 = randomBytes(200);
				const { preamble: p1, encrypted: e1 } = sealAndCollect(cipher, key, [pt1]);
				const { preamble: p2, encrypted: e2 } = sealAndCollect(cipher, key, [pt2]);
				// Different nonces — preambles differ
				expect(p1).not.toEqual(p2);
				// Both decrypt independently
				expect(openAll(cipher, key, p1, e1)[0]).toEqual(pt1);
				expect(openAll(cipher, key, p2, e2)[0]).toEqual(pt2);
			});
		});

		// ── dispose() ───────────────────────────────────────────────────

		describe('SealStream dispose()', () => {
			it('dispose() wipes keys and prevents further push/finalize', () => {
				const sealer = new SealStream(cipher, key, { chunkSize: 1024 });
				sealer.dispose();
				expect(() => sealer.push(new Uint8Array(10))).toThrow(/finalize/);
				expect(() => sealer.finalize(new Uint8Array(0))).toThrow(/finalize/);
			});

			it('dispose() after finalize() is a no-op', () => {
				const sealer = new SealStream(cipher, key, { chunkSize: 1024 });
				sealer.finalize(new Uint8Array(0));
				expect(() => sealer.dispose()).not.toThrow();
			});
		});

		describe('OpenStream dispose()', () => {
			it('dispose() wipes keys and prevents further pull/finalize', () => {
				const pt = randomBytes(100);
				const { preamble } = sealAndCollect(cipher, key, [pt]);
				const opener = new OpenStream(cipher, key, preamble);
				opener.dispose();
				expect(() => opener.pull(new Uint8Array(100))).toThrow(/finalize/);
				expect(() => opener.finalize(new Uint8Array(100))).toThrow(/finalize/);
			});

			it('dispose() after finalize() is a no-op', () => {
				const pt = randomBytes(100);
				const { preamble, encrypted } = sealAndCollect(cipher, key, [pt]);
				const opener = new OpenStream(cipher, key, preamble);
				opener.finalize(encrypted[0]);
				expect(() => opener.dispose()).not.toThrow();
			});
		});

		// ── Chunk size validation ───────────────────────────────────────

		describe('chunk size validation', () => {
			it('chunkSize below minimum → throws', () => {
				expect(() => new SealStream(cipher, key, { chunkSize: 512 })).toThrow(/chunkSize/);
			});

			it('chunkSize above maximum → throws', () => {
				expect(() => new SealStream(cipher, key, { chunkSize: CHUNK_MAX + 1 })).toThrow(/chunkSize/);
			});

			it('chunk exceeds chunkSize → throws', () => {
				const sealer = new SealStream(cipher, key, { chunkSize: 1024 });
				expect(() => sealer.push(randomBytes(2048))).toThrow(/chunkSize/);
			});

			it('finalize chunk exceeds chunkSize → throws', () => {
				const sealer = new SealStream(cipher, key, { chunkSize: 1024 });
				expect(() => sealer.finalize(randomBytes(2048))).toThrow(/chunkSize/);
			});

			it('wrong key length → throws RangeError', () => {
				expect(() => new SealStream(cipher, randomBytes(16))).toThrow(/key must be/);
				expect(() => new SealStream(cipher, randomBytes(64))).toThrow(/key must be/);
			});

			it('wrong _nonce length → throws RangeError', () => {
				expect(() => SealStream._fromNonce(cipher, key, {}, randomBytes(12)))
					.toThrow(/_nonce must be 16 bytes/);
				expect(() => SealStream._fromNonce(cipher, key, {}, randomBytes(32)))
					.toThrow(/_nonce must be 16 bytes/);
			});

			it('valid _nonce is accepted', () => {
				const nonce = randomBytes(16);
				const sealer = SealStream._fromNonce(cipher, key, {}, nonce);
				expect(sealer.preamble).toBeDefined();
			});
		});
	});
}

// ── Cross-cipher rejection ──────────────────────────────────────────────────

describe('cross-cipher rejection', () => {
	it('XChaCha20 preamble → SerpentCipher opener → throws Error (not AuthenticationError)', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(XChaCha20Cipher, key);
		const preamble = sealer.preamble;
		sealer.finalize(new Uint8Array(0));
		expect(() => new OpenStream(SerpentCipher, key, preamble))
			.toThrow(/expected format 0x02.*got 0x01/);
	});

	it('Serpent preamble → XChaCha20Cipher opener → throws Error (not AuthenticationError)', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(SerpentCipher, key);
		const preamble = sealer.preamble;
		sealer.finalize(new Uint8Array(0));
		expect(() => new OpenStream(XChaCha20Cipher, key, preamble))
			.toThrow(/expected format 0x01.*got 0x02/);
	});

	it('format mismatch error is Error, not AuthenticationError', () => {
		const key = randomBytes(32);
		const sealer = new SealStream(XChaCha20Cipher, key);
		const preamble = sealer.preamble;
		sealer.finalize(new Uint8Array(0));
		try {
			new OpenStream(SerpentCipher, key, preamble);
			expect.unreachable('should have thrown');
		} catch (e) {
			expect(e).toBeInstanceOf(Error);
			expect(e).not.toBeInstanceOf(AuthenticationError);
		}
	});
});

// ── OpenStream preamble chunkSize validation ────────────────────────────────

describe('OpenStream preamble chunkSize validation', () => {
	// writeHeader rejects chunkSize < CHUNK_MIN now, so construct the header
	// manually to exercise OpenStream's own defense against forged preambles.
	function forgeHeader(formatEnum: number, framed: boolean, nonce: Uint8Array, chunkSize: number): Uint8Array {
		const h = new Uint8Array(HEADER_SIZE);
		h[0] = (framed ? 0x80 : 0) | formatEnum;
		h.set(nonce, 1);
		h[17] = (chunkSize >> 16) & 0xff;
		h[18] = (chunkSize >>  8) & 0xff;
		h[19] =  chunkSize        & 0xff;
		return h;
	}

	it('chunkSize below CHUNK_MIN → throws RangeError', () => {
		const key = randomBytes(32);
		const badHeader = forgeHeader(XChaCha20Cipher.formatEnum, false, randomBytes(16), 512);
		expect(() => new OpenStream(XChaCha20Cipher, key, badHeader))
			.toThrow(/header chunkSize/);
	});

	it('chunkSize above CHUNK_MAX → throws RangeError', () => {
		expect(() => writeHeader(XChaCha20Cipher.formatEnum, false, randomBytes(16), CHUNK_MAX + 1))
			.toThrow(/chunkSize/);
	});

	it('chunkSize = 0 → throws RangeError', () => {
		const key = randomBytes(32);
		const badHeader = forgeHeader(SerpentCipher.formatEnum, false, randomBytes(16), 0);
		expect(() => new OpenStream(SerpentCipher, key, badHeader))
			.toThrow(/header chunkSize/);
	});
});

// ── CipherSuite contract verification ───────────────────────────────────────

describe('CipherSuite contract', () => {
	it('XChaCha20Cipher properties', () => {
		expect(XChaCha20Cipher.formatEnum).toBe(0x01);
		expect(XChaCha20Cipher.keySize).toBe(32);
		expect(XChaCha20Cipher.tagSize).toBe(16);
		expect(XChaCha20Cipher.padded).toBe(false);
		expect(XChaCha20Cipher.hkdfInfo).toBe('xchacha20-sealstream-v2');
		expect(XChaCha20Cipher.wasmModules).toEqual(['chacha20']);
	});

	it('SerpentCipher properties', () => {
		expect(SerpentCipher.formatEnum).toBe(0x02);
		expect(SerpentCipher.keySize).toBe(32);
		expect(SerpentCipher.tagSize).toBe(32);
		expect(SerpentCipher.padded).toBe(true);
		expect(SerpentCipher.hkdfInfo).toBe('serpent-sealstream-v2');
		expect(SerpentCipher.wasmModules).toEqual(['serpent', 'sha2']);
	});

	it('format enum values are unique', () => {
		expect(XChaCha20Cipher.formatEnum).not.toBe(SerpentCipher.formatEnum);
	});

	it('createPoolWorker returns a Worker (or throws in non-browser env)', () => {
		// In Node.js test env, Worker is not defined — that's expected
		// In a browser, createPoolWorker returns a real Worker
		expect(() => XChaCha20Cipher.createPoolWorker()).toThrow();
		expect(() => SerpentCipher.createPoolWorker()).toThrow();
	});
});

// ── Serpent-specific ────────────────────────────────────────────────────────

describe('stream layer sha2 init gate', () => {
	it('SealStream without sha2 → clear error', async () => {
		_resetForTesting();
		await init({ chacha20: chacha20Wasm });
		expect(() => new SealStream(XChaCha20Cipher, randomBytes(32)))
			.toThrow(/sha2/);
		// Restore
		await init({ chacha20: chacha20Wasm, serpent: serpentWasm, sha2: sha2Wasm });
	});

	it('OpenStream without sha2 → clear error', async () => {
		_resetForTesting();
		await init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
		const sealer = new SealStream(XChaCha20Cipher, randomBytes(32));
		const preamble = sealer.preamble;
		sealer.finalize(new Uint8Array(0));

		_resetForTesting();
		await init({ chacha20: chacha20Wasm });
		expect(() => new OpenStream(XChaCha20Cipher, randomBytes(32), preamble))
			.toThrow(/sha2/);
		// Restore
		await init({ chacha20: chacha20Wasm, serpent: serpentWasm, sha2: sha2Wasm });
	});
});

describe('SerpentCipher specific', () => {
	it('key separation: enc_key ≠ mac_key ≠ iv_key', () => {
		const key = randomBytes(32);
		const nonce = randomBytes(16);
		const derived = SerpentCipher.deriveKeys(key, nonce);
		const encKey = derived.bytes.subarray(0, 32);
		const macKey = derived.bytes.subarray(32, 64);
		const ivKey = derived.bytes.subarray(64, 96);
		expect(encKey).not.toEqual(macKey);
		expect(macKey).not.toEqual(ivKey);
		expect(encKey).not.toEqual(ivKey);
		SerpentCipher.wipeKeys(derived);
	});

	it('IV derivation determinism: same counter + keys → same IV', () => {
		const key = randomBytes(32);
		const nonce = randomBytes(16);
		const pt = randomBytes(100);
		const sealer1 = SealStream._fromNonce(SerpentCipher, key, { chunkSize: 1024 }, nonce);
		const sealer2 = SealStream._fromNonce(SerpentCipher, key, { chunkSize: 1024 }, nonce);
		const ct1 = sealer1.finalize(pt);
		const ct2 = sealer2.finalize(pt);
		expect(ct1).toEqual(ct2);
	});

	it('counter binding in HMAC: chunk at counter=3 fails at counter=5', () => {
		const key2 = randomBytes(32);
		const chunks = Array.from({ length: 6 }, () => randomBytes(200));
		const { preamble, encrypted } = sealAndCollect(SerpentCipher, key2, chunks, { chunkSize: 1024 });
		const opener = new OpenStream(SerpentCipher, key2, preamble);
		// Pull chunks 0-2 normally
		opener.pull(encrypted[0]);
		opener.pull(encrypted[1]);
		opener.pull(encrypted[2]);
		// Seek to counter=5, try to pull chunk 3's ciphertext
		opener.seek(5);
		expect(() => opener.pull(encrypted[3])).toThrow(AuthenticationError);
	});
});
