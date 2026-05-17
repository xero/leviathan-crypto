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
// Emit / parse round-trip coverage for the c2sp.org/signed-note (Note)
// §Format envelope codec. Builds a checkpoint body via
// `serializeCheckpointBody`, appends one or more signature lines with
// `emitSignedNote`, parses the bytes back via `parseSignedNote`, and
// asserts byte-identical recovery of the body, signature names, key
// IDs, and signature payloads.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { describe, it, beforeAll, expect } from 'vitest';
import {
	init,
	serializeCheckpointBody,
	parseCheckpointBody,
	emitSignedNote,
	parseSignedNote,
	deriveKeyId,
	base64ToBytes,
	hexToBytes,
} from '../../../src/ts/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { ROUNDTRIP_RECORDS } from '../../vectors/merkle_signed_note.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

beforeAll(async () => {
	_resetForTesting();
	const wasmBytes = readFileSync(join(__dirname, '../../../build/sha2.wasm'));
	await init({ sha2: wasmBytes });
});

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

describe('emitSignedNote + parseSignedNote round-trip', () => {
	for (const rec of ROUNDTRIP_RECORDS) {
		it(`round-trip: ${rec.desc}`, async () => {
			const body = serializeCheckpointBody({
				origin: rec.origin,
				treeSize: rec.treeSize,
				rootHash: base64ToBytes(rec.rootHashB64),
			});

			const sigLines = rec.signatures.map(s => {
				const pubkey  = hexToBytes(s.pubkeyHex);
				const sigPayload = hexToBytes(s.sigPayloadHex);
				const keyId = deriveKeyId(s.name, s.algoByte, pubkey);
				return { name: s.name, keyId, signature: sigPayload };
			});

			const envelope = emitSignedNote(body, sigLines);

			// Envelope layout invariant: body bytes appear at the start,
			// followed by a single 0x0A blank-line separator, followed by
			// the signature lines. Per c2sp.org/signed-note §Format.
			expect(envelope.subarray(0, body.length)).toEqual(body);
			expect(envelope[body.length]).toBe(0x0a);

			// Byte-stability cross-check against the frozen envelope
			// digest in the vector file. Both this test and the Rust
			// verifier under scripts/verify-vectors/src/merkle_checkpoint.rs
			// reproduce the envelope from the same inputs and compare
			// their SHA-256 against the same recorded value.
			expect(envelope.length).toBe(rec.expectedEnvelopeLen);
			// Copy into a fresh ArrayBuffer so the digest call gets a
			// concrete ArrayBuffer-backed view, dodging the SharedArrayBuffer
			// branch of `BufferSource`.
			const copy = new Uint8Array(envelope.length);
			copy.set(envelope);
			const digest = await crypto.subtle.digest('SHA-256', copy.buffer);
			const digestHex = Array.from(new Uint8Array(digest))
				.map(b => b.toString(16).padStart(2, '0')).join('');
			expect(digestHex).toBe(rec.expectedEnvelopeSha256Hex);

			const parsed = parseSignedNote(envelope);
			expect(parsed.ignoredCount).toBe(0);
			expect(parsed.signatures.length).toBe(rec.signatures.length);
			expect(parsed.body).toEqual(body);

			// Re-parse the body bytes through `parseCheckpointBody` to
			// confirm the round-trip carries the checkpoint structure
			// intact, not just the byte buffer.
			const cp = parseCheckpointBody(parsed.body);
			expect(cp.origin).toBe(rec.origin);
			expect(cp.treeSize).toBe(rec.treeSize);

			for (let i = 0; i < sigLines.length; i++) {
				expect(parsed.signatures[i].name).toBe(sigLines[i].name);
				expect(bytesEqual(parsed.signatures[i].keyId, sigLines[i].keyId)).toBe(true);
				expect(bytesEqual(parsed.signatures[i].signature, sigLines[i].signature)).toBe(true);
			}

			// Re-emit from the parsed signatures and assert byte
			// equality with the original envelope. Producer / verifier
			// agreement on body bytes is what the STH signature is
			// computed over, so byte stability is the gate.
			const reEmitted = emitSignedNote(parsed.body, parsed.signatures);
			expect(reEmitted).toEqual(envelope);
		});
	}

	it('emit rejects body that does not end with U+000A', () => {
		expect(() => emitSignedNote(new Uint8Array([0x61, 0x62, 0x63]), [{
			name: 'k', keyId: new Uint8Array(4), signature: new Uint8Array(8),
		}])).toThrow(/end with U\+000A/);
	});

	it('emit rejects empty signatures array', () => {
		expect(() => emitSignedNote(new Uint8Array([0x61, 0x0a]), [])).toThrow(/at least one/);
	});

	it('emit rejects keyId not exactly 4 bytes', () => {
		expect(() => emitSignedNote(new Uint8Array([0x61, 0x0a]), [{
			name: 'k', keyId: new Uint8Array(3), signature: new Uint8Array(8),
		}])).toThrow(/4 bytes/);
	});

	it('emit rejects signature name containing space', () => {
		expect(() => emitSignedNote(new Uint8Array([0x61, 0x0a]), [{
			name: 'bad name', keyId: new Uint8Array(4), signature: new Uint8Array(8),
		}])).toThrow(/whitespace|plus/);
	});
});
