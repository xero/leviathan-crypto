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
// test/unit/sign/verify-stream.test.ts
//
// VerifyStream state-machine, header-parser, sliding-window sig detection,
// and wipe-on-failure semantics. Uses the streamable fixture suite from
// helpers.ts.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import {
	Sign, SignStream, VerifyStream,
} from '../../../src/ts/sign/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import { concat } from '../../../src/ts/utils.js';
import {
	makeStreamableFixtureSuite,
	fixtureSk,
	FIXTURE_SIG_SIZE,
} from './helpers.js';

beforeAll(async () => {
	await init({ sha3: sha3Wasm });
});

function expectSigningError(fn: () => unknown, discriminator: string): void {
	let caught: unknown;
	try {
		fn();
	} catch (e) {
		caught = e;
	}
	expect(caught).toBeInstanceOf(SigningError);
	expect((caught as SigningError).discriminator).toBe(discriminator);
}

function signBlob(
	msg: Uint8Array, ctx: Uint8Array = new Uint8Array(0),
): Uint8Array {
	const suite = makeStreamableFixtureSuite();
	return Sign.sign(suite, fixtureSk(), msg, ctx);
}

describe('VerifyStream header parser', () => {
	it('accepts header bytes 1 at a time then data', () => {
		const msg = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22]);
		const ctx = new Uint8Array([1, 2, 3]);
		const blob = signBlob(msg, ctx);

		const v = new VerifyStream(makeStreamableFixtureSuite(), fixtureSk(), ctx);
		for (let i = 0; i < blob.length; i++)
			v.update(blob.subarray(i, i + 1));
		const out = v.finalize();
		expect(Array.from(out)).toEqual(Array.from(msg));
	});

	it('accepts the entire blob in one update', () => {
		const msg = new Uint8Array(64);
		for (let i = 0; i < msg.length; i++) msg[i] = i;
		const ctx = new Uint8Array(0);
		const blob = signBlob(msg, ctx);

		const v = new VerifyStream(makeStreamableFixtureSuite(), fixtureSk(), ctx);
		v.update(blob);
		const out = v.finalize();
		expect(Array.from(out)).toEqual(Array.from(msg));
	});

	it('header bytes + data bytes in a single chunk both process', () => {
		const msg = new Uint8Array([0x10, 0x20, 0x30]);
		const ctx = new Uint8Array([0xaa]);
		const blob = signBlob(msg, ctx);

		// One chunk covers header (3 bytes) + partial data.
		const v = new VerifyStream(makeStreamableFixtureSuite(), fixtureSk(), ctx);
		v.update(blob.subarray(0, 10));
		v.update(blob.subarray(10));
		const out = v.finalize();
		expect(Array.from(out)).toEqual(Array.from(msg));
	});

	it('wire suite_byte mismatch throws sig-suite-mismatch', () => {
		const msg = new Uint8Array([1, 2, 3]);
		const ctx = new Uint8Array(0);
		const blob = signBlob(msg, ctx);
		const corrupted = blob.slice();
		corrupted[0] ^= 0x01;

		const v = new VerifyStream(makeStreamableFixtureSuite(), fixtureSk(), ctx);
		expectSigningError(() => v.update(corrupted), 'sig-suite-mismatch');
	});

	it('wire ctx mismatch throws sig-ctx-mismatch', () => {
		const msg = new Uint8Array([1, 2, 3]);
		const ctx = new Uint8Array([0x01, 0x02, 0x03]);
		const blob = signBlob(msg, ctx);

		const wrongCtx = new Uint8Array([0x01, 0x02, 0x04]);
		const v = new VerifyStream(makeStreamableFixtureSuite(), fixtureSk(), wrongCtx);
		expectSigningError(() => v.update(blob), 'sig-ctx-mismatch');
	});
});

describe('VerifyStream finalize success and failure', () => {
	it('finalize returns payload on success', () => {
		const msg = new Uint8Array([5, 6, 7, 8, 9]);
		const ctx = new Uint8Array(0);
		const blob = signBlob(msg, ctx);

		const v = new VerifyStream(makeStreamableFixtureSuite(), fixtureSk(), ctx);
		v.update(blob);
		const out = v.finalize();
		expect(Array.from(out)).toEqual(Array.from(msg));
	});

	it('finalize throws verify-failed on sig-corrupted blob', () => {
		const msg = new Uint8Array([5, 6, 7, 8, 9]);
		const ctx = new Uint8Array(0);
		const blob = signBlob(msg, ctx);
		// Flip a bit in the sig (last byte).
		blob[blob.length - 1] ^= 0x01;

		const v = new VerifyStream(makeStreamableFixtureSuite(), fixtureSk(), ctx);
		v.update(blob);
		expectSigningError(() => v.finalize(), 'verify-failed');
	});

	it('after verify-failed, subsequent operations are terminal', () => {
		const msg = new Uint8Array([1, 2, 3]);
		const ctx = new Uint8Array(0);
		const blob = signBlob(msg, ctx);
		blob[blob.length - 1] ^= 0x01;

		const v = new VerifyStream(makeStreamableFixtureSuite(), fixtureSk(), ctx);
		v.update(blob);
		try {
			v.finalize();
		} catch { /* expected */ }
		expectSigningError(() => v.finalize(), 'sig-stream-finalized');
	});

	it('finalize before complete header throws sig-blob-too-short', () => {
		const v = new VerifyStream(
			makeStreamableFixtureSuite(), fixtureSk(), new Uint8Array(0),
		);
		expectSigningError(() => v.finalize(), 'sig-blob-too-short');
	});

	it('finalize with sigWindow < sigSize throws sig-blob-too-short', () => {
		const suite = makeStreamableFixtureSuite();
		const ctx = new Uint8Array(0);
		// header is 2 bytes; feed those plus only half of a sigSize sig.
		const v = new VerifyStream(suite, fixtureSk(), ctx);
		const header = new Uint8Array([suite.formatEnum, 0]);
		v.update(header);
		v.update(new Uint8Array(FIXTURE_SIG_SIZE / 2));
		expectSigningError(() => v.finalize(), 'sig-blob-too-short');
	});
});

describe('VerifyStream sliding window', () => {
	it('correctly identifies last sigSize bytes as the sig', () => {
		const payloadLen = 200;
		const msg = new Uint8Array(payloadLen);
		for (let i = 0; i < payloadLen; i++) msg[i] = (i * 13) & 0xff;
		const ctx = new Uint8Array(0);
		const blob = signBlob(msg, ctx);

		// Total wire bytes: 2 (header) + payloadLen + FIXTURE_SIG_SIZE.
		expect(blob.length).toBe(2 + payloadLen + FIXTURE_SIG_SIZE);

		// Feed in awkward chunks; verify the recovered payload matches msg.
		const v = new VerifyStream(makeStreamableFixtureSuite(), fixtureSk(), ctx);
		v.update(blob.subarray(0, 1));
		v.update(blob.subarray(1, 70));
		v.update(blob.subarray(70, 71));
		v.update(blob.subarray(71, blob.length - 1));
		v.update(blob.subarray(blob.length - 1));
		const out = v.finalize();
		expect(Array.from(out)).toEqual(Array.from(msg));
	});

	it('preserves payload across many fragmented updates', () => {
		const msg = new Uint8Array(257);
		for (let i = 0; i < msg.length; i++) msg[i] = i & 0xff;
		const ctx = new Uint8Array(0);
		const blob = signBlob(msg, ctx);

		// Reassemble payload + sig from blob chunks of size 7.
		const v = new VerifyStream(makeStreamableFixtureSuite(), fixtureSk(), ctx);
		const stride = 7;
		for (let off = 0; off < blob.length; off += stride)
			v.update(blob.subarray(off, Math.min(off + stride, blob.length)));
		const out = v.finalize();
		expect(Array.from(out)).toEqual(Array.from(msg));
	});
});

describe('VerifyStream dispose', () => {
	it('is idempotent', () => {
		const v = new VerifyStream(
			makeStreamableFixtureSuite(), fixtureSk(), new Uint8Array(0),
		);
		v.dispose();
		expect(() => v.dispose()).not.toThrow();
	});

	it('update after dispose throws sig-stream-disposed', () => {
		const v = new VerifyStream(
			makeStreamableFixtureSuite(), fixtureSk(), new Uint8Array(0),
		);
		v.dispose();
		expectSigningError(() => v.update(new Uint8Array([1])), 'sig-stream-disposed');
	});

	it('finalize after dispose throws sig-stream-disposed', () => {
		const v = new VerifyStream(
			makeStreamableFixtureSuite(), fixtureSk(), new Uint8Array(0),
		);
		v.dispose();
		expectSigningError(() => v.finalize(), 'sig-stream-disposed');
	});
});

describe('VerifyStream consumes SignStream output', () => {
	it('round-trips with SignStream end-to-end', () => {
		const suite = makeStreamableFixtureSuite();
		const sk = fixtureSk();
		const ctx = new Uint8Array([0x10, 0x11]);
		const msg = new Uint8Array(1024);
		for (let i = 0; i < msg.length; i++) msg[i] = (i * 3 + 7) & 0xff;

		const signer = new SignStream(suite, sk, ctx);
		signer.update(msg);
		const sig = signer.finalize();
		const blob = concat(signer.preamble, msg, sig);

		const v = new VerifyStream(suite, sk, ctx);
		v.update(blob);
		const out = v.finalize();
		expect(Array.from(out)).toEqual(Array.from(msg));
	});
});
