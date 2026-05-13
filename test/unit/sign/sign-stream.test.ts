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
// test/unit/sign/sign-stream.test.ts
//
// SignStream construction, update/finalize/dispose lifecycle, and error
// paths. Equivalence with Sign.sign output bytes is asserted in
// sign-stream-equivalence.test.ts; this file focuses on the state machine
// and observable behavior.

import { describe, it, expect, beforeAll } from 'vitest';
import { init } from '../../../src/ts/index.js';
import { SignStream } from '../../../src/ts/sign/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import {
	makeStreamableFixtureSuite,
	fixtureSk,
	FIXTURE_STREAM_FORMAT_ENUM,
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

describe('SignStream preamble', () => {
	it('preamble is available immediately after construction', () => {
		const suite = makeStreamableFixtureSuite();
		const sk = fixtureSk();
		const ctx = new Uint8Array([0xaa, 0xbb, 0xcc]);
		const s = new SignStream(suite, sk, ctx);
		try {
			expect(s.preamble.length).toBe(2 + ctx.length);
			expect(s.preamble[0]).toBe(FIXTURE_STREAM_FORMAT_ENUM);
			expect(s.preamble[1]).toBe(ctx.length);
			expect(Array.from(s.preamble.subarray(2))).toEqual(Array.from(ctx));
		} finally {
			s.dispose();
		}
	});

	it('preamble for empty ctx is exactly 2 bytes', () => {
		const suite = makeStreamableFixtureSuite();
		const sk = fixtureSk();
		const s = new SignStream(suite, sk, new Uint8Array(0));
		try {
			expect(s.preamble.length).toBe(2);
			expect(s.preamble[0]).toBe(FIXTURE_STREAM_FORMAT_ENUM);
			expect(s.preamble[1]).toBe(0);
		} finally {
			s.dispose();
		}
	});
});

describe('SignStream update + finalize', () => {
	it('accepts a single 1-byte chunk and finalizes', () => {
		const suite = makeStreamableFixtureSuite();
		const s = new SignStream(suite, fixtureSk(), new Uint8Array(0));
		s.update(new Uint8Array([0x42]));
		const sig = s.finalize();
		expect(sig.length).toBe(FIXTURE_SIG_SIZE);
	});

	it('accepts one large chunk (>4 KiB)', () => {
		const suite = makeStreamableFixtureSuite();
		const s = new SignStream(suite, fixtureSk(), new Uint8Array(0));
		const big = new Uint8Array(8192);
		for (let i = 0; i < big.length; i++) big[i] = (i * 7) & 0xff;
		s.update(big);
		const sig = s.finalize();
		expect(sig.length).toBe(FIXTURE_SIG_SIZE);
	});

	it('accepts mixed chunk sizes', () => {
		const suite = makeStreamableFixtureSuite();
		const s = new SignStream(suite, fixtureSk(), new Uint8Array(0));
		s.update(new Uint8Array([1, 2]));
		s.update(new Uint8Array(200).fill(0x55));
		s.update(new Uint8Array([0xff]));
		const sig = s.finalize();
		expect(sig.length).toBe(FIXTURE_SIG_SIZE);
	});
});

describe('SignStream state-machine errors', () => {
	it('update after finalize throws sig-stream-finalized', () => {
		const suite = makeStreamableFixtureSuite();
		const s = new SignStream(suite, fixtureSk(), new Uint8Array(0));
		s.finalize();
		expectSigningError(
			() => s.update(new Uint8Array([1])), 'sig-stream-finalized',
		);
	});

	it('update after dispose throws sig-stream-disposed', () => {
		const suite = makeStreamableFixtureSuite();
		const s = new SignStream(suite, fixtureSk(), new Uint8Array(0));
		s.dispose();
		expectSigningError(
			() => s.update(new Uint8Array([1])), 'sig-stream-disposed',
		);
	});

	it('finalize after finalize throws sig-stream-finalized', () => {
		const suite = makeStreamableFixtureSuite();
		const s = new SignStream(suite, fixtureSk(), new Uint8Array(0));
		s.finalize();
		expectSigningError(() => s.finalize(), 'sig-stream-finalized');
	});

	it('finalize after dispose throws sig-stream-disposed', () => {
		const suite = makeStreamableFixtureSuite();
		const s = new SignStream(suite, fixtureSk(), new Uint8Array(0));
		s.dispose();
		expectSigningError(() => s.finalize(), 'sig-stream-disposed');
	});
});

describe('SignStream dispose', () => {
	it('is idempotent', () => {
		const suite = makeStreamableFixtureSuite();
		const s = new SignStream(suite, fixtureSk(), new Uint8Array(0));
		s.dispose();
		expect(() => s.dispose()).not.toThrow();
	});

	it('after finalize is a no-op', () => {
		const suite = makeStreamableFixtureSuite();
		const s = new SignStream(suite, fixtureSk(), new Uint8Array(0));
		s.update(new Uint8Array([1, 2, 3]));
		s.finalize();
		expect(() => s.dispose()).not.toThrow();
	});

	it('releases the sha3 module so a new SignStream can be built', () => {
		const suite = makeStreamableFixtureSuite();
		const a = new SignStream(suite, fixtureSk(), new Uint8Array(0));
		a.dispose();
		const b = new SignStream(suite, fixtureSk(), new Uint8Array(0));
		expect(() => b.finalize()).not.toThrow();
	});
});
