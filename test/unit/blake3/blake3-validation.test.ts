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
 * BLAKE3 caller-validation gates, BLAKE3 §2.3 Modes / §2.6 XOF surface
 * contracts plus the v3 lifecycle guards (update after finalize,
 * read after dispose).
 *
 * Each case exercises one validator in `src/ts/blake3/validate.ts` or
 * one lifecycle guard in `src/ts/blake3/index.ts`. The discriminator
 * shape (RangeError vs TypeError vs plain Error) is part of the public
 * contract; consumer code can pattern-match on these and we lock the
 * pattern here.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
	BLAKE3, BLAKE3Stream,
	BLAKE3KeyedHash, BLAKE3KeyedHashStream,
	BLAKE3DeriveKey, BLAKE3DeriveKeyStream,
	blake3Init,
} from '../../../src/ts/blake3/index.js';
import { blake3Wasm } from '../../../src/ts/blake3/embedded.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { blake3Key, blake3ContextString } from '../../vectors/blake3.js';

const KEY_BYTES = new TextEncoder().encode(blake3Key);

beforeAll(async () => {
	_resetForTesting();
	await blake3Init(blake3Wasm);
});

describe('BLAKE3 validation: validateKey (§2.3 keyed_hash)', () => {
	it('key length 31 throws RangeError', () => {
		const h = new BLAKE3KeyedHash();
		try {
			expect(() => h.hash(new Uint8Array(31), new Uint8Array(0))).toThrow(RangeError);
		} finally {
			h.dispose();
		}
	});

	it('key length 33 throws RangeError', () => {
		const h = new BLAKE3KeyedHash();
		try {
			expect(() => h.hash(new Uint8Array(33), new Uint8Array(0))).toThrow(RangeError);
		} finally {
			h.dispose();
		}
	});

	it('key length 0 throws RangeError', () => {
		const h = new BLAKE3KeyedHash();
		try {
			expect(() => h.hash(new Uint8Array(0), new Uint8Array(0))).toThrow(RangeError);
		} finally {
			h.dispose();
		}
	});

	it('non-Uint8Array key throws TypeError', () => {
		const h = new BLAKE3KeyedHash();
		try {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			expect(() => h.hash('not-a-key' as any, new Uint8Array(0))).toThrow(TypeError);
		} finally {
			h.dispose();
		}
	});

	it('Stream constructor with wrong key length throws RangeError', () => {
		expect(() => new BLAKE3KeyedHashStream(new Uint8Array(20))).toThrow(RangeError);
		expect(() => new BLAKE3KeyedHashStream(new Uint8Array(40))).toThrow(RangeError);
	});
});

describe('BLAKE3 validation: validateContext (§2.3 derive_key)', () => {
	it('non-string non-Uint8Array context throws TypeError', () => {
		const dk = new BLAKE3DeriveKey();
		try {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			expect(() => dk.derive(123 as any, new Uint8Array(0))).toThrow(TypeError);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			expect(() => dk.derive(null as any, new Uint8Array(0))).toThrow(TypeError);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			expect(() => dk.derive({} as any, new Uint8Array(0))).toThrow(TypeError);
		} finally {
			dk.dispose();
		}
	});

	it('empty string context throws RangeError (defeats §2.3 domain separation)', () => {
		const dk = new BLAKE3DeriveKey();
		try {
			expect(() => dk.derive('',                 new Uint8Array(0))).toThrow(RangeError);
			expect(() => dk.derive(new Uint8Array(0),  new Uint8Array(0))).toThrow(RangeError);
		} finally {
			dk.dispose();
		}
	});

	it('non-empty string context is accepted', () => {
		const dk = new BLAKE3DeriveKey();
		try {
			expect(() => dk.derive('valid-context-string', new Uint8Array(8))).not.toThrow();
		} finally {
			dk.dispose();
		}
	});

	it('Stream constructor with empty context throws RangeError', () => {
		expect(() => new BLAKE3DeriveKeyStream('')).toThrow(RangeError);
		expect(() => new BLAKE3DeriveKeyStream(new Uint8Array(0))).toThrow(RangeError);
	});
});

describe('BLAKE3 validation: validateOutputLen', () => {
	it('outLen = 0 throws RangeError', () => {
		const h = new BLAKE3();
		try        {
			expect(() => h.hash(new Uint8Array(0), 0)).toThrow(RangeError);
		} finally    {
			h.dispose();
		}
	});

	it('outLen = -1 throws RangeError', () => {
		const h = new BLAKE3();
		try        {
			expect(() => h.hash(new Uint8Array(0), -1)).toThrow(RangeError);
		} finally    {
			h.dispose();
		}
	});

	it('outLen = 1.5 throws RangeError (non-integer)', () => {
		const h = new BLAKE3();
		try        {
			expect(() => h.hash(new Uint8Array(0), 1.5)).toThrow(RangeError);
		} finally    {
			h.dispose();
		}
	});

	it('outLen = NaN throws RangeError', () => {
		const h = new BLAKE3();
		try        {
			expect(() => h.hash(new Uint8Array(0), NaN)).toThrow(RangeError);
		} finally    {
			h.dispose();
		}
	});

	it('outLen = Infinity throws RangeError', () => {
		const h = new BLAKE3();
		try        {
			expect(() => h.hash(new Uint8Array(0), Infinity)).toThrow(RangeError);
		} finally    {
			h.dispose();
		}
	});

	it('Stream finalize with outLen = 0 throws RangeError', () => {
		const s = new BLAKE3Stream();
		expect(() => s.finalize(0)).toThrow(RangeError);
		s.dispose();
	});
});

describe('BLAKE3 validation: message type', () => {
	it('non-Uint8Array message to BLAKE3.hash throws TypeError', () => {
		const h = new BLAKE3();
		try {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			expect(() => h.hash('hello' as any)).toThrow(TypeError);
		} finally {
			h.dispose();
		}
	});

	it('non-Uint8Array message to BLAKE3KeyedHash.hash throws TypeError', () => {
		const h = new BLAKE3KeyedHash();
		try {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			expect(() => h.hash(KEY_BYTES, 'hello' as any)).toThrow(TypeError);
		} finally {
			h.dispose();
		}
	});

	it('non-Uint8Array material to BLAKE3DeriveKey.derive throws TypeError', () => {
		const dk = new BLAKE3DeriveKey();
		try {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			expect(() => dk.derive(blake3ContextString, 'hello' as any)).toThrow(TypeError);
		} finally {
			dk.dispose();
		}
	});
});

describe('BLAKE3 lifecycle guards', () => {
	it('update() after finalize() throws (BLAKE3Stream)', () => {
		const s = new BLAKE3Stream();
		s.finalize();
		expect(() => s.update(new Uint8Array(1))).toThrow();
	});

	it('update() after finalizeXof() throws (BLAKE3Stream)', () => {
		const s = new BLAKE3Stream();
		const r = s.finalizeXof();
		try        {
			expect(() => s.update(new Uint8Array(1))).toThrow();
		} finally    {
			r.dispose();
		}
	});

	it('finalize() after dispose() throws (BLAKE3Stream)', () => {
		const s = new BLAKE3Stream();
		s.dispose();
		expect(() => s.finalize()).toThrow();
	});

	it('update() after dispose() throws (BLAKE3KeyedHashStream)', () => {
		const s = new BLAKE3KeyedHashStream(KEY_BYTES);
		s.dispose();
		expect(() => s.update(new Uint8Array(1))).toThrow();
	});

	it('update() after dispose() throws (BLAKE3DeriveKeyStream)', () => {
		const s = new BLAKE3DeriveKeyStream(blake3ContextString);
		s.dispose();
		expect(() => s.update(new Uint8Array(1))).toThrow();
	});

	it('read() on OutputReader after dispose() throws', () => {
		const s = new BLAKE3Stream();
		const r = s.finalizeXof();
		r.dispose();
		expect(() => r.read(8)).toThrow();
	});

	it('dispose() is idempotent across all classes', () => {
		const a = new BLAKE3();                                    a.dispose(); a.dispose();
		const b = new BLAKE3KeyedHash();                           b.dispose(); b.dispose();
		const c = new BLAKE3DeriveKey();                           c.dispose(); c.dispose();
		const d = new BLAKE3Stream();                              d.dispose(); d.dispose();
		const e = new BLAKE3KeyedHashStream(KEY_BYTES);            e.dispose(); e.dispose();
		const f = new BLAKE3DeriveKeyStream(blake3ContextString);  f.dispose(); f.dispose();
		const g = new BLAKE3Stream();
		const r = g.finalizeXof();                                  r.dispose(); r.dispose();
	});
});
