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
// test/unit/sign/sign-errors.test.ts
//
// SigningError class unit tests, mirrors test/unit/errors.test.ts.

import { describe, it, expect } from 'vitest';
import { SigningError } from '../../../src/ts/errors.js';

// 11 discriminator strings: 3 suite + 5 envelope + 3 stream.
const KNOWN_DISCRIMINATORS = [
	// suite layer
	'sig-key-size',
	'sig-ctx-too-long',
	'sig-malformed-input',
	// envelope layer
	'sig-blob-too-short',
	'sig-suite-unknown',
	'sig-ctx-overflow',
	'sig-ctx-mismatch',
	'verify-failed',
	// stream layer
	'sig-stream-finalized',
	'sig-stream-disposed',
	'sig-suite-mismatch',
] as const;

describe('SigningError', () => {
	it('discriminator-only constructor auto-generates the message', () => {
		const e = new SigningError('sig-key-size');
		expect(e.message).toBe('leviathan-crypto SigningError: sig-key-size');
	});

	it('discriminator + custom message uses the custom message verbatim', () => {
		const e = new SigningError('sig-ctx-too-long', 'user_ctx length 999 > 255');
		expect(e.message).toBe('user_ctx length 999 > 255');
	});

	it('discriminator field is readable on the instance', () => {
		const e = new SigningError('sig-malformed-input');
		expect(e.discriminator).toBe('sig-malformed-input');
	});

	it('name === \'SigningError\'', () => {
		expect(new SigningError('sig-key-size').name).toBe('SigningError');
	});

	it('instanceof Error is true', () => {
		expect(new SigningError('verify-failed')).toBeInstanceOf(Error);
	});

	it('instanceof SigningError is true (verifies setPrototypeOf)', () => {
		expect(new SigningError('verify-failed')).toBeInstanceOf(SigningError);
	});

	it('prototype chain is correct', () => {
		const e = new SigningError('sig-suite-mismatch');
		expect(Object.getPrototypeOf(e)).toBe(SigningError.prototype);
	});

	it('accepts every known discriminator string', () => {
		for (const d of KNOWN_DISCRIMINATORS) {
			const e = new SigningError(d);
			expect(e.discriminator).toBe(d);
			expect(e.name).toBe('SigningError');
			expect(e).toBeInstanceOf(SigningError);
		}
	});
});
