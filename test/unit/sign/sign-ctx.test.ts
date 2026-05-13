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
// test/unit/sign/sign-ctx.test.ts
//
// buildEffectiveCtx layout/cap tests + prehashAlgoToMldsa map coverage.

import { describe, it, expect } from 'vitest';
import {
	buildEffectiveCtx,
	prehashAlgoToMldsa,
	USER_CTX_MAX,
	CTX_DOMAIN_MAX,
} from '../../../src/ts/sign/index.js';
import type { PrehashAlgorithm } from '../../../src/ts/sign/index.js';
import { SigningError } from '../../../src/ts/errors.js';
import { utf8ToBytes } from '../../../src/ts/utils.js';

describe('buildEffectiveCtx', () => {
	it('empty user_ctx produces [domain_len][domain][0]', () => {
		const out = buildEffectiveCtx('domain', new Uint8Array(0));
		const expected = new Uint8Array([
			6,
			...utf8ToBytes('domain'),
			0,
		]);
		expect(out).toEqual(expected);
	});

	it('produces [u8 domain_len][domain][u8 ctx_len][ctx] byte-for-byte', () => {
		const userCtx = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
		const out = buildEffectiveCtx('abc', userCtx);
		expect(out[0]).toBe(3);
		expect(out.slice(1, 4)).toEqual(utf8ToBytes('abc'));
		expect(out[4]).toBe(4);
		expect(out.slice(5)).toEqual(userCtx);
		expect(out.length).toBe(1 + 3 + 1 + 4);
	});

	it('accepts user_ctx exactly USER_CTX_MAX bytes (boundary)', () => {
		const ctx = new Uint8Array(USER_CTX_MAX);
		const out = buildEffectiveCtx('d', ctx);
		expect(out.length).toBe(1 + 1 + 1 + USER_CTX_MAX);
		expect(out[2]).toBe(USER_CTX_MAX);
	});

	it('user_ctx of USER_CTX_MAX+1 throws SigningError(\'sig-ctx-too-long\')', () => {
		const ctx = new Uint8Array(USER_CTX_MAX + 1);
		let caught: unknown;
		try {
			buildEffectiveCtx('d', ctx);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(SigningError);
		expect((caught as SigningError).discriminator).toBe('sig-ctx-too-long');
	});

	it('rejects a ctxDomain longer than CTX_DOMAIN_MAX with a plain Error', () => {
		const tooLong = 'x'.repeat(CTX_DOMAIN_MAX + 1);
		let caught: unknown;
		try {
			buildEffectiveCtx(tooLong, new Uint8Array(0));
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(Error);
		// must NOT be SigningError; that's reserved for caller mistakes.
		expect(caught).not.toBeInstanceOf(SigningError);
	});

	it('USER_CTX_MAX and CTX_DOMAIN_MAX constants are 200 / 32', () => {
		expect(USER_CTX_MAX).toBe(200);
		expect(CTX_DOMAIN_MAX).toBe(32);
	});
});

describe('prehashAlgoToMldsa', () => {
	const MAP: Record<PrehashAlgorithm, string> = {
		'sha-256': 'SHA2-256',
		'sha-512': 'SHA2-512',
		'sha3-256': 'SHA3-256',
		'sha3-512': 'SHA3-512',
		'shake-128': 'SHAKE128',
		'shake-256': 'SHAKE256',
	};

	for (const [algo, expected] of Object.entries(MAP) as [PrehashAlgorithm, string][]) {
		it(`${algo} → ${expected}`, () => {
			expect(prehashAlgoToMldsa(algo)).toBe(expected);
		});
	}

	it('shake entries map to \'SHAKE128\' / \'SHAKE256\' (no hyphen)', () => {
		expect(prehashAlgoToMldsa('shake-128')).toBe('SHAKE128');
		expect(prehashAlgoToMldsa('shake-256')).toBe('SHAKE256');
	});

	it('unknown algo (cast through unknown) throws', () => {
		expect(() =>
			prehashAlgoToMldsa('not-an-algo' as unknown as PrehashAlgorithm),
		).toThrow();
	});
});
