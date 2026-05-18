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
// test/unit/sign/sign-types.test.ts
//
// Type-level + runtime conformance tests for SignatureSuite /
// StreamableSignatureSuite. Exists primarily as a compile-time gate; the
// `// @ts-expect-error` is the negative assertion.

import { describe, it, expect } from 'vitest';
import type {
	SignatureSuite,
	StreamableSignatureSuite,
	PrehashAlgorithm,
} from '../../../src/ts/sign/index.js';

const STUB_SIG = new Uint8Array(0);
const STUB_KEY = { pk: new Uint8Array(0), sk: new Uint8Array(0) };

const pureSuite: SignatureSuite = {
	formatEnum: 0x00,
	formatName: 'stub-pure',
	ctxDomain: 'stub-envelope-v3',
	pkSize: 0,
	skSize: 0,
	sigMaxSize: 0,
	wasmModules: ['mldsa', 'sha3'] as const,
	sign: () => STUB_SIG,
	verify: () => true,
	keygen: () => STUB_KEY,
};

const streamSuite: StreamableSignatureSuite = {
	formatEnum: 0x10,
	formatName: 'stub-prehash',
	ctxDomain: 'stub-prehash-envelope-v3',
	pkSize: 0,
	skSize: 0,
	sigMaxSize: 0,
	wasmModules: ['mldsa', 'sha3'] as const,
	prehashAlgorithm: 'sha3-256',
	prehashSize: 32,
	sign: () => STUB_SIG,
	verify: () => true,
	signPrehashed: () => STUB_SIG,
	verifyPrehashed: () => true,
	keygen: () => STUB_KEY,
};

describe('SignatureSuite type contract', () => {
	it('a literal pure suite satisfies SignatureSuite', () => {
		// type-level: assignment to typed binding above is the assertion.
		expect(pureSuite.formatName).toBe('stub-pure');
	});

	it('all 7 required readonly fields are enumerable on a pure suite', () => {
		const keys = Object.keys(pureSuite);
		for (const k of [
			'formatEnum',
			'formatName',
			'ctxDomain',
			'pkSize',
			'skSize',
			'sigMaxSize',
			'wasmModules',
		]) {
			expect(keys).toContain(k);
		}
	});

	it('the 3 required methods are callable on a pure suite', () => {
		expect(typeof pureSuite.sign).toBe('function');
		expect(typeof pureSuite.verify).toBe('function');
		expect(typeof pureSuite.keygen).toBe('function');
	});
});

describe('StreamableSignatureSuite type contract', () => {
	it('a literal streamable suite satisfies StreamableSignatureSuite', () => {
		expect(streamSuite.formatName).toBe('stub-prehash');
	});

	it('streamable suite inherits the base SignatureSuite shape', () => {
		// upcast must compile; a streamable suite IS a SignatureSuite.
		const base: SignatureSuite = streamSuite;
		expect(base.formatEnum).toBe(0x10);
	});

	it('prehash-only fields and methods are present', () => {
		expect(streamSuite.prehashAlgorithm).toBe('sha3-256');
		expect(streamSuite.prehashSize).toBe(32);
		expect(typeof streamSuite.signPrehashed).toBe('function');
		expect(typeof streamSuite.verifyPrehashed).toBe('function');
	});

	it('a pure suite does NOT satisfy StreamableSignatureSuite', () => {
		// @ts-expect-error pureSuite lacks prehashAlgorithm / prehashSize /
		// signPrehashed / verifyPrehashed.
		const _bad: StreamableSignatureSuite = pureSuite;
		void _bad;
	});
});

describe('PrehashAlgorithm union', () => {
	it('exposes the 6 lowercase, hyphenated variants', () => {
		const all: PrehashAlgorithm[] = [
			'sha-256',
			'sha-512',
			'sha3-256',
			'sha3-512',
			'shake-128',
			'shake-256',
		];
		expect(all).toHaveLength(6);
		expect(new Set(all).size).toBe(6);
	});
});
