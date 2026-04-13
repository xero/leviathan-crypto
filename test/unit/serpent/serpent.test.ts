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
 * Constructor gate tests for SerpentCbc/SerpentCtr
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	init,
	SerpentCbc, SerpentCtr,
} from '../../../src/ts/index.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm, sha2: sha2Wasm });
});

// ── SerpentCbc/SerpentCtr constructor gate ───────────────────────────────────

describe('SerpentCbc — dangerUnauthenticated gate', () => {
	it('new SerpentCbc() throws without dangerUnauthenticated flag', () => {
		expect(() => new SerpentCbc()).toThrow(
			'leviathan-crypto: SerpentCbc is unauthenticated — use Seal with SerpentCipher instead.'
		);
	});

	it('new SerpentCbc({ dangerUnauthenticated: true }) constructs successfully', () => {
		const c = new SerpentCbc({ dangerUnauthenticated: true });
		expect(c).toBeDefined();
		c.dispose();
	});
});

describe('SerpentCtr — dangerUnauthenticated gate', () => {
	it('new SerpentCtr() throws without dangerUnauthenticated flag', () => {
		expect(() => new SerpentCtr()).toThrow(
			'leviathan-crypto: SerpentCtr is unauthenticated — use Seal with SerpentCipher instead.'
		);
	});

	it('new SerpentCtr({ dangerUnauthenticated: true }) constructs successfully', () => {
		const c = new SerpentCtr({ dangerUnauthenticated: true });
		expect(c).toBeDefined();
		c.dispose();
	});
});
