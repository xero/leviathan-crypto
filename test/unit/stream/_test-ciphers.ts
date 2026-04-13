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
// test/unit/stream/_test-ciphers.ts
//
// Test-only cipher overrides. The shipping XChaCha20Cipher and
// SerpentCipher spawn pool workers via blob URLs (see
// scripts/embed-workers.ts). The @vitest/web-worker test setup
// intercepts the syntactic `new Worker(new URL(..., import.meta.url))`
// pattern through Vite's module graph; it does NOT intercept blob URLs.
// So tests run against these spread-overrides instead.
//
// This incidentally exercises the spread-override seam that strict-CSP
// consumers can use in production to plug in their own URL-based
// factories.

import { XChaCha20Cipher } from '../../../src/ts/chacha20/cipher-suite.js';
import { SerpentCipher }   from '../../../src/ts/serpent/cipher-suite.js';

export const TestXChaCha20Cipher = {
	...XChaCha20Cipher,
	createPoolWorker: (): Worker => new Worker(
		new URL('../../../src/ts/chacha20/pool-worker.ts', import.meta.url),
		{ type: 'module' },
	),
};

export const TestSerpentCipher = {
	...SerpentCipher,
	createPoolWorker: (): Worker => new Worker(
		new URL('../../../src/ts/serpent/pool-worker.ts', import.meta.url),
		{ type: 'module' },
	),
};
