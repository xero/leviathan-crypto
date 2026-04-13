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
// src/ts/sha2/hash.ts
//
// Stateless SHA-256 HashFn for Fortuna's accumulator and reseed slots.

import { _assertNotOwned, getInstance } from '../init.js';
import type { HashFn } from '../types.js';

interface Sha2Min {
	memory:               WebAssembly.Memory;
	getSha256InputOffset: () => number;
	getSha256OutOffset:   () => number;
	sha256Init:           () => void;
	sha256Update:         (len: number) => void;
	wipeBuffers:          () => void;
	sha256Final:          () => void;
}

export const SHA256Hash: HashFn = {
	outputSize: 32,
	wasmModules: ['sha2'],

	digest(msg: Uint8Array): Uint8Array {
		_assertNotOwned('sha2');
		const x = getInstance('sha2').exports as unknown as Sha2Min;
		const mem = new Uint8Array(x.memory.buffer);
		try {
			x.sha256Init();
			const inOff = x.getSha256InputOffset();
			let pos = 0;
			while (pos < msg.length) {
				const n = Math.min(msg.length - pos, 64);
				mem.set(msg.subarray(pos, pos + n), inOff);
				x.sha256Update(n);
				pos += n;
			}
			x.sha256Final();
			const outOff = x.getSha256OutOffset();
			return mem.slice(outOff, outOff + 32);
		} finally {
			// Wipe the SHA-256 input/output/state scratch so secret-derived
			// inputs (e.g. Fortuna pool entropy) do not outlive this call.
			x.wipeBuffers();
		}
	},
};
