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
import type { WasmSource } from './wasm-source.js';
import { loadWasm } from './loader.js';
import { hasSIMD } from './utils.js';

export type Module = 'serpent' | 'chacha20' | 'sha2' | 'sha3'

// Module-scope cache: one WebAssembly.Instance per module
const instances = new Map<Module, WebAssembly.Instance>();

export async function initModule(mod: Module, source: WasmSource): Promise<void> {
	if (instances.has(mod)) return;
	if ((mod === 'serpent' || mod === 'chacha20') && !hasSIMD())
		throw new Error(
			'leviathan-crypto: serpent and chacha20 require WebAssembly SIMD — '
			+ 'this runtime does not support it',
		);
	instances.set(mod, await loadWasm(source));
}

export function getInstance(mod: Module): WebAssembly.Instance {
	const inst = instances.get(mod);
	if (!inst) {
		throw new Error(`leviathan-crypto: call init({ ${mod}: ... }) before using this class`);
	}
	return inst;
}

export function isInitialized(mod: Module): boolean {
	return instances.has(mod);
}

/** Reset all cached instances — for testing only */
export function _resetForTesting(): void {
	instances.clear();
}
