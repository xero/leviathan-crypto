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
export type Module = 'serpent' | 'chacha20' | 'sha2' | 'sha3'

export type Mode = 'embedded' | 'streaming' | 'manual'

export interface InitOpts {
  wasmUrl?: URL | string
  wasmBinary?: Partial<Record<Module, Uint8Array | ArrayBuffer>>
}

// Module-scope cache: one WebAssembly.Instance per module
const instances = new Map<Module, WebAssembly.Instance>();

// Map from public module name to WASM filename
const WASM_FILES: Record<Module, string> = {
	serpent: 'serpent.wasm',
	chacha20: 'chacha.wasm',
	sha2: 'sha2.wasm',
	sha3: 'sha3.wasm',
};

export async function init(
	modules: Module | Module[],
	mode: Mode = 'embedded',
	opts?: InitOpts,
): Promise<void> {
	const list = Array.isArray(modules) ? modules : [modules];

	for (const mod of list) {
		if (instances.has(mod)) continue;

		let instance: WebAssembly.Instance;

		if (mode === 'embedded') {
			const { loadEmbedded } = await import('./loader.js');
			instance = await loadEmbedded(mod);
		} else if (mode === 'streaming') {
			if (!opts?.wasmUrl) throw new Error('leviathan-crypto: streaming mode requires wasmUrl');
			const { loadStreaming } = await import('./loader.js');
			instance = await loadStreaming(mod, opts.wasmUrl, WASM_FILES[mod]);
		} else if (mode === 'manual') {
			const binary = opts?.wasmBinary?.[mod];
			if (!binary) throw new Error(`leviathan-crypto: manual mode requires wasmBinary['${mod}']`);
			const { loadManual } = await import('./loader.js');
			instance = await loadManual(binary);
		} else {
			throw new Error(`leviathan-crypto: unknown mode '${mode}'`);
		}

		instances.set(mod, instance);
	}
}

export function getInstance(mod: Module): WebAssembly.Instance {
	const inst = instances.get(mod);
	if (!inst) {
		throw new Error(`leviathan-crypto: call init(['${mod}']) before using this class`);
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
