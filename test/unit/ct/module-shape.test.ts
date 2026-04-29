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
 * ct.wasm module shape invariants.
 *
 * Locks in the structural shape of the ct.wasm module, which follows the
 * same export-memory convention as every other module in the library:
 *   - zero imports
 *   - exports its own single-page (64 KB) linear memory
 *   - exports `compare` as a function
 *
 * A regression that accidentally adds `--importMemory`, removes the memory
 * export, or renames `compare` fails the relevant assertion immediately.
 */
import { describe, it, expect } from 'vitest';
import { CT_WASM } from '../../../src/ts/ct-wasm.js';

describe('ct.wasm module shape invariants', () => {
	const buf = CT_WASM.buffer.slice(CT_WASM.byteOffset, CT_WASM.byteOffset + CT_WASM.byteLength);
	const mod = new WebAssembly.Module(buf as ArrayBuffer);

	it('imports nothing', () => {
		// ct is self-contained like every other module in the library; any
		// future `--importMemory` regression would trip this assertion.
		expect(WebAssembly.Module.imports(mod)).toEqual([]);
	});

	it('exports a "memory" of kind "memory" sized at 1 page', () => {
		const exports = WebAssembly.Module.exports(mod);
		const memoryExport = exports.find(e => e.name === 'memory');
		expect(memoryExport).toBeDefined();
		expect(memoryExport!.kind).toBe('memory');

		// Inspect the actual Memory by instantiating — kind/name alone doesn't
		// carry the page-count invariant, so we verify it via a fresh instance.
		const inst = new WebAssembly.Instance(mod);
		const mem = (inst.exports as { memory: WebAssembly.Memory }).memory;
		expect(mem).toBeInstanceOf(WebAssembly.Memory);
		expect(mem.buffer.byteLength).toBe(64 * 1024); // 1 page = 64 KB
	});

	it('exports a "compare" function', () => {
		const exports = WebAssembly.Module.exports(mod);
		const compareExport = exports.find(e => e.name === 'compare');
		expect(compareExport).toBeDefined();
		expect(compareExport!.kind).toBe('function');
	});
});
