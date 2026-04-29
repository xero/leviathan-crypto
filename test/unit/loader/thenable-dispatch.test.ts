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
 * Loader thenable dispatch with depth guard.
 *
 * `loadWasm` / `compileWasm` resolve any `PromiseLike<WasmSource>` first,
 * then re-dispatch by the runtime type of the resolved value. This lets
 * `Promise<Response>`, `Promise<ArrayBuffer>`, `Promise<Uint8Array>`, and
 * `Promise<string>` (gzip blob) all work alongside the direct types.
 * Recursion is depth-capped at 3 to catch caller-bug infinite nesting.
 *
 * Cases:
 *   1. Promise<Response> works.
 *   2. Promise<ArrayBuffer> works.
 *   3. Promise<Uint8Array> works.
 *   4. Nested Promise<Promise<...>> up to depth 3 works.
 *   5. Depth-4+ nesting throws 'thenable nesting too deep'.
 *   6. Non-thenable non-type throws 'invalid WasmSource'.
 */

import { describe, test, expect, beforeAll, beforeEach } from 'vitest';
import { loadWasm, compileWasm } from '../../../src/ts/loader.js';
import type { WasmSource } from '../../../src/ts/wasm-source.js';
import { _resetForTesting } from '../../../src/ts/init.js';

let wasmBytes: Uint8Array;

beforeAll(async () => {
	const { readFileSync } = await import('fs');
	const { resolve, dirname } = await import('path');
	const { fileURLToPath } = await import('url');
	const dir = dirname(fileURLToPath(import.meta.url));
	const nodeBuf = readFileSync(resolve(dir, '../../../build/sha3.wasm'));
	wasmBytes = new Uint8Array(nodeBuf.buffer.slice(nodeBuf.byteOffset, nodeBuf.byteOffset + nodeBuf.byteLength));
});

beforeEach(() => {
	_resetForTesting();
});

// Reusable: build a fresh Response each time so each test has its own body stream.
function makeResponse(): Response {
	return new Response(wasmBytes.slice(), {
		headers: { 'Content-Type': 'application/wasm' },
	});
}

describe('loader thenable dispatch', () => {
	test('1. Promise<Response> works', async () => {
		const src: WasmSource = Promise.resolve(makeResponse());
		const inst = await loadWasm(src);
		expect(inst).toBeInstanceOf(WebAssembly.Instance);
	});

	test('2. Promise<ArrayBuffer> works (previously failed opaquely)', async () => {
		const ab = wasmBytes.buffer.slice(wasmBytes.byteOffset, wasmBytes.byteOffset + wasmBytes.byteLength) as ArrayBuffer;
		const src = Promise.resolve(ab) as unknown as WasmSource;
		const inst = await loadWasm(src);
		expect(inst).toBeInstanceOf(WebAssembly.Instance);
	});

	test('3. Promise<Uint8Array> works (previously failed opaquely)', async () => {
		const src = Promise.resolve(wasmBytes.slice()) as unknown as WasmSource;
		const inst = await loadWasm(src);
		expect(inst).toBeInstanceOf(WebAssembly.Instance);
	});

	test('4. nested Promise<Promise<...>>: native Promise flattening still loads correctly', async () => {
		// Per Promises/A+ §2.3.3.3 and ECMAScript's PromiseResolveThenableJob,
		// `Promise.resolve(Promise.resolve(x))` flattens to a single
		// `Promise.resolve(x)`. Wrapping a Response in multiple layers of
		// `Promise.resolve` therefore does not actually build a `Promise<Promise<…>>`;
		// each layer collapses during await. The loader's depth counter is
		// provably correct against the *statically* counted number of thenable
		// layers (see test 5 below), but via the public `loadWasm` API any
		// user-level chain always resolves in a single await step.
		const outer = Promise.resolve(Promise.resolve(Promise.resolve(makeResponse()))) as unknown as WasmSource;
		await expect(loadWasm(outer)).resolves.toBeInstanceOf(WebAssembly.Instance);
	});

	test('5. depth-4+ nesting throws "thenable nesting too deep"', async () => {
		// Exercises the depth guard directly by calling `compileWasm` with a
		// seeded `_depth` of 4. In production code the counter is bumped on
		// each recursive entry; this test pins the guard's trip point so that
		// a future change that relaxes the recursion (e.g. turning it into a
		// loop or removing the cap) fails loudly here.
		const bogus = {} as unknown as WasmSource;
		await expect(compileWasm(bogus, 4)).rejects.toThrow(/thenable nesting too deep/);
		// Any input at depth > 3 trips the guard — thenables included.
		const thenable = Promise.resolve(makeResponse()) as unknown as WasmSource;
		await expect(compileWasm(thenable, 4)).rejects.toThrow(/thenable nesting too deep \(max 3\)/);
	});

	test('6. non-thenable non-type throws "invalid WasmSource"', async () => {
		// {} has no .then, isn't any known WasmSource type → the invalid-source throw.
		const bogus = {} as unknown as WasmSource;
		await expect(loadWasm(bogus)).rejects.toThrow(/invalid WasmSource/);
	});
});
