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
import { base64ToBytes as _b64 } from './utils.js';

// Each WASM module gets its own fresh Memory — never shared between instances.
function makeImports() {
	return { env: { memory: new WebAssembly.Memory({ initial: 3, maximum: 3 }) } };
}

// TS 5.9 generified Uint8Array<TArrayBuffer> with default ArrayBufferLike, which
// no longer satisfies BufferSource = ArrayBufferView<ArrayBuffer> | ArrayBuffer.
// Convert Uint8Array to a proper ArrayBuffer before calling WebAssembly APIs.
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength)
		return bytes.buffer as ArrayBuffer;
	const buf = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(buf).set(bytes);
	return buf;
}

/**
 * Decode a gzip+base64 embedded WASM string to raw bytes.
 * Guards against missing DecompressionStream (Node <18, non-browser runtimes).
 * Exported for pool worker launchers that decode blobs before spawning threads.
 */
export async function decodeWasm(b64: string): Promise<Uint8Array> {
	if (typeof DecompressionStream === 'undefined')
		throw new Error(
			'leviathan-crypto: DecompressionStream not available — '
			+ 'use a URL, ArrayBuffer, or WebAssembly.Module source in this runtime',
		);
	const compressed = _b64(b64);
	if (!compressed) throw new Error('leviathan-crypto: corrupt embedded WASM — base64 decode failed');
	const ds = new DecompressionStream('gzip');
	const writer = ds.writable.getWriter();
	const reader = ds.readable.getReader();
	const writePromise = writer.write(compressed as unknown as BufferSource).then(() => writer.close());
	const chunks: Uint8Array[] = [];
	let done: boolean, value: Uint8Array | undefined;
	while ({ done, value } = await reader.read(), !done)
		if (value) chunks.push(value);
	await writePromise;
	const len = chunks.reduce((s, c) => s + c.length, 0);
	const out = new Uint8Array(len);
	let off = 0;
	for (const c of chunks) {
		out.set(c, off); off += c.length;
	}
	return out;
}

/**
 * Compile a WASM source to a Module without instantiating.
 * Used by pool infrastructure to send compiled modules to workers.
 */
export async function compileWasm(source: WasmSource): Promise<WebAssembly.Module> {
	if (typeof source === 'string') {
		if (source.length === 0) throw new TypeError('leviathan-crypto: invalid WasmSource — empty string');
		return WebAssembly.compile(toArrayBuffer(await decodeWasm(source)));
	}
	if (source instanceof URL)
		return WebAssembly.compileStreaming(fetch(source.href));
	if (source instanceof ArrayBuffer)
		return WebAssembly.compile(source);
	if (source instanceof Uint8Array)
		return WebAssembly.compile(toArrayBuffer(source));
	if (source instanceof WebAssembly.Module)
		return source;
	if (typeof Response !== 'undefined' && source instanceof Response)
		return WebAssembly.compileStreaming(source);
	if (source != null && typeof (source as unknown as Record<string, unknown>).then === 'function')
		return WebAssembly.compileStreaming(source as Promise<Response>);
	throw new TypeError(
		`leviathan-crypto: invalid WasmSource — got ${source === null ? 'null' : typeof source}`,
	);
}

/**
 * Load a WASM module from any accepted source type.
 * The loading strategy is inferred from the argument type — no mode string.
 *
 * Throws `TypeError` for null, numeric, or unrecognised inputs.
 */
export async function loadWasm(source: WasmSource): Promise<WebAssembly.Instance> {
	if (typeof source === 'string') {
		if (source.length === 0) throw new TypeError('leviathan-crypto: invalid WasmSource — empty string');
		return (await WebAssembly.instantiate(toArrayBuffer(await decodeWasm(source)), makeImports())).instance;
	}
	if (source instanceof URL)
		return (await WebAssembly.instantiateStreaming(fetch(source.href), makeImports())).instance;
	if (source instanceof ArrayBuffer)
		return (await WebAssembly.instantiate(source, makeImports())).instance;
	if (source instanceof Uint8Array)
		return (await WebAssembly.instantiate(toArrayBuffer(source), makeImports())).instance;
	if (source instanceof WebAssembly.Module)
		return WebAssembly.instantiate(source, makeImports());
	if (typeof Response !== 'undefined' && source instanceof Response)
		return (await WebAssembly.instantiateStreaming(source, makeImports())).instance;
	if (source != null && typeof (source as unknown as Record<string, unknown>).then === 'function')
		return (await WebAssembly.instantiateStreaming(source as Promise<Response>, makeImports())).instance;
	throw new TypeError(
		`leviathan-crypto: invalid WasmSource — got ${source === null ? 'null' : typeof source}`,
	);
}
