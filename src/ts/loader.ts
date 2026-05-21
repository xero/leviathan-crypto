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
 * @internal
 */
export async function decodeWasm(b64: string): Promise<Uint8Array> {
	if (typeof DecompressionStream === 'undefined')
		throw new Error(
			'leviathan-crypto: DecompressionStream not available, '
			+ 'use a URL, ArrayBuffer, or WebAssembly.Module source in this runtime',
		);
	// _b64 throws RangeError on invalid base64, no nullish check required.
	const compressed = _b64(b64);
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

// Cap thenable-source nesting at 3 to prevent runaway recursion.
const MAX_THENABLE_DEPTH = 3;

/**
 * Compile a WASM source to a Module without instantiating.
 * Used by pool infrastructure to send compiled modules to workers.
 *
 * Thenable sources (Promise<Response>, Promise<ArrayBuffer>, etc.) are
 * resolved and then re-dispatched by the runtime type of the resolved value.
 * Depth is capped at `MAX_THENABLE_DEPTH` to prevent runaway recursion.
 * @internal
 */
export async function compileWasm(source: WasmSource, depth = 0): Promise<WebAssembly.Module> {
	if (depth > MAX_THENABLE_DEPTH)
		throw new TypeError(`leviathan-crypto: thenable nesting too deep (max ${MAX_THENABLE_DEPTH})`);
	if (typeof source === 'string') {
		if (source.length === 0) throw new TypeError('leviathan-crypto: invalid WasmSource, empty string');
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
	if (source != null && typeof (source as { then?: unknown }).then === 'function') {
		const resolved = await (source as PromiseLike<unknown>);
		return compileWasm(resolved as WasmSource, depth + 1);
	}
	throw new TypeError(
		`leviathan-crypto: invalid WasmSource, got ${source === null ? 'null' : typeof source}`,
	);
}

/**
 * Load a WASM module from any accepted source type.
 * The loading strategy is inferred from the argument type, no mode string.
 *
 * Throws `TypeError` for null, numeric, or unrecognised inputs, or if a
 * thenable source nests deeper than `MAX_THENABLE_DEPTH`.
 * @internal
 */
export async function loadWasm(source: WasmSource): Promise<WebAssembly.Instance> {
	// All modules export their own memory; no host imports today.
	const mod = await compileWasm(source);
	return WebAssembly.instantiate(mod);
}
