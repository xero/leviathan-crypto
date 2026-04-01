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
import type { Module } from './init.js';
import { base64ToBytes as _b64 } from './utils.js';

/**
 * Decode a gzip+base64 embedded WASM string to raw bytes.
 * Throws if the base64 is malformed (should never happen for build artifacts).
 * Used by loadEmbedded() and the pool worker launchers.
 */
export async function decodeWasm(b64: string): Promise<Uint8Array> {
	if (typeof DecompressionStream === 'undefined')
		throw new Error(
			'leviathan-crypto: DecompressionStream not available — '
			+ 'use streaming or manual init mode in this runtime',
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

async function instantiateFromBytes(
	bytes: Uint8Array,
): Promise<WebAssembly.Instance> {
	const result = await WebAssembly.instantiate(
		bytes.buffer as ArrayBuffer,
		{ env: { memory: new WebAssembly.Memory({ initial: 3, maximum: 3 }) } },
	);
	return result.instance;
}

export async function loadEmbedded(
	thunk: () => Promise<string>,
): Promise<WebAssembly.Instance> {
	const b64 = await thunk();
	const bytes = await decodeWasm(b64);
	return instantiateFromBytes(bytes);
}

export async function loadStreaming(
	_mod: Module,
	baseUrl: URL | string,
	filename: string,
): Promise<WebAssembly.Instance> {
	const url = new URL(filename, baseUrl).href;
	const result = await WebAssembly.instantiateStreaming(fetch(url), {
		env: { memory: new WebAssembly.Memory({ initial: 3, maximum: 3 }) },
	});
	return result.instance;
}

export async function loadManual(
	binary: Uint8Array | ArrayBuffer,
): Promise<WebAssembly.Instance> {
	const bytes = binary instanceof ArrayBuffer ? new Uint8Array(binary) : binary;
	return instantiateFromBytes(bytes);
}
