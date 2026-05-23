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

export type Module = 'serpent' | 'chacha20' | 'sha2' | 'sha3' | 'keccak' | 'mlkem' | 'aes' | 'mldsa' | 'slhdsa' | 'blake3' | 'curve25519' | 'p256'

// 'keccak' is an alias for 'sha3', same WASM binary, same instance slot
const ALIASES: Partial<Record<Module, Module>> = { keccak: 'sha3' };

function resolve(mod: Module): Module {
	return ALIASES[mod] ?? mod;
}

// Per-canonical-module instance cache.
const instances = new Map<Module, WebAssembly.Instance>();
// Coalesces concurrent initModule calls.
const pending = new Map<Module, Promise<WebAssembly.Instance>>();
// Per-module exclusivity token held by a stateful wrapper.
const owners = new Map<Module, symbol>();

export async function initModule(mod: Module, source: WasmSource): Promise<void> {
	const resolved = resolve(mod);
	if (instances.has(resolved)) return;
	const inflight = pending.get(resolved);
	if (inflight) {
		await inflight; return;
	}
	if ((resolved === 'serpent' || resolved === 'chacha20' || resolved === 'mlkem' || resolved === 'aes' || resolved === 'mldsa' || resolved === 'blake3') && !hasSIMD())
		throw new Error(
			'leviathan-crypto: serpent, chacha20, mlkem, aes, mldsa, and blake3 require WebAssembly SIMD, '
			+ 'this runtime does not support it',
		);
	const p = loadWasm(source);
	pending.set(resolved, p);
	try {
		instances.set(resolved, await p);
	} finally {
		pending.delete(resolved);
	}
}

export function getInstance(mod: Module): WebAssembly.Instance {
	const r = resolve(mod);
	const inst = instances.get(r);
	if (!inst) {
		throw new Error(`leviathan-crypto: call init({ ${mod}: ... }) before using this class`);
	}
	if (owners.has(r)) {
		throw new Error(
			`leviathan-crypto: another stateful instance is using the '${r}' WASM module, `
			+ 'call dispose() on it before constructing a new one',
		);
	}
	return inst;
}

export function isInitialized(mod: Module): boolean {
	return instances.has(resolve(mod));
}

/**
 * Acquire exclusive access to `mod`. Throws if another stateful instance
 * currently holds it. Returned token must be passed to `_releaseModule`.
 * @internal
 */
export function _acquireModule(mod: Module): symbol {
	const r = resolve(mod);
	if (owners.has(r))
		throw new Error(
			`leviathan-crypto: another stateful instance is using the '${r}' WASM module, `
			+ 'call dispose() on it before constructing a new one',
		);
	const tok = Symbol(r);
	owners.set(r, tok);
	return tok;
}

/**
 * Release exclusive access. No-op if the token doesn't match the current
 * owner (makes dispose idempotent).
 * @internal
 */
export function _releaseModule(mod: Module, tok: symbol): void {
	const r = resolve(mod);
	if (owners.get(r) === tok) owners.delete(r);
}

/**
 * True if a stateful instance currently holds the module.
 * @internal
 */
export function _isModuleBusy(mod: Module): boolean {
	return owners.has(resolve(mod));
}

/** @internal */
export function _assertNotOwned(mod: Module): void {
	const r = resolve(mod);
	if (owners.has(r))
		throw new Error(
			`leviathan-crypto: another stateful instance is using the '${r}' WASM module, `
			+ 'call dispose() on it before constructing a new one',
		);
}

/**
 * Reset all cached instances, for testing only. Clears `instances`, `pending`,
 * and `owners` so tests can re-exercise module lifecycle (init, exclusivity,
 * race) from a known-empty state.
 * @internal
 */
export function _resetForTesting(): void {
	instances.clear();
	pending.clear();
	owners.clear();
}
