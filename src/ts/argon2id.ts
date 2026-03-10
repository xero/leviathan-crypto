// src/ts/argon2id.ts
//
// Argon2id password hashing and key derivation — RFC 9106.
// Wraps the argon2id npm package's WASM binary with its own init gate
// and singleton cache. Does not use initModule/getInstance.

import setupWasm from 'argon2id/lib/setup.js';
import type { computeHash } from 'argon2id/lib/setup.js';
import { constantTimeEqual, wipe } from './utils.js';

// ── Types ────────────────────────────────────────────────────────────────────

/**
 * Argon2id tuning parameters.
 * Use the named presets rather than constructing raw objects.
 */
export interface Argon2idParams {
	memoryCost: number
	timeCost: number
	parallelism: number
	saltLength: number
	hashLength: number
}

/**
 * Result returned by Argon2id.hash().
 * Store all three fields — all are required to verify or re-derive later.
 */
export interface Argon2idResult {
	hash: Uint8Array
	salt: Uint8Array
	params: Argon2idParams
}

/**
 * Options for Argon2id.init() in manual mode.
 * Provide pre-loaded binary data for both SIMD and non-SIMD builds.
 */
export interface ArgonOpts {
	simdBinary?: Uint8Array | ArrayBuffer
	noSimdBinary?: Uint8Array | ArrayBuffer
}

// ── Presets ───────────────────────────────────────────────────────────────────

/** OWASP Password Storage Cheat Sheet Option 2 — 19 MiB, 2 passes, 1 thread */
export const ARGON2ID_INTERACTIVE: Argon2idParams = {
	memoryCost: 19456,
	timeCost: 2,
	parallelism: 1,
	saltLength: 16,
	hashLength: 32,
};

/** RFC 9106 §4 recommended — 64 MiB, 3 passes, 4 threads */
export const ARGON2ID_SENSITIVE: Argon2idParams = {
	memoryCost: 65536,
	timeCost: 3,
	parallelism: 4,
	saltLength: 16,
	hashLength: 32,
};

/** Key derivation — INTERACTIVE params, always 32-byte output */
export const ARGON2ID_DERIVE: Argon2idParams = {
	memoryCost: 19456,
	timeCost: 2,
	parallelism: 1,
	saltLength: 16,
	hashLength: 32,
};

// ── Singleton cache ──────────────────────────────────────────────────────────

let _hasher: computeHash | undefined;

// ── Validation ───────────────────────────────────────────────────────────────

function validateParams(params: Argon2idParams): void {
	if (params.memoryCost < 8)
		throw new RangeError('leviathan-crypto: argon2id memoryCost must be >= 8 KiB');
	if (params.timeCost < 1)
		throw new RangeError('leviathan-crypto: argon2id timeCost must be >= 1');
	if (params.parallelism < 1)
		throw new RangeError('leviathan-crypto: argon2id parallelism must be >= 1');
	if (params.hashLength < 4)
		throw new RangeError('leviathan-crypto: argon2id hashLength must be >= 4');
	if (params.saltLength < 8)
		throw new RangeError('leviathan-crypto: argon2id saltLength must be >= 8');
}

// ── Embedded thunks ──────────────────────────────────────────────────────────

const _simdThunk = () =>
	import('./embedded/argon2id_simd.js').then(m => m.WASM_BASE64);
const _noSimdThunk = () =>
	import('./embedded/argon2id_nosimd.js').then(m => m.WASM_BASE64);

function base64ToUint8Array(b64: string): Uint8Array {
	const raw = atob(b64);
	const out = new Uint8Array(raw.length);
	for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
	return out;
}

function makeInstantiator(thunk: () => Promise<string>) {
	return async (importObject: WebAssembly.Imports) => {
		const b64 = await thunk();
		const bytes = base64ToUint8Array(b64);
		return WebAssembly.instantiate(bytes as BufferSource, importObject);
	};
}

function makeManualInstantiator(binary: Uint8Array | ArrayBuffer) {
	return async (importObject: WebAssembly.Imports) => {
		const bytes = binary instanceof ArrayBuffer ? new Uint8Array(binary) : binary;
		return WebAssembly.instantiate(bytes as BufferSource, importObject);
	};
}

// ── Init ─────────────────────────────────────────────────────────────────────

export async function init(
	mode: 'embedded' | 'manual' = 'embedded',
	opts?: ArgonOpts,
): Promise<void> {
	if (_hasher) return;

	if (mode === 'embedded') {
		_hasher = await setupWasm(
			makeInstantiator(_simdThunk),
			makeInstantiator(_noSimdThunk),
		);
	} else if (mode === 'manual') {
		if (!opts?.simdBinary || !opts?.noSimdBinary)
			throw new Error('leviathan-crypto: argon2id manual mode requires opts.simdBinary and opts.noSimdBinary');
		_hasher = await setupWasm(
			makeManualInstantiator(opts.simdBinary),
			makeManualInstantiator(opts.noSimdBinary),
		);
	} else {
		throw new Error('leviathan-crypto: argon2id does not support streaming mode');
	}
}

export function isArgon2idInitialized(): boolean {
	return _hasher !== undefined;
}

/** @internal — exposed for testing only */
export function _resetArgon2idForTesting(): void {
	_hasher = undefined;
}

/** @internal — exposed for gate test (RFC 9106 vector requires secret+AD) */
export function _getHasher(): computeHash | undefined {
	return _hasher;
}

// ── Argon2id class ───────────────────────────────────────────────────────────

export class Argon2id {
	// eslint-disable-next-line @typescript-eslint/no-empty-function
	private constructor() {}

	static async create(): Promise<Argon2id> {
		if (!_hasher)
			throw new Error(
				'leviathan-crypto: call init([\'argon2id\']) before using Argon2id',
			);
		return new Argon2id();
	}

	async hash(
		password: string | Uint8Array,
		salt?: Uint8Array,
		params: Argon2idParams = ARGON2ID_INTERACTIVE,
	): Promise<Argon2idResult> {
		if (!_hasher)
			throw new Error('leviathan-crypto: call init([\'argon2id\']) before using Argon2id');
		validateParams(params);

		const pw = typeof password === 'string'
			? new TextEncoder().encode(password)
			: password;

		const s = salt ?? crypto.getRandomValues(new Uint8Array(params.saltLength));

		const result = _hasher({
			password: pw,
			salt: s,
			passes: params.timeCost,
			memorySize: params.memoryCost,
			parallelism: params.parallelism,
			tagLength: params.hashLength,
		});

		return { hash: new Uint8Array(result), salt: s, params };
	}

	async verify(
		password: string | Uint8Array,
		hash: Uint8Array,
		salt: Uint8Array,
		params: Argon2idParams = ARGON2ID_INTERACTIVE,
	): Promise<boolean> {
		const result = await this.hash(password, salt, params);
		const equal = constantTimeEqual(result.hash, hash);
		wipe(result.hash);
		return equal;
	}

	async deriveKey(
		passphrase: string | Uint8Array,
		salt?: Uint8Array,
		keyLength: 16 | 24 | 32 = 32,
	): Promise<{ key: Uint8Array; salt: Uint8Array; params: Argon2idParams }> {
		const derivedParams: Argon2idParams = {
			...ARGON2ID_DERIVE,
			hashLength: keyLength,
		};
		const result = await this.hash(passphrase, salt, derivedParams);
		return { key: result.hash, salt: result.salt, params: derivedParams };
	}
}
