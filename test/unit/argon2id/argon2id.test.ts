import { describe, test, expect, beforeAll } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import {
	init as initArgon,
	isArgon2idInitialized,
	Argon2id,
	ARGON2ID_INTERACTIVE,
	ARGON2ID_SENSITIVE,
	ARGON2ID_DERIVE,
	_resetArgon2idForTesting,
	_getHasher,
} from '../../../src/ts/argon2id.js';
import type { Argon2idParams } from '../../../src/ts/argon2id.js';
import { argon2idVectors } from '../../vectors/argon2id.js';

// GATE — RFC 9106 §5.3 Argon2id test vector
// Gate passes when the underlying computeHash produces byte-identical output to the RFC vector.
// The RFC vector uses secret+AD fields not exposed by our public API, so the gate
// calls _getHasher() directly.
describe('Argon2id Gate', () => {
	beforeAll(async () => {
		_resetArgon2idForTesting();
		await initArgon('embedded');
	});

	test('RFC 9106 §5.3 — Argon2id KAT via computeHash', () => { // GATE
		const v = argon2idVectors[0];
		const hasher = _getHasher()!;
		expect(hasher).toBeDefined();

		const result = hasher({
			password: v.password,
			salt: v.salt,
			secret: v.secret,
			ad: v.data,
			passes: v.params.timeCost,
			memorySize: v.params.memoryCost,
			parallelism: v.params.parallelism,
			tagLength: v.params.hashLength,
		});

		expect(new Uint8Array(result)).toEqual(v.expected);
	});
});

// ── Full test suite (runs after gate passes) ─────────────────────────────────

describe('Argon2id', () => {
	beforeAll(async () => {
		_resetArgon2idForTesting();
		await initArgon('embedded');
	});

	// ── Init tests ───────────────────────────────────────────────────────

	describe('init', () => {
		test('Argon2id.create() throws before init', async () => {
			_resetArgon2idForTesting();
			await expect(Argon2id.create()).rejects.toThrow(
				'leviathan-crypto: call init([\'argon2id\']) before using Argon2id',
			);
			// Restore for remaining tests
			await initArgon('embedded');
		});

		test('init() is idempotent — calling twice does not throw', async () => {
			await initArgon('embedded');
			await initArgon('embedded');
			expect(isArgon2idInitialized()).toBe(true);
		});

		test('isArgon2idInitialized() returns false before init, true after', async () => {
			_resetArgon2idForTesting();
			expect(isArgon2idInitialized()).toBe(false);
			await initArgon('embedded');
			expect(isArgon2idInitialized()).toBe(true);
		});
	});

	// ── Vector tests ─────────────────────────────────────────────────────

	describe('vectors', () => {
		for (const v of argon2idVectors) {
			test(v.description, () => {
				const hasher = _getHasher()!;
				const result = hasher({
					password: v.password,
					salt: v.salt,
					secret: v.secret,
					ad: v.data,
					passes: v.params.timeCost,
					memorySize: v.params.memoryCost,
					parallelism: v.params.parallelism,
					tagLength: v.params.hashLength,
				});
				expect(new Uint8Array(result)).toEqual(v.expected);
			});
		}
	});

	// ── Preset tests ─────────────────────────────────────────────────────

	describe('presets', () => {
		test('ARGON2ID_INTERACTIVE produces a 32-byte output', async () => {
			const a = await Argon2id.create();
			const result = await a.hash('password1234', undefined, ARGON2ID_INTERACTIVE);
			expect(result.hash.length).toBe(32);
		});

		test('ARGON2ID_SENSITIVE produces a 32-byte output', async () => {
			const a = await Argon2id.create();
			const result = await a.hash('password1234', undefined, ARGON2ID_SENSITIVE);
			expect(result.hash.length).toBe(32);
		});

		test('ARGON2ID_DERIVE always produces a 32-byte output', async () => {
			const a = await Argon2id.create();
			const result = await a.hash('password1234', undefined, ARGON2ID_DERIVE);
			expect(result.hash.length).toBe(32);
		});
	});

	// ── hash() tests ─────────────────────────────────────────────────────

	describe('hash()', () => {
		test('auto-generates salt when not provided', async () => {
			const a = await Argon2id.create();
			const result = await a.hash('password1234');
			expect(result.salt).toBeDefined();
			expect(result.salt.length).toBe(ARGON2ID_INTERACTIVE.saltLength);
		});

		test('returned params matches the params passed in', async () => {
			const a = await Argon2id.create();
			const result = await a.hash('password1234', undefined, ARGON2ID_INTERACTIVE);
			expect(result.params).toEqual(ARGON2ID_INTERACTIVE);
		});

		test('same password + salt + params produces identical output', async () => {
			const a = await Argon2id.create();
			const salt = crypto.getRandomValues(new Uint8Array(16));
			const r1 = await a.hash('deterministic', salt, ARGON2ID_INTERACTIVE);
			const r2 = await a.hash('deterministic', salt, ARGON2ID_INTERACTIVE);
			expect(r1.hash).toEqual(r2.hash);
		});

		test('same password but different salts produces different output', async () => {
			const a = await Argon2id.create();
			const salt1 = new Uint8Array(16).fill(0xaa);
			const salt2 = new Uint8Array(16).fill(0xbb);
			const r1 = await a.hash('password1234', salt1, ARGON2ID_INTERACTIVE);
			const r2 = await a.hash('password1234', salt2, ARGON2ID_INTERACTIVE);
			expect(r1.hash).not.toEqual(r2.hash);
		});
	});

	// ── verify() tests ───────────────────────────────────────────────────

	describe('verify()', () => {
		let a: Argon2id;
		let hash: Uint8Array;
		let salt: Uint8Array;

		beforeAll(async () => {
			a = await Argon2id.create();
			const result = await a.hash('correct-password', undefined, ARGON2ID_INTERACTIVE);
			hash = result.hash;
			salt = result.salt;
		});

		test('returns true for matching password', async () => {
			const ok = await a.verify('correct-password', hash, salt, ARGON2ID_INTERACTIVE);
			expect(ok).toBe(true);
		});

		test('returns false for wrong password', async () => {
			const ok = await a.verify('wrong-password!!', hash, salt, ARGON2ID_INTERACTIVE);
			expect(ok).toBe(false);
		});

		test('returns false for wrong salt', async () => {
			const wrongSalt = new Uint8Array(16).fill(0xff);
			const ok = await a.verify('correct-password', hash, wrongSalt, ARGON2ID_INTERACTIVE);
			expect(ok).toBe(false);
		});

		test('returns false for tampered hash (flip one bit)', async () => {
			const tampered = new Uint8Array(hash);
			tampered[0] ^= 0x01;
			const ok = await a.verify('correct-password', tampered, salt, ARGON2ID_INTERACTIVE);
			expect(ok).toBe(false);
		});
	});

	// ── deriveKey() tests ────────────────────────────────────────────────

	describe('deriveKey()', () => {
		test('returns 32 bytes by default', async () => {
			const a = await Argon2id.create();
			const result = await a.deriveKey('my passphrase');
			expect(result.key.length).toBe(32);
		});

		test('returns 16 bytes when keyLength: 16', async () => {
			const a = await Argon2id.create();
			const result = await a.deriveKey('my passphrase', undefined, 16);
			expect(result.key.length).toBe(16);
		});

		test('returns 24 bytes when keyLength: 24', async () => {
			const a = await Argon2id.create();
			const result = await a.deriveKey('my passphrase', undefined, 24);
			expect(result.key.length).toBe(24);
		});

		test('returned params includes hashLength matching requested keyLength', async () => {
			const a = await Argon2id.create();
			const r16 = await a.deriveKey('passphrase', undefined, 16);
			const r24 = await a.deriveKey('passphrase', undefined, 24);
			const r32 = await a.deriveKey('passphrase', undefined, 32);
			expect(r16.params.hashLength).toBe(16);
			expect(r24.params.hashLength).toBe(24);
			expect(r32.params.hashLength).toBe(32);
		});

		test('same passphrase + same salt → same key', async () => {
			const a = await Argon2id.create();
			const salt = new Uint8Array(16).fill(0xcc);
			const r1 = await a.deriveKey('deterministic', salt, 32);
			const r2 = await a.deriveKey('deterministic', salt, 32);
			expect(r1.key).toEqual(r2.key);
		});
	});

	// ── Validation tests ─────────────────────────────────────────────────

	describe('validation', () => {
		test('memoryCost < 8 throws', async () => {
			const a = await Argon2id.create();
			const bad: Argon2idParams = { ...ARGON2ID_INTERACTIVE, memoryCost: 4 };
			await expect(a.hash('pw', undefined, bad)).rejects.toThrow('memoryCost must be >= 8');
		});

		test('timeCost < 1 throws', async () => {
			const a = await Argon2id.create();
			const bad: Argon2idParams = { ...ARGON2ID_INTERACTIVE, timeCost: 0 };
			await expect(a.hash('pw', undefined, bad)).rejects.toThrow('timeCost must be >= 1');
		});

		test('parallelism < 1 throws', async () => {
			const a = await Argon2id.create();
			const bad: Argon2idParams = { ...ARGON2ID_INTERACTIVE, parallelism: 0 };
			await expect(a.hash('pw', undefined, bad)).rejects.toThrow('parallelism must be >= 1');
		});

		test('hashLength < 4 throws', async () => {
			const a = await Argon2id.create();
			const bad: Argon2idParams = { ...ARGON2ID_INTERACTIVE, hashLength: 2 };
			await expect(a.hash('pw', undefined, bad)).rejects.toThrow('hashLength must be >= 4');
		});

		test('saltLength < 8 throws', async () => {
			const a = await Argon2id.create();
			const bad: Argon2idParams = { ...ARGON2ID_INTERACTIVE, saltLength: 4 };
			await expect(a.hash('pw', undefined, bad)).rejects.toThrow('saltLength must be >= 8');
		});
	});

	// ── Manual mode test ─────────────────────────────────────────────────

	describe('manual mode', () => {
		test('init with manually loaded binaries produces correct output', async () => {
			_resetArgon2idForTesting();

			const simdBinary = readFileSync(
				resolve(__dirname, '../../../node_modules/argon2id/dist/simd.wasm'),
			);
			const noSimdBinary = readFileSync(
				resolve(__dirname, '../../../node_modules/argon2id/dist/no-simd.wasm'),
			);

			await initArgon('manual', {
				simdBinary: new Uint8Array(simdBinary),
				noSimdBinary: new Uint8Array(noSimdBinary),
			});

			const v = argon2idVectors[0];
			const hasher = _getHasher()!;
			const result = hasher({
				password: v.password,
				salt: v.salt,
				secret: v.secret,
				ad: v.data,
				passes: v.params.timeCost,
				memorySize: v.params.memoryCost,
				parallelism: v.params.parallelism,
				tagLength: v.params.hashLength,
			});
			expect(new Uint8Array(result)).toEqual(v.expected);

			// Restore embedded mode for any subsequent tests
			_resetArgon2idForTesting();
			await initArgon('embedded');
		});
	});
});
