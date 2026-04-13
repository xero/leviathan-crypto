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
import { describe, test, expect, beforeAll, afterEach, vi } from 'vitest';
import { init, Fortuna } from '../../../src/ts/index.js';
import { SerpentGenerator } from '../../../src/ts/serpent/index.js';
import { ChaCha20Generator } from '../../../src/ts/chacha20/index.js';
import { SHA256Hash } from '../../../src/ts/sha2/index.js';
import { SHA3_256Hash } from '../../../src/ts/sha3/index.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { chacha20Wasm } from '../../../src/ts/chacha20/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import * as fortunaKat from '../../vectors/fortuna_kat.js';
import { hexToBytes } from '../../../src/ts/index.js';

beforeAll(async () => {
	await init({ serpent: serpentWasm, chacha20: chacha20Wasm, sha2: sha2Wasm, sha3: sha3Wasm });
});

describe('Fortuna — pluggable primitives validation', () => {
	test('hash.outputSize must match generator.keySize', async () => {
		const bigHash = { outputSize: 64, wasmModules: ['sha2'] as const, digest: (_: Uint8Array) => new Uint8Array(64) };
		await expect(
			Fortuna.create({ generator: SerpentGenerator, hash: bigHash }),
		).rejects.toThrow(/Fortuna requires hash\.outputSize \(64\) to match generator\.keySize \(32\)/);

		const smallGen = { keySize: 16, blockSize: 16, counterSize: 16, wasmModules: ['serpent'] as const, generate: (_k: Uint8Array, _c: Uint8Array, n: number) => new Uint8Array(n) };
		await expect(
			Fortuna.create({ generator: smallGen, hash: SHA256Hash }),
		).rejects.toThrow(/Fortuna requires hash\.outputSize \(32\) to match generator\.keySize \(16\)/);
	});

	test('Fortuna.create() requires both generator and hash', async () => {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await expect(Fortuna.create({ generator: SerpentGenerator } as any)).rejects.toThrow(/requires \{ generator, hash \}/);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await expect(Fortuna.create({ hash: SHA256Hash } as any)).rejects.toThrow(/requires \{ generator, hash \}/);
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await expect(Fortuna.create({} as any)).rejects.toThrow(/requires \{ generator, hash \}/);
	});
});

// ── Combination tests ────────────────────────────────────────────────────────

const combinations = [
	{ name: 'serpent+sha2',   generator: SerpentGenerator,  hash: SHA256Hash,   kat: fortunaKat.serpent_sha2   },
	{ name: 'serpent+sha3',   generator: SerpentGenerator,  hash: SHA3_256Hash, kat: fortunaKat.serpent_sha3   },
	{ name: 'chacha20+sha2',  generator: ChaCha20Generator, hash: SHA256Hash,   kat: fortunaKat.chacha20_sha2  },
	{ name: 'chacha20+sha3',  generator: ChaCha20Generator, hash: SHA3_256Hash, kat: fortunaKat.chacha20_sha3  },
] as const;

for (const combo of combinations) {
	describe(`Fortuna — ${combo.name}`, () => {
		let fortuna: Fortuna;

		afterEach(() => {
			try {
				if (fortuna) fortuna.stop();
			} catch { /* already disposed */ }
		});

		test(`${combo.name}: produces correct KAT output`, async () => {
			const entropy = hexToBytes(combo.kat.entropySeed);
			fortuna = await Fortuna._createDeterministicForTesting({ generator: combo.generator, hash: combo.hash, entropy });
			expect(Array.from(fortuna._getGenKey())).toEqual(Array.from(hexToBytes(combo.kat.genKeyAfterCreate)));
			const out = fortuna.get(32);
			expect(Array.from(out)).toEqual(Array.from(hexToBytes(combo.kat.firstGet32)));
		});

		test(`${combo.name}: get(N) returns correct length`, async () => {
			fortuna = await Fortuna.create({ generator: combo.generator, hash: combo.hash, msPerReseed: 0 });
			expect(fortuna.get(1)).toHaveLength(1);
			expect(fortuna.get(31)).toHaveLength(31);
			expect(fortuna.get(32)).toHaveLength(32);
			expect(fortuna.get(64)).toHaveLength(64);
			expect(fortuna.get(128)).toHaveLength(128);
		});

		test(`${combo.name}: stop() wipes state`, async () => {
			fortuna = await Fortuna.create({ generator: combo.generator, hash: combo.hash, msPerReseed: 0 });
			fortuna.get(16);
			const keyView = fortuna._getGenKey();
			fortuna.stop();
			expect(keyView.every(b => b === 0)).toBe(true);
			expect(() => fortuna.get(32)).toThrow('disposed');
			expect(() => fortuna.addEntropy(new Uint8Array(8))).toThrow('disposed');
		});
	});
}

// ── Tree-shaking: chacha20-only init ─────────────────────────────────────────

describe('Fortuna — chacha20-only init (tree-shaking canary)', () => {
	let fortuna: Fortuna;

	beforeAll(async () => {
		// Reset and re-init with only the modules ChaCha20+SHA256 needs.
		_resetForTesting();
		await init({ chacha20: chacha20Wasm, sha2: sha2Wasm });
	});

	afterEach(() => {
		try {
			if (fortuna) fortuna.stop();
		} catch { /* already disposed */ }
	});

	test('chacha20+sha2 Fortuna works without serpent module loaded', async () => {
		fortuna = await Fortuna.create({ generator: ChaCha20Generator, hash: SHA256Hash, msPerReseed: 0 });
		const out = fortuna.get(32);
		expect(out).toBeInstanceOf(Uint8Array);
		expect(out.length).toBe(32);
	});
});

// ── F-2 regression: loud failure on no entropy ───────────────────────────────

describe('Fortuna — F-2 zero-entropy regression', () => {
	beforeAll(async () => {
		_resetForTesting();
		await init({ serpent: serpentWasm, sha2: sha2Wasm });
	});

	test('F-2: throws when no OS entropy reaches pool 0', async () => {
		// Stubbing the OS-entropy collector starves pool 0 (initialize() invokes
		// it 128 times). The other collectors credit a handful of bits each, far
		// below the 64-bit RESEED_LIMIT, so the post-init invariant fires.
		const spy = vi.spyOn(
			Fortuna.prototype as unknown as { collectorCryptoRandom: () => void },
			'collectorCryptoRandom',
		).mockImplementation(() => { /* starve pool 0 of OS entropy */ });
		try {
			await expect(
				Fortuna.create({ generator: SerpentGenerator, hash: SHA256Hash }),
			).rejects.toThrow(/could not gather sufficient entropy/);
		} finally {
			spy.mockRestore();
		}
	});
});
