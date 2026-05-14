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
 * SLH-DSA validation hard-gates.
 *
 * Covers FIPS 205 §3.6.2 length checks (vk / sk / σ), §10.2.1 / §10.2.2
 * Algorithm 22 / 23 line 1 ctx length cap, FIPS 205 §3.4 / §9.2 opt_rand
 * length contract, and the FIPS 205 §10.2.2 category restriction on
 * SHA-256 / SHAKE128.
 *
 * Splits behavior across:
 *   - sign:    wrong-length sk → throw RangeError.
 *              oversize ctx    → throw SigningError('sig-ctx-too-long').
 *   - verify:  wrong-length pk or σ → return false (not throw).
 *              oversize ctx          → throw SigningError.
 *
 * GATE: SLH-DSA validation discipline, every length / structural check
 * required by FIPS 205 fires correctly.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import {
	SlhDsa128f, SlhDsa192f, SlhDsa256f, SlhDsaBase, slhdsaInit,
} from '../../../src/ts/slhdsa/index.js';
import { slhdsaWasm } from '../../../src/ts/slhdsa/embedded.js';
import { sha3Init }   from '../../../src/ts/sha3/index.js';
import { sha3Wasm }   from '../../../src/ts/sha3/embedded.js';
import { sha2Init }   from '../../../src/ts/sha2/index.js';
import { sha2Wasm }   from '../../../src/ts/sha2/embedded.js';
import { _resetForTesting } from '../../../src/ts/init.js';
import { SigningError }     from '../../../src/ts/errors.js';
import {
	SLHDSA128F, SLHDSA192F,
} from '../../../src/ts/slhdsa/params.js';
import type { PreHashAlgorithm } from '../../../src/ts/slhdsa/index.js';

beforeAll(async () => {
	_resetForTesting();
	await Promise.all([
		slhdsaInit(slhdsaWasm),
		sha3Init(sha3Wasm),
		sha2Init(sha2Wasm),
	]);
});

const KSEED_128 = new Uint8Array(3 * SLHDSA128F.n).fill(0xA1);

// ── Length attacks on sk / vk / σ ───────────────────────────────────────────

describe('sign, wrong-length sk throws RangeError', () => {
	it('sk too short', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(() => dsa.sign(new Uint8Array(SLHDSA128F.skBytes - 1), new Uint8Array(8)))
				.toThrow(/signing key must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('sk too long', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(() => dsa.sign(new Uint8Array(SLHDSA128F.skBytes + 1), new Uint8Array(8)))
				.toThrow(/signing key must be/);
		} finally {
			dsa.dispose();
		}
	});
});

describe('verify, wrong-length pk / σ returns false (FIPS 205 §3.6.2)', () => {
	it('pk too short → false (no throw)', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(dsa.verify(
				new Uint8Array(SLHDSA128F.pkBytes - 1),
				new Uint8Array(8),
				new Uint8Array(SLHDSA128F.sigBytes),
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('pk too long → false', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(dsa.verify(
				new Uint8Array(SLHDSA128F.pkBytes + 1),
				new Uint8Array(8),
				new Uint8Array(SLHDSA128F.sigBytes),
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('σ too short → false', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(dsa.verify(
				new Uint8Array(SLHDSA128F.pkBytes),
				new Uint8Array(8),
				new Uint8Array(SLHDSA128F.sigBytes - 1),
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});

	it('σ too long → false', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(dsa.verify(
				new Uint8Array(SLHDSA128F.pkBytes),
				new Uint8Array(8),
				new Uint8Array(SLHDSA128F.sigBytes + 1),
			)).toBe(false);
		} finally {
			dsa.dispose();
		}
	});
});

// ── ctx length cap (FIPS 205 §10.2.1 / §10.2.2 line 1) ─────────────────────

describe('ctx > 255 bytes throws SigningError(sig-ctx-too-long)', () => {
	it('sign throws when ctx is 256 bytes', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygenDerand(KSEED_128);
			expect(() => dsa.sign(signingKey, new Uint8Array(8), new Uint8Array(256)))
				.toThrow(SigningError);
			expect(() => dsa.sign(signingKey, new Uint8Array(8), new Uint8Array(256)))
				.toThrow(/ctx must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('sign carries sig-ctx-too-long discriminator', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygenDerand(KSEED_128);
			try {
				dsa.sign(signingKey, new Uint8Array(8), new Uint8Array(256));
				expect.fail('should have thrown');
			} catch (e) {
				expect(e).toBeInstanceOf(SigningError);
				expect((e as SigningError).discriminator).toBe('sig-ctx-too-long');
			}
		} finally {
			dsa.dispose();
		}
	});

	it('signDeterministic throws when ctx is 256 bytes', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygenDerand(KSEED_128);
			expect(() => dsa.signDeterministic(signingKey, new Uint8Array(8), new Uint8Array(256)))
				.toThrow(/ctx must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('signDerand throws when ctx is 256 bytes', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygenDerand(KSEED_128);
			expect(() => dsa.signDerand(
				signingKey,
				new Uint8Array(8),
				new Uint8Array(SLHDSA128F.n),
				new Uint8Array(256),
			)).toThrow(/ctx must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('verify throws when ctx is 256 bytes', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey } = dsa.keygenDerand(KSEED_128);
			expect(() => dsa.verify(
				verificationKey,
				new Uint8Array(8),
				new Uint8Array(SLHDSA128F.sigBytes),
				new Uint8Array(256),
			)).toThrow(/ctx must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('255-byte ctx is accepted (boundary)', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey, signingKey } = dsa.keygen();
			const msg = new Uint8Array([1, 2, 3]);
			const ctx = new Uint8Array(255).fill(0x42);
			const sig = dsa.signDeterministic(signingKey, msg, ctx);
			expect(dsa.verify(verificationKey, msg, sig, ctx)).toBe(true);
		} finally {
			dsa.dispose();
		}
	});
});

// ── Empty-ctx default round-trip ────────────────────────────────────────────

describe('empty ctx default, sign + verify with no ctx argument', () => {
	it('uses the empty Uint8Array default', () => {
		const dsa = new SlhDsa192f();
		try {
			const { verificationKey, signingKey } = dsa.keygen();
			const msg = new Uint8Array([9, 9, 9]);
			const sig = dsa.sign(signingKey, msg);
			expect(dsa.verify(verificationKey, msg, sig)).toBe(true);
		} finally {
			dsa.dispose();
		}
	});
});

// ── signDerand opt_rand validation ──────────────────────────────────────────

describe('signDerand, wrong-length optRand throws RangeError', () => {
	it('optRand too short', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygenDerand(KSEED_128);
			expect(() => dsa.signDerand(signingKey, new Uint8Array(8), new Uint8Array(SLHDSA128F.n - 1)))
				.toThrow(/opt_rand must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('optRand too long', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygenDerand(KSEED_128);
			expect(() => dsa.signDerand(signingKey, new Uint8Array(8), new Uint8Array(SLHDSA128F.n + 1)))
				.toThrow(/opt_rand must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('per-set sizes 16 / 24 / 32 are required', () => {
		const cases = [
			{ make: (): SlhDsaBase => new SlhDsa128f(), n: 16 },
			{ make: (): SlhDsaBase => new SlhDsa192f(), n: 24 },
			{ make: (): SlhDsaBase => new SlhDsa256f(), n: 32 },
		];
		for (const { make, n } of cases) {
			const dsa = make();
			try {
				const { signingKey } = dsa.keygen();
				// Wrong length for this param set (16 byte rnd on 192f / 256f, etc.)
				expect(() => dsa.signDerand(signingKey, new Uint8Array(8), new Uint8Array(n - 1)))
					.toThrow(/opt_rand must be/);
				// Correct length succeeds (round-trip).
				const sig = dsa.signDerand(signingKey, new Uint8Array(8), new Uint8Array(n));
				expect(sig.length).toBeGreaterThan(0);
			} finally {
				dsa.dispose();
			}
		}
	});
});

// ── keygenDerand seed validation ────────────────────────────────────────────

describe('keygenDerand, wrong-length seed throws RangeError', () => {
	it('seed too short on 128f (expects 48 bytes)', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(() => dsa.keygenDerand(new Uint8Array(47)))
				.toThrow(/keygen seed must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('seed too short on 256f (expects 96 bytes)', () => {
		const dsa = new SlhDsa256f();
		try {
			expect(() => dsa.keygenDerand(new Uint8Array(95)))
				.toThrow(/keygen seed must be/);
		} finally {
			dsa.dispose();
		}
	});

	it('non-Uint8Array seed throws TypeError', () => {
		const dsa = new SlhDsa128f();
		try {
			expect(() => dsa.keygenDerand(null as unknown as Uint8Array))
				.toThrow(TypeError);
		} finally {
			dsa.dispose();
		}
	});
});

// ── FIPS 205 §10.2.2 category restriction ──────────────────────────────────

describe('Category restriction, SHA-256 / SHAKE128 rejected on non-128f', () => {
	it('192f: SHA2-256 throws RangeError with cite', () => {
		const dsa = new SlhDsa192f();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHash(signingKey, new Uint8Array(8), 'SHA2-256'))
				.toThrow(/FIPS 205 §10.2.2/);
		} finally {
			dsa.dispose();
		}
	});

	it('192f: SHAKE128 throws RangeError with cite', () => {
		const dsa = new SlhDsa192f();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHash(signingKey, new Uint8Array(8), 'SHAKE128'))
				.toThrow(/FIPS 205 §10.2.2/);
		} finally {
			dsa.dispose();
		}
	});

	it('256f: SHA2-256 throws RangeError', () => {
		const dsa = new SlhDsa256f();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHashDeterministic(signingKey, new Uint8Array(8), 'SHA2-256'))
				.toThrow(/security category 1/);
		} finally {
			dsa.dispose();
		}
	});

	it('256f: SHAKE128 throws RangeError', () => {
		const dsa = new SlhDsa256f();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHashDeterministic(signingKey, new Uint8Array(8), 'SHAKE128'))
				.toThrow(/security category 1/);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHashPrehashed enforces the same gate', () => {
		const dsa = new SlhDsa192f();
		try {
			const { verificationKey } = dsa.keygen();
			expect(() => dsa.verifyHashPrehashed(
				verificationKey,
				new Uint8Array(32),
				new Uint8Array(SLHDSA192F.sigBytes),
				'SHA2-256',
			)).toThrow(/security category 1/);
		} finally {
			dsa.dispose();
		}
	});

	it('128f accepts SHA-256 (positive control)', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey, signingKey } = dsa.keygen();
			const msg = new Uint8Array([1, 2, 3]);
			const sig = dsa.signHashDeterministic(signingKey, msg, 'SHA2-256');
			expect(dsa.verifyHash(verificationKey, msg, sig, 'SHA2-256')).toBe(true);
		} finally {
			dsa.dispose();
		}
	});

	it('128f accepts SHAKE128 (positive control)', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey, signingKey } = dsa.keygen();
			const msg = new Uint8Array([1, 2, 3]);
			const sig = dsa.signHashDeterministic(signingKey, msg, 'SHAKE128');
			expect(dsa.verifyHash(verificationKey, msg, sig, 'SHAKE128')).toBe(true);
		} finally {
			dsa.dispose();
		}
	});
});

// ── Unsupported prehash ─────────────────────────────────────────────────────

describe('unsupported PreHashAlgorithm throws RangeError', () => {
	it('signHash with BLAKE2b throws', () => {
		const dsa = new SlhDsa128f();
		try {
			const { signingKey } = dsa.keygen();
			expect(() => dsa.signHash(
				signingKey,
				new Uint8Array(8),
				'BLAKE2b' as unknown as PreHashAlgorithm,
			)).toThrow(/unsupported HashSLH-DSA pre-hash/);
		} finally {
			dsa.dispose();
		}
	});

	it('verifyHash with bogus alg throws', () => {
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey } = dsa.keygen();
			expect(() => dsa.verifyHash(
				verificationKey,
				new Uint8Array(8),
				new Uint8Array(SLHDSA128F.sigBytes),
				'SHA-2-256' as unknown as PreHashAlgorithm,
			)).toThrow(/unsupported HashSLH-DSA pre-hash/);
		} finally {
			dsa.dispose();
		}
	});
});

// ── Module prerequisite checks ──────────────────────────────────────────────

describe('Module prerequisite checks (sha2 / sha3 init required for prehash)', () => {
	it('SlhDsa128f throws when slhdsa is not initialized', () => {
		_resetForTesting();
		expect(() => new SlhDsa128f()).toThrow(/init.*slhdsa/);
		// Restore for subsequent tests.
	});
});

// Restore module init after the negative test above (the global beforeAll
// only fires once; per-test reset would force re-init for every test).
describe('restore init for trailing tests', () => {
	it('re-initializes slhdsa, sha3, sha2', async () => {
		await Promise.all([
			slhdsaInit(slhdsaWasm),
			sha3Init(sha3Wasm),
			sha2Init(sha2Wasm),
		]);
		const dsa = new SlhDsa128f();
		try {
			const { verificationKey, signingKey } = dsa.keygen();
			expect(signingKey.length).toBe(SLHDSA128F.skBytes);
			expect(verificationKey.length).toBe(SLHDSA128F.pkBytes);
		} finally {
			dsa.dispose();
		}
	});
});
