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
 * PKCS7 padding-oracle normalisation tests.
 *
 * `SerpentCbc.decrypt()` must throw a single generic `RangeError` with message
 * `'invalid ciphertext'` for every failure mode — empty input, non-multiple-of-16
 * length, out-of-range pad byte, and pad-byte mismatch — with timing that does
 * not distinguish the failure mode. Error messages must not leak any numeric
 * input-dependent data (byte values, lengths). Happy-path decrypt remains
 * byte-identical.
 *
 * `SerpentCipher` must continue to verify HMAC before invoking `pkcs7Strip`,
 * so a ciphertext whose HMAC fails raises `AuthenticationError` regardless of
 * its inner PKCS7 validity — the authenticated path never exercises the
 * padding check on attacker-controlled bytes.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { init, SerpentCbc, Seal, SerpentCipher, AuthenticationError, randomBytes } from '../../../src/ts/index.js';
import { serpentWasm } from '../../../src/ts/serpent/embedded.js';
import { sha2Wasm } from '../../../src/ts/sha2/embedded.js';
import { pkcs7Pad, pkcs7Strip } from '../../../src/ts/serpent/shared-ops.js';

const PKCS7_INVALID = 'invalid ciphertext';

beforeAll(async () => {
	await init({ serpent: serpentWasm, sha2: sha2Wasm });
});

// Helper: run decrypt and capture the thrown error, or fail the test if no
// error was thrown. Keeps assertion matchers uniform across all cases.
function capture(fn: () => unknown): Error {
	try {
		fn();
	} catch (e) {
		return e as Error;
	}
	throw new Error('expected decrypt() to throw, but it returned normally');
}

// Produce a valid CBC ciphertext with known key/iv whose first full block
// decrypts to recoverable plaintext. We then overwrite the last block with
// adversarial bytes to trigger each failure mode; CBC chaining means the
// last plaintext block is fully determined by the ciphertext's last block
// and the preceding ciphertext block (not by any key state beyond loadKey).
// The point is that the CBC transform produces 16 bytes whose tail byte
// we control via the crafted ciphertext block.
//
// For the "final byte = N, but tail bytes != N" case we need the post-CBC
// plaintext's last byte to be N while at least one other byte in the tail
// region is not N. The simplest route: encrypt a plaintext whose final
// block already has the pattern we want, then the decrypt output matches
// it exactly.
function makeBogusCiphertext(
	cbc: SerpentCbc,
	key: Uint8Array,
	iv: Uint8Array,
	tailPattern: Uint8Array,
): Uint8Array {
	// tailPattern is exactly 16 bytes. We encrypt a 32-byte plaintext where
	// the last 16 bytes are the tailPattern. CBC.encrypt will PKCS7-pad the
	// 32-byte input to 48 bytes, but we only want to feed decrypt 32 bytes
	// such that its LAST plaintext block equals tailPattern.
	//
	// The wrapper's encrypt always adds a full 16-byte pad block when input
	// is a multiple of 16. So the first 32 bytes of the 48-byte ciphertext
	// correspond to the 32-byte input plaintext. Slice that off and use it
	// as our adversarial ciphertext.
	expect(tailPattern.length).toBe(16);
	const pt = new Uint8Array(32);
	pt.set(tailPattern, 16);
	const ctFull = cbc.encrypt(key, iv, pt);
	return ctFull.subarray(0, 32).slice();
}

// ── 1. Happy path unchanged ─────────────────────────────────────────────────

describe('SerpentCbc — happy path round-trip unchanged', () => {
	const key = new Uint8Array(32);
	for (let i = 0; i < 32; i++) key[i] = i;
	const iv = new Uint8Array(16);
	for (let i = 0; i < 16; i++) iv[i] = (i + 10) & 0xff;

	// Use the same plaintext lengths as the existing SerpentCbc KAT suite
	// (serpent_cbc.test.ts). If the CT rewrite altered the happy-path output
	// path, these would regress.
	const cases = [
		{ label: '0-byte plaintext', len: 0 },
		{ label: '1-byte plaintext', len: 1 },
		{ label: '15-byte plaintext', len: 15 },
		{ label: '16-byte plaintext (one block)', len: 16 },
		{ label: '17-byte plaintext', len: 17 },
		{ label: '31-byte plaintext (partial block)', len: 31 },
		{ label: '64-byte plaintext (four blocks)', len: 64 },
	];

	for (const c of cases) {
		it(`${c.label} encrypt → decrypt returns original bytes`, () => {
			const pt = new Uint8Array(c.len);
			for (let i = 0; i < c.len; i++) pt[i] = (i * 7) & 0xff;
			const cbc = new SerpentCbc({ dangerUnauthenticated: true });
			try {
				const ct = cbc.encrypt(key, iv, pt);
				const recovered = cbc.decrypt(key, iv, ct);
				expect(Array.from(recovered)).toEqual(Array.from(pt));
			} finally {
				cbc.dispose();
			}
		});
	}
});

// ── 2. All failure modes throw the same message ─────────────────────────────

describe('SerpentCbc — all failure modes throw identical error', () => {
	const key = new Uint8Array(32).fill(0x33);
	const iv  = new Uint8Array(16).fill(0x44);

	function run(adversarial: Uint8Array): Error {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		try {
			return capture(() => cbc.decrypt(key, iv, adversarial));
		} finally {
			cbc.dispose();
		}
	}

	it('empty ciphertext throws RangeError("invalid ciphertext")', () => {
		const err = run(new Uint8Array(0));
		expect(err).toBeInstanceOf(RangeError);
		expect(err.message).toBe(PKCS7_INVALID);
	});

	it('length 17 (not a multiple of 16) throws RangeError("invalid ciphertext")', () => {
		const err = run(new Uint8Array(17));
		expect(err).toBeInstanceOf(RangeError);
		expect(err.message).toBe(PKCS7_INVALID);
	});

	it('valid length, final plaintext byte = 0 throws RangeError("invalid ciphertext")', () => {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		let err: Error;
		try {
			// A 16-byte tail whose last byte is 0 — padLen 0 is invalid.
			const tail = new Uint8Array(16);  // all zeros
			const ct = makeBogusCiphertext(cbc, key, iv, tail);
			err = capture(() => cbc.decrypt(key, iv, ct));
		} finally {
			cbc.dispose();
		}
		expect(err).toBeInstanceOf(RangeError);
		expect(err.message).toBe(PKCS7_INVALID);
	});

	it('valid length, final plaintext byte = 17 throws RangeError("invalid ciphertext")', () => {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		let err: Error;
		try {
			// A 16-byte tail whose last byte is 17 — padLen > 16 is invalid.
			const tail = new Uint8Array(16);
			tail[15] = 17;
			const ct = makeBogusCiphertext(cbc, key, iv, tail);
			err = capture(() => cbc.decrypt(key, iv, ct));
		} finally {
			cbc.dispose();
		}
		expect(err).toBeInstanceOf(RangeError);
		expect(err.message).toBe(PKCS7_INVALID);
	});

	it('valid length, final byte = 5 but trailing bytes != 5 throws RangeError("invalid ciphertext")', () => {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		let err: Error;
		try {
			// Tail ends with ...00 00 00 00 05 → padLen=5, but the 4 preceding
			// bytes are not 5, so the PKCS7 check must fail.
			const tail = new Uint8Array(16);
			tail[15] = 5;
			const ct = makeBogusCiphertext(cbc, key, iv, tail);
			err = capture(() => cbc.decrypt(key, iv, ct));
		} finally {
			cbc.dispose();
		}
		expect(err).toBeInstanceOf(RangeError);
		expect(err.message).toBe(PKCS7_INVALID);
	});

	it('all five adversarial inputs produce strictly identical .message', () => {
		const messages: string[] = [];
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		try {
			// (a) empty
			messages.push(capture(() => cbc.decrypt(key, iv, new Uint8Array(0))).message);
			// (b) length 17
			messages.push(capture(() => cbc.decrypt(key, iv, new Uint8Array(17))).message);
			// (c) padLen=0
			const tailZero = new Uint8Array(16);
			const ctZero = makeBogusCiphertext(cbc, key, iv, tailZero);
			messages.push(capture(() => cbc.decrypt(key, iv, ctZero)).message);
			// (d) padLen=17
			const tail17 = new Uint8Array(16); tail17[15] = 17;
			const ct17 = makeBogusCiphertext(cbc, key, iv, tail17);
			messages.push(capture(() => cbc.decrypt(key, iv, ct17)).message);
			// (e) padLen=5 mismatch
			const tail5 = new Uint8Array(16); tail5[15] = 5;
			const ct5 = makeBogusCiphertext(cbc, key, iv, tail5);
			messages.push(capture(() => cbc.decrypt(key, iv, ct5)).message);
		} finally {
			cbc.dispose();
		}
		expect(messages.length).toBe(5);
		for (const m of messages) expect(m).toBe(PKCS7_INVALID);
		// All strictly identical — Set collapses to size 1
		expect(new Set(messages).size).toBe(1);
	});
});

// ── 3. No numeric leaks in error messages ───────────────────────────────────

describe('SerpentCbc — error messages leak no numeric data', () => {
	const key = new Uint8Array(32).fill(0x55);
	const iv  = new Uint8Array(16).fill(0x66);

	function assertNoDigits(msg: string): void {
		// Regex /\d/ matches any decimal digit. Our normalised message
		// 'invalid ciphertext' has no digits; any digit found indicates a
		// regression that re-introduced a leak like "pad length N" or
		// "got N bytes".
		expect(msg).not.toMatch(/\d/);
	}

	it('empty input — no digits leaked', () => {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		try {
			assertNoDigits(capture(() => cbc.decrypt(key, iv, new Uint8Array(0))).message);
		} finally {
			cbc.dispose();
		}
	});

	it('length 17 — no digits leaked', () => {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		try {
			assertNoDigits(capture(() => cbc.decrypt(key, iv, new Uint8Array(17))).message);
		} finally {
			cbc.dispose();
		}
	});

	it('padLen 0 — no digits leaked', () => {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		try {
			const tail = new Uint8Array(16);
			const ct = makeBogusCiphertext(cbc, key, iv, tail);
			assertNoDigits(capture(() => cbc.decrypt(key, iv, ct)).message);
		} finally {
			cbc.dispose();
		}
	});

	it('padLen 17 — no digits leaked', () => {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		try {
			const tail = new Uint8Array(16); tail[15] = 17;
			const ct = makeBogusCiphertext(cbc, key, iv, tail);
			assertNoDigits(capture(() => cbc.decrypt(key, iv, ct)).message);
		} finally {
			cbc.dispose();
		}
	});

	it('padLen=5 mismatch — no digits leaked', () => {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		try {
			const tail = new Uint8Array(16); tail[15] = 5;
			const ct = makeBogusCiphertext(cbc, key, iv, tail);
			assertNoDigits(capture(() => cbc.decrypt(key, iv, ct)).message);
		} finally {
			cbc.dispose();
		}
	});
});

// ── 4. Timing invariance (best-effort, loose threshold) ─────────────────────

describe('SerpentCbc — pkcs7Strip timing invariance (loose)', () => {
	// Regression guard for the pre-fix behaviour where a bad-padLen input
	// short-circuited before the xor-accumulate loop ran. We measure wall-
	// clock time per adversarial category and fail only on massive outliers
	// (>10×). Node's timer granularity and GC pauses make tighter thresholds
	// unreliable.
	const key = new Uint8Array(32).fill(0x77);
	const iv  = new Uint8Array(16).fill(0x88);
	const ITERS = 1000;
	const TRIALS = 5;

	function bestMs(ct: Uint8Array): number {
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		try {
			// Warm up JIT / caches.
			for (let i = 0; i < 200; i++) {
				try {
					cbc.decrypt(key, iv, ct);
				} catch { /* expected */ }
			}
			let best = Infinity;
			for (let t = 0; t < TRIALS; t++) {
				const start = performance.now();
				for (let i = 0; i < ITERS; i++) {
					try {
						cbc.decrypt(key, iv, ct);
					} catch { /* expected */ }
				}
				const dt = performance.now() - start;
				if (dt < best) best = dt;
			}
			return best / ITERS;
		} finally {
			cbc.dispose();
		}
	}

	it('padLen=0 / padLen=17 / padLen=5-mismatch all complete within 10× of each other', () => {
		// Build three adversarial ciphertexts that decrypt to controlled tails.
		const cbc = new SerpentCbc({ dangerUnauthenticated: true });
		let ctZero: Uint8Array;
		let ct17: Uint8Array;
		let ct5: Uint8Array;
		try {
			ctZero = makeBogusCiphertext(cbc, key, iv, new Uint8Array(16));
			const tail17 = new Uint8Array(16); tail17[15] = 17;
			ct17 = makeBogusCiphertext(cbc, key, iv, tail17);
			const tail5 = new Uint8Array(16); tail5[15] = 5;
			ct5 = makeBogusCiphertext(cbc, key, iv, tail5);
		} finally {
			cbc.dispose();
		}

		const tZero = bestMs(ctZero);
		const t17   = bestMs(ct17);
		const t5    = bestMs(ct5);

		const all = [tZero, t17, t5];
		const lo  = Math.min(...all);
		const hi  = Math.max(...all);
		// Loose 10× threshold — catches the pre-fix class of bug (early return
		// before the xor loop gave O(1) vs O(16) timing spread, typically
		// 2-5× but easily larger under load) while tolerating CI jitter.
		expect(hi / lo).toBeLessThan(10.0);
	}, 30_000);
});

// ── 5. SerpentCipher still authenticates first (verify-then-decrypt) ────────

describe('SerpentCipher — HMAC verified before pkcs7Strip runs', () => {
	it('wrong key on Seal.decrypt throws AuthenticationError, not RangeError', () => {
		// A legitimate SerpentCipher blob decrypted under the wrong key must
		// fail HMAC before reaching the inner CBC pkcs7Strip. If the padding
		// layer were reachable pre-auth, a caller observing RangeError would
		// be learning padding-oracle information.
		const correctKey = randomBytes(32);
		const wrongKey   = randomBytes(32);
		const pt = new Uint8Array(48);
		for (let i = 0; i < 48; i++) pt[i] = (i * 11) & 0xff;
		const blob = Seal.encrypt(SerpentCipher, correctKey, pt);
		expect(() => Seal.decrypt(SerpentCipher, wrongKey, blob))
			.toThrow(AuthenticationError);
	});

	it('tampered blob (may produce bad PKCS7 after CBC) still throws AuthenticationError', () => {
		// Flipping a byte in the ciphertext region typically corrupts the
		// recovered plaintext — including its PKCS7 tail. The HMAC check must
		// reject it before pkcs7Strip ever sees the mangled output.
		const key = randomBytes(32);
		const pt = new Uint8Array(32).fill(0xAB);
		const blob = Seal.encrypt(SerpentCipher, key, pt).slice();
		// Flip a byte in the middle of the ciphertext region (past the
		// header, before the trailing HMAC). Exact offset doesn't matter for
		// this test — the HMAC covers the whole ciphertext, so any change
		// must fail auth.
		const midpoint = (blob.length >>> 1);
		blob[midpoint] ^= 0xff;
		expect(() => Seal.decrypt(SerpentCipher, key, blob))
			.toThrow(AuthenticationError);
	});
});

// ── 6. Correctness-equivalence regression guard for the rewrite ─────────────

describe('pkcs7Strip — correctness across padLen ∈ [1,16]', () => {
	// Regression guard for the branch-free rewrite. Probe `pkcs7Strip` directly
	// so the test isolates the padding check from CBC decrypt behaviour.
	//
	// Acceptance table: for each padLen in [1, 16], build a 16-byte tail with
	// the correct trailing `padLen` bytes all equal to `padLen`. The previous
	// implementation accepted these; the rewrite must too. Rejection table:
	// flip exactly one byte inside the pad region — the previous implementation
	// rejected these; the rewrite must too.

	function tailAccepted(padLen: number): Uint8Array {
		// One full block whose trailing `padLen` bytes all equal padLen.
		const blk = new Uint8Array(16);
		for (let i = 0; i < padLen; i++) blk[15 - i] = padLen;
		return blk;
	}

	for (let padLen = 1; padLen <= 16; padLen++) {
		it(`accepts padLen=${padLen} with all-matching trailing bytes`, () => {
			const blk = tailAccepted(padLen);
			const stripped = pkcs7Strip(blk);
			expect(stripped.length).toBe(16 - padLen);
			// The non-pad bytes (indices 0..15-padLen-1, all zeros) must be
			// preserved in the slice return.
			for (const byte of stripped) expect(byte).toBe(0);
		});
	}

	// For padLen == 1 there is only one pad byte — no "other byte in the pad
	// region" to flip. padLen == 2..16 gives `padLen - 1` internal flip sites
	// per case; we exercise every internal flip position to cover the mask.
	for (let padLen = 2; padLen <= 16; padLen++) {
		for (let flipOffset = 1; flipOffset < padLen; flipOffset++) {
			it(`rejects padLen=${padLen} with flipped byte at offset ${flipOffset} from end`, () => {
				const blk = tailAccepted(padLen);
				// flipOffset ∈ [1, padLen-1] — position inside pad region but
				// not the final byte, so padLen byte itself is preserved.
				blk[15 - flipOffset] ^= 0xff;
				expect(() => pkcs7Strip(blk)).toThrow(RangeError);
				try {
					pkcs7Strip(blk);
				} catch (e) {
					expect((e as Error).message).toBe(PKCS7_INVALID);
				}
			});
		}
	}
});

// ── 7. Exhaustive rejection for padLen ∈ {0} ∪ [17, 255] ────────────────────

describe('pkcs7Strip — rejects every out-of-range trailing byte', () => {
	// Every byte value outside [1, 16] for the last byte of a 16-byte input
	// must throw the same RangeError('invalid ciphertext'), regardless of
	// the leading 15 bytes. Use a valid 16-aligned length (exactly one block)
	// with arbitrary leading bytes; the branch-free implementation must
	// reject the tail byte before any slice is returned.

	const outOfRange: number[] = [0];
	for (let v = 17; v <= 255; v++) outOfRange.push(v);

	for (const v of outOfRange) {
		it(`rejects final byte = ${v}`, () => {
			const blk = new Uint8Array(16);
			// Leading bytes arbitrary; pick a pattern that does not
			// coincidentally match `v` so the test is unambiguous.
			for (let i = 0; i < 15; i++) blk[i] = (i * 3 + 1) & 0xff;
			blk[15] = v;
			expect(() => pkcs7Strip(blk)).toThrow(RangeError);
			try {
				pkcs7Strip(blk);
			} catch (e) {
				expect((e as Error).message).toBe(PKCS7_INVALID);
			}
		});
	}

	it('pkcs7Pad round-trip still works for lengths 0..17 (sanity)', () => {
		// Ensure the rewrite did not disturb the happy path at the primitive
		// level (serpent_cbc.test.ts exercises this too; this is a local
		// sanity check co-located with the rejection sweep).
		for (let len = 0; len <= 17; len++) {
			const data = new Uint8Array(len);
			for (let i = 0; i < len; i++) data[i] = (i * 13) & 0xff;
			const stripped = pkcs7Strip(pkcs7Pad(data));
			expect(Array.from(stripped)).toEqual(Array.from(data));
		}
	});
});
