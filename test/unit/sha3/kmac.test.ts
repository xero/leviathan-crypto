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
// cSHAKE128/256, KMAC128/256, KMACXOF128/256, Known-Answer Tests.
//
// Source: NIST SP 800-185 sample documents + NIST ACVP byte-aligned subset.
// Vectors: test/vectors/kmac.ts (24 records, byte-oriented, pinned in
// SHA256SUMS).

import { describe, test, expect, beforeAll } from 'vitest';
import {
	init,
	CSHAKE128, CSHAKE256, KMAC128, KMAC256, KMACXOF128, KMACXOF256,
	AuthenticationError,
} from '../../../src/ts/index.js';
import { getInstance } from '../../../src/ts/init.js';
import { _cshake128Raw, _cshake256Raw } from '../../../src/ts/sha3/kmac.js';
import { sha3Wasm } from '../../../src/ts/sha3/embedded.js';
import {
	cshake128_appendix_a, cshake128_acvp,
	cshake256_appendix_a, cshake256_acvp,
	kmac128_appendix_a, kmac128_acvp,
	kmac256_appendix_a, kmac256_acvp,
	kmacxof128_appendix_a, kmacxof128_acvp,
	kmacxof256_appendix_a, kmacxof256_acvp,
} from '../../vectors/kmac.js';
import type { CshakeAcvpVector, KmacAcvpVector } from '../../vectors/kmac.js';

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return bytes;
}

function fromAscii(s: string): Uint8Array {
	return new TextEncoder().encode(s);
}

function acvpCustomization(vec: CshakeAcvpVector | KmacAcvpVector): Uint8Array {
	if (vec.hexCustomization) {
		const hex = (vec as KmacAcvpVector).customizationHex ?? (vec as CshakeAcvpVector).customization;
		return fromHex(hex);
	}
	const ascii = (vec as CshakeAcvpVector).customization ?? (vec as KmacAcvpVector).customization ?? '';
	return fromAscii(ascii);
}

beforeAll(async () => {
	await init({ sha3: sha3Wasm });
});

// GATE: cSHAKE128 SP 800-185 Appendix A sample #1, the structural
// prerequisite for every other test in this file. If this fails, the encoding
// helpers (left_encode / right_encode / encode_string / bytepad), the cSHAKE
// prefix construction, or the AS-side cshake128Init domain byte is wrong.
// Vector: test/vectors/kmac.ts → cshake128_appendix_a[0]
describe('Gate 8, cSHAKE128 SP 800-185 sample #1', () => {
	test('cSHAKE128(msg=0001..03, N="", S="Email Signature", L=256) matches SP 800-185 §A', () => {
		const vec = cshake128_appendix_a[0];
		const c = new CSHAKE128(fromAscii(vec.S));
		const out = c.hash(fromHex(vec.msg), vec.outLenBits / 8);
		expect(toHex(out)).toBe(vec.expected);
		c.dispose();
	});
});

// ── vector file invariants, corpus shape ──────────────────────────────────
//
// Two ACVP slots are empty by design after the byte-alignment filter and the
// xof/non-xof routing: KMAC-256 ACVP records that were byte-aligned all had
// xof=true (so they routed to kmacxof256_acvp), and KMAC-128 ACVP records
// that were byte-aligned all had xof=false (so they routed to kmac128_acvp).
// See test/vectors/kmac.ts header for the full scope statement.
//
// These tests pin the empty-corpus invariant. If a future ACVP refresh
// fills either slot with records, the corresponding test FAILS and forces
// an explicit review of the new records before they get wired in via the
// conditional describes below.

describe('vector file invariants', () => {
	test('kmac256_acvp is empty (no byte-aligned KMAC-256 ACVP records survived the filter)', () => {
		expect(kmac256_acvp.length).toBe(0);
	});

	test('kmacxof128_acvp is empty (no byte-aligned KMACXOF-128 ACVP records survived the filter)', () => {
		expect(kmacxof128_acvp.length).toBe(0);
	});
});

// ── CSHAKE128, SP 800-185 samples ──────────────────────────────────────────

describe('CSHAKE128, SP 800-185 samples', () => {
	for (const vec of cshake128_appendix_a) {
		test(vec.description, () => {
			const c = new CSHAKE128(fromAscii(vec.S));
			try {
				const out = c.hash(fromHex(vec.msg), vec.outLenBits / 8);
				expect(toHex(out)).toBe(vec.expected);
			} finally {
				c.dispose();
			}
		});
	}
});

// ── CSHAKE128, ACVP byte-aligned ───────────────────────────────────────────
// ACVP records carry NIST-reserved function names ("KMAC", "TupleHash", …),
// the public CSHAKE128 class hides N per SP 800-185 §3.4. Reach into the
// internal _cshake128Raw helper so the byte-aligned subset is still validated
// against the WASM sponge end-to-end.

describe('CSHAKE128, ACVP byte-aligned', () => {
	for (const vec of cshake128_acvp) {
		test(`AFT tcId ${vec.tcId}`, () => {
			const out = _cshake128Raw(
				fromAscii(vec.functionName),
				acvpCustomization(vec),
				fromHex(vec.msg),
				vec.outLenBits / 8,
			);
			expect(toHex(out)).toBe(vec.md);
		});
	}
});

// ── CSHAKE256, SP 800-185 samples ──────────────────────────────────────────

describe('CSHAKE256, SP 800-185 samples', () => {
	for (const vec of cshake256_appendix_a) {
		test(vec.description, () => {
			const c = new CSHAKE256(fromAscii(vec.S));
			try {
				const out = c.hash(fromHex(vec.msg), vec.outLenBits / 8);
				expect(toHex(out)).toBe(vec.expected);
			} finally {
				c.dispose();
			}
		});
	}
});

// ── CSHAKE256, ACVP byte-aligned ───────────────────────────────────────────

describe('CSHAKE256, ACVP byte-aligned', () => {
	for (const vec of cshake256_acvp) {
		test(`AFT tcId ${vec.tcId}`, () => {
			const out = _cshake256Raw(
				fromAscii(vec.functionName),
				acvpCustomization(vec),
				fromHex(vec.msg),
				vec.outLenBits / 8,
			);
			expect(toHex(out)).toBe(vec.md);
		});
	}
});

// ── KMAC128, SP 800-185 samples ────────────────────────────────────────────

describe('KMAC128, SP 800-185 samples', () => {
	for (const vec of kmac128_appendix_a) {
		test(vec.description, () => {
			const m = new KMAC128(fromHex(vec.key), vec.outLenBits / 8, fromAscii(vec.S));
			try {
				const tag = m.mac(fromHex(vec.msg));
				expect(toHex(tag)).toBe(vec.expected);
			} finally {
				m.dispose();
			}
		});
	}
});

// ── KMAC128, ACVP byte-aligned ─────────────────────────────────────────────

describe('KMAC128, ACVP byte-aligned', () => {
	for (const vec of kmac128_acvp) {
		test(`${vec.testType} tcId ${vec.tcId}`, () => {
			const key = fromHex(vec.key);
			const msg = fromHex(vec.msg);
			const cust = acvpCustomization(vec);
			const macBytes = vec.macLenBits / 8;
			if (vec.testType === 'MVT') {
				if (vec.testPassed === true) {
					expect(KMAC128.verify(fromHex(vec.mac), key, msg, cust)).toBe(true);
				} else {
					expect(() => KMAC128.verify(fromHex(vec.mac), key, msg, cust))
						.toThrow(AuthenticationError);
				}
			} else {
				const m = new KMAC128(key, macBytes, cust);
				try {
					const tag = m.mac(msg);
					expect(toHex(tag)).toBe(vec.mac);
				} finally {
					m.dispose();
				}
			}
		});
	}
});

// ── KMAC256, SP 800-185 samples ────────────────────────────────────────────

describe('KMAC256, SP 800-185 samples', () => {
	for (const vec of kmac256_appendix_a) {
		test(vec.description, () => {
			const m = new KMAC256(fromHex(vec.key), vec.outLenBits / 8, fromAscii(vec.S));
			try {
				const tag = m.mac(fromHex(vec.msg));
				expect(toHex(tag)).toBe(vec.expected);
			} finally {
				m.dispose();
			}
		});
	}
});

// ── KMAC256, ACVP byte-aligned ─────────────────────────────────────────────
// Empty by design (see invariants block above). The conditional describe
// materializes automatically if a future ACVP refresh wires records in;
// the invariant test then breaks first, forcing review.

if (kmac256_acvp.length > 0) {
	describe('KMAC256, ACVP byte-aligned', () => {
		for (const vec of kmac256_acvp) {
			test(`${vec.testType} tcId ${vec.tcId}`, () => {
				const m = new KMAC256(fromHex(vec.key), vec.macLenBits / 8, acvpCustomization(vec));
				try {
					const tag = m.mac(fromHex(vec.msg));
					expect(toHex(tag)).toBe(vec.mac);
				} finally {
					m.dispose();
				}
			});
		}
	});
}

// ── KMACXOF128, SP 800-185 samples ─────────────────────────────────────────

describe('KMACXOF128, SP 800-185 samples', () => {
	for (const vec of kmacxof128_appendix_a) {
		test(vec.description, () => {
			const m = new KMACXOF128(fromHex(vec.key), fromAscii(vec.S));
			try {
				const out = m.mac(fromHex(vec.msg), vec.outLenBits / 8);
				expect(toHex(out)).toBe(vec.expected);
			} finally {
				m.dispose();
			}
		});
	}
});

// ── KMACXOF128, ACVP byte-aligned ──────────────────────────────────────────
// Empty by design (see invariants block above). The conditional describe
// materializes automatically if a future ACVP refresh wires records in;
// the invariant test then breaks first, forcing review.

if (kmacxof128_acvp.length > 0) {
	describe('KMACXOF128, ACVP byte-aligned', () => {
		for (const vec of kmacxof128_acvp) {
			test(`${vec.testType} tcId ${vec.tcId}`, () => {
				const m = new KMACXOF128(fromHex(vec.key), acvpCustomization(vec));
				try {
					const out = m.mac(fromHex(vec.msg), vec.macLenBits / 8);
					expect(toHex(out)).toBe(vec.mac);
				} finally {
					m.dispose();
				}
			});
		}
	});
}

// ── KMACXOF256, SP 800-185 samples ─────────────────────────────────────────

describe('KMACXOF256, SP 800-185 samples', () => {
	for (const vec of kmacxof256_appendix_a) {
		test(vec.description, () => {
			const m = new KMACXOF256(fromHex(vec.key), fromAscii(vec.S));
			try {
				const out = m.mac(fromHex(vec.msg), vec.outLenBits / 8);
				expect(toHex(out)).toBe(vec.expected);
			} finally {
				m.dispose();
			}
		});
	}
});

// ── KMACXOF256, ACVP byte-aligned ──────────────────────────────────────────

describe('KMACXOF256, ACVP byte-aligned', () => {
	for (const vec of kmacxof256_acvp) {
		test(`${vec.testType} tcId ${vec.tcId}`, () => {
			const key = fromHex(vec.key);
			const msg = fromHex(vec.msg);
			const cust = acvpCustomization(vec);
			const m = new KMACXOF256(key, cust);
			try {
				const out = m.mac(msg, vec.macLenBits / 8);
				if (vec.testType === 'MVT' && vec.testPassed === false) {
					expect(toHex(out)).not.toBe(vec.mac);
				} else {
					expect(toHex(out)).toBe(vec.mac);
				}
			} finally {
				m.dispose();
			}
		});
	}
});

// ── Streaming matches one-shot ──────────────────────────────────────────────

describe('streaming matches one-shot', () => {
	test('KMAC128 split update produces same tag as mac()', () => {
		const vec = kmac128_appendix_a[2];
		const key = fromHex(vec.key);
		const msg = fromHex(vec.msg);
		const cust = fromAscii(vec.S);
		const outLen = vec.outLenBits / 8;
		const half = msg.length >>> 1;

		const a = new KMAC128(key, outLen, cust);
		const oneShot = a.mac(msg);
		a.dispose();

		const b = new KMAC128(key, outLen, cust);
		b.update(msg.subarray(0, half));
		b.update(msg.subarray(half));
		const streamed = b.finalize();
		b.dispose();

		expect(toHex(streamed)).toBe(toHex(oneShot));
	});

	test('KMAC256 split update produces same tag as mac()', () => {
		const vec = kmac256_appendix_a[2];
		const key = fromHex(vec.key);
		const msg = fromHex(vec.msg);
		const cust = fromAscii(vec.S);
		const outLen = vec.outLenBits / 8;
		const half = msg.length >>> 1;

		const a = new KMAC256(key, outLen, cust);
		const oneShot = a.mac(msg);
		a.dispose();

		const b = new KMAC256(key, outLen, cust);
		b.update(msg.subarray(0, half));
		b.update(msg.subarray(half));
		const streamed = b.finalize();
		b.dispose();

		expect(toHex(streamed)).toBe(toHex(oneShot));
	});

	test('KMACXOF128 split update produces same stream as mac()', () => {
		const vec = kmacxof128_appendix_a[2];
		const key = fromHex(vec.key);
		const msg = fromHex(vec.msg);
		const cust = fromAscii(vec.S);
		const outLen = vec.outLenBits / 8;
		const half = msg.length >>> 1;

		const a = new KMACXOF128(key, cust);
		const oneShot = a.mac(msg, outLen);
		a.dispose();

		const b = new KMACXOF128(key, cust);
		b.update(msg.subarray(0, half));
		b.update(msg.subarray(half));
		const streamed = b.squeeze(outLen);
		b.dispose();

		expect(toHex(streamed)).toBe(toHex(oneShot));
	});

	test('KMACXOF256 split squeeze matches single squeeze', () => {
		const vec = kmacxof256_appendix_a[0];
		const key = fromHex(vec.key);
		const msg = fromHex(vec.msg);
		const cust = fromAscii(vec.S);
		const outLen = vec.outLenBits / 8;

		const a = new KMACXOF256(key, cust);
		const oneShot = a.mac(msg, outLen);
		a.dispose();

		const b = new KMACXOF256(key, cust);
		b.update(msg);
		const half = outLen >>> 1;
		const part1 = b.squeeze(half);
		const part2 = b.squeeze(outLen - half);
		b.dispose();
		const combined = new Uint8Array(outLen);
		combined.set(part1, 0);
		combined.set(part2, part1.length);

		expect(toHex(combined)).toBe(toHex(oneShot));
	});
});

// ── Error paths ─────────────────────────────────────────────────────────────

describe('error paths', () => {
	test('CSHAKE128 with empty customization throws', () => {
		expect(() => new CSHAKE128(new Uint8Array(0))).toThrow(/SHAKE128/);
	});

	test('CSHAKE256 with empty customization throws', () => {
		expect(() => new CSHAKE256(new Uint8Array(0))).toThrow(/SHAKE256/);
	});

	test('KMAC128 with empty key throws', () => {
		expect(() => new KMAC128(new Uint8Array(0), 32, fromAscii('s')))
			.toThrow(/CSHAKE128/);
	});

	test('KMAC256 with empty key throws', () => {
		expect(() => new KMAC256(new Uint8Array(0), 32, fromAscii('s')))
			.toThrow(/CSHAKE256/);
	});

	test('KMAC128 with outLen=0 throws', () => {
		expect(() => new KMAC128(new Uint8Array([1, 2, 3, 4]), 0, fromAscii('s')))
			.toThrow(RangeError);
	});

	test('KMAC256 with outLen=0 throws', () => {
		expect(() => new KMAC256(new Uint8Array([1, 2, 3, 4]), 0, fromAscii('s')))
			.toThrow(RangeError);
	});

	test('KMACXOF128 with empty key throws', () => {
		expect(() => new KMACXOF128(new Uint8Array(0), fromAscii('s')))
			.toThrow(/CSHAKE128/);
	});

	test('KMACXOF256 with empty key throws', () => {
		expect(() => new KMACXOF256(new Uint8Array(0), fromAscii('s')))
			.toThrow(/CSHAKE256/);
	});

	test('KMACXOF128.squeeze(-1) throws', () => {
		const m = new KMACXOF128(new Uint8Array([1, 2, 3, 4]), fromAscii('s'));
		try {
			expect(() => m.squeeze(-1)).toThrow(RangeError);
		} finally {
			m.dispose();
		}
	});

	test('KMACXOF128.squeeze(0) throws', () => {
		const m = new KMACXOF128(new Uint8Array([1, 2, 3, 4]), fromAscii('s'));
		try {
			expect(() => m.squeeze(0)).toThrow(RangeError);
		} finally {
			m.dispose();
		}
	});

	test('KMACXOF256.squeeze(0) throws', () => {
		const m = new KMACXOF256(new Uint8Array([1, 2, 3, 4]), fromAscii('s'));
		try {
			expect(() => m.squeeze(0)).toThrow(RangeError);
		} finally {
			m.dispose();
		}
	});

	test('KMAC128 update after finalize throws', () => {
		const m = new KMAC128(new Uint8Array([1, 2, 3, 4]), 32, fromAscii('s'));
		m.finalize();
		expect(() => m.update(new Uint8Array([5]))).toThrow(/after finalize/);
		m.dispose();
	});

	test('KMAC128 finalize twice throws', () => {
		const m = new KMAC128(new Uint8Array([1, 2, 3, 4]), 32, fromAscii('s'));
		m.finalize();
		expect(() => m.finalize()).toThrow(/finalized/);
		m.dispose();
	});

	test('KMACXOF128 update after squeeze throws', () => {
		const m = new KMACXOF128(new Uint8Array([1, 2, 3, 4]), fromAscii('s'));
		m.squeeze(8);
		expect(() => m.update(new Uint8Array([5]))).toThrow(/after squeeze/);
		m.dispose();
	});

	test('KMAC128.verify throws AuthenticationError with kmac128 discriminator on tag mismatch', () => {
		const vec = kmac128_appendix_a[0];
		const key = fromHex(vec.key);
		const msg = fromHex(vec.msg);
		const cust = fromAscii(vec.S);
		// Flip one bit of the correct tag.
		const bad = fromHex(vec.expected);
		bad[0] ^= 0x01;
		let caught: unknown;
		try {
			KMAC128.verify(bad, key, msg, cust);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(AuthenticationError);
		expect((caught as Error).message.includes('kmac128')).toBe(true);
	});

	test('KMAC256.verify throws AuthenticationError with kmac256 discriminator on tag mismatch', () => {
		const vec = kmac256_appendix_a[0];
		const key = fromHex(vec.key);
		const msg = fromHex(vec.msg);
		const cust = fromAscii(vec.S);
		const bad = fromHex(vec.expected);
		bad[0] ^= 0x01;
		let caught: unknown;
		try {
			KMAC256.verify(bad, key, msg, cust);
		} catch (e) {
			caught = e;
		}
		expect(caught).toBeInstanceOf(AuthenticationError);
		expect((caught as Error).message.includes('kmac256')).toBe(true);
	});

	test('KMAC128.verify returns true for a correct tag', () => {
		const vec = kmac128_appendix_a[1];
		expect(KMAC128.verify(
			fromHex(vec.expected),
			fromHex(vec.key),
			fromHex(vec.msg),
			fromAscii(vec.S),
		)).toBe(true);
	});
});

// ── dispose zeroes WASM state ───────────────────────────────────────────────

describe('dispose zeroes WASM state', () => {
	test('CSHAKE128 dispose zeroes the 200-byte state', () => {
		const c = new CSHAKE128(fromAscii('s'));
		c.hash(new Uint8Array([0x61, 0x62, 0x63]), 32);
		c.dispose();
		const x = getInstance('sha3').exports as unknown as {
			memory: WebAssembly.Memory;
			getStateOffset: () => number;
		};
		const mem = new Uint8Array(x.memory.buffer);
		const stateOff = x.getStateOffset();
		let nz = 0;
		for (let i = 0; i < 200; i++) nz |= mem[stateOff + i];
		expect(nz).toBe(0);
	});

	test('KMAC128 dispose zeroes the 200-byte state', () => {
		const m = new KMAC128(new Uint8Array([1, 2, 3, 4]), 32, fromAscii('s'));
		m.mac(new Uint8Array([0x61, 0x62, 0x63]));
		m.dispose();
		const x = getInstance('sha3').exports as unknown as {
			memory: WebAssembly.Memory;
			getStateOffset: () => number;
		};
		const mem = new Uint8Array(x.memory.buffer);
		const stateOff = x.getStateOffset();
		let nz = 0;
		for (let i = 0; i < 200; i++) nz |= mem[stateOff + i];
		expect(nz).toBe(0);
	});

	test('KMACXOF256 dispose zeroes the 200-byte state', () => {
		const m = new KMACXOF256(new Uint8Array([1, 2, 3, 4]), fromAscii('s'));
		m.mac(new Uint8Array([0x61, 0x62, 0x63]), 64);
		m.dispose();
		const x = getInstance('sha3').exports as unknown as {
			memory: WebAssembly.Memory;
			getStateOffset: () => number;
		};
		const mem = new Uint8Array(x.memory.buffer);
		const stateOff = x.getStateOffset();
		let nz = 0;
		for (let i = 0; i < 200; i++) nz |= mem[stateOff + i];
		expect(nz).toBe(0);
	});
});

// ── dispose idempotency ─────────────────────────────────────────────────────

describe('dispose idempotency', () => {
	test('CSHAKE128 dispose twice does not throw', () => {
		const c = new CSHAKE128(fromAscii('s'));
		c.dispose();
		expect(() => c.dispose()).not.toThrow();
	});

	test('KMAC128 dispose twice does not throw', () => {
		const m = new KMAC128(new Uint8Array([1, 2, 3, 4]), 32, fromAscii('s'));
		m.dispose();
		expect(() => m.dispose()).not.toThrow();
	});

	test('KMACXOF256 dispose twice does not throw', () => {
		const m = new KMACXOF256(new Uint8Array([1, 2, 3, 4]), fromAscii('s'));
		m.dispose();
		expect(() => m.dispose()).not.toThrow();
	});
});

// ── post-dispose method calls ───────────────────────────────────────────────

describe('post-dispose method calls throw', () => {
	test('CSHAKE128 absorb / squeeze / hash after dispose throw', () => {
		const c = new CSHAKE128(fromAscii('s'));
		c.dispose();
		expect(() => c.absorb(new Uint8Array([1]))).toThrow(/disposed/);
		expect(() => c.squeeze(1)).toThrow(/disposed/);
		expect(() => c.hash(new Uint8Array([1]), 32)).toThrow(/disposed/);
	});

	test('KMAC128 update / finalize / mac after dispose throw', () => {
		const m = new KMAC128(new Uint8Array([1, 2, 3, 4]), 32, fromAscii('s'));
		m.dispose();
		expect(() => m.update(new Uint8Array([1]))).toThrow(/disposed/);
		expect(() => m.finalize()).toThrow(/disposed/);
		expect(() => m.mac(new Uint8Array([1]))).toThrow(/disposed/);
	});

	test('KMACXOF128 update / squeeze / mac after dispose throw', () => {
		const m = new KMACXOF128(new Uint8Array([1, 2, 3, 4]), fromAscii('s'));
		m.dispose();
		expect(() => m.update(new Uint8Array([1]))).toThrow(/disposed/);
		expect(() => m.squeeze(8)).toThrow(/disposed/);
		expect(() => m.mac(new Uint8Array([1]), 8)).toThrow(/disposed/);
	});
});
