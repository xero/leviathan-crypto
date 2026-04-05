import { describe, it, expect } from 'vitest';
import { readHeader, writeHeader, makeCounterNonce } from '../../../src/ts/stream/header.js';
import { HEADER_SIZE, TAG_DATA, TAG_FINAL } from '../../../src/ts/stream/constants.js';

// ── readHeader strict length ────────────────────────────────────────────────

describe('readHeader()', () => {
	const valid = writeHeader(0x01, false, new Uint8Array(16), 65536);

	it('accepts exactly HEADER_SIZE bytes', () => {
		const h = readHeader(valid);
		expect(h.formatEnum).toBe(0x01);
		expect(h.chunkSize).toBe(65536);
	});

	it('rejects header shorter than HEADER_SIZE', () => {
		expect(() => readHeader(valid.subarray(0, HEADER_SIZE - 1)))
			.toThrow(RangeError);
	});

	it('rejects header longer than HEADER_SIZE', () => {
		const padded = new Uint8Array(HEADER_SIZE + 1);
		padded.set(valid);
		expect(() => readHeader(padded)).toThrow(RangeError);
	});

	it('rejects header with reserved bit 6 set (0x40)', () => {
		// Manually construct a header byte with bit 6 set alongside a valid formatEnum.
		// Without this check, 0x41 would silently parse as formatEnum=0x01 and pass
		// cipher format checks for xchacha20 — a malformed wire format accepted silently.
		const bad = new Uint8Array(valid);
		bad[0] = 0x41; // xchacha20 (0x01) | reserved bit 6 (0x40)
		expect(() => readHeader(bad)).toThrow(RangeError);
	});
});

// ── makeCounterNonce safe integer guard ─────────────────────────────────────

describe('makeCounterNonce()', () => {
	it('counter = 0 → valid', () => {
		const n = makeCounterNonce(0, TAG_DATA);
		expect(n.length).toBe(12);
		expect(n[11]).toBe(TAG_DATA);
	});

	it('counter = MAX_SAFE_INTEGER → valid', () => {
		const n = makeCounterNonce(Number.MAX_SAFE_INTEGER, TAG_FINAL);
		expect(n.length).toBe(12);
		expect(n[11]).toBe(TAG_FINAL);
	});

	it('counter = MAX_SAFE_INTEGER + 1 → throws RangeError', () => {
		expect(() => makeCounterNonce(Number.MAX_SAFE_INTEGER + 1, TAG_DATA))
			.toThrow(RangeError);
	});

	it('negative counter → throws RangeError', () => {
		expect(() => makeCounterNonce(-1, TAG_DATA)).toThrow(RangeError);
	});

	it('fractional counter → throws RangeError', () => {
		expect(() => makeCounterNonce(1.5, TAG_DATA)).toThrow(RangeError);
	});

	it('NaN counter → throws RangeError', () => {
		expect(() => makeCounterNonce(NaN, TAG_DATA)).toThrow(RangeError);
	});

	it('Infinity counter → throws RangeError', () => {
		expect(() => makeCounterNonce(Infinity, TAG_DATA)).toThrow(RangeError);
	});
});

describe('writeHeader() formatEnum range', () => {
	it('accepts 0x00 (minimum)', () => {
		expect(() => writeHeader(0x00, false, new Uint8Array(16), 65536)).not.toThrow();
	});

	it('accepts 0x3f (maximum valid)', () => {
		expect(() => writeHeader(0x3f, false, new Uint8Array(16), 65536)).not.toThrow();
	});

	it('rejects 0x40 (one above maximum)', () => {
		expect(() => writeHeader(0x40, false, new Uint8Array(16), 65536))
			.toThrow(RangeError);
	});

	it('rejects 0x7f (old maximum, now invalid)', () => {
		expect(() => writeHeader(0x7f, false, new Uint8Array(16), 65536))
			.toThrow(RangeError);
	});

	it('KEM nibble + cipher nibble roundtrips through readHeader', () => {
		// mlkem768 (0x20) | xchacha20 (0x01) = 0x21
		const h = writeHeader(0x21, false, new Uint8Array(16), 65536);
		const parsed = readHeader(h);
		expect(parsed.formatEnum).toBe(0x21);
		expect((parsed.formatEnum >> 4) & 0x07).toBe(0x02); // KEM nibble = mlkem768
		expect(parsed.formatEnum & 0x0f).toBe(0x01);         // cipher nibble = xchacha20
	});
});
