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
