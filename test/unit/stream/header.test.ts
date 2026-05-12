import { describe, it, expect } from 'vitest';
import { readHeader, writeHeader, makeCounterNonce } from '../../../src/ts/stream/header.js';
import { HEADER_SIZE, TAG_DATA, TAG_FINAL } from '../../../src/ts/stream/constants.js';

// ── readHeader strict length ────────────────────────────────────────────────

describe('readHeader()', () => {
	// 0x03 is the XChaCha20 v3 format enum; readHeader simply parses it,
	// the per-cipher format check happens downstream in OpenStream.
	const valid = writeHeader(0x03, false, new Uint8Array(16), 65536);

	it('accepts exactly HEADER_SIZE bytes', () => {
		const h = readHeader(valid);
		expect(h.formatEnum).toBe(0x03);
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
		// Manually construct a header byte with bit 6 set alongside a valid
		// formatEnum. Without this check, 0x43 would silently parse as
		// formatEnum=0x03 and pass cipher format checks for xchacha20 v3,
		// a malformed wire format accepted silently.
		const bad = new Uint8Array(valid);
		bad[0] = 0x43; // xchacha20 v3 (0x03) | reserved bit 6 (0x40)
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
		// mlkem768 (0x20) | xchacha20 v3 (0x03) = 0x23
		const h = writeHeader(0x23, false, new Uint8Array(16), 65536);
		const parsed = readHeader(h);
		expect(parsed.formatEnum).toBe(0x23);
		expect((parsed.formatEnum >> 4) & 0x07).toBe(0x02); // KEM nibble = mlkem768
		expect(parsed.formatEnum & 0x0f).toBe(0x03);         // cipher nibble = xchacha20 v3
	});

	it('aes-gcm-siv cipher nibble (0x04) roundtrips through readHeader', () => {
		const h = writeHeader(0x04, false, new Uint8Array(16), 65536);
		const parsed = readHeader(h);
		expect(parsed.formatEnum).toBe(0x04);
		expect(parsed.formatEnum & 0x0f).toBe(0x04);         // cipher nibble = aes-gcm-siv
	});

	it('mlkem512 (0x10) | aes-gcm-siv (0x04) = 0x14 roundtrips', () => {
		const h = writeHeader(0x14, false, new Uint8Array(16), 65536);
		const parsed = readHeader(h);
		expect(parsed.formatEnum).toBe(0x14);
		expect((parsed.formatEnum >> 4) & 0x07).toBe(0x01); // KEM nibble = mlkem512
		expect(parsed.formatEnum & 0x0f).toBe(0x04);         // cipher nibble = aes-gcm-siv
	});

	it('mlkem768 (0x20) | aes-gcm-siv (0x04) = 0x24 roundtrips', () => {
		const h = writeHeader(0x24, false, new Uint8Array(16), 65536);
		const parsed = readHeader(h);
		expect(parsed.formatEnum).toBe(0x24);
		expect((parsed.formatEnum >> 4) & 0x07).toBe(0x02); // KEM nibble = mlkem768
		expect(parsed.formatEnum & 0x0f).toBe(0x04);         // cipher nibble = aes-gcm-siv
	});

	it('mlkem1024 (0x30) | aes-gcm-siv (0x04) = 0x34 roundtrips', () => {
		const h = writeHeader(0x34, false, new Uint8Array(16), 65536);
		const parsed = readHeader(h);
		expect(parsed.formatEnum).toBe(0x34);
		expect((parsed.formatEnum >> 4) & 0x07).toBe(0x03); // KEM nibble = mlkem1024
		expect(parsed.formatEnum & 0x0f).toBe(0x04);         // cipher nibble = aes-gcm-siv
	});
});
