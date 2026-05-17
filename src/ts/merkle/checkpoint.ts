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
// src/ts/merkle/checkpoint.ts
//
// Canonical checkpoint body codec per c2sp.org/tlog-checkpoint (Transparency
// Log Checkpoints) §Note text. Three newline-terminated lines: origin, tree
// size in ASCII decimal with no leading zeroes, base64-encoded root hash.
// The body bytes are exactly what the STH signature is computed over, so
// producers and verifiers MUST serialize byte-for-byte identically.
//
// Extension lines are spec-listed as OPTIONAL and NOT RECOMMENDED. The
// ML-DSA-44 cosignature format defined in c2sp.org/tlog-cosignature does
// not commit to extension lines, so leviathan emits empty extension sections
// and the parser rejects any input that contains extension lines.

import { utf8ToBytes, bytesToUtf8, base64ToBytes, bytesToBase64 } from '../utils.js';

// ── types ───────────────────────────────────────────────────────────────────

/**
 * Decoded form of a c2sp.org/tlog-checkpoint body. The body shape is
 * hash-and-algo-agnostic: `rootHash` is 32 bytes for both the SHA-256 and
 * BLAKE3 trees Phase 7 ships, but the codec only enforces a caller-supplied
 * length in `parseCheckpointBody`. The signed-note envelope that wraps a
 * checkpoint is handled in `signed-note.ts`.
 */
export interface Checkpoint {
	/**
	 * Log identity, non-empty UTF-8 with no Unicode spaces, plus signs, or
	 * embedded newlines. Per c2sp.org/tlog-checkpoint §Note text the origin
	 * SHOULD be a schemeless URL such as `example.com/log42`, but the codec
	 * only enforces the MUST-level structural constraints; broader URL
	 * shape policy is a caller concern.
	 */
	readonly origin: string;
	/**
	 * Number of leaves in the tree at signing time. Must be a non-negative
	 * safe integer; ASCII decimal serialization carries no leading zeroes
	 * (the literal `0` is the only valid string starting with `0`).
	 */
	readonly treeSize: number;
	/**
	 * Merkle root hash. 32 bytes for both Sha256Tree and Blake3Tree; the
	 * caller-supplied `expectedHashLen` parameter on `parseCheckpointBody`
	 * pins the exact length for a given hasher.
	 */
	readonly rootHash: Uint8Array;
}

// ── serialization ───────────────────────────────────────────────────────────

const LF = 0x0a;       // U+000A, the only legal line terminator in the body
const SPACE = 0x20;    // U+0020, illegal anywhere inside origin
const PLUS = 0x2b;     // U+002B, illegal anywhere inside origin

/**
 * Decimal-encode a non-negative integer per c2sp.org/tlog-checkpoint §Note
 * text: ASCII digits, no leading zeroes, the literal `0` for an empty tree.
 * `Number.toString(10)` is already in this form for non-negative safe
 * integers, the explicit guard exists so a Number that slipped past the
 * upstream call site does not silently produce `"1e+21"` or similar.
 */
function decimalTreeSize(n: number): string {
	if (!Number.isInteger(n) || n < 0 || n > Number.MAX_SAFE_INTEGER)
		throw new RangeError(
			`serializeCheckpointBody: treeSize must be a non-negative safe integer, got ${n}`,
		);
	return n.toString(10);
}

/**
 * Throw if `origin` violates the c2sp.org/tlog-checkpoint §Note text MUSTs:
 * non-empty, no embedded newlines, no Unicode spaces, no plus characters.
 * The "schemeless URL" advice from the spec is SHOULD-level and not
 * enforced here, broader policy belongs to the application layer.
 */
function validateOrigin(origin: string): void {
	if (origin.length === 0)
		throw new RangeError('checkpoint: origin must be non-empty');
	// Unicode space classes are wider than ASCII 0x20; the c2sp spec text
	// says "Unicode spaces", so we use \s which covers the same family.
	if (/\s/.test(origin) || origin.includes('+'))
		throw new RangeError(
			'checkpoint: origin must not contain whitespace or plus characters',
		);
}

/**
 * Serialize a Checkpoint into its canonical body bytes per
 * c2sp.org/tlog-checkpoint §Note text. Layout:
 *
 *     utf8(origin) || 0x0A || utf8(decimal(treeSize)) || 0x0A
 *         || base64(rootHash) || 0x0A
 *
 * Base64 uses the RFC 4648 §4 standard alphabet with `=` padding (NOT the
 * URL-safe variant from §5 and NOT padding-stripped). The body has no
 * leading or trailing whitespace beyond the final 0x0A; byte stability
 * is the entire purpose of the codec, since the body bytes are what the
 * STH signature is computed over.
 */
export function serializeCheckpointBody(c: Checkpoint): Uint8Array {
	validateOrigin(c.origin);
	const originBytes = utf8ToBytes(c.origin);
	const sizeBytes = utf8ToBytes(decimalTreeSize(c.treeSize));
	const rootB64 = bytesToBase64(c.rootHash);
	const rootBytes = utf8ToBytes(rootB64);
	const out = new Uint8Array(originBytes.length + 1 + sizeBytes.length + 1 + rootBytes.length + 1);
	let off = 0;
	out.set(originBytes, off); off += originBytes.length;
	out[off++] = LF;
	out.set(sizeBytes, off); off += sizeBytes.length;
	out[off++] = LF;
	out.set(rootBytes, off); off += rootBytes.length;
	out[off] = LF;
	return out;
}

// ── parsing ─────────────────────────────────────────────────────────────────

/**
 * Reject ASCII control characters below U+0020 other than 0x0A. The
 * signed-note spec at c2sp.org/signed-note §Format prohibits these in the
 * envelope; the checkpoint body inherits the same rule because the body
 * is the prefix of a signed-note text region.
 */
function hasIllegalControls(bytes: Uint8Array): boolean {
	for (const b of bytes) {
		if (b < 0x20 && b !== LF) return true;
		if (b === 0x7f) return true;
	}
	return false;
}

/**
 * Validate that a decimal tree-size string carries no leading zeroes per
 * c2sp.org/tlog-checkpoint §Note text. The literal `"0"` is the sole legal
 * string starting with `0`.
 */
function parseTreeSize(s: string): number {
	if (s.length === 0) throw new RangeError('checkpoint: empty tree-size line');
	if (!/^[0-9]+$/.test(s)) throw new RangeError(`checkpoint: tree size '${s}' is not ASCII decimal`);
	if (s.length > 1 && s.charCodeAt(0) === 0x30 /* '0' */)
		throw new RangeError(`checkpoint: tree size '${s}' has a leading zero`);
	const n = Number(s);
	if (!Number.isInteger(n) || n < 0 || n > Number.MAX_SAFE_INTEGER)
		throw new RangeError(`checkpoint: tree size '${s}' exceeds Number.MAX_SAFE_INTEGER`);
	return n;
}

/**
 * Parse a canonical checkpoint body. Inverse of `serializeCheckpointBody`;
 * round-trips byte-for-byte. Rejects extension lines, leading or trailing
 * whitespace beyond the mandatory final 0x0A, non-newline ASCII control
 * characters, malformed base64, and root hashes whose decoded length does
 * not match `expectedHashLen` (default 32, the size for both Sha256Tree
 * and Blake3Tree).
 *
 * The caller pins `expectedHashLen` to its hasher's `outputSize`; a future
 * SignedLog (TASK-4) will bind this to the tree's hasher automatically.
 *
 * Per c2sp.org/tlog-checkpoint §Note text and c2sp.org/signed-note
 * §Format.
 */
export function parseCheckpointBody(
	bytes: Uint8Array,
	expectedHashLen = 32,
): Checkpoint {
	if (!(bytes instanceof Uint8Array))
		throw new TypeError('parseCheckpointBody: input must be a Uint8Array');
	if (bytes.length === 0)
		throw new RangeError('parseCheckpointBody: empty body');
	if (bytes[bytes.length - 1] !== LF)
		throw new RangeError('parseCheckpointBody: body must end with U+000A');
	if (hasIllegalControls(bytes))
		throw new RangeError('parseCheckpointBody: body contains non-newline ASCII control characters');

	// Collect line offsets without TextDecoder gymnastics, so an embedded
	// newline inside the origin can be caught structurally rather than via
	// post-hoc string checks.
	const lineStarts: number[] = [0];
	for (let i = 0; i < bytes.length; i++) {
		if (bytes[i] === LF && i + 1 < bytes.length) lineStarts.push(i + 1);
	}
	// Three mandatory lines, each newline-terminated, plus the trailing LF
	// at end of body. Extension lines (4th line and beyond) are NOT
	// RECOMMENDED per c2sp.org/tlog-checkpoint §Note text; the ML-DSA-44
	// cosignature format does not sign them, so leviathan rejects them
	// outright to keep the wire format witness-ready end to end.
	if (lineStarts.length !== 3)
		throw new RangeError(
			`parseCheckpointBody: expected exactly 3 lines, got ${lineStarts.length}`,
		);

	// Slice the three lines without their terminating LF.
	const sliceLine = (idx: number): Uint8Array => {
		const start = lineStarts[idx];
		const end = idx + 1 < lineStarts.length ? lineStarts[idx + 1] - 1 : bytes.length - 1;
		return bytes.subarray(start, end);
	};
	const originBytes = sliceLine(0);
	const sizeBytes = sliceLine(1);
	const rootB64Bytes = sliceLine(2);

	if (originBytes.length === 0)
		throw new RangeError('parseCheckpointBody: empty origin line');

	let origin: string;
	try {
		origin = bytesToUtf8(originBytes);
	} catch {
		throw new RangeError('parseCheckpointBody: origin is not valid UTF-8');
	}
	validateOrigin(origin);
	// The byte-level scan caught most disallowed characters above; reject
	// stray SP/PLUS bytes that slipped past the UTF-8 validation in case
	// of a future encoding edge case.
	for (const b of originBytes)
		if (b === SPACE || b === PLUS)
			throw new RangeError('parseCheckpointBody: origin contains space or plus');

	const sizeStr = bytesToUtf8(sizeBytes);
	const treeSize = parseTreeSize(sizeStr);

	const rootB64 = bytesToUtf8(rootB64Bytes);
	// RFC 4648 §4 standard alphabet, with padding. `base64ToBytes` accepts
	// the URL-safe variant and the padding-stripped form; reject both
	// explicitly so the codec stays strictly compliant with
	// c2sp.org/tlog-checkpoint §Conventions. A standard padded base64
	// string always has length divisible by 4.
	if (/[-_]/.test(rootB64))
		throw new RangeError('parseCheckpointBody: root hash uses URL-safe base64');
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(rootB64))
		throw new RangeError('parseCheckpointBody: root hash is not standard base64');
	if (rootB64.length % 4 !== 0)
		throw new RangeError('parseCheckpointBody: root hash base64 length is not a multiple of 4 (padding missing)');
	let rootHash: Uint8Array;
	try {
		rootHash = base64ToBytes(rootB64);
	} catch {
		throw new RangeError('parseCheckpointBody: root hash failed base64 decoding');
	}
	if (rootHash.length !== expectedHashLen)
		throw new RangeError(
			`parseCheckpointBody: root hash length ${rootHash.length} != expected ${expectedHashLen}`,
		);

	return { origin, treeSize, rootHash };
}
