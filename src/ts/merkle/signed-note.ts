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
// src/ts/merkle/signed-note.ts
//
// Envelope codec for c2sp.org/signed-note §Format and the
// `key_id = SHA-256(name || 0x0A || algo || pubkey)[:4]` derivation
// from c2sp.org/tlog-cosignature §Format.
//
// Algorithm-byte registry, confirmed against C2SP commit
// 3752ba5b3590dc3754e04fcc8369bd3612897c02 (github.com/C2SP/C2SP,
// 2026-04-23):
//
//   Ed25519Suite (formatEnum 0x01)  → C2SP algo byte 0x04
//   MlDsa44Suite (formatEnum 0x03)  → C2SP algo byte 0x06
//
// 0x04 = timestamped Ed25519 cosignatures, 0x06 = timestamped ML-DSA-44
// (sub)tree cosignatures per c2sp.org/tlog-cosignature §Format. Other
// registry bytes (0x01 base Ed25519, 0x02 ECDSA witness, 0x05 RFC 6962
// TreeHeadSignature) are unwired; new suites need an authoritative
// C2SP byte (raise an issue per AGENTS.md, never mint locally).
//
// Cosignature signed messages: `buildCosigSignedMessage` builds the
// Ed25519 form per §"Ed25519 signed message". §"ML-DSA-44 signed
// message" specifies a separate `cosigned_message` TLS-Presentation
// struct; the registry entry below carries
// messageConstruction='cosigned-message' so consumers can branch.

import { MerkleCodecError } from '../errors.js';
import { SHA256 } from '../sha2/index.js';
import {
	utf8ToBytes,
	bytesToUtf8,
	base64ToBytes,
	bytesToBase64,
	concat,
} from '../utils.js';

// ── algorithm-byte registry ─────────────────────────────────────────────────

/**
 * c2sp.org/signed-note §Format signature type for plain Ed25519
 * signatures over the raw note text per RFC 8032. Listed for spec
 * completeness; no leviathan SignatureSuite currently routes here
 * because Phase 7 cosignatures use the timestamped Ed25519 variant
 * (`ALGO_BYTE_ED25519_COSIG`) per c2sp.org/tlog-cosignature §Format.
 */
export const ALGO_BYTE_ED25519_NOTE = 0x01;

/**
 * c2sp.org/tlog-cosignature §Format signature type for timestamped
 * Ed25519 checkpoint cosignatures. The signature payload is
 * `u64_be(timestamp) || ed25519_signature(64)` for a total of 72
 * bytes, base64-encoded together with the 4-byte key ID on the
 * signature line.
 */
export const ALGO_BYTE_ED25519_COSIG = 0x04;

/**
 * c2sp.org/tlog-cosignature §Format signature type for timestamped
 * ML-DSA-44 (sub)tree cosignatures. The signature payload is
 * `u64_be(timestamp) || ml_dsa_44_signature(2420)` for a total of
 * 2428 bytes, base64-encoded together with the 4-byte key ID.
 */
export const ALGO_BYTE_MLDSA44_COSIG = 0x06;

/**
 * How the cosigner constructs the bytes it signs.
 *
 *   'cosig'             c2sp.org/tlog-cosignature §"Ed25519 signed
 *                       message". Produced by `buildCosigSignedMessage`.
 *   'cosigned-message'  c2sp.org/tlog-cosignature §"ML-DSA-44 signed
 *                       message", `cosigned_message` struct.
 */
export type MessageConstruction = 'cosig' | 'cosigned-message';

/**
 * Per-signature payload encoding bundled with the 4-byte key ID.
 *
 *   'timestamped'  c2sp.org/tlog-cosignature §Format
 *                  `timestamped_signature` struct, shared by 0x04 and 0x06.
 */
export type SignaturePayload = 'timestamped';

/**
 * Per c2sp.org/tlog-cosignature §Format algorithm-byte registry. One
 * entry per registered (leviathan suite, C2SP byte) pair; the entry
 * carries the message-construction and payload-encoding rules a
 * cosigner needs to sign and a verifier needs to parse.
 */
export interface AlgoEntry {
	/** Leviathan `SignatureSuite.formatEnum`. */
	readonly formatEnum: number;
	/** C2SP signed-note algorithm byte from §Format. */
	readonly algoByte: number;
	/** How the cosigner constructs the bytes it signs. */
	readonly messageConstruction: MessageConstruction;
	/** How the per-signature payload is encoded on the signature line. */
	readonly signaturePayload: SignaturePayload;
	/**
	 * Raw signature size in bytes from the underlying primitive. For
	 * Ed25519 this is 64 (RFC 8032 §5.1.6); for ML-DSA-44 this is
	 * 2420 (FIPS 204 Table 1). The `timestamped` payload encoding
	 * adds an 8-byte BE timestamp prefix per `timestamped_signature`,
	 * so the total payload length on the wire is `8 + sigSize`.
	 */
	readonly sigSize: number;
}

/**
 * c2sp.org/tlog-cosignature §Format algorithm-byte catalog. Future
 * spec additions extend the constants and this array. Both the
 * emitter and the verifier consult this single table; suites without
 * an entry cannot be used to derive a signed-note key ID and cannot
 * be cosigned through this codec.
 */
const ALGO_REGISTRY: readonly AlgoEntry[] = Object.freeze([
	Object.freeze({
		formatEnum: 0x01,
		algoByte: ALGO_BYTE_ED25519_COSIG,
		messageConstruction: 'cosig' as MessageConstruction,
		signaturePayload: 'timestamped' as SignaturePayload,
		sigSize: 64,
	}),
	Object.freeze({
		formatEnum: 0x03,
		algoByte: ALGO_BYTE_MLDSA44_COSIG,
		messageConstruction: 'cosigned-message' as MessageConstruction,
		signaturePayload: 'timestamped' as SignaturePayload,
		sigSize: 2420,
	}),
]);

/**
 * Look up the algo-entry for a leviathan `SignatureSuite.formatEnum`.
 * Returns `undefined` for suites not registered in the catalog;
 * callers that need a hard guarantee should check the return value
 * and raise an issue per AGENTS.md rather than locally mint a byte
 * for a suite the C2SP spec has not registered.
 */
export function lookupAlgoEntryByFormatEnum(formatEnum: number): AlgoEntry | undefined {
	for (const e of ALGO_REGISTRY)
		if (e.formatEnum === formatEnum) return e;
	return undefined;
}

/**
 * Look up the algo-entry for a wire-format C2SP algorithm byte. Used
 * by verifiers that see an unknown signature line and need to decide
 * how to reshape the payload (or whether to defer to
 * `parseSignedNote`'s "unknown signatures MUST be ignored" rule).
 */
export function lookupAlgoEntryByByte(algoByte: number): AlgoEntry | undefined {
	for (const e of ALGO_REGISTRY)
		if (e.algoByte === algoByte) return e;
	return undefined;
}

/**
 * Resolve a leviathan SignatureSuite formatEnum to its C2SP signed-note
 * algorithm byte. Thin shim over `lookupAlgoEntryByFormatEnum`; kept for
 * the call sites that only need the byte (e.g. `deriveKeyId` callers).
 */
export function suiteFormatEnumToAlgoByte(formatEnum: number): number | undefined {
	return lookupAlgoEntryByFormatEnum(formatEnum)?.algoByte;
}

// ── key-ID derivation ───────────────────────────────────────────────────────

const LF = 0x0a;
const SPACE = 0x20;
const PLUS = 0x2b;

// UTF-8 encoding of em dash (U+2014) followed by space (U+0020), the
// fixed prefix on every signed-note signature line per
// c2sp.org/signed-note §Format.
const EMDASH_SPACE = new Uint8Array([0xe2, 0x80, 0x94, 0x20]);

/**
 * Per c2sp.org/signed-note §Signatures and c2sp.org/tlog-cosignature
 * §Format, the recommended key ID is:
 *
 *     key_id = SHA-256(utf8(name) || 0x0A || algo_byte || pubkey)[:4]
 *
 * The leading newline byte is U+000A (0x0A); `algo_byte` is the
 * signature-type identifier from `c2sp.org/signed-note` §Signatures
 * §Signature types. The key ID is intentionally short (4 bytes); it
 * is an identifier, not a collision-resistant hash, and key ID
 * collisions only produce verification failures, not forgeries (the
 * verifier holds the authoritative public key).
 *
 * Acquires the sha2 module per call inside try / finally and disposes;
 * does not hold long-lived state. The `name` argument must satisfy the
 * signed-note key-name MUSTs (non-empty, no Unicode whitespace, no
 * plus characters).
 */
export function deriveKeyId(
	name: string,
	algoByte: number,
	pubkey: Uint8Array,
): Uint8Array {
	if (name.length === 0)
		throw new RangeError('deriveKeyId: name must be non-empty');
	if (/\s/.test(name) || name.includes('+'))
		throw new RangeError(
			'deriveKeyId: name must not contain whitespace or plus characters',
		);
	if (!Number.isInteger(algoByte) || algoByte < 0 || algoByte > 0xff)
		throw new RangeError(`deriveKeyId: algoByte must be a byte in [0, 255], got ${algoByte}`);
	if (!(pubkey instanceof Uint8Array))
		throw new TypeError('deriveKeyId: pubkey must be a Uint8Array');

	const nameBytes = utf8ToBytes(name);
	const preimage = new Uint8Array(nameBytes.length + 1 + 1 + pubkey.length);
	let off = 0;
	preimage.set(nameBytes, off); off += nameBytes.length;
	preimage[off++] = LF;
	preimage[off++] = algoByte;
	preimage.set(pubkey, off);

	const h = new SHA256();
	try {
		const digest = h.hash(preimage);
		return digest.subarray(0, 4);
	} finally {
		h.dispose();
	}
}

// ── signed-note envelope types ──────────────────────────────────────────────

/**
 * Decoded signed-note signature line per c2sp.org/signed-note §Format.
 * `name` is the verified UTF-8 key name from the line; `keyId` is the
 * 4-byte prefix extracted from the base64 payload; `signature` is the
 * remaining bytes after the prefix, opaque to the parser (the format
 * is defined by whatever algorithm corresponds to this key, which the
 * parser does not look up).
 */
export interface SignatureLine {
	readonly name: string;
	readonly keyId: Uint8Array;
	readonly signature: Uint8Array;
}

/**
 * Decoded signed-note envelope. `body` includes the body's terminating
 * U+000A but NOT the blank line that separates body from signatures;
 * `signatures` contains every signature line that parsed structurally;
 * `ignoredCount` is the number of signature lines that failed structural
 * validation and were discarded per the signed-note §Signatures rule
 * that unknown signatures MUST be ignored.
 */
export interface SignedNote {
	readonly body: Uint8Array;
	readonly signatures: SignatureLine[];
	readonly ignoredCount: number;
}

// ── envelope emit ───────────────────────────────────────────────────────────

/**
 * Emit a signed-note envelope per c2sp.org/signed-note §Format. The
 * caller supplies the body bytes (which MUST end in U+000A; the
 * checkpoint body codec already enforces this) and one or more
 * signature lines. The wire layout is:
 *
 *     body || '\n' || (— name b64(keyId||sig) '\n')+
 *
 * The blank line that separates body from signature lines is the
 * extra newline between the body's own trailing newline and the
 * first signature line; both `serializeCheckpointBody` and this
 * function MUST agree on this convention.
 *
 * Throws RangeError on a body that does not end in U+000A, on an
 * empty signatures array, or on any signature whose key name violates
 * the signed-note key-name MUSTs.
 */
export function emitSignedNote(
	body: Uint8Array,
	sigs: readonly SignatureLine[],
): Uint8Array {
	if (!(body instanceof Uint8Array))
		throw new TypeError('emitSignedNote: body must be a Uint8Array');
	if (body.length === 0 || body[body.length - 1] !== LF)
		throw new RangeError('emitSignedNote: body must end with U+000A');
	if (sigs.length === 0)
		throw new RangeError('emitSignedNote: at least one signature line is required');

	const sigLines: Uint8Array[] = [];
	for (const s of sigs) {
		validateSigName(s.name);
		if (s.keyId.length !== 4)
			throw new RangeError(`emitSignedNote: keyId must be 4 bytes, got ${s.keyId.length}`);
		const payload = concat(s.keyId, s.signature);
		const lineText = `${bytesToUtf8(EMDASH_SPACE)}${s.name} ${bytesToBase64(payload)}\n`;
		sigLines.push(utf8ToBytes(lineText));
	}
	// Body's trailing 0x0A is line N's terminator; the explicit extra
	// 0x0A here is the blank separator line required by signed-note
	// §Format.
	return concat(body, new Uint8Array([LF]), ...sigLines);
}

function validateSigName(name: string): void {
	if (name.length === 0)
		throw new RangeError('signed-note: signature name must be non-empty');
	if (/\s/.test(name) || name.includes('+'))
		throw new RangeError(
			'signed-note: signature name must not contain whitespace or plus characters',
		);
}

// ── envelope parse ──────────────────────────────────────────────────────────

/**
 * Parse a signed-note envelope per c2sp.org/signed-note §Format. The
 * input must be valid UTF-8 and MUST NOT contain ASCII control
 * characters below U+0020 other than newline. The body is everything
 * up to and including the first blank line, MINUS the blank line
 * itself, MINUS the newline that immediately precedes the blank line
 * (no, including it; see body convention below).
 *
 * Per the body convention in `emitSignedNote`, the returned `body`
 * field includes the body's terminating U+000A but excludes the
 * blank-line separator.
 *
 * Signature-line parsing is permissive: a line that does not match
 * `— <name> <base64>\n` exactly, or whose base64 payload decodes to
 * fewer than 4 bytes (no room for a key ID), is counted in
 * `ignoredCount` and discarded rather than throwing. The signed-note
 * §Signatures rule is that unknown signatures MUST be ignored, and
 * "unknown" subsumes any line a future spec extension might add in
 * a format leviathan does not recognize.
 *
 * Whole-envelope structural errors (missing blank separator, body
 * not ending in newline, ASCII control bytes, invalid UTF-8) throw
 * RangeError. The behaviour of "throw on envelope, ignore on line"
 * is what makes the codec forward-compatible with future cosignature
 * algorithms without changing the byte-stable body region.
 */
export function parseSignedNote(bytes: Uint8Array): SignedNote {
	if (!(bytes instanceof Uint8Array))
		throw new TypeError('parseSignedNote: input must be a Uint8Array');
	if (bytes.length === 0)
		throw new RangeError('parseSignedNote: empty input');
	for (const b of bytes) {
		if (b < 0x20 && b !== LF)
			throw new RangeError('parseSignedNote: input contains non-newline ASCII control bytes');
		if (b === 0x7f)
			throw new RangeError('parseSignedNote: input contains DEL (0x7F)');
	}

	// Locate the LAST blank line that separates body from signatures.
	// Per c2sp.org/signed-note §Format: "The note text MAY contain
	// empty lines; the text is separated from the signatures by the
	// last empty line in the note." A blank line is a 0x0A immediately
	// followed by another 0x0A within the envelope. Scan forward
	// looking at every 0x0A 0x0A pair, but keep updating to the last
	// one whose successor line opens with the em dash prefix; the
	// signatures region MUST be non-empty per spec.
	const sigStart = locateSignaturesStart(bytes);

	// Body includes the LF that terminates its last text line; this
	// matches the c2sp.org/signed-note §Format requirement that the
	// note text "ends in newline (U+000A)".
	const body = bytes.subarray(0, sigStart - 1);
	if (body.length === 0 || body[body.length - 1] !== LF)
		throw new RangeError('parseSignedNote: body must end with U+000A');

	// Sanity-check the body region for valid UTF-8 here so a partial
	// envelope is caught before any signature work happens.
	try {
		bytesToUtf8(body);
	} catch {
		throw new RangeError('parseSignedNote: body is not valid UTF-8');
	}

	const sigRegion = bytes.subarray(sigStart);
	if (sigRegion.length === 0)
		throw new RangeError('parseSignedNote: signature region is empty');
	if (sigRegion[sigRegion.length - 1] !== LF)
		throw new RangeError('parseSignedNote: signature region must end with U+000A');

	const signatures: SignatureLine[] = [];
	let ignoredCount = 0;
	let lineStart = 0;
	for (let i = 0; i < sigRegion.length; i++) {
		if (sigRegion[i] !== LF) continue;
		const line = sigRegion.subarray(lineStart, i);
		lineStart = i + 1;
		// An empty line inside the signatures region is impossible by
		// construction: `locateSignaturesStart` already advanced past
		// the LAST blank line per c2sp.org/signed-note §Format, so any
		// remaining 0x0A 0x0A pair would have been chosen as the
		// separator instead.
		if (line.length === 0) continue;
		const parsed = tryParseSignatureLine(line);
		if (parsed) signatures.push(parsed);
		else ignoredCount++;
	}

	return { body, signatures, ignoredCount };
}

/**
 * Locate the byte offset where the signatures region starts. Per
 * c2sp.org/signed-note §Format the note text "MAY contain empty lines;
 * the text is separated from the signatures by the last empty line in
 * the note." Concretely: walk every 0x0A 0x0A pair in the input, take
 * the LAST one, and the signatures region begins at the byte after
 * the second 0x0A.
 *
 * The choice of "last blank line" is what makes the codec accept
 * bodies that themselves contain empty lines (e.g., a free-form text
 * note with a stanza break). The signatures region MUST be non-empty
 * per §Format ("followed by one or more signature lines"), so a final
 * blank line with no following bytes throws.
 */
function locateSignaturesStart(bytes: Uint8Array): number {
	let last = -1;
	for (let i = 0; i + 1 < bytes.length; i++) {
		if (bytes[i] === LF && bytes[i + 1] === LF) last = i + 2;
	}
	if (last < 0)
		throw new RangeError('parseSignedNote: no blank-line separator between body and signatures');
	if (last >= bytes.length)
		throw new RangeError('parseSignedNote: signature region is empty');
	return last;
}

function lineStartsWithPrefix(buf: Uint8Array, start: number, prefix: Uint8Array): boolean {
	if (start + prefix.length > buf.length) return false;
	for (let i = 0; i < prefix.length; i++)
		if (buf[start + i] !== prefix[i]) return false;
	return true;
}

/**
 * Attempt to parse one signature line per c2sp.org/signed-note §Format:
 *
 *     — <key name> <base64(key_id || signature)>
 *
 * Returns `null` on any structural defect (no em dash + space prefix,
 * empty key name, no second space, malformed base64, base64 payload
 * shorter than 4 bytes). The caller counts `null` returns in
 * `ignoredCount` per the signed-note §Signatures rule that unknown
 * signatures MUST be ignored.
 */
function tryParseSignatureLine(line: Uint8Array): SignatureLine | null {
	if (!lineStartsWithPrefix(line, 0, EMDASH_SPACE)) return null;
	const rest = line.subarray(EMDASH_SPACE.length);
	// Name is everything up to the first 0x20; the base64 payload
	// follows. Per signed-note §Format the key name MUST be non-empty
	// and MUST NOT contain Unicode spaces or plus characters; rejecting
	// here keeps the parser symmetric with the emitter.
	let spaceAt = -1;
	for (let i = 0; i < rest.length; i++) {
		if (rest[i] === SPACE) {
			spaceAt = i; break;
		}
		if (rest[i] === PLUS) return null;
	}
	if (spaceAt <= 0) return null;

	const nameBytes = rest.subarray(0, spaceAt);
	const b64Bytes = rest.subarray(spaceAt + 1);
	if (b64Bytes.length === 0) return null;

	let name: string;
	try {
		name = bytesToUtf8(nameBytes);
	} catch {
		return null;
	}
	// One last guard: bytes-level scan caught SP/PLUS in the name; a
	// UTF-8 codepoint that decodes to a different whitespace class
	// (NBSP, ideographic space, etc.) is still spec-forbidden.
	if (/\s/.test(name)) return null;

	let b64: string;
	try {
		b64 = bytesToUtf8(b64Bytes);
	} catch {
		return null;
	}
	// Standard alphabet per RFC 4648 §4 only. URL-safe characters are
	// rejected for consistency with the checkpoint body codec; the
	// signed-note spec also references §4, not §5.
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) return null;

	let payload: Uint8Array;
	try {
		payload = base64ToBytes(b64);
	} catch {
		return null;
	}
	if (payload.length < 4) return null;

	return {
		name,
		keyId: payload.subarray(0, 4),
		signature: payload.subarray(4),
	};
}

// ── cosignature signed-message construction ─────────────────────────────────

// `cosignature/v1\ntime ` UTF-8, the fixed prefix of the Ed25519
// cosignature signed message per c2sp.org/tlog-cosignature §"Ed25519
// signed message" (header + timestamp opener).
const COSIG_V1_PREFIX = utf8ToBytes('cosignature/v1\ntime ');
const TIME_LINE_TERMINATOR = new Uint8Array([LF]);

/**
 * Reject timestamps that cannot round-trip through u64-BE without
 * precision loss. Spec allows `<= 2^63 - 1`
 * (c2sp.org/tlog-cosignature §Format); leviathan uses Number, so the
 * effective cap is Number.MAX_SAFE_INTEGER (2^53 - 1).
 */
function assertSafeTimestamp(timestamp: number): void {
	if (!Number.isInteger(timestamp) || timestamp < 0 || timestamp > Number.MAX_SAFE_INTEGER)
		throw new MerkleCodecError(
			'timestamp-out-of-range',
			`timestamp ${timestamp} must be a non-negative safe integer`,
		);
}

/**
 * Build the bytes a cosigner signs when issuing a cosignature for a
 * checkpoint, per c2sp.org/tlog-cosignature §"Ed25519 signed message".
 *
 * Layout (each `\n` is U+000A):
 *
 *     cosignature/v1\n
 *     time <decimal_timestamp>\n
 *     <body>
 *
 * `body` is the canonical checkpoint body produced by
 * `serializeCheckpointBody` and already terminates in `\n`; the
 * function adds no separator between the timestamp line and the
 * body. Decimal carries no leading zeroes per the §Format rule on
 * the timestamp line (mirrored from checkpoint §Note text).
 *
 * Spec-correct only for Ed25519 cosignatures (C2SP algo byte 0x04).
 * ML-DSA-44 cosignatures sign the separate `cosigned_message` struct
 * defined in §"ML-DSA-44 signed message" (codec not in this patch);
 * callers reaching for this function with an ML-DSA-44 suite are
 * producing the wrong wire format and should branch on the
 * `messageConstruction` field of the suite's `AlgoEntry`.
 *
 * Throws `MerkleCodecError('timestamp-out-of-range')` if `timestamp`
 * is not a non-negative safe integer.
 */
export function buildCosigSignedMessage(
	body: Uint8Array,
	timestamp: number,
): Uint8Array {
	if (!(body instanceof Uint8Array))
		throw new TypeError('buildCosigSignedMessage: body must be a Uint8Array');
	if (body.length === 0 || body[body.length - 1] !== LF)
		throw new RangeError('buildCosigSignedMessage: body must end with U+000A');
	assertSafeTimestamp(timestamp);
	const tsBytes = utf8ToBytes(timestamp.toString(10));
	return concat(COSIG_V1_PREFIX, tsBytes, TIME_LINE_TERMINATOR, body);
}

// ── timestamped_signature payload codec ─────────────────────────────────────

/**
 * Encode the `timestamped_signature` struct payload per
 * c2sp.org/tlog-cosignature §Format. Layout (per RFC 8446 §3.3,
 * Presentation Language; integers in network byte order):
 *
 *     u64_be(timestamp) || signature[N]
 *
 * The result is the opaque payload portion of a signed-note signature
 * line: prefixed by the 4-byte key ID and then base64-encoded by
 * `emitSignedNote`. `signature` length is suite-dependent (64 for
 * Ed25519, 2420 for ML-DSA-44); the encoder does not validate length
 * here because both registry-allowed sizes round-trip correctly.
 *
 * Throws `MerkleCodecError('timestamp-out-of-range')` if `timestamp`
 * is not a non-negative safe integer.
 */
export function emitCosigSignaturePayload(
	timestamp: number,
	signature: Uint8Array,
): Uint8Array {
	if (!(signature instanceof Uint8Array))
		throw new TypeError('emitCosigSignaturePayload: signature must be a Uint8Array');
	assertSafeTimestamp(timestamp);
	const out = new Uint8Array(8 + signature.length);
	writeU64Be(out, 0, timestamp);
	out.set(signature, 8);
	return out;
}

function writeU64Be(out: Uint8Array, off: number, value: number): void {
	const hi = Math.floor(value / 0x100000000);
	const lo = value >>> 0;
	out[off    ] = (hi >>> 24) & 0xff;
	out[off + 1] = (hi >>> 16) & 0xff;
	out[off + 2] = (hi >>>  8) & 0xff;
	out[off + 3] =  hi         & 0xff;
	out[off + 4] = (lo >>> 24) & 0xff;
	out[off + 5] = (lo >>> 16) & 0xff;
	out[off + 6] = (lo >>>  8) & 0xff;
	out[off + 7] =  lo         & 0xff;
}

/**
 * Decode a `timestamped_signature` payload per c2sp.org/tlog-cosignature
 * §Format. Inverse of `emitCosigSignaturePayload`; round-trips
 * byte-for-byte.
 *
 * `sigSize` is suite-locked (64 for Ed25519, 2420 for ML-DSA-44); the
 * caller supplies it via the suite's `AlgoEntry.sigSize`. The decoder
 * asserts `payload.length === 8 + sigSize` and throws
 * `MerkleCodecError('cosig-payload-length-mismatch')` otherwise so a
 * wrong-length payload fails loudly rather than producing a silently
 * truncated signature.
 *
 * The wire timestamp is u64-BE; values exceeding `Number.MAX_SAFE_INTEGER`
 * cannot round-trip through JavaScript Number and throw
 * `MerkleCodecError('timestamp-exceeds-safe-integer')`. The cutoff is
 * `tsHi >= 0x200000` (i.e. `2^53 / 2^32`).
 */
export function parseCosigSignaturePayload(
	payload: Uint8Array,
	sigSize: number,
): { timestamp: number; signature: Uint8Array } {
	if (!(payload instanceof Uint8Array))
		throw new TypeError('parseCosigSignaturePayload: payload must be a Uint8Array');
	if (!Number.isInteger(sigSize) || sigSize < 0)
		throw new RangeError(
			`parseCosigSignaturePayload: sigSize must be a non-negative integer, got ${sigSize}`,
		);
	if (payload.length !== 8 + sigSize)
		throw new MerkleCodecError(
			'cosig-payload-length-mismatch',
			`payload length ${payload.length} != expected 8 + sigSize (${8 + sigSize})`,
		);
	const tsHi =
		((payload[0] << 24) |
		 (payload[1] << 16) |
		 (payload[2] <<  8) |
		 (payload[3]      )) >>> 0;
	const tsLo =
		((payload[4] << 24) |
		 (payload[5] << 16) |
		 (payload[6] <<  8) |
		 (payload[7]      )) >>> 0;
	// 0x200000 = 2^53 / 2^32; tsHi at or above this overflows
	// Number safe-integer precision.
	if (tsHi >= 0x200000)
		throw new MerkleCodecError(
			'timestamp-exceeds-safe-integer',
			`wire timestamp high32 ${tsHi} exceeds Number.MAX_SAFE_INTEGER / 2^32`,
		);
	const timestamp = tsHi * 0x100000000 + tsLo;
	const signature = payload.subarray(8, 8 + sigSize);
	return { timestamp, signature };
}

// ── ML-DSA-44 cosigned_message construction ─────────────────────────────────

// Fixed 12-byte label per c2sp.org/tlog-cosignature §"ML-DSA-44 signed
// message". The spec text reads `subtree/v1\n\0`; the literal bytes
// are the 10 ASCII characters of "subtree/v1", a 0x0A newline, and a
// 0x00 nul terminator (12 bytes total). The label appears verbatim
// for every cosignature regardless of whether the signed range is a
// full checkpoint (start=0) or a non-zero-start subtree.
const COSIGNED_MESSAGE_LABEL = new Uint8Array([
	0x73, 0x75, 0x62, 0x74, 0x72, 0x65, 0x65, 0x2f,  // "subtree/"
	0x76, 0x31,                                      // "v1"
	0x0a,                                            // "\n"
	0x00,                                            // "\0"
]);

/**
 * Inputs to `buildCosignedMessage`, one named field per `cosigned_message`
 * struct member from c2sp.org/tlog-cosignature §"ML-DSA-44 signed
 * message". `start` and `end` are numbers in [0, Number.MAX_SAFE_INTEGER];
 * they encode on the wire as big-endian u64. `hash` is exactly 32 bytes.
 */
export interface CosignedMessageInput {
	/**
	 * UTF-8 cosigner identity, 1-255 bytes after encoding. For a log's
	 * cosignature on its own checkpoint this matches `logOrigin`; for a
	 * witness cosignature it identifies the witness.
	 */
	readonly cosignerName: string;
	/**
	 * POSIX-seconds timestamp. Per c2sp.org/tlog-cosignature §"ML-DSA-44
	 * signed message", `timestamp` MUST be zero when `start` is not
	 * zero (subtree case); both MAY be zero (the cosigner is making no
	 * statement about being the largest observed tree).
	 */
	readonly timestamp: number;
	/**
	 * UTF-8 log identity, 1-255 bytes after encoding. Matches the
	 * checkpoint body's origin line (without the trailing newline).
	 */
	readonly logOrigin: string;
	/**
	 * Index of the first leaf included in the signed range. MUST be 0
	 * for a checkpoint cosignature; non-zero only for subtree
	 * cosignatures (out of Phase 7 scope but supported by the codec).
	 */
	readonly start: number;
	/**
	 * Exclusive upper bound of the leaf indexes in the signed range.
	 * For a checkpoint cosignature, equals the tree size.
	 */
	readonly end: number;
	/** 32-byte Merkle root hash of the signed range. */
	readonly hash: Uint8Array;
}

/**
 * Build the bytes a cosigner signs when issuing an ML-DSA-44
 * cosignature, per c2sp.org/tlog-cosignature §"ML-DSA-44 signed
 * message". Layout (TLS-Presentation per RFC 8446 §3.3, lengths in
 * big-endian network order):
 *
 *     uint8 label[12] = "subtree/v1\n\0"
 *     opaque cosigner_name<1..2^8-1>
 *     uint64 timestamp
 *     opaque log_origin<1..2^8-1>
 *     uint64 start
 *     uint64 end
 *     uint8 hash[32]
 *
 * Total length is `70 + utf8(cosignerName).length + utf8(logOrigin).length`.
 *
 * Spec-correct for both checkpoint (start=0) and subtree (start>0)
 * ML-DSA-44 cosignatures. Phase 7 uses only the checkpoint case;
 * subtree cosignatures land with the witness-protocol work. The
 * codec is agnostic so future TASKs do not re-cut the surface.
 *
 * Throws `MerkleCodecError`:
 *   'timestamp-out-of-range'  timestamp / start / end not safe non-negative
 *   'cosigner-name-length'    UTF-8 cosignerName empty or > 255 bytes
 *   'log-origin-length'       UTF-8 logOrigin empty or > 255 bytes
 *   'cosigned-message-state'  start > 0 and timestamp != 0 (spec MUST)
 *
 * Throws `RangeError` on a `hash` whose length is not 32 (the
 * `cosigned_message.hash` field is fixed-length per the struct).
 */
export function buildCosignedMessage(input: CosignedMessageInput): Uint8Array {
	const { cosignerName, timestamp, logOrigin, start, end, hash } = input;

	assertSafeTimestamp(timestamp);
	// Reuse the same safe-integer guard for start / end; the spec
	// allows up to 2^63 - 1 per §Format, the leviathan surface caps
	// at 2^53 - 1 to keep Number-based math precise.
	if (!Number.isInteger(start) || start < 0 || start > Number.MAX_SAFE_INTEGER)
		throw new MerkleCodecError(
			'timestamp-out-of-range',
			`cosigned_message.start ${start} must be a non-negative safe integer`,
		);
	if (!Number.isInteger(end) || end < 0 || end > Number.MAX_SAFE_INTEGER)
		throw new MerkleCodecError(
			'timestamp-out-of-range',
			`cosigned_message.end ${end} must be a non-negative safe integer`,
		);

	const cosignerBytes = utf8ToBytes(cosignerName);
	if (cosignerBytes.length === 0 || cosignerBytes.length > 0xff)
		throw new MerkleCodecError(
			'cosigner-name-length',
			`cosigned_message.cosigner_name UTF-8 length ${cosignerBytes.length} must be in [1, 255]`,
		);
	const originBytes = utf8ToBytes(logOrigin);
	if (originBytes.length === 0 || originBytes.length > 0xff)
		throw new MerkleCodecError(
			'log-origin-length',
			`cosigned_message.log_origin UTF-8 length ${originBytes.length} must be in [1, 255]`,
		);

	if (!(hash instanceof Uint8Array))
		throw new TypeError('buildCosignedMessage: hash must be a Uint8Array');
	if (hash.length !== 32)
		throw new RangeError(
			`buildCosignedMessage: cosigned_message.hash must be 32 bytes, got ${hash.length}`,
		);

	// Per c2sp.org/tlog-cosignature §"ML-DSA-44 signed message": if
	// start is non-zero the cosignature is for a subtree (not a
	// checkpoint) and timestamp MUST be zero. The reverse case
	// (start = 0 with timestamp = 0) is allowed: the cosigner makes
	// no statement about observation time.
	if (start !== 0 && timestamp !== 0)
		throw new MerkleCodecError(
			'cosigned-message-state',
			'cosigned_message with start != 0 (subtree cosignature) requires timestamp == 0',
		);

	const totalLen =
		COSIGNED_MESSAGE_LABEL.length
		+ 1 + cosignerBytes.length
		+ 8
		+ 1 + originBytes.length
		+ 8 + 8
		+ hash.length;
	const out = new Uint8Array(totalLen);
	let off = 0;
	out.set(COSIGNED_MESSAGE_LABEL, off); off += COSIGNED_MESSAGE_LABEL.length;
	// opaque cosigner_name<1..2^8-1>: 1-byte length prefix per RFC 8446
	// §3.4 (variable-length vector with the smallest length encoding
	// that holds 2^8 - 1).
	out[off++] = cosignerBytes.length;
	out.set(cosignerBytes, off); off += cosignerBytes.length;
	writeU64Be(out, off, timestamp); off += 8;
	out[off++] = originBytes.length;
	out.set(originBytes, off); off += originBytes.length;
	writeU64Be(out, off, start); off += 8;
	writeU64Be(out, off, end); off += 8;
	out.set(hash, off);
	return out;
}
