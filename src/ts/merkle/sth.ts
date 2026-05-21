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
// src/ts/merkle/sth.ts
//
// SignedTreeHead type: a c2sp.org/tlog-checkpoint body plus the
// signature lines that authenticate it. The body and signatures pair
// is the wire-format unit a SignedLog (built on top of MerkleTree in
// a later phase) produces and a verifier consumes. The byte-stable
// serialization is `emitSignedNote(serializeCheckpointBody(c), sigs)`;
// the parse side is `parseSignedNote` followed by `parseCheckpointBody`
// on the resulting body region.

import type { Checkpoint } from './checkpoint.js';
import type { SignatureLine } from './signed-note.js';

/**
 * In-memory pairing of a parsed Checkpoint, the signature lines
 * extracted from its signed-note envelope, and the primary log
 * signature's POSIX-seconds timestamp.
 *
 * The wire format is the concatenation of
 * `serializeCheckpointBody(checkpoint)` and the emitted signature
 * lines per c2sp.org/signed-note §Format. Each signature line's
 * opaque payload is a `timestamped_signature` struct per
 * c2sp.org/tlog-cosignature §Format; the `timestamp` field surfaced
 * here is the one extracted from the primary log signature (the
 * signature line whose `name` matches the checkpoint origin). For
 * checkpoints with additional witness cosignatures, each witness
 * carries its own timestamp inside its own signature line's payload
 * and is accessed by re-parsing that line via
 * `parseCosigSignaturePayload`.
 */
export interface SignedTreeHead {
	readonly checkpoint: Checkpoint;
	readonly signatures: readonly SignatureLine[];
	/**
	 * POSIX-seconds timestamp the primary log cosignature was issued
	 * at, per the `timestamped_signature` struct in
	 * c2sp.org/tlog-cosignature §Format. Non-negative safe integer;
	 * see `parseCosigSignaturePayload` for the upper-bound semantics
	 * (Number-safe range, smaller than the spec's `2^63 - 1` ceiling).
	 */
	readonly timestamp: number;
}
