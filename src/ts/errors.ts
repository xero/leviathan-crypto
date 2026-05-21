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
// src/ts/errors.ts
//
// Typed error classes for leviathan-crypto.

/**
 * Thrown when AEAD authentication fails.
 *
 * `cipher` is the cipher name passed by the call site (e.g. `'serpent'`,
 * `'chacha20-poly1305'`, `'xchacha20-poly1305'`). The class appends
 * `': authentication failed'`, do not include that text in the cipher name.
 */
export class AuthenticationError extends Error {
	constructor(cipher: string) {
		super(`${cipher}: authentication failed`);
		this.name = 'AuthenticationError';
		Object.setPrototypeOf(this, AuthenticationError.prototype);
	}
}

/**
 * Thrown on signing or verification contract violations and signature
 * failures within the v3 sign module.
 *
 * `discriminator` is a stable string identifier for the failure mode;
 * consumers may switch on it. Categories:
 *
 *   Suite layer (suite.sign / verify / signPrehashed / verifyPrehashed):
 *     'sig-key-size'             wrong sk or pk size for the suite
 *     'sig-ctx-too-long'         effective_ctx would exceed the FIPS 204 cap
 *     'sig-ctx-unsupported'      suite has no native context binding (pure Ed25519)
 *     'sig-malformed-input'      primitive validation failure, e.g. wrong digest length
 *
 *   Envelope layer (Sign.sign / verify / signDetached / verifyDetached):
 *     'sig-blob-too-short'       Sign.verify input shorter than minimum
 *     'sig-suite-unknown'        suite_byte does not map to a known suite
 *     'sig-ctx-overflow'         wire ctx_len pushes past sig boundary
 *     'sig-ctx-mismatch'         caller ctx not equal to wire ctx
 *     'verify-failed'            suite.verify returned false during envelope verify
 *
 *   Stream layer (SignStream / VerifyStream):
 *     'sig-stream-finalized'     update() called after finalize()
 *     'sig-stream-disposed'      operation on disposed stream
 *     'sig-suite-mismatch'       wire suite_byte not equal to VerifyStream constructor suite
 */
export class SigningError extends Error {
	constructor(
		public readonly discriminator: string,
		message?: string,
	) {
		super(message ?? `leviathan-crypto SigningError: ${discriminator}`);
		this.name = 'SigningError';
		Object.setPrototypeOf(this, SigningError.prototype);
	}
}

/**
 * Thrown when an X25519 Diffie-Hellman shared secret is all-zero. Per RFC
 * 7748 §6.1 and §7, an all-zero output indicates that the peer's public key
 * is a small-order point on Curve25519 and the resulting shared secret
 * carries no contributory entropy from the local secret. Callers must
 * reject the exchange rather than proceed with a known-weak key.
 */
export class KeyAgreementError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'KeyAgreementError';
		Object.setPrototypeOf(this, KeyAgreementError.prototype);
	}
}

/**
 * Thrown on construction-time contract violations of the normie merkle
 * surface (`MerkleLog`, `MerkleVerifier`). Wraps inputs that fail the
 * c2sp.org/tlog-cosignature §Format algorithm-byte registry check, an
 * unknown `hashing` value, an uninitialised required WASM module, or
 * a public-key length that does not match `suite.pkSize`. Keeps the
 * normie surface error class distinct from the lower-level
 * `SigningError('sig-unsupported-suite')` that `SignedLog` throws so
 * callers can branch cleanly on either class.
 *
 * `discriminator` is a stable string identifier for the failure mode;
 * consumers may switch on it. Documented discriminators:
 *
 *   'unsupported-suite'    suite.formatEnum not in the C2SP cosignature
 *                          algorithm-byte registry
 *   'unsupported-hashing'  hashing argument is not 'sha256' or 'blake3'
 *   'module-not-initialized' a required WASM module has not been init()'d
 *   'pubkey-size'          pubkey.length != suite.pkSize
 *   'origin-invalid'       origin empty, contains whitespace, or contains plus
 */
export class MerkleLogError extends Error {
	constructor(
		public readonly discriminator: string,
		message?: string,
	) {
		super(message ?? `leviathan-crypto MerkleLogError: ${discriminator}`);
		this.name = 'MerkleLogError';
		Object.setPrototypeOf(this, MerkleLogError.prototype);
	}
}

/**
 * Thrown on wire-format contract violations in the merkle module's
 * cosignature codec (c2sp.org/tlog-cosignature §Format and §Signed
 * message). Whole-envelope errors in `parseSignedNote` and
 * `parseCheckpointBody` continue to throw `RangeError` / `TypeError`;
 * this class covers the cosignature-payload layer specifically.
 *
 * `discriminator` is a stable string identifier for the failure mode;
 * consumers may switch on it. Categories:
 *
 *   Cosignature message construction (buildCosigSignedMessage):
 *     'timestamp-out-of-range'         timestamp not a non-negative safe integer
 *
 *   Timestamped-signature payload codec (emit/parseCosigSignaturePayload):
 *     'timestamp-out-of-range'         timestamp not a non-negative safe integer (emit)
 *     'timestamp-exceeds-safe-integer' wire timestamp > Number.MAX_SAFE_INTEGER (parse)
 *     'cosig-payload-length-mismatch'  payload bytes != expected 8 + sigSize
 *
 *   ML-DSA-44 cosigned_message construction (buildCosignedMessage):
 *     'timestamp-out-of-range'         timestamp / start / end not non-negative safe int
 *     'cosigner-name-length'           UTF-8 cosigner_name empty or > 255 bytes
 *     'log-origin-length'              UTF-8 log_origin empty or > 255 bytes
 *     'cosigned-message-state'         start != 0 with timestamp != 0 (spec MUST)
 */
export class MerkleCodecError extends Error {
	constructor(
		public readonly discriminator: string,
		message?: string,
	) {
		super(message ?? `leviathan-crypto MerkleCodecError: ${discriminator}`);
		this.name = 'MerkleCodecError';
		Object.setPrototypeOf(this, MerkleCodecError.prototype);
	}
}
