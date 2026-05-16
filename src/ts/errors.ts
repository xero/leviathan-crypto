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
