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

// test/vectors/x25519.ts
//
// RFC 7748 known-answer test vectors for X25519. Three records: the §6.1
// Diffie-Hellman exchange between Alice and Bob, plus the §5 iterated
// scalar-mult tests at iter=1 and iter=1000. The §5 iter=1000000 case
// is deliberately omitted as a future optional addition (documented in
// docs/vector_audit.md); the iter=1000 case catches the same correctness
// bugs at a CI-affordable runtime.
//
// Transcribed by hand from the RFC text.
//
// Source:
//   RFC 7748, Elliptic Curves for Security
//   @see https://www.rfc-editor.org/rfc/rfc7748.txt
//   §5    Iterated test vectors (initial k = u = 0x0900..00, run
//         x25519(k, u) → next k, u := old k, for iter iterations)
//   §6.1  Diffie-Hellman exchange
//
// Iterated test loop (RFC 7748 §5.2 in pseudocode):
//   k = 0x0900000000000000000000000000000000000000000000000000000000000000
//   u = 0x0900000000000000000000000000000000000000000000000000000000000000
//   for _ in 0..iter:
//       next = x25519(k, u)
//       u = k
//       k = next
//   assert k == expected_k
//
// The initial value 0x09 || 31 zero bytes is the encoded u-coordinate
// of the X25519 base point (little-endian 9 in the low byte). It is
// not carried as a vector field; the verifier hardcodes it per spec.
//
// All hex strings are lowercase, no separators, matching the RFC text.
//
// Audit status: VERIFIED (independent oracle,
// scripts/verify-vectors/src/x25519.rs against x25519-dalek 2.x using
// the standalone `x25519(scalar, u)` function and `StaticSecret`/`PublicKey`
// for the Diffie-Hellman record).

export interface X25519ExchangeVector {
	kind:        'exchange';
	aliceSkHex:  string;  // 32 bytes, Alice's clamped scalar
	alicePkHex:  string;  // 32 bytes, X25519(a, 9)
	bobSkHex:    string;  // 32 bytes, Bob's clamped scalar
	bobPkHex:    string;  // 32 bytes, X25519(b, 9)
	sharedHex:   string;  // 32 bytes, X25519(a, X25519(b, 9)) = X25519(b, X25519(a, 9))
}

export interface X25519IteratedVector {
	kind:     'iterated';
	iter:     number;     // iteration count
	kHex:     string;     // 32 bytes, expected k after `iter` iterations
}

export type X25519Vector = X25519ExchangeVector | X25519IteratedVector;

/** RFC 7748 §5 + §6.1 KATs for X25519. Alice/Bob exchange + iter=1 + iter=1000. */
export const x25519Vectors: readonly X25519Vector[] = [
	{
		// RFC 7748 §6.1 Curve25519 test vector. Alice and Bob each
		// publish K_X = X25519(x, 9) and compute the shared secret K
		// from the peer's public key and their own private key.
		kind: 'exchange',
		aliceSkHex: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
		alicePkHex: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
		bobSkHex: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
		bobPkHex: 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
		sharedHex: '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
	},
	{
		// RFC 7748 §5 X25519 iterated, after one iteration.
		kind: 'iterated',
		iter: 1,
		kHex: '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079',
	},
	{
		// RFC 7748 §5 X25519 iterated, after 1 000 iterations.
		// iter=1000000 is documented in the spec but deliberately not
		// pinned in this corpus, the runtime is too long for a CI-fast
		// verifier. See docs/vector_audit.md for the rationale.
		kind: 'iterated',
		iter: 1000,
		kHex: '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51',
	},
];
