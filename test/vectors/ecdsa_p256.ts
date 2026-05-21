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

// test/vectors/ecdsa_p256.ts
//
// RFC 6979 §A.2.5 deterministic ECDSA test vectors (NIST P-256, SHA-256).
//
// Source:
//   RFC 6979, Appendix A.2.5, "ECDSA, 256 Bits (Prime Field)"
//   @see https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5
//
// The deterministic-K gate corpus. ACVP ECDSA-SigGen-FIPS186-5 supplies an
// explicit per-record `k` and therefore cannot exercise RFC 6979's k-from-
// (d, H(m)) derivation; only this corpus does. FIPS 186-5 §6.4.1 mandates
// RFC 6979 as the conforming deterministic ECDSA construction, so the
// derivation under test here is the same one §6.4.1 references.
//
// 2 records: the (msg, k, r, s) tuples from §A.2.5 for SHA-256 over the
// two RFC-supplied messages ('sample' and 'test'). The fixed key
// `RFC6979_P256_KEY` is the §A.2.5 keypair (x, Ux, Uy); the verifier
// threads it through every record.
//
// Hex casing: uppercase, matching the on-the-wire form printed in the RFC.
// utf8ToBytes is applied to msgUtf8 at test time; the field carries the
// literal ASCII string as printed in the RFC, not its hex encoding, so the
// transcription is human-checkable against §A.2.5 verbatim.

export const RFC6979_P256_KEY = {
	// RFC 6979 §A.2.5: private key x (the scalar `d` for §A.2.5's signer).
	xHex: 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721',
	// Public point U = xG, uncompressed (Ux, Uy) per SEC1 §2.3.3.
	uxHex: '60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
	uyHex: '7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
} as const;

export interface Rfc6979P256Vector {
	id:      string; // RFC's message-naming convention: 'sample' | 'test'
	msgUtf8: string; // ASCII message string; utf8ToBytes inside the test
	hashAlg: 'SHA-256';
	kHex:    string; // 32 bytes: RFC-supplied deterministic nonce
	rHex:    string; // 32 bytes
	sHex:    string; // 32 bytes
}

export const ecdsa_p256_rfc6979: Rfc6979P256Vector[] = [
	{
		id: 'sample',
		msgUtf8: 'sample',
		hashAlg: 'SHA-256',
		kHex: 'A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60',
		rHex: 'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716',
		sHex: 'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8',
	},
	{
		id: 'test',
		msgUtf8: 'test',
		hashAlg: 'SHA-256',
		kHex: 'D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0',
		rHex: 'F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367',
		sHex: '019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083',
	},
];
