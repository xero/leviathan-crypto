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
// test/vectors/merkle_sha256.ts
//
// RFC 6962-bis SHA-256 leaf, internal, and empty-hash KATs, the gate
// values for any RFC 9162 §2.1.1 Merkle Hash Tree implementation
// driven by SHA-256.
//
// Source:
//   transparency-dev/merkle, file rfc6962/rfc6962_test.go
//   @see https://github.com/transparency-dev/merkle/blob/fefdc92cb8cbf22503f34fe1d106d150a9204370/rfc6962/rfc6962_test.go
//   pin: fefdc92cb8cbf22503f34fe1d106d150a9204370
//
// Spec:
//   RFC 9162 (Certificate Transparency Version 2.0) §2.1.1, Merkle Hash Trees
//   - MTH({}) = SHA-256()                   (empty tree)
//   - MTH({d}) = SHA-256(0x00 || d)         (leaf)
//   - MTH(D[n]) = SHA-256(0x01 || L || R)   (internal node)
//
// Vectors are immutable. If a future test exposes a discrepancy, debug
// the implementation; do not modify the expected hex.

export interface MerkleSha256Kat {
	desc:        string;
	inputUtf8?:  string;
	leftUtf8?:   string;
	rightUtf8?:  string;
	expectedHex: string;
}

export const merkleSha256EmptyKat: MerkleSha256Kat = {
	desc: 'RFC 6962 Empty: MTH({}) = SHA-256()',
	expectedHex: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
};

export const merkleSha256EmptyLeafKat: MerkleSha256Kat = {
	desc: 'RFC 6962 Empty Leaf: MTH({""}) = SHA-256(0x00)',
	inputUtf8: '',
	expectedHex: '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
};

export const merkleSha256LeafKat: MerkleSha256Kat = {
	desc: 'RFC 6962 Leaf: MTH({"L123456"}) = SHA-256(0x00 || "L123456")',
	inputUtf8: 'L123456',
	expectedHex: '395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56',
};

export const merkleSha256NodeKat: MerkleSha256Kat = {
	desc: 'RFC 6962 Node: SHA-256(0x01 || "N123" || "N456")',
	leftUtf8: 'N123',
	rightUtf8: 'N456',
	expectedHex: 'aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb',
};
