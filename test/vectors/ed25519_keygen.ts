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

// test/vectors/ed25519_keygen.ts
//
// NIST ACVP EDDSA keyGen test vectors (ed25519 only).
//
// Source:
//   ACVP-Server/gen-val/json-files/EDDSA-KeyGen-1.0/internalProjection.json
//   @see https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/EDDSA-KeyGen-1.0
//   algorithm=EDDSA, mode=keyGen, revision=1.0, isSample=true
//   ACVP-Server pin: 15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0
//
// 1 group (curve=ED-25519, testType=AFT), 3 tests total. ed448 records
// are filtered out at transcription time, ed448 is out of scope for v3.
//
// RFC 8032 §5.1.5, Ed25519 key generation: deterministic from a 32-byte
// seed (d). Each test gives the seed and the expected encoded public
// key (q), 32 bytes per RFC 8032 §5.1.2.

export interface KeyGenVector {
	tcId: number;
	seed: string; // 32 bytes (d, the Ed25519 seed)
	q:    string; // 32 bytes (encoded public key per RFC 8032 §5.1.2)
}

// ed25519 | tgId=1 | testType=AFT | 3 tests
export const ed25519_keygen: KeyGenVector[] = [
	{
		tcId: 1,
		seed: '19165F660A63D78678924F2685FC0E868CFF1C8969A1889E30705A425D7D9869',
		q: '1B2D8A0851500FBEF13B18AE3E0A418D45BB803B1635012C906DDC96519C83F4',
	},
	{
		tcId: 2,
		seed: '640CA510093F24625B8E43289D35B6DF0E7B34365344796EDD08AFB3D08CB874',
		q: '9929129EF72FE01841D2DF2B75C80E8A5095EFD5758CAC6352731282832A5B7D',
	},
	{
		tcId: 3,
		seed: '76564304E0BC04E32F65568894D01662C5FCB3AFCD77705A6447C767BBB5DEEA',
		q: 'EDEE7099AE2C4476CF78C9728E7A23E20DA651FEB2F2AF9734096A4DC7AB4CBF',
	},
];
