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

// test/vectors/ecdsa_p256_keygen.ts
//
// NIST ACVP ECDSA-FIPS186-5 keyGen test vectors (P-256 only).
//
// Source:
//   ACVP-Server/gen-val/json-files/ECDSA-KeyGen-FIPS186-5/internalProjection.json
//   @see https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ECDSA-KeyGen-FIPS186-5
//   algorithm=ECDSA, mode=keyGen, revision=FIPS186-5, isSample=true
//   ACVP-Server pin: 15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0
//
// 2 P-256 groups, 6 tests total. P-{224,384,521}, secp256k1, and the
// binary B/K curves are filtered out at transcription time; this file
// covers only the P-256 records the v3 substrate exercises.
//
// FIPS 186-5 §6.2.1, ECC Key Pair Generation Using Extra Random Bits:
// `secretGenerationMode = 'extra bits'` (tgId 4) is the spec-recommended
// path (Algorithm A.4.2 in SP 800-186 / FIPS 186-5 §A.2.1).
// FIPS 186-5 §6.2.2, ECC Key Pair Generation by Testing Candidates:
// `secretGenerationMode = 'testing candidates'` (tgId 3) is the
// alternative §A.2.2 method. Both produce the same (d, q) relation
// (q = d * G per SEC1 §2.2.1); the verifier branches only on q
// reconstruction, the generation-mode discriminator is surfaced for
// the per-record audit log.

export type SecretGenerationMode = 'testing candidates' | 'extra bits';

export interface KeyGenVector {
	tcId:                 number;
	secretGenerationMode: SecretGenerationMode;
	d:  string; // 32 bytes (the P-256 scalar in [1, n-1])
	qx: string; // 32 bytes (encoded x-coordinate of q = d*G per SEC1 §2.3.5)
	qy: string; // 32 bytes (encoded y-coordinate of q = d*G per SEC1 §2.3.5)
}

// P-256 | tgId=3 | testType=AFT | secretGenerationMode='testing candidates' | 3 tests
export const ecdsa_p256_keygen_tg3: KeyGenVector[] = [
	{
		tcId: 7,
		secretGenerationMode: 'testing candidates',
		d: 'BF049D775057F1199612F4BD6AB0AF695A78FB488453E261CA3C277AD57E55DB',
		qx: 'C6E20135457DC6F738E60CF6999D2416F31D7C12AFEA248434A547A9AA8A34B0',
		qy: '6E5610C1CFC091AD58AA43F2B8A96D9561EE80594C5BC5DC4CB08BE679AA45FF',
	},
	{
		tcId: 8,
		secretGenerationMode: 'testing candidates',
		d: '2AB6B85FD0558C1441B0DBC3F6DA65737BF560470AF0A44731137D68B77FCAC7',
		qx: '0DBBBAC1AFCCE89664D0FFC873FCE1A33CAE7B6F3F115460BE1933382BC7D810',
		qy: '7BFF3F0EBCEAA1E9F9747C36E804C3F3ABB9182D4C27F1E44B7930DD33AFBAF9',
	},
	{
		tcId: 9,
		secretGenerationMode: 'testing candidates',
		d: 'B96354281CB2105CFA04442579FB12802B6DE66ACE9D6F923D7191350CE29397',
		qx: 'C6FDEA385D0F95ED24CEC889A69DC13020469AECA37EE5B7758C961BFA2CBF66',
		qy: 'C6C025BDAC339F52CB3DFE9D53EEA9D42F0188501A6E5E609613CB5C4345BECD',
	},
];

// P-256 | tgId=4 | testType=AFT | secretGenerationMode='extra bits' | 3 tests
export const ecdsa_p256_keygen_tg4: KeyGenVector[] = [
	{
		tcId: 10,
		secretGenerationMode: 'extra bits',
		d: '940E5B7EA955A27B422429CE5B77EB570D52B012C4C70506E30E2047F74B081A',
		qx: 'D9B776AF7B19C98B11B749AFF852C8B21C92F7DAFC0776EAC6B38CBA43ECD18E',
		qy: 'FE8068F7B5A82CEBB8861753E336A5FDE0D0279792238EF741ADD2C98D355400',
	},
	{
		tcId: 11,
		secretGenerationMode: 'extra bits',
		d: 'BAAFC001C40903FAEA71C0E66B3BB74DAADDF3D9B720F3F1DAC92D1F7B0797FB',
		qx: '7E217FB17391EFE1178D8DF8C19EFDD5F651A645FE142667F4F29242F09EBBA0',
		qy: '173ED310724A8F7C3CEB57DD6977943ECD057F0ECB5E3E749124510E4CE7AE94',
	},
	{
		tcId: 12,
		secretGenerationMode: 'extra bits',
		d: '87D98392DCCC5315E853533556287E526743C6DB062F7B39584709E3005395DD',
		qx: '5998D67F4376362E482BDB2EE16D523CDE6315E0B0175A0527336F195228A568',
		qy: 'CF187EF771D0001061FA6A1156CE669E74F0761BF12E2A1B9257B6EB3AEBFC8A',
	},
];
