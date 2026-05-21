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

// test/vectors/ed25519.ts
//
// RFC 8032 §7 known-answer test vectors. Five records: four §7.1 Ed25519
// pure tests (TEST 1, TEST 2, TEST 3, TEST 1024) plus the single §7.3
// Ed25519ph test (TEST abc). These are the Curve25519 family
// gate corpus, transcribed by hand from the RFC text.
//
// Source:
//   RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)
//   @see https://www.rfc-editor.org/rfc/rfc8032.txt
//   §7.1 Test Vectors for Ed25519     (pure)
//   §7.3 Test Vectors for Ed25519ph   (prehash)
//
// Per-record fields:
//   - mode: 'pure' for §7.1 (Ed25519 / PureEdDSA, no dom2 prefix), 'ph'
//     for §7.3 (Ed25519ph, dom2(phflag=1, ctx) prefix + SHA-512(M)).
//   - skHex, pkHex: 32 bytes each. Ed25519 seed is the 32-byte secret;
//     the RFC's "PUBLIC KEY" is the verifying key derived from the seed.
//   - msgHex: the pre-prehash message. For mode='ph' the SHA-512 digest
//     is computed inside the verifier; the vector carries M directly.
//   - sigHex: 64 bytes, the (R || s) signature.
//   - ctxHex (mode='ph' only): RFC 8032 §7.3 TEST abc uses an empty
//     context, so ctxHex is the empty string. The field is present so
//     the type captures the Ed25519ph signature shape (which always
//     accepts a context, possibly empty).
//
// All hex strings are lowercase, no separators, matching the RFC text.
//
// Audit status: VERIFIED (independent oracle,
// scripts/verify-vectors/src/ed25519.rs against ed25519-dalek 2.x,
// `_strict` verification path per FIPS 186-5 §7.6.4).

export type Ed25519Mode = 'pure' | 'ph';

export interface Ed25519Vector {
	mode:   Ed25519Mode;
	skHex:  string;  // 32 bytes (Ed25519 seed)
	pkHex:  string;  // 32 bytes (Ed25519 verifying key)
	msgHex: string;  // hex of the pre-prehash message
	sigHex: string;  // 64 bytes (R || s)
	ctxHex?: string; // hex of the context (Ed25519ph only; '' for §7.3)
}

/** RFC 8032 §7.1-§7.3 KATs. 4 pure + 1 ph. */
export const ed25519Vectors: readonly Ed25519Vector[] = [
	{
		// RFC 8032 §7.1 TEST 1, empty message.
		mode: 'pure',
		skHex: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
		pkHex: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
		msgHex: '',
		sigHex:
			'e5564300c360ac729086e2cc806e828a' +
			'84877f1eb8e5d974d873e06522490155' +
			'5fb8821590a33bacc61e39701cf9b46b' +
			'd25bf5f0595bbe24655141438e7a100b',
	},
	{
		// RFC 8032 §7.1 TEST 2, single-byte message 0x72.
		mode: 'pure',
		skHex: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
		pkHex: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
		msgHex: '72',
		sigHex:
			'92a009a9f0d4cab8720e820b5f642540' +
			'a2b27b5416503f8fb3762223ebdb69da' +
			'085ac1e43e15996e458f3613d0f11d8c' +
			'387b2eaeb4302aeeb00d291612bb0c00',
	},
	{
		// RFC 8032 §7.1 TEST 3, two-byte message 0xaf82.
		mode: 'pure',
		skHex: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
		pkHex: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
		msgHex: 'af82',
		sigHex:
			'6291d657deec24024827e69c3abe01a3' +
			'0ce548a284743a445e3680d7db5ac3ac' +
			'18ff9b538d16f290ae67f760984dc659' +
			'4a7c15e9716ed28dc027beceea1ec40a',
	},
	{
		// RFC 8032 §7.1 TEST 1024, the 1023-byte message case.
		// Exercises a message that crosses many SHA-512 blocks.
		mode: 'pure',
		skHex: 'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5',
		pkHex: '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e',
		msgHex:
			'08b8b2b733424243760fe426a4b54908' +
			'632110a66c2f6591eabd3345e3e4eb98' +
			'fa6e264bf09efe12ee50f8f54e9f77b1' +
			'e355f6c50544e23fb1433ddf73be84d8' +
			'79de7c0046dc4996d9e773f4bc9efe57' +
			'38829adb26c81b37c93a1b270b20329d' +
			'658675fc6ea534e0810a4432826bf58c' +
			'941efb65d57a338bbd2e26640f89ffbc' +
			'1a858efcb8550ee3a5e1998bd177e93a' +
			'7363c344fe6b199ee5d02e82d522c4fe' +
			'ba15452f80288a821a579116ec6dad2b' +
			'3b310da903401aa62100ab5d1a36553e' +
			'06203b33890cc9b832f79ef80560ccb9' +
			'a39ce767967ed628c6ad573cb116dbef' +
			'efd75499da96bd68a8a97b928a8bbc10' +
			'3b6621fcde2beca1231d206be6cd9ec7' +
			'aff6f6c94fcd7204ed3455c68c83f4a4' +
			'1da4af2b74ef5c53f1d8ac70bdcb7ed1' +
			'85ce81bd84359d44254d95629e9855a9' +
			'4a7c1958d1f8ada5d0532ed8a5aa3fb2' +
			'd17ba70eb6248e594e1a2297acbbb39d' +
			'502f1a8c6eb6f1ce22b3de1a1f40cc24' +
			'554119a831a9aad6079cad88425de6bd' +
			'e1a9187ebb6092cf67bf2b13fd65f270' +
			'88d78b7e883c8759d2c4f5c65adb7553' +
			'878ad575f9fad878e80a0c9ba63bcbcc' +
			'2732e69485bbc9c90bfbd62481d9089b' +
			'eccf80cfe2df16a2cf65bd92dd597b07' +
			'07e0917af48bbb75fed413d238f5555a' +
			'7a569d80c3414a8d0859dc65a46128ba' +
			'b27af87a71314f318c782b23ebfe808b' +
			'82b0ce26401d2e22f04d83d1255dc51a' +
			'ddd3b75a2b1ae0784504df543af8969b' +
			'e3ea7082ff7fc9888c144da2af58429e' +
			'c96031dbcad3dad9af0dcbaaaf268cb8' +
			'fcffead94f3c7ca495e056a9b47acdb7' +
			'51fb73e666c6c655ade8297297d07ad1' +
			'ba5e43f1bca32301651339e22904cc8c' +
			'42f58c30c04aafdb038dda0847dd988d' +
			'cda6f3bfd15c4b4c4525004aa06eeff8' +
			'ca61783aacec57fb3d1f92b0fe2fd1a8' +
			'5f6724517b65e614ad6808d6f6ee34df' +
			'f7310fdc82aebfd904b01e1dc54b2927' +
			'094b2db68d6f903b68401adebf5a7e08' +
			'd78ff4ef5d63653a65040cf9bfd4aca7' +
			'984a74d37145986780fc0b16ac451649' +
			'de6188a7dbdf191f64b5fc5e2ab47b57' +
			'f7f7276cd419c17a3ca8e1b939ae49e4' +
			'88acba6b965610b5480109c8b17b80e1' +
			'b7b750dfc7598d5d5011fd2dcc5600a3' +
			'2ef5b52a1ecc820e308aa342721aac09' +
			'43bf6686b64b2579376504ccc493d97e' +
			'6aed3fb0f9cd71a43dd497f01f17c0e2' +
			'cb3797aa2a2f256656168e6c496afc5f' +
			'b93246f6b1116398a346f1a641f3b041' +
			'e989f7914f90cc2c7fff357876e506b5' +
			'0d334ba77c225bc307ba537152f3f161' +
			'0e4eafe595f6d9d90d11faa933a15ef1' +
			'369546868a7f3a45a96768d40fd9d034' +
			'12c091c6315cf4fde7cb68606937380d' +
			'b2eaaa707b4c4185c32eddcdd306705e' +
			'4dc1ffc872eeee475a64dfac86aba41c' +
			'0618983f8741c5ef68d3a101e8a3b8ca' +
			'c60c905c15fc910840b94c00a0b9d0',
		sigHex:
			'0aab4c900501b3e24d7cdf4663326a3a' +
			'87df5e4843b2cbdb67cbf6e460fec350' +
			'aa5371b1508f9f4528ecea23c436d94b' +
			'5e8fcd4f681e30a6ac00a9704a188a03',
	},
	{
		// RFC 8032 §7.3 TEST abc, the single Ed25519ph test in the RFC.
		// Empty context. SHA-512 of the message is computed inside the
		// verifier; the vector carries the pre-prehash message bytes
		// (ASCII 'abc').
		mode: 'ph',
		ctxHex: '',
		skHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		pkHex: 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
		msgHex: '616263',
		sigHex:
			'98a70222f0b8121aa9d30f813d683f80' +
			'9e462b469c7ff87639499bb94e6dae41' +
			'31f85042463c2a355a2003d062adf5aa' +
			'a10b8c61e636062aaad11c2a26083406',
	},
];
