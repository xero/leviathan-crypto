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
// test/vectors/sign_ed25519.ts
//
// Suite-level KAT vectors locking the v3 attached envelope wire format
// produced by the Ed25519 suite consts: `Ed25519Suite` (formatEnum 0x01,
// pure Ed25519 per RFC 8032 §5.1.6) and `Ed25519PreHashSuite`
// (formatEnum 0x11, Ed25519ph per RFC 8032 §5.1.7 with the
// `ed25519-prehash-envelope-v3` ctxDomain bound via `buildEffectiveCtx`
// into the dom2(F=1, effective_ctx) construction). Unlike ML-DSA, both
// Ed25519 modes are fully deterministic per RFC 8032, so KATs cover
// both pure and prehash records.
//
// Audit status: SELF-GENERATED (wire-format gate). Records V1-V3 use
// the RFC 8032 §7.1 TEST 1 / 2 / 3 seeds and messages; V1-V3 sig bytes
// inside the envelope match the RFC §7.1 expected sigs verbatim (the
// envelope's [formatEnum, ctxLen, ...] preamble simply prefixes them).
// Records V4-V7 use the RFC §7.3 TEST abc seed; the sig bytes diverge
// from the RFC §7.3 expected sig because the suite always binds its
// ctxDomain into the effective_ctx fed to dom2 (the RFC's reference
// signature is computed with ctx=empty).
//
// Inputs per record:
//   id, description     human-readable identifiers
//   formatEnum          0x01 for pure, 0x11 for prehash
//   mode                'pure' | 'prehash' discriminator
//   seedHex             32-byte RFC 8032 secret seed
//   pkHex, skHex        32-byte verifying key + 32-byte sk (= seed)
//   msgHex              payload bytes
//   ctxHex              user_ctx bytes (always '' for pure records;
//                       the pure suite rejects non-empty user_ctx per
//                       the TASK-F lock)
//   blobHex             attached envelope: [formatEnum, ctxLen, ctx,
//                       payload, sig]
//
// All hex strings are lowercase, no separators.

export type SignEd25519Mode = 'pure' | 'prehash';

export interface SignEd25519Vector {
	id:          string;
	description: string;
	formatEnum:  number;
	mode:        SignEd25519Mode;
	seedHex:     string;  // 32 bytes
	pkHex:       string;  // 32 bytes
	skHex:       string;  // 32 bytes (= seed, redundant but explicit)
	msgHex:      string;
	ctxHex:      string;  // '' for pure records
	blobHex:     string;
}

export const signEd25519Vectors: SignEd25519Vector[] = [
	{
		id: 'V1',
		description: 'V1, pure Ed25519, RFC 8032 §7.1 TEST 1 seed, empty msg, empty ctx',
		formatEnum: 0x01,
		mode: 'pure',
		seedHex: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
		pkHex: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
		skHex: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
		msgHex: '',
		ctxHex: '',
		blobHex:
			'0100' +
			'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' +
			'5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
	},
	{
		id: 'V2',
		description: 'V2, pure Ed25519, RFC 8032 §7.1 TEST 2 seed, 1-byte msg 0x72, empty ctx',
		formatEnum: 0x01,
		mode: 'pure',
		seedHex: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
		pkHex: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
		skHex: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
		msgHex: '72',
		ctxHex: '',
		blobHex:
			'010072' +
			'92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' +
			'085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
	},
	{
		id: 'V3',
		description: 'V3, pure Ed25519, RFC 8032 §7.1 TEST 3 seed, 2-byte msg 0xaf82, empty ctx',
		formatEnum: 0x01,
		mode: 'pure',
		seedHex: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
		pkHex: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
		skHex: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
		msgHex: 'af82',
		ctxHex: '',
		blobHex:
			'0100af82' +
			'6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac' +
			'18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
	},
	{
		id: 'V4',
		description: 'V4, Ed25519ph, RFC 8032 §7.3 TEST abc seed, msg "abc", empty ctx',
		formatEnum: 0x11,
		mode: 'prehash',
		seedHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		pkHex: 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
		skHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		msgHex: '616263',
		ctxHex: '',
		blobHex:
			'1100616263' +
			'380e713928c993525cc92f28961a14cb7ea7859dd0abf972d48a5b1fc5956996' +
			'f6764dd34490d6ef88500eac2a33650f0083972b5a360cb1cf88228e45279305',
	},
	{
		id: 'V5',
		description: 'V5, Ed25519ph, RFC 8032 §7.3 seed, 38-byte msg, ctx = utf8(\'v3-suite-kat\')',
		formatEnum: 0x11,
		mode: 'prehash',
		seedHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		pkHex: 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
		skHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		msgHex: '4c657669617468616e2043727970746f2c2045643235353139207633205355495445204b4154',
		ctxHex: '76332d73756974652d6b6174',
		blobHex:
			'110c76332d73756974652d6b6174' +
			'4c657669617468616e2043727970746f2c2045643235353139207633205355495445204b4154' +
			'34d0e6ffed94b2b49bda6797eb5774b03f20528b176cfec3a05bd547f829122e' +
			'c46044f3c11072ae06372ed74cad93b9f9227500d05fe2755a846e9a9741d607',
	},
	{
		id: 'V6',
		description: 'V6, Ed25519ph, RFC 8032 §7.3 seed, 40-byte msg, 100-byte ctx',
		formatEnum: 0x11,
		mode: 'prehash',
		seedHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		pkHex: 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
		skHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		msgHex: '4c657669617468616e2043727970746f2076332d706d2d3130302d63747820676174652d6b6174',
		ctxHex:
			'1f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8' +
			'ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8' +
			'dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8' +
			'bfc6cdd4',
		blobHex:
			'1164' +
			'1f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8' +
			'ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8' +
			'dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8' +
			'bfc6cdd4' +
			'4c657669617468616e2043727970746f2076332d706d2d3130302d63747820676174652d6b6174' +
			'86d97156d5de6b65af06db3762cee1ee50678d26307f26ea50f96893a9a4f29e' +
			'25b93e961ed8af96661ce58ed9e22565540237bffa0d74e8b271bea96a4d4906',
	},
	{
		id: 'V7',
		description: 'V7, Ed25519ph, RFC 8032 §7.3 seed, 40-byte msg, 200-byte ctx (USER_CTX_MAX)',
		formatEnum: 0x11,
		mode: 'prehash',
		seedHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		pkHex: 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
		skHex: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
		msgHex: '4c657669617468616e2043727970746f2076332d706d2d3230302d63747820626f756e64617279',
		ctxHex:
			'05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98' +
			'a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b38' +
			'45525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8' +
			'e5f2ff0c192633404d5a6774818e9ba8b5c2cfdce9f603101d2a3744515e6b78' +
			'85929facb9c6d3e0edfa0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b18' +
			'25323f4c596673808d9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8' +
			'c5d2dfecf9061320',
		blobHex:
			'11c8' +
			'05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98' +
			'a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b38' +
			'45525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8' +
			'e5f2ff0c192633404d5a6774818e9ba8b5c2cfdce9f603101d2a3744515e6b78' +
			'85929facb9c6d3e0edfa0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b18' +
			'25323f4c596673808d9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8' +
			'c5d2dfecf9061320' +
			'4c657669617468616e2043727970746f2076332d706d2d3230302d63747820626f756e64617279' +
			'fceb0821411a9cfadaf105c5c864354f53b06a882dca2942f18f74d5a88c07b1' +
			'000aecf005efd84ace22f86df17eee3ea81b93b0e4706c2b93aa4fd5402a3e0b',
	},
];
