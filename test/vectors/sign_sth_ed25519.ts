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
// test/vectors/sign_sth_ed25519.ts
//
// SignedLog<Ed25519Suite> wire-format KAT vectors per
// c2sp.org/tlog-cosignature §Format and §"Ed25519 signed message".
//
// Each record carries a fixed (origin, leaves, seed, timestamp)
// tuple. The leaves are appended to a fresh Sha256Tree to derive
// the recorded treeSize and rootHash; the seed feeds Ed25519
// keygenDerand to derive (sk, pk). The envelope is the byte-stable
// output of `SignedLog.signCheckpoint({ timestamp })` for this
// configuration; byte stability is provided by RFC 8032 §5.1.6
// (Ed25519 sign is deterministic).
//
// Audit status: SELF-GENERATED. Cross-checked by
// scripts/verify-vectors/src/sign_sth.rs against ed25519-dalek.
//
// C2SP commit pinned for this corpus:
// 3752ba5b3590dc3754e04fcc8369bd3612897c02 (github.com/C2SP/C2SP).

export interface SignSthEd25519Vector {
	id:               string;
	desc:             string;
	origin:           string;
	leaves:           string[];
	treeSize:         number;
	rootHashHex:      string;
	seedHex:          string;
	skHex:            string;
	pkHex:            string;
	timestamp:        number;
	bodyHex:          string;
	signedMessageHex: string;
	keyIdHex:         string;
	sigHex:           string;
	cosigPayloadHex:  string;
	envelopeHex:      string;
}

export const signSthEd25519Vectors: SignSthEd25519Vector[] = [
	{
		id: 'V1',
		desc: 'V1, single-leaf log, timestamp = c2sp.org/tlog-cosignature §"Ed25519 signed message" example value',
		origin: 'leviathan.test/log1',
		leaves: [
			'leaf-0-leviathan-crypto',
		],
		treeSize: 1,
		rootHashHex: '48cc1a7f324f551d71dfe5e976bd275a52ecd495120358cade4e3003b220a25d',
		seedHex: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
		skHex: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
		pkHex: '79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664',
		timestamp: 1679315147,
		bodyHex:
			'6c657669617468616e2e746573742f6c6f67310a310a534d7761667a4a505652' +
			'3178332b58706472306e576c4c73314a555341316a4b336b3477413749676f6c' +
			'303d0a',
		signedMessageHex:
			'636f7369676e61747572652f76310a74696d6520313637393331353134370a6c' +
			'657669617468616e2e746573742f6c6f67310a310a534d7761667a4a50565231' +
			'78332b58706472306e576c4c73314a555341316a4b336b3477413749676f6c30' +
			'3d0a',
		keyIdHex: '19bad1da',
		sigHex:
			'44f033d8a2cc91e140b15f3073c69d8b0242e6d0be519fb589d240717c24487b' +
			'7b6cb49c3042fe948ec27bf36e880b0d4f1bd28486205005d882823095056a01',
		cosigPayloadHex:
			'00000000641850cb44f033d8a2cc91e140b15f3073c69d8b0242e6d0be519fb5' +
			'89d240717c24487b7b6cb49c3042fe948ec27bf36e880b0d4f1bd28486205005' +
			'd882823095056a01',
		envelopeHex:
			'6c657669617468616e2e746573742f6c6f67310a310a534d7761667a4a505652' +
			'3178332b58706472306e576c4c73314a555341316a4b336b3477413749676f6c' +
			'303d0a0ae28094206c657669617468616e2e746573742f6c6f67312047627252' +
			'326741414141426b4746444c5250417a324b4c4d6b6546417356387763386164' +
			'69774a433574432b555a2b3169644a416358776b53487437624c53634d454c2b' +
			'6c493743652f4e756941734e547876536849596755415859676f49776c515671' +
			'41513d3d0a',
	},
	{
		id: 'V2',
		desc: 'V2, three-leaf log, timestamp 1700000000',
		origin: 'leviathan.test/log2',
		leaves: [
			'leaf-A',
			'leaf-B',
			'leaf-C',
		],
		treeSize: 3,
		rootHashHex: 'a3560a9c8d4b3f8c0915a179d268c06270b8cc2bbce446ccfcaaf5b14a13b2bb',
		seedHex: '2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40',
		skHex: '2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40',
		pkHex: 'e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0',
		timestamp: 1700000000,
		bodyHex:
			'6c657669617468616e2e746573742f6c6f67320a330a6f31594b6e49314c5034' +
			'774a46614635306d6a41596e43347a4375383545624d2f4b723173556f547372' +
			'733d0a',
		signedMessageHex:
			'636f7369676e61747572652f76310a74696d6520313730303030303030300a6c' +
			'657669617468616e2e746573742f6c6f67320a330a6f31594b6e49314c503477' +
			'4a46614635306d6a41596e43347a4375383545624d2f4b723173556f54737273' +
			'3d0a',
		keyIdHex: '4f0ddb0f',
		sigHex:
			'72c41f570433363c51639ec204347d483a0913bd562165c19e8a857ab610aceb' +
			'5c414c69b0b86a6005e7c79bf143c6e0a1e44798aef9bf8d663b21f058376c0d',
		cosigPayloadHex:
			'000000006553f10072c41f570433363c51639ec204347d483a0913bd562165c1' +
			'9e8a857ab610aceb5c414c69b0b86a6005e7c79bf143c6e0a1e44798aef9bf8d' +
			'663b21f058376c0d',
		envelopeHex:
			'6c657669617468616e2e746573742f6c6f67320a330a6f31594b6e49314c5034' +
			'774a46614635306d6a41596e43347a4375383545624d2f4b723173556f547372' +
			'733d0a0ae28094206c657669617468616e2e746573742f6c6f67322054773362' +
			'447741414141426c552f4541637351665677517a4e6a78525935374342445239' +
			'53446f4a45373157495758426e6f714665725951724f746351557870734c6871' +
			'5941586e78357678513862676f6552486d4b37357634316d4f79487757446473' +
			'44513d3d0a',
	},
	{
		id: 'V3',
		desc: 'V3, seven-leaf log, larger timestamp covering the BE u64 high-byte boundary',
		origin: 'sigsum.example.org/v1/transparency-log',
		leaves: [
			'L0',
			'L1',
			'L2',
			'L3',
			'L4',
			'L5',
			'L6',
		],
		treeSize: 7,
		rootHashHex: '9a01afc3a2f698368e6143b81124c362459916ce16f62ca7b96933fc862735ed',
		seedHex: '4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60',
		skHex: '4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60',
		pkHex: 'adc14011f82d1c56d956aa4f9d73d8858361a606048525e0d08c638dc75dd8c7',
		timestamp: 9999999999,
		bodyHex:
			'73696773756d2e6578616d706c652e6f72672f76312f7472616e73706172656e' +
			'63792d6c6f670a370a6d67477677364c326d44614f59554f3445535444596b57' +
			'5a467334573969796e75576b7a2f49596e4e65303d0a',
		signedMessageHex:
			'636f7369676e61747572652f76310a74696d6520393939393939393939390a73' +
			'696773756d2e6578616d706c652e6f72672f76312f7472616e73706172656e63' +
			'792d6c6f670a370a6d67477677364c326d44614f59554f3445535444596b575a' +
			'467334573969796e75576b7a2f49596e4e65303d0a',
		keyIdHex: '786aee9b',
		sigHex:
			'881c8e883446a0b3ae6506df5c680cbf36715fbf682585856ff608d065d05415' +
			'a1834f5be2e352087a94468c0a7bddb05ab37a810a38756f74393fb387f64e03',
		cosigPayloadHex:
			'00000002540be3ff881c8e883446a0b3ae6506df5c680cbf36715fbf68258585' +
			'6ff608d065d05415a1834f5be2e352087a94468c0a7bddb05ab37a810a38756f' +
			'74393fb387f64e03',
		envelopeHex:
			'73696773756d2e6578616d706c652e6f72672f76312f7472616e73706172656e' +
			'63792d6c6f670a370a6d67477677364c326d44614f59554f3445535444596b57' +
			'5a467334573969796e75576b7a2f49596e4e65303d0a0ae28094207369677375' +
			'6d2e6578616d706c652e6f72672f76312f7472616e73706172656e63792d6c6f' +
			'6720654772756d77414141414a55432b502f6942794f694452476f4c4f755a51' +
			'62665847674d767a5a785837396f4a595746622f594930475851564257686730' +
			'396234754e5343487155526f774b6539327757724e3667516f34645739304f54' +
			'2b7a682f5a4f41773d3d0a',
	},
];
