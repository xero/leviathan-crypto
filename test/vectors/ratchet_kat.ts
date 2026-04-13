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
// Ratchet KDF reference vectors
//
// Source: scripts/gen-ratchet-vectors.ts
// Generator: bun scripts/gen-ratchet-vectors.ts > test/vectors/ratchet_kat.ts
// Algorithm: HKDF-SHA-256 (leviathan-crypto WASM primitive, sha2 module)
//
// Note: kemRatchetDecapVectors uses fixed ACVP ML-KEM-512 inputs (tcId 77).
// Re-running the generator recomputes the HKDF outputs but the dk/kemCt
// inputs are embedded constants sourced from NIST ACVP. They do not change
// unless the gate vector is intentionally replaced.
// Spec: Signal Double Ratchet §5 + §7.2 (Sparse Post-Quantum Ratchet)
//   KDF_SCKA_INIT — info = 'leviathan-ratchet-v1 Chain Start'
//   KDF_SCKA_CK   — info = 'leviathan-ratchet-v1 Chain Step' + uint64be(N)
//   KDF_SCKA_RK   — info = 'leviathan-ratchet-v1 Chain Add Epoch'
//                          || u32be(|peerEk|) || peerEk
//                          || u32be(|kemCt|)  || kemCt
//                          || u32be(|context|) || context
//                  (peerEk and kemCt are bound into the info string with
//                   u32be length prefixes, giving defense-in-depth on top
//                   of the KEM FO transform.)
//
// Vectors derived by calling HKDF_SHA256.derive() directly — no ratchet
// wrapper code involved. HKDF_SHA256 is independently verified against
// RFC 5869 vectors in test/unit/sha2/hkdf.test.ts.
//
// SELF-VERIFIED (KEM inputs: NIST ACVP tcId 77)

export interface RatchetInitVector {
	id:           number
	sk:           string  // hex, 32 bytes
	context:      string  // hex, empty string means no context
	nextRootKey:  string  // hex, 32 bytes
	sendChainKey: string  // hex, 32 bytes
	recvChainKey: string  // hex, 32 bytes
}

export interface KdfChainStep {
	n:            number  // counter value used in this step (1-indexed)
	messageKey:   string  // hex, 32 bytes
	nextChainKey: string  // hex, 32 bytes
}

export interface KdfChainVector {
	id:        number
	initialCk: string        // hex, 32 bytes
	steps:     KdfChainStep[]
}

export const ratchetInitVectors: RatchetInitVector[] = [
	{
		id: 0,
		sk: '0000000000000000000000000000000000000000000000000000000000000000',
		context: '',
		nextRootKey: '084bf83c10c6130b52a9aa2cae4704e5132c855db97f5bd49f314737881bc01d',
		sendChainKey: '3068437e1c0ecdf76ea043484f4953da8e27a7209b15fe58c4782f8943f63046',
		recvChainKey: '80b4f5a95d1f3e8cdf4df14c6311f06e3e4c09e39646f0ae5ba2ac18471abd2a',
	},
	{
		id: 1,
		sk: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
		context: '',
		nextRootKey: 'c8b682106b969cb67b237c4b5c8e6129795863991abf37fa6a302cc2373c2a85',
		sendChainKey: '1588791a6158e21af7782778ca6b7d9d72ac58b2d33f767256115f724974c655',
		recvChainKey: '19e4b8709f07518dc0cc3b75bd08f41c505d77c35364ca7e96ad2549853b5988',
	},
	{
		id: 2,
		sk: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
		context: '',
		nextRootKey: 'b70b1479107ba54fd77e827f57d09a8802f91777d48cf1eeb20844f47366f335',
		sendChainKey: '6e0fe4702f5f725cbe84357b8291ebb9617a68d4b735e33d4dd502bcfe829188',
		recvChainKey: '6985d4c4e986f4617c85cf6bf6ba234ab0482ec84d77e5a2cf0e3f4be5757f3c',
	},
	{
		id: 3,
		sk: '0000000000000000000000000000000000000000000000000000000000000000',
		context: '746573742d636f6e74657874',
		nextRootKey: '02ad14c2933ac356032b64ec034347379ec2d429f0256b5aa65369b73362e603',
		sendChainKey: '2d956df8fb48c354857aa135b1d7bd9b770b69035a343f5012cb0417965a4ec5',
		recvChainKey: 'bc2d38413b6f6eab85f1a9dab833a6b2531e7c18a7cc094b3d0fa5bf8b849f2e',
	},
	{
		id: 4,
		sk: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
		context: '746573742d636f6e74657874',
		nextRootKey: '50e29238f66a2a6da5fbc717fd6f2fc16bf19d3d3a5b1978cf5ae5892b0eecce',
		sendChainKey: '295ca4e6f74f43dfb2ed6217592e480980f89b613cca4c2f82deac5ec57077b0',
		recvChainKey: '8c669306dd5c73dfeb6a9d220decdea64f172fb63e44d6b6fef7069fe9f0aeb6',
	},
	{
		id: 5,
		sk: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
		context: '746573742d636f6e74657874',
		nextRootKey: '1ce04bedd0bd2ffaf39965a17302486aba2c56d1bf140abf330924c785d5427b',
		sendChainKey: '128f9d1896376c2082587c6807c943b056ed115db0ff0d1ed619b3587d1dc7ee',
		recvChainKey: 'bab63a3975afbf3275f4139df37f8220b8babc8915ea52e69c79cdc10ec7f125',
	},
];

export const kdfChainVectors: KdfChainVector[] = [
	{
		id: 0,
		initialCk: '0000000000000000000000000000000000000000000000000000000000000000',
		steps: [
			{
				n: 1,
				messageKey: 'a448e97f0713ccf285d1c80b68b1a3d4df6c1074e4eededa95cb0f7fe6acdae5',
				nextChainKey: '3d7883f8a8adefb85113ad037914e714705758ba78b0b481335097e099195463',
			},
			{
				n: 2,
				messageKey: '7de7cc72901f253b5d38f1283ac8937736dd5f96b7ae6fc9a1605f8f19bff54f',
				nextChainKey: '4dc28f3ff332bc61748df0162c65eb01a3279e3d5d23fb996630982f9eda3ef7',
			},
			{
				n: 3,
				messageKey: 'fe7090a8e093bacae7b1df7764fc4e482568c89371d169d9c7344537a1b2a862',
				nextChainKey: '36dd7a589a041e70dadd8105560f61d702af068f03afb29f82a8d05bcf9a0184',
			},
			{
				n: 4,
				messageKey: '1bad41f10ea6a07060df884a91f2aa78cf1bc6850c2145979c00916a39bdd885',
				nextChainKey: '2c952a2f8da89917d9c27046093dfc6ba2e001a1b3a6f508d927b4aa86ecf92e',
			},
			{
				n: 5,
				messageKey: 'dddecca49ec3b4581c1b69150f3bfd038d350aa9dcd3cac250b1348097958d7b',
				nextChainKey: '13593231706aad41868597e1f23e2fbcdb76eb9ac1a93886bcf20bb9bb5c7a0a',
			},
		],
	},
	{
		id: 1,
		initialCk: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
		steps: [
			{
				n: 1,
				messageKey: 'a54613abc27dd3089ed5bafaa6ef8389a98fc0519de4d3b1434875bffaed423f',
				nextChainKey: 'ff0563719242f1552d5ee0b864f143ed0152f7e45735aa59caec42688bd81391',
			},
			{
				n: 2,
				messageKey: '1c45a9bfd8a3e0f2e3dcc57aa8c1f8021ba888818849415df8b0e5ad163c90f1',
				nextChainKey: '6989942eb8818a8832440bb49544df7ec73923c9ac6e7930a900dce0ca2a7f18',
			},
			{
				n: 3,
				messageKey: 'c5daee44dffb3222782360261cc89f39b8e6fbd47febc75105890a340394b282',
				nextChainKey: '788ab0ded3f62787bddabb66fc54c1d67d4c3a1ef3f15b1a27c2f579e736541c',
			},
			{
				n: 4,
				messageKey: 'b994efd607adcc0533e17be378ee45683b93a00955bb1cd8c426e2dbfb9cd216',
				nextChainKey: 'cae1ec6031b6e283e6f85afdc08a71fbe2165b5c3f761dcd8130cedd6e1ced1c',
			},
			{
				n: 5,
				messageKey: '148586a123aebaf02b5f406eca2c8360f74cea050ec2ac6a4d8446588388b381',
				nextChainKey: 'ddce3d413a1d9bc7d120f377101d09a7fe7c2274a308d5b74272ffce9e02da42',
			},
		],
	},
];

// ── kemRatchetDecapVectors ──────────────────────────────────────────────────
// KEM inputs: ML-KEM-512 ACVP tcId 77 (valid decapsulation).
// rk: fixed 32 bytes of 0x01.
// HKDF outputs independently verified against Python hmac/hashlib.
// Re-running the generator recomputes HKDF outputs; dk and kemCt are fixed
// ACVP inputs that do not change unless the gate vector is intentionally
// replaced.
//
// HKDF info binding: info = INFO_ROOT || u32be(|ek|) || ek || u32be(|ct|) || ct
// || u32be(|context|) || context. The encapsulation key is embedded inside dk
// at dk[768:1568]; tests must extract it from that slice before calling
// kemRatchetDecap.
const DK_ACVP_TCID_77 = '3b5879284a33a6204c06f84bf91843cf9b23cd8256e3d23bd1012325686138f40e435275298a614d30950d98b00f59ae6a04bbc37510d4dcbe738b90530b455b048df4f4af191b59db8a3d37c83190d425d40014775b507d43a2e2204b9aa6b6241057663a782a411419f0a0e1e8a4d7f5995b197114e832c7fab5f2d69923d53a46f07c403038c29219ef228da1746ed27978d9723d09ea6d6f32856d8b5589382af4f32d2dda0eadf342ed3248eb0ccb7b9424fce6432f8a3892a24d610b9f35b7a4d63b918203bef239c07277433d8122eda503c3d596b7c670893051286044ea919bb4863ab6a7cd8d43255c099ce1db832b109cc24c1b15bca2f5383f03cc7263775ad39a90de6a1e1cbb4ee8683295353fde05478cfbb4c5249500faa9d35b264e36494f009d8cea06ac096ff3965de5980b8e8485149b6912ba7b8e935341755ac67499647391a181158f3ac719f3b36ca0624b6c6f26800904609759b0c5d4270accaa01159c4235685d1b079624576c73f498a3f9a37b5090fd6010960c3ec9d7a1d95c3749dc3e225b800d2b8f3b597090f0b83cb315b7a43fb69151ad2b2ef21c8e3d6028a650716bd96f466baec316a230232b59a97d371c3df6d2476c51c64f48271ea38aae9c8eacd1a0f9318dfbc273d382cdfc0043b0c47b35834eb2069a0e306a53826c49c7a69ae3442947c37ed01f55e9411146870da50194e778caf71a7561429d1ac02ac362fad196ce1331bf2a00001da290f2b136b92b576c2831717908682412462af101c3ed3685180112d41a73bb164553f9b79ca71f0932693a630e4209bebe7baa7aea295150b1b827716f47464204258f414bdb6c5fffc42249c782494a4268f60bc5c195ae9c1efd778cbc15af2003b3dab7336af5037bfb4eed702ec887af43eba616414914b08493d53ed9f89ec2805ea1b40b634610b458236a2aca1610565350234e9b23be27166fb8abdb441138f44e79d8541c3aae85fc553fb884cca95e6c84325df29e112b6d863444a52721f5a5a6d0db5a65564a545633cb121a927136408c16763191eb10270e6a1604b486770ab5fcca728f659556c212f9925f28493cd3c2a60ad743830769f9b387422ac46385c88f4a10d8c43764f5200e810d20ab9a7aeb5c8b100cb751c55b301976d7bd4f0a1de7d7cfbf0379cc6b9844b16749b8c6659824b65c2659a430914b322289b88d51324772c4a507cbaf240436aac23950088e41973fcc487f57bd1d14321664afc6ea2b66403c881509be445933528a4f97c2a5b86f1cbc08816484f9432241a09e16d6b6c7068f0356505227216127af9506250e59ada3ab4611d7ba4a999621241a3d8c4fe0e7cbae2492b6f44e6afca27f33940e3233f5a382549b9da2c52b9bc99a8bdc1e541b274987a5bc4a272f330f725856220961c659cd9ba534716c5a113b53cd243d5c907fd6e1b2cde69090b40314b7ca85f2185f9401fa758c3fd8ad91441a6dcb88b7350b753cc06ae5a1fbcb4df61cae1dfc7e60c28c7787654a068dd06821983aaed658c110bc19c2fc61e76caa65d9c0914887a77571b3e63cd63a437028bc03dc8f69346585d023f01465e430220607948619975fac993703cf60055d9af28eaa1a2ce412322d11497df22137380714b701dae205ef308e2eb8a1b0b09adb896bb8ab3f34f9ba2695056b7785fd51acd043cdc1919c6b0335d7e7bdd1c43693582ed5e71d534163a48c45796b43e98bcb3df47e075b8ae3e96a640ca659747b287c4714113ddccbc83d37c54022cd321409be74c331900cb17a72dc27bb6d4401d974b4e236b82f894ef5dc9a7a29091ab475d584b52d9672ddbc8d63b0bdb51554709041cc07cdee435f39463c04ba0dc2b4c085aac7822aa4ba50cd470a75c53a7c1318839df4086d8a8d3510780081112453134f15601f810895b287195866fc237669f5b212c002f62b2130952b99bac4e0ab002fa915520a715a41b1d541cb54cb7dd0291655f14fd2d0b3d802c9d6cb569fc815b69b1a0787463104a30ab34e7bd732feea3c8cc8764fe199947513889942b7c110482c9a1477348c3c3b491060a78b8299490e4dbabd22b054929ba77ee31922e1439d15b530a0c307e72c2f9c568622301dfa261c885a6f66399dc79e593486b11ff236b8367bf6864a1a596448fc251898a3c89ccd0b5511311826546e56b6967ee923e5733561d5a4bf940caac4960bf60cb769a40e396bfc370f094a00986d708ac731b420fdc11fcb071bda0786a23f80269341ae270b8ed6844b';
const KEMCT_ACVP_TCID_77 = '30991222b8ea47530f7c703d85bf4357f61f47615539781920effdf067172e32ef1ba77b21670eca074c4b2401bb591b21ca0f4bfba9f8be4a26a9de2eceaa8303a91073c0c91205daf6ddb17d35104969c5036ba722b176f6a3e6d92e1e5eddad9a6a3561f7e5338ba2b163702e297f9c6f27c5bcb7975139dff287b739d2053bbc4307946b89df3d9c963379b932ddba015a6ea396e729996f7ff573a0c24040de323e60b95b2197c89127661db35d44588e132742b62949ea45d3e8527f0b2b71295e0943f1fa1f87d3b3ef11f840b59e2bbb10aa22b687ff23d22cda109d5ce33f3527fea041579793530226009d48cae3e499fd0eccd036d04b8da21f939908e53f5bbbe41dbacaf3a7f9f5839d479ba0909f0df0b2c8cd7ae8b11f160b16eba19656744ac38d9aee3a31e698380b3b9483e3a5f3c3b3767c519acbb515706b1f192b16aa7b1e0b8178f28c65cab578368de5bd0dd5691b659293b3b212a5547e60727f69b33d3938a301572fdd931f5f71e7c647bf9cb4b3a8b294e2a17cf504319278648e59da78f0fc5bbad5abc37551c30aab853cc50df796f308ec99d56a2348954edaf7af6e4d62fa6b1bb6fac370226f47f1a91e2bc6731875c09ccbf8e635745def1a607f15ba774e7a1fce8822c07916d352bf24de6218350c5356d627411f884623496620500337654dbb8048d58db94bcd8bf18adff7eafe9dc8687156f426379ff0d57b880b8f86fd94861cf865db231b9adf9fcc53a7d8e5bec45ef2edeeaf2109f35a365c1287ac81d18ef302c9313b357870db914e2e8300440a0c44e3940fab6b35f1bc4bdf9b7a54eec634897f1f715a334e553f2aef6eccd13966364cb942ca7c91a90ee2ed924dad7f7a0907a56323ba787967f687e1c8bab45976e20ae14301139e989e4257ec9f87728f4ac56a5f0588d96908ff7dd901ac4fbd8ab336eac865377dce7c22b4e8193f17769e1c1d6a2365d21715f014e9634834eec80e4f6c97fdfda6559ba2f88f81ca57a03aed25a0d818e7823bd08713e1667815a5e4776ace6fb5658053e6dd38a01aa0aa9819802bd83e';

export interface KemRatchetDecapVector {
	id:           number
	rk:           string  // hex, 32 bytes
	dk:           string  // hex, ML-KEM-512 dk — from ACVP tcId 77
	kemCt:        string  // hex, ML-KEM-512 ciphertext — from ACVP tcId 77
	nextRootKey:  string  // hex, 32 bytes
	recvChainKey: string  // hex, 32 bytes
	sendChainKey: string  // hex, 32 bytes
}

export const kemRatchetDecapVectors: KemRatchetDecapVector[] = [
	{
		id: 0,
		rk: '0101010101010101010101010101010101010101010101010101010101010101',
		dk: DK_ACVP_TCID_77,
		kemCt: KEMCT_ACVP_TCID_77,
		nextRootKey: '07f46b3979e6dad9c54461a937f793c8dd796a0715d96c59ea198c6fd30386d3',
		recvChainKey: '62f386c445ee508d85f9ba30420b1e2207a8cac99f81fd11a6666affa42d49b9',
		sendChainKey: 'd3906456ce05ac72c9d8e18651369a0bc3d54a0149077fc4cce31e5764ea0e79',
	},
];

