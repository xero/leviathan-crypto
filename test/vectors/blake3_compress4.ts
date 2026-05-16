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

// test/vectors/blake3_compress4.ts
//
// BLAKE3 compress4 (v128-external SIMD) direct KAT corpus, BLAKE3 §2.1
// lane-parallel form. Four records exercising distinct input shapes:
//   1) all-zero / IV with ROOT flag (lane 0 ties to blake3Vectors[0])
//   2) shared IV across lanes, distinct counters / messages / blockLens
//   3) distinct per-lane CVs under FLAG_PARENT (multi-chunk parent shape)
//   4) distinct per-lane CVs with non-zero counter high half (v12/v13 pair)
//
// SELF-GENERATED via scripts/gen-blake3-compress4-vectors.ts. Each
// expectedOut is the concatenation of four BLAKE3 §2.2 compress1 calls
// against the per-lane inputs in the same record. compress1 is gated
// against the upstream BLAKE3 KAT corpus at
// test/unit/blake3/blake3-compress.test.ts (empty-input record from
// test/vectors/blake3.ts[0]), so these vectors inherit that gate's
// authority. Not sourced from any third-party BLAKE3 implementation.
//
// The generator also re-runs compress4 against the same staged inputs
// and asserts byte-equality against the compress1 concatenation, so
// generation doubles as a self-consistency check. The corpus is the
// primary regression gate on compress4, independent of hash() and
// the XOF / multi-chunk-parallel transitive paths.
//
// All hex strings are lowercase, no separators.
// Audit status: SELF-GENERATED (gate: BLAKE3 compress4)

export interface Blake3Compress4KatVector {
	name:        string;                            // human label, used in test reporter messages
	cv:          [string, string, string, string];  // 4 × 64 hex chars (32 bytes per lane)
	msg:         [string, string, string, string];  // 4 × 128 hex chars (64 bytes per lane)
	counterLo:   [number, number, number, number];  // u32 per lane
	counterHi:   [number, number, number, number];  // u32 per lane
	blockLen:    [number, number, number, number];  // u32 per lane
	flags:       number;                            // shared across lanes (compress4 contract, §2.1 "d")
	expectedOut: string;                            // 4 × 128 hex chars; lane-K bytes at K*64
}

export const blake3Compress4Kat: readonly Blake3Compress4KatVector[] = [
	{
		name: 'all-zero-iv-root',
		cv: ['67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b', '67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b', '67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b', '67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b'],
		msg: ['00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'],
		counterLo: [0, 0, 0, 0],
		counterHi: [0, 0, 0, 0],
		blockLen: [0, 0, 0, 0],
		flags: 11,
		expectedOut: 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243aaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243aaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243aaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a',
	},
	{
		name: 'shared-iv-distinct-counters',
		cv: ['67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b', '67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b', '67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b', '67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b'],
		msg: ['a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf', 'c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa00010203040506070809', 'eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e', '1415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50515253'],
		counterLo: [0, 1, 4294967295, 0],
		counterHi: [0, 0, 0, 1],
		blockLen: [64, 32, 16, 1],
		flags: 0,
		expectedOut: '4d281ddc82892e17cb22ea8e342e15f61b6f56fd1067e30515b9cc6e7e0f5ed19567611f72ded4a4c1afe2dfba1a2412317dabd7e3a4e7593c8bec149f51430cbd0d8739b220b65ffedb5ea3ee8d3c6c542841b70ccf94c216b8dbb94acacb9ce89bf6a4e00086a673aa58c3f360254540188ffdd89d598ab89dfa274a7e6f82e7f93ae5833433fc940a1aae32d0dde736e21baef34c8e675ebf35139b5e0ead7d302cb1992e1763055778c9c0e031f89f00b05dfc60607c614d89d33ec4a23644ce66a0915e94ae145eeb5c07a86db6f4d6de42739037562f58f298990414d0f12af4faae5c69cc54d3c04bf6c7ce605d11a1cffd4e86282855e18d48f257d7',
	},
	{
		name: 'distinct-cv-flag-parent',
		cv: ['3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50', '565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475', '7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a', 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'],
		msg: ['b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef', 'd5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa000102030405060708090a0b0c0d0e0f10111213141516171819', 'fa000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e', '2425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263'],
		counterLo: [0, 0, 0, 0],
		counterHi: [0, 0, 0, 0],
		blockLen: [64, 64, 64, 64],
		flags: 4,
		expectedOut: 'ed429ccdc90e556a7f407420eab2b9839df4ad030b09098a6e3f947ff4a113b02d5fbf725d3c540179bfe05e54b167ae966741b3b8a6ca8fa57894cbc0e6b1a775262e6f209e4ea281a563fe9a9b524eec09ab48ac3c8546a47398de7175eb5a4452bed291b5eee7013372bfddfc45e2e59f7080700742953b4aa7cd4585cb39b5c643c426b484ae7a61abb1f06f1f729aaab05147e975dad75bc5215937794aefa0788821949a8f58f26e039ad4290f227801539a41b40901fe37c178def4fedae5b8db6eac7e5a2820c91bcff7b89c4644d4a335a73152ed9bc119abd24f3ae09a0a039c7b0fdc6e69bab59536a315758e399bedd595da541ceb07c93dff9b',
	},
	{
		name: 'distinct-cv-high-counter',
		cv: ['4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60', '666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485', '8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aa', 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf'],
		msg: ['c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa0001020304', 'e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829', '0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e', '3435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70717273'],
		counterLo: [0, 1, 2, 3],
		counterHi: [256, 257, 258, 259],
		blockLen: [64, 64, 64, 64],
		flags: 0,
		expectedOut: '0a420c87293a59bf2347ee01916bae8beb5a024d61574bb7be2d8561ff3c7e4a9d3d5a8bce46d5bee843c620d5eddeb11f4e705b604dcb7c5f70b2cc8ca241ef4255898d28a82559524d9925d2d4444a7c17a3f5b3506aa1e8a188297692840becc19964d8b40276cad0f239e709180ad7d391fec71fdedc73542e020e8f26658c069605aad934c238de097b38b80d5f3a7d0f52301e24167f69f390f87fb039cea8b8b5f8a82dce25799edf83e2b010ebf7668c27a7a6f87034f68ddfad633f6bcaca095261d1649223ac1fefb847460034a3926064d47aad9487cec7209444b359ffe373a377a44c8dc70014ddae58202cde30d95ab3ae32cd91ea7274096c',
	},
];
