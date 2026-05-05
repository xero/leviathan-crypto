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
// test/vectors/serpent_ctr.ts
//
// CTR mode test vectors for Serpent v3 (NIST natural byte order).
//
// Block cipher correctness is established by the NESSIE gate suite
// (test/unit/serpent/serpent_nessie*.test.ts), which exercises the
// Serpent block primitive against authoritative NIST-format vectors.
// CTR mode is a deterministic construction over the block primitive
// (ks_i = encryptBlock(counter_i); ct = ks XOR pt) with little-endian
// 128-bit counter increment per src/asm/serpent/ctr.ts.

export interface CtrVector {
  label:  string
  key:    string  // hex
  nonce:  string  // hex (16 bytes = 32 hex chars)
  pt:     string  // hex
  ct:     string  // hex
  blocks: number
}

export const CTR_VECTORS: CtrVector[] = [
	{
		label: 'A',
		key: '00000000000000000000000000000000',                            // 128-bit all-zero key
		nonce: '00000000000000000000000000000000',
		pt: '000000000000000000000000000000000000000000000000' +           // 3 blocks all-zero PT
            '000000000000000000000000000000000000000000000000',
		ct: '3620B17AE6A993D09618B8768266BAE9' +                          // block 0
            '32F1FA100E43561146DCA08D15B90636' +                          // block 1
            '69DD947EFADCD15A06A0D79E078B35AE',                           // block 2
		blocks: 3,
	},
	{
		label: 'B',
		key: '0000000000000000000000000000000000000000000000000000000000000000', // 256-bit all-zero key
		nonce: '00000000000000000000000000000000',
		pt: '000000000000000000000000000000000000000000000000' +
            '000000000000000000000000000000000000000000000000',
		ct: '49672BA898D98DF9501918044549108907E5E5AD7097B849' +
            'BADC2D5D803B7F6ADF5E38BE0362C35E8AF472C6327987DA',
		blocks: 3,
	},
	{
		label: 'C',
		key: '00000000000000000000000000000000',                            // 128-bit all-zero key
		nonce: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',                            // all-FF IV (counter wrap test)
		pt: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +                          // 2 blocks all-FF PT
            'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
		ct: '4DB589F13B4046FAFD69E8EC0F769416' +                         // block 0 (ctr=0xFF×16)
            'C9DF4E8519566C2F69E747897D994516',                           // block 1 (ctr wrapped to 0x00×16)
		blocks: 2,
	},
	{
		label: 'D',
		key: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', // 256-bit key
		nonce: '000102030405060708090A0B0C0D0E0F',
		pt: '000102030405060708090A0B0C0D0E0F' +
            '101112131415161718191A1B1C1D1E1F',
		ct: 'DE279DFB37E134BF532782D97C11E953' +
            'B353B5F21703CE43886305825BBEFA78',
		blocks: 2,
	},
	{
		label: 'E',
		key: '000000000000000000000000000000000000000000000000', // 192-bit all-zero key
		nonce: '00000000000000000000000000000000',
		pt: '000000000000000000000000000000000000000000000000' +
            '000000000000000000000000000000000000000000000000',
		ct: 'A583EF976A292B406BBD5DC8256B0442' +
            '7610F6DBE8F3F19682DCC01AF57DCD79' +
            'D4257D927C7F2A6390DF198B573DD1BA',
		blocks: 3,
	},
];
