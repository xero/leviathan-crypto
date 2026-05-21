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
// cSHAKE and KMAC test vectors (SP 800-185, NIST ACVP-Server).
//
// Sources (Tier 1, external authority, values are immutable per AGENTS.md §1):
//
//   NIST SP 800-185 sample documents (the "Appendix A" exports):
//     cSHAKE: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf
//     KMAC:   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
//     KMACXOF: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMACXOF_samples.pdf
//
//   NIST ACVP-Server sample corpora:
//     cSHAKE-128: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/cSHAKE-128-1.0  (vsId=0, AFT 100)
//     cSHAKE-256: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/cSHAKE-256-1.0  (vsId=0, AFT 100)
//     KMAC-128:   https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/KMAC-128-1.0    (vsId=0, AFT 400 + MVT 400)
//     KMAC-256:   https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/KMAC-256-1.0    (vsId=0, AFT 400 + MVT 400)
//
// Scope: byte-oriented API only.
//
// leviathan-crypto's KMAC and cSHAKE WASM surface consumes Uint8Array, every
// primitive in the library is byte-oriented. The ACVP-Server corpus is
// overwhelmingly bit-level: messages, keys, and MACs typically carry
// non-byte-aligned lengths. Records whose keyLen, msgLen, or macLen is not a
// multiple of 8 cannot be exercised through the byte-oriented public API and
// have been excluded. Surviving counts (after filtering for `% 8 == 0` on all
// length fields):
//
//   KMAC-128:   2 / 800   (one MVT group, xof=false, hexCustomization=true)
//   KMAC-256:   1 / 800   (one MVT case, xof=true,  hexCustomization=false)
//   cSHAKE-128: 2 / 100   (AFT group)
//   cSHAKE-256: 3 / 100   (AFT group)
//
// The 16 sample values from the NIST CSRC sample PDFs are byte-aligned by
// construction and supply the primary correctness signal. ACVP records
// surviving the filter are kept as additional spot-checks.
//
// MCT (Monte Carlo Test) groups in cSHAKE-128 / cSHAKE-256 are excluded.
// MCT chains derive each iteration's outLen from the previous output, which
// drifts to bit-level lengths past the first iteration regardless of the
// initial outLen. The byte-oriented API cannot drive the chain.
//
// Empty exports, kmacxof128_appendix_a / kmacxof256_appendix_a are never
// empty (NIST publishes 3 samples each). kmac256_acvp and kmacxof128_acvp are
// empty arrays: no records survived the byte-alignment filter. The exports are
// retained for symmetry with the variant-grouping convention and so
// downstream imports remain stable as ACVP corpora evolve upstream.
//
// Every record was crosschecked byte-for-byte against an independent reference
// in an ephemeral Rust project (`tiny-keccak` for KMAC / KMACXOF, the `sha3`
// crate for cSHAKE) before the file was pinned in `SHA256SUMS`. The scratch
// project lived under /tmp and was deleted after a clean green run; the audit
// trail is this comment block plus the SHA256 pin.
//
// Audit status: VERIFIED.

// ============================================================
// Interfaces
// ============================================================

/** SP 800-185 sample for cSHAKE, N and S are ASCII strings. */
export interface CshakeSampleVector {
	description:  string;
	msg:          string;  // hex
	msgLenBits:   number;
	N:            string;  // function-name string (ASCII text)
	S:            string;  // customization string (ASCII text)
	outLenBits:   number;
	expected:     string;  // hex
}

/** SP 800-185 sample for KMAC / KMACXOF, S is an ASCII string. */
export interface KmacSampleVector {
	description:  string;
	key:          string;  // hex
	keyLenBits:   number;
	msg:          string;  // hex
	msgLenBits:   number;
	S:            string;  // customization string (ASCII text)
	outLenBits:   number;
	expected:     string;  // hex
}

/** ACVP cSHAKE AFT record. customization is ASCII text when hexCustomization
 *  is false; the raw bytes when true. */
export interface CshakeAcvpVector {
	tcId:             number;
	tgId:             number;
	testType:         'AFT';
	hexCustomization: boolean;
	msg:              string;  // hex
	msgLenBits:       number;
	functionName:     string;  // ASCII text (per ACVP convention)
	customization:    string;  // ASCII text or hex per hexCustomization
	md:               string;  // hex
	outLenBits:       number;
}

/** ACVP KMAC / KMACXOF record. xof selects the right_encode(0) tail. AFT
 *  records compute and compare; MVT records compute and verify the supplied
 *  mac matches the expected truth value testPassed. */
export interface KmacAcvpVector {
	tcId:              number;
	tgId:              number;
	testType:          'AFT' | 'MVT';
	xof:               boolean;
	hexCustomization:  boolean;
	key:               string;   // hex
	keyLenBits:        number;
	msg:               string;   // hex
	msgLenBits:        number;
	customization?:    string;   // ASCII text (when hexCustomization=false)
	customizationHex?: string;   // hex (when hexCustomization=true)
	mac:               string;   // hex
	macLenBits:        number;
	testPassed?:       boolean;  // MVT only
}

// ============================================================
// cSHAKE-128, SP 800-185 sample values
// Source: csrc.nist.gov/.../examples/cSHAKE_samples.pdf, samples #1, #2
// Records: 2
// ============================================================

export const cshake128_appendix_a: CshakeSampleVector[] = [
	{
		description: 'NIST cSHAKE sample #1 (strength=128-bit, S=\'Email Signature\')',
		msg: '00010203',
		msgLenBits: 32,
		N: '',
		S: 'Email Signature',
		outLenBits: 256,
		expected: 'c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5',
	},
	{
		description: 'NIST cSHAKE sample #2 (strength=128-bit, S=\'Email Signature\')',
		msg: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
		+ '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
		+ '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
		+ '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
		+ '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
		+ 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
		+ 'c0c1c2c3c4c5c6c7',
		msgLenBits: 1600,
		N: '',
		S: 'Email Signature',
		outLenBits: 256,
		expected: 'c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b',
	},
];

// ============================================================
// cSHAKE-128, ACVP AFT (byte-aligned filter applied)
// Source: ACVP-Server cSHAKE-128-1.0, vsId=0, tgId=1, byte-aligned subset
// Records: 2
// ============================================================

export const cshake128_acvp: CshakeAcvpVector[] = [
	{
		tcId: 25,
		tgId: 1,
		testType: 'AFT',
		hexCustomization: false,
		msg: 'ca88f708fa',
		msgLenBits: 40,
		functionName: 'KMAC',
		customization: '`kiEF`&I))7]yq0?*sKa q)[jP`4R=)lV_9tyvT$kAbH$)1}p].bbeomb.',
		md: 'bebb534ccfccd300f731d2911fb4351d5fcc95ac2509e9abae8f9dc51106e28d'
			+ '7f25ae11738334',
		outLenBits: 312,
	},
	{
		tcId: 27,
		tgId: 1,
		testType: 'AFT',
		hexCustomization: false,
		msg: '',
		msgLenBits: 0,
		functionName: 'KMAC',
		customization: '`P;u|*`jK@5~e$6UxvbE8)Bo*~.Dfs/zdX>&@m*Nbns<H}5r<kIDze&W.Kk}{;$W1:;,d16+m4cH4\'F+i:)zIj }Revt!',
		md: '1e5ca2a14cc46de9a6510003516cddcf4fd6f3dc073f64633bfe5c43172e97c7'
			+ 'd63a',
		outLenBits: 272,
	},
];

// ============================================================
// cSHAKE-256, SP 800-185 sample values
// Source: csrc.nist.gov/.../examples/cSHAKE_samples.pdf, samples #3, #4
// Records: 2
// ============================================================

export const cshake256_appendix_a: CshakeSampleVector[] = [
	{
		description: 'NIST cSHAKE sample #3 (strength=256-bit, S=\'Email Signature\')',
		msg: '00010203',
		msgLenBits: 32,
		N: '',
		S: 'Email Signature',
		outLenBits: 512,
		expected: 'd008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd1'
		+ '64020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c',
	},
	{
		description: 'NIST cSHAKE sample #4 (strength=256-bit, S=\'Email Signature\')',
		msg: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
		+ '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
		+ '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
		+ '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
		+ '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
		+ 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
		+ 'c0c1c2c3c4c5c6c7',
		msgLenBits: 1600,
		N: '',
		S: 'Email Signature',
		outLenBits: 512,
		expected: '07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac864302730917'
		+ '27f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb',
	},
];

// ============================================================
// cSHAKE-256, ACVP AFT (byte-aligned filter applied)
// Source: ACVP-Server cSHAKE-256-1.0, vsId=0, tgId=1, byte-aligned subset
// Records: 3
// ============================================================

export const cshake256_acvp: CshakeAcvpVector[] = [
	{
		tcId: 50,
		tgId: 1,
		testType: 'AFT',
		hexCustomization: false,
		msg: '31a5b91183d04c3f2adf8a92507e44515ce6cb5bb8129862da36b773f692a011'
			+ '83576b88da8a1f21741c6fbfaaad821edb05e3e3f5b29e9d2e949ba2f2c05b9a'
			+ '9e',
		msgLenBits: 520,
		functionName: 'TupleHash',
		customization: ']Mr[iW->\'{sI%i:yVadE{p!W^Y<V>R=gsxX:.EUaE0W]cti}YBfd`>!lK:}/;T S^-T+1~l1,# l8Dshp>|zkX(TwlnsGGFp/%}V@_mYUTW^>5S',
		md: 'fae091032fc8c74b7d3912a783eb6c0598e65e576fe71e5ded3c057120bd6022',
		outLenBits: 256,
	},
	{
		tcId: 58,
		tgId: 1,
		testType: 'AFT',
		hexCustomization: false,
		msg: 'd5d7e7517f',
		msgLenBits: 40,
		functionName: 'ParallelHash',
		customization: 'vD-1>T,f.R*V%ZA<NtW0$3UZD[$X%QVQE,H6E;xqYQI4co^F#Sf:CU!dmQkbPRbZ{V1x3,v3{fTPiBvT}[UOk</o*dGrN7@(nm7,^d4v]R>[ OyJ',
		md: '442be69b2afd7c8282839920a8446aaf16a5049d3d018eac87e04cf9225870ef'
			+ 'ca6f88db415829',
		outLenBits: 312,
	},
	{
		tcId: 78,
		tgId: 1,
		testType: 'AFT',
		hexCustomization: false,
		msg: '4536b6658644353b029aa69b9a03b0d819a8af5a89e1d194270cd3390e10c40e'
			+ '49d0413be1db3870b765b218ba1e3e7388e276802c853387719741beb5eda1b5'
			+ 'b260b9d87738ba8f28dbe0bd68432c68cb8927afc6776f03a8b9739c6b614c97'
			+ '221b5ce68609fdaf913cf89b88dc40e534ac1f0184c3d00f4740e174e74ccb21'
			+ '776999a9296014eb8bac739687b7438a2d5be83682c300bcc486479bf4885b04'
			+ 'd27f52cc676e411ce2a2c5858094958fdcd6fc42509da1ca3500176a7df78d50'
			+ '31f32b1d461f612a9e39d4238e36bddbf0c49382d98df7fd9c98ecc899df56b7'
			+ 'c654bc3d7086536f58d6d0489b3d6322c8b04ad3af54a5ee309ba3998fb9016e'
			+ '816f61f159868c3b9842d67e7b289840327c819a4dd727284616c3fcc2ecb22f'
			+ '544b70347e969e4a4a98abd67ceb05f398668542e955baf2a3e088f8d0d7d343'
			+ '195369801b30a6b8be6aef08c9ca08ce0e94d3952fcb82bdcc8c64254e5db53a'
			+ 'a074a185b913876cfbb50d6b13867e0806d756861174b8bad92394a39ca26dcc'
			+ 'd6038f48d30fa5641ae509e7855ce1613001c8bc298c3d2fbd74955e78a25205'
			+ '9c93c8f4e8ae0ace937f124fa3752e6e820d46eea80a5f9ef777f7ddde39e42c'
			+ '35ad5cb4ca636e76f071c7892b35a6b45273985dcf87b3f94792575725fb405b'
			+ '093d844a2980e11a6a15765c03a7314fce1cd91e94ee6abaf78635ab7dd98c67'
			+ 'cdca305c8475d02b912c4b3a41ab7f7c3ed531b2620d253a9a09bffaac7246b6'
			+ '4fb80782236f24ffce3b2bb92805c3b780e11ec490dc1fd44d54cca9749f67bc'
			+ 'e6733f0562ff5d5d9ac18e82e1728e66b3349a142f2d2a8fbe698281cdbfc15d'
			+ 'be0d2cb66c77ec1af54ef1ba6bde3ecfd5996836fc26c9132aab7d4e1a53ab8b'
			+ '7cf960204264001b6a963af940543a3bb89dd5784a3d571f2d6f1a6c9356b12f'
			+ '47310fa619f66dab12b3735345f782451810a5cc83f2bd8ba07a16b00f12cfde'
			+ 'ea7ff0c399534b5e69586b08c9f79a441f2a7f62359caf38f5a9f96554d7037d'
			+ 'bb3c4be03ba26f9772da68322bb2359ae06b87128f8b1b365f2c6509eabe39d2'
			+ '8a96bbfe917bafa73c0fed50d20f645bb2e4248da98e13763bdd5beb4aaca660'
			+ '2b3b428f0de77e04f931a0a3025613bb17afb5911e640ecc26c9e6107fa9d8dd'
			+ 'b2efa7e5ca7c0b677542f2b85a393f21edda9522895850d2210c0c184ff447ec'
			+ 'e9fbdc42770095acd23eea6e372fd932e13604c795c1d88e311fe66029dda660'
			+ 'b129e8346b2157f2a12ae462e781f1076c35f6f654f915d12f4864cff237d7b6'
			+ 'a1d2f028374568d82c59c0ab9308d795eed99700944732a252207ad3fa844b62'
			+ 'd6776bbf17e0e104368a3e879b68f1aa1c5e533e99ad2e0c910809184a9e636a'
			+ 'e05b1485b2f4f4421731aec254c4aa5c39c4725dee2cbdeafd1eb30c22f836e5'
			+ '4d924b46c42a6e8fbc426b57982b2a45152b118084b0fd2ca1d8b02183b08482'
			+ '8946ee7e09bf874a45f60dec585fc3ad3f37bca77bbf2c3b1055064c75b386c9'
			+ '2ec3b65bd96a7cd1d38d40b0eb0d81a72526d5097ab34640a1c7e885915ad785'
			+ 'a7f9f9da07e8d31440375ac1ffce02f9db98a74d392dc3289ebe43ac7ebd092d'
			+ '4f407eee075c40cc730e363edce4fee57367439b8826c525e8013647b4472277'
			+ '7536a6feb376601e332f74fe53ab29d405f8f3a1347e64f53e3265677a73fce8'
			+ '0c8ae905b904de67087719ed1c03574d69b0bab12f2f015f3c600291de68954c'
			+ '1c9102abf99285c0aa23d036dda15640c443d00fc019790e35e3983ec4888bd8'
			+ 'adf78e72441c9139c07acaa93d3642d59fc61a6a414344ab0446c78acc463a74'
			+ 'cc0e6c1f76f507deae125304c47d55fc6d6585fffd58e71a1704674bfa3f4c13'
			+ '7e8f269332b03a24c617c2295d5baf6c91c1ca195ab904f3a19fd0b119cdf570'
			+ '3cb15f74e9e7bd387edfb9014b88bae7b68119efaf88c4de03107af0e8b9037f'
			+ '180db2184366edabb179a11f9807041b90b86b1c4d0d7deec9a2dad6926fb220'
			+ 'fe510850a44aa0219d66fd2d768e81dde70c609ada01d1215d5663e3878a11af'
			+ 'a718ad19e5ec27f053451e1e2fdb442c866261a31e5939ab6bee3ccb3bf467bc'
			+ '842d09bbba074049af7ff413ad3c0f9a229ed7ee4795dcb0d467212535d76f48'
			+ '58cb5a3e7567cb5d51a939fb0a0e138c1372a3ab3cc088de6b7f23856591f2e8'
			+ '7aff21c0c8230cc54a13aecf74482ff8ed86b628bfea477a8c2262822c1571ff'
			+ '78ad433a060012ca9a6296833a1401cd01509bd6916b96be3927c1dbeda728e1'
			+ '97e9e376163148885d479356a980a24dfe4f2955f709e95c245a6b4e896f122e'
			+ 'b83f04dd62ff1d2ba592e07ac7ba18a5764a4b00d5e1209cc64676345ced1b3d'
			+ 'c25a10c22618984950fe3617a5b0a29a8ec83ca4add489c9012af5fa496d29dc'
			+ 'aa852a6954a76db2eef8d45eab22c6bc40bfa286cac5c3edc4656993cb864124'
			+ '5de13a6c6ce25a304e066a70c14d2f6bbec0818b9287bde4f2974caed8bcb958'
			+ '6996abda8d857dc14a350d87aab5841014415084dfabbb08bbc7f1e9a4a4655c'
			+ '8e1425465d43ac0e4561364e9079ace381f0533d18476d8fdc091d3a93c22281'
			+ '839d0156990500687f69cc4d3a9812d90285acc625e9fa906abf4b5eac2c7711'
			+ 'ae70e6a253ae692db7792613d7d84e2867ca660bd4d1f1694055050232b7e2a6'
			+ '7ca32588c179a36890809817523ae570c17e158ed2f3b5d3f9a71bf717f9ae4f'
			+ '91794dbd480fa77d5838fe89a4eb115b4c1cfbe007731fc9606d9868f6fca18f'
			+ '0a3c036496328cbd5f1c01f2bd1641911012f3b888b88c95dee3efd4cc079a5a'
			+ '2abba0e67d216e40d484999308fead5042656f9156cb4aaa23808605726041f8'
			+ 'b00af06a6684f77fa44983d363af1665e861350eff4a641b26066a74a1138958'
			+ '57fc431e6396b178736fdbbae771b18ef52818fcb999f5f329540018fc6aef80'
			+ '046b44143e0b8d015deea7f53d8e6f271e67df91938ec39c11812af0970e671a'
			+ '6419495698d0f6d5b9ab8a7c35067454459826638554994dc1dce534e046ace7'
			+ '6bdcfcb2e2b4bf45cb64e52ddb8479f6b50b3744f6d2f760cc2b0a5716c13a9e'
			+ 'd86601aefd2a5f7cdc1d367cb56678cc34fbf51ae5854d6d8af9dc41319c6301'
			+ 'e19a935450aef2ab251dc94440825aa96c3bf47ac31b396bba525cefd5849aa5'
			+ '6276ff0f0fe5072975b8361ef108bfe7e9b2c6cb41c578e1a9a23a58d768645c'
			+ '3cba4d0069435c3307353f3bfde20ef5ab33583ae1d760af7668526b190f5eb5'
			+ 'f43301fffe6b1b41eca7a2a274ef4afc0e5468361e58903eba4b6b848449dbaa'
			+ 'd8b42b47df1c491369769271151afae2edd7b4f4ba376a1f7be11c477f84b87f'
			+ '19b8bc6fd137d4c248236d88770b1fd692ea093dc8f5639524fc7fb3df9237d7'
			+ 'ff0a7c34f08dccf7147de91dcc8e1cfa94fbd9b65bb78a96edadfc9d2fe83f32'
			+ '4139179405b4d26ca065f4528b5042209aae9c1fc57810169e82e9c3f96c5c09'
			+ 'cf756d0fafb7a8311b9e2e6cce2819d671f60a8bf20fa8ae48c64baee5ed0bcf'
			+ 'd1c27ba426b317a53a8e2f6d2759ddea30ceb1053b2ecc4b1a94c3c75ce2c04a'
			+ '0c55c6ab134aa522fc46babe5ac2430b8da791a5381724976e8eeecbd613ebf4'
			+ '4d8a306a656b92c274ea1d60c63ad9096099da48d70dd43cc02b16a50c190c19'
			+ 'a780f934cca4a568f068b30d53e5c38533fbe5e32d937447befc0e0ad3822a28'
			+ 'f7714689c00d04467d08db4c559338cf36ea273641048aed09b941d0ea2271cb'
			+ 'b509a08cb5f96f5a3127e7b7807e0100cdf92d444edf3198fdfb822f68366d64'
			+ 'c05ccb579306c8632f7516739c88e98ce9a90758873128806034927e5c9ed048'
			+ '9b83406a0beba9d451b476766092cc907adfce387e08e800c7d6423dda1a17a5'
			+ 'ec76056819636bb7e285616f32ef57a3716d987444bdbfa0ec59ce77a38c5ab2'
			+ '24a866b7353dfe125312f63da9d55a954ee5c934cc3b4d532e3ba61776bfcad8'
			+ 'c30a458c85a5893aa265b09110eddb937145376d641dbd6934eb5dbe78a07804'
			+ 'a4062b8568ccda85532e528aa5823e8bf91eb8efc46fdfee90ad58602bdc68f5'
			+ 'ef55144f79d5b12934fbdc430c4d168d4b899be1956859b955a45a1af50f8130'
			+ '725fd7bb108a1495ff4e571e283492eac84e6fad0cdb54c71124d98e6ab1778c'
			+ '1904789f38dedcbb36a8bcea306bdd2f32c5cc6d9b9b35eafe0f9aec464b3dbc'
			+ '3887890564c5b094bc0b4841c552d7ac1020d9a86eaf14a30adc64e87398c67e'
			+ 'ea823c0717ee4f0b6d3a1db03e3fc762f80d840cc9273e748fa1f3b3d01eced9'
			+ 'bb86818db5cfb9942da2d0ac24a344fe903506417282056b0ff2d6d1837cae3d'
			+ 'e74253833d5797fe4ff68fce934d67667376307e5cb51c0f0abee44dce098bbc'
			+ '7163fa8b09b774c0b362f78e920f2af43fa5db0e391fa1e1ce5d3bb2184b6147'
			+ '8421debe42a60b4e85699dfd97ea6d4571fd9930500fde4f213c321406f92a51'
			+ '608f78ff559bf1d9d52c1e176ec31e007241ac429dc2d6fc21335a337fe07aa3'
			+ '810cc1b6eae0871d3f37f2270cff827c70b2f5809dab5e214562dfdcb93110c7'
			+ '532a17f03f8fb268c149eefbe41c5f010f13648fa7cecd98fc00459d4849662d'
			+ '33d6446c01928fd5429d4e6a445a228bff2725205e439d98961883cf64f40510'
			+ 'b4325606a75f293534c3d3456664b180d0a9914d591a5f89ddeccb2ac7c39815'
			+ 'e2b4cff5dbf23491757f3bbecd7a8462424b93fd09e7c5832731f9dcf19eb46f'
			+ '82a0c0eac6f4cb63a69b351e9e87bbd6c8bcc87c331bb5a39f96e9a656db2daa'
			+ '9dd94688514c1f0bc8c618bf8b641911d74fb71e495248c9281237e5ff9329bf'
			+ '5ac082b898932680db11cf7ce4deb5d67ce9397f9a886a2092df1c78cdfa1d97'
			+ '42fd9d403a95fa11cf52a6b373dba8458a04e01c2a6bbcf800bd4e92a4f6d381'
			+ 'c543578c233fda5c0564eb57816bdee071c16ea07ce2db9989c18015f10075ba'
			+ 'aa271f52bb1906f9a45cff060446ba81d240921ab07da9e59512a629397fb805'
			+ '6aef9e3becb12004db1f1e25c871ab30ebb995aa05e0aa48630c03db1ee118c2'
			+ '82c877b077a53a68ea98fa5bc60cf299eec50b52423acee2a015e027190b9dd6'
			+ '7ae432ba0a9af6f60bd7e5d3c24a5e43341ce7bcb893a6b582814a6d9b463fcf'
			+ '6cbda6245026b6d582c3e5e9ef5063ea837c6e59db0a93210883e0c06f78b9f1'
			+ 'c1d4242635e1c0a276c2c74cb4af386342bae5553801a491e3db0510c82c9749'
			+ '0f9a9828b4a6a568d2a65a7f9c77fd0d93a9ed07c1c98c5afdd8ccdb4a9249d0'
			+ '4263c3b1bccc0c2fc1a71fc55ba16ab0b74fa212fcdaacd34c54f4c0d66710f1'
			+ '6bb5210628b45c36bbeae16e9dd9aff199a3425a83b5866469eb651802c819a3'
			+ '15bc9e0a930353f9a926c7833e16bfb26df689f00a26ae09c0b40a7cad065d82'
			+ '6d1f855c8b1ce822934d8032be46197368131f604a87c39a1829277b26e7462a'
			+ '5885c9578a27c58d56d477cec1c733e7303063f331b60837760f8350aa3ef60b'
			+ '1b42f9f22e49a4cc06501653be3aaa9c7ad1ba1cf2616c5177f7a02ef3ccdd6c'
			+ '2736086b63adb9ea4d56559d07802f173e771d88ab1e4123ad5c9fe733f1225c'
			+ 'ee1dd3ed51e8149759653b34851aae17ded3201628cc8afb235a547845124f88'
			+ '8adab8b6970dea5e8d46543619647e02d4e4f98379ad36a7d46bfb3c47a1deae'
			+ '9c5499031c83fcd8579ac35f735f661f979b1a23c0ecdc23ddd53994e641f851'
			+ 'a5c8968084159eee08ba6f56d1147c0e00e27e40f3837632d41d18ba720493c6'
			+ 'f09574ef6d660115dc0da7371fb141f690ac987908e9e71ab803e7852a7afcaf'
			+ 'f28f07120b0cba985b8729da9e2f36bba243356eb38555f8a87ffc28ff5d9d05'
			+ 'e84566556ce339c51b4cff5ee18f99b42ce6e2c87fe4f459e474f644d1d5e55b'
			+ 'e60b6938e362a2840bb453a8de3a6c9ec4cefee4b88310527d4ab80e68447a6e'
			+ 'f5de994e2d5e822acb9a4b903672a49d835e894b44da3980599796668d6d1f57'
			+ '448a1b82d7f0fc4d1942bff1036ae914b1457c879bbef91060713e29ab9c6d8b'
			+ '8b4ffa208755e2ffe5250a3deb99f198c14203faf9aaa63faaa2d8baefe27324'
			+ '80aa8bf502aa56b53f753242fea3b2392b2e0b1fc1ed351744fdcadd0a227517'
			+ '6709e19dd31dc6cd61c4e72ec1eb3c7480e3dc65f9da2d61485e12c977b87a27'
			+ 'a4f42d3a18331c089405f9ef4f7d7557c641958549190c9544f9d0ef265ad35b'
			+ 'b337ac374303b61568267f0570715b194e39244a132e5e502b703ece48842f13'
			+ '0b6a60aa97c390eb8ca9b3a86a370682c81974556edec514e143fbd3ee42be1b'
			+ 'cfea3d76f32333c28e9229d942409426442c1007a0fefd49e154cdca861f7eb5'
			+ '82f5e8ff5e4aaed82114546c28a769af0e81f26cf74111b7e99cc1a2fc54d7e2'
			+ 'ff5180acefa3a837980849b1b6e7e5a3f7ca1f5e027d0703a2d8a2078246e16b'
			+ 'c60a540e4a60792edff5e9fe44b3908ca344e9ddbf9ded5360cb0c69d1882c82'
			+ '078d64467489e7e0a7dffbefd067ceae42748fafc9e9f82b51c8973240210ddb'
			+ 'e4ba661262d20032f3b2c6b8c83e1bf8fd4d8bde63113c6ea0c71975bcda926e'
			+ '98c42dec60cbfccd53f3c0055799f26b3d540dd390a5a012a7c7de5ea05425b3'
			+ 'b81e52bba9594c0a201b840423e4357f25bac9e28e4b8cea80d746acd61de9d8'
			+ 'f7e3ea8c18172506369b1e1d9020e9ed73b57b892c1d97a2aa6ad2ce6082a63f'
			+ '3815250dd2a934a143f5ff25ed375552a6a72f7d5c21ed1cf1bc354cb968fc35'
			+ 'c10c54e5739094a332d8ab193a885ee0b78b375cb8674b8dfa989d664c667aee'
			+ '0e3aad4c170cdedd03e8e4a8aee8b58e2382b233570b706e586bf1526e988b16'
			+ '815a01f01681626abf8f6728d6a4f9ecea0cffd87dfb48102ac4ce79769d6c6b'
			+ '11ba4ca8d4a09a225a2f2ea01b9a3326e568efdb049cd1ce02d690b1a4bc99ee'
			+ '2f83c309cbde55dae704744ec94ae6ba767236108b9ceed4c41886297a8227ce'
			+ '7ef8ea0155a9991b787b77f37196e688ff0a33cb8b18e6198418b364facd565e'
			+ 'f8e6e5b0d3e5c5aa3ec12972b673ed777d81f7d1e01fb563a8bee71a53d8dda1'
			+ 'ee2d665f0d630af7db14ea407c8fd86b33063dd76f448c5e45f213dedda1bf29'
			+ '01a5018ede217eba5966156d7dfa56bb9cc4bb1201de47f0bc45808c1d635ef1'
			+ '81683ad34b752fef193eb6b63448a4c67e30413b9240913c784d030d1097f80f'
			+ '1d4ab521c0d5ecdeff4e53921abf3dc053912316737b3c378afba838532f3e6d'
			+ 'd1d1767208f757a247b4b7cf781b382185573c4e04c9e094bcbd1918783393b6'
			+ '1ecbae53e1c2178fe028df5310f9f5a314206be7e55c387f2458341f8738cb27'
			+ '08c7c86dbf4c42f03e22ab3d4905ecf1dda050435a9c7de6386e9f23b356b28b'
			+ '652958fcead2436564c683634371edc47be77639c3315061c3b34003b1a6b7c1'
			+ '86eeae37c968d854da1374abfd419a787151ca6a18397914602264c2261e79d9'
			+ '7280a5ddea5f1546518e723c45b183287567212a8029422bcb9996deae2ae24d'
			+ '50ba5c81690fdf937c4a945b6444adf70012ed096bc993cf020eeccaf29191e6'
			+ 'e9d781f3a8843a62708cf413f9453ab86389703f10cb24d2ae0505a472501f70'
			+ '5e8da09efd11807152fed58f9c42d407b35f1a1202ef7489767e0529f58d6045'
			+ '1c9056cd4ced187d9b722e85559a50b32ffb31d3963c01b45bed8c158f1be381'
			+ '832a2aedf60302e433b04e03a4d07602939445d90ee470477d4cd14fd14b2ee9'
			+ '75d355cc9de44874d43fb706837e012d3c5e60bd055954d8f7c8d13e78d724eb'
			+ 'b7d182a5fdb361f4524b3362bd670f4f8b4a27f636e5bbf8785280fed89abf07'
			+ 'a2756e92cd8c77645497a3c151cd2b77c7aad938dfc660256450327417b58bf6'
			+ '0c842fe8dfd6f9648206bc970b2048abc798b46390cc8cd25e4d69c7f1f96a11'
			+ '2eafe29978f30f7c0d6a046c98be72ce17236e82c7b9a5ee1ea8dcee5206cf86'
			+ '7255557eef5fce361a7b1c36bbab7a3a3bbccec080dd66832dd1f947292af72a'
			+ 'a0bf1713f8ae8be5e4ef602d3cd2c017f006184a316f468a694e2c7a44b3257b'
			+ 'a959087bc36b405407ff2fc667d0d15a4c3dfa4fa5a183a83adb7e390293e414'
			+ 'b5c8fe0e2c0c55ea56bdecb4188065e7872f0e29c7db43a767348719559611f3'
			+ 'b44847cdb859895a67c12be849eaddc2f4d4d01487995cfd95b667b567bdac81'
			+ 'a6359ff64359bc574395c323d9d85eceeaeed60218b729533e8b2774b1ccf02a'
			+ 'e504c1a7b9c8b1cad6e8ccb0ed9b88bc2a188257e8928667dd58bef42493400f'
			+ '46b0be619588e76d46be949e1f06acfd7f4b08f1dc36daa4665630a035f7896b'
			+ '87ebb799980808320a5e8dc236edbe0df9f4ecaeffc8fafe4a576a9ebbf1ccd3'
			+ '81ca8bdd14a6f26cfa07bad63424fbd1f5eb9201cb0a3613c8cb408b740239c4'
			+ '35c2e731beb3f98bf6b8b935dbc3ca8ae2dea1f5b6019669fc4a900d32e924b3'
			+ '3c969afeafdeb096e148036174325d59d9727498b6765ad0c0960f6e49dad4fa'
			+ '192d67391ca3fc5777576b11d157000cb8dae806e43ee1a3cfb6a2ac3527ee4d'
			+ '59d5b8743e1533c27958d7971a2a866343459637282ed0d2a1a64e506576b04e'
			+ 'ef853b58ba43524e121134b410824a1e060822e576ddd3952e73b7906346d3ae'
			+ '0de71a64488d6b652b0c15fbc3fe455937b2963924bd3609ea83e625a87d5b27'
			+ '0cf8b356db81d19d4146a3ade7be181498600ebf6de0a6c03ef6e6192aacabce'
			+ 'bafcb9dc13deb945710319ca7e75ffd19d11d2544c1524c6d4c63595c743a15a'
			+ '102123e68fb6256ab45ad591a77b87738bae5ccb07bcf0dde3499239496da046'
			+ '95c04505e98a7ffaddd9103cf3070f67007e02688a361b56270c710eb00244c5'
			+ '97c899b6e288f28d17e602231317ea5557433c8d32380f2f77288ddb1896e0df'
			+ 'fc2454de5c67aa3c0c35a19966927fb5e88aa591e241e9eca7f61e8dc4fec2b8'
			+ '8068b692cdd3dffdd41fcf1c25b72596b552dadb4f6148b3b622b13c657e5bdb'
			+ '51c6518b293408c365f5f22bf4a00e5932830b20da147fd1f4dfc7d59645f2c6'
			+ '4ac3bc33105819c172b4efce333d927ef748825845a69f0dfa62e343f67a7755'
			+ 'c42568861e06a1b5dc50c679227933d822bd500e9bb6ecb34ada3ab20df61239'
			+ '2d12486715b43b47561d0f3159e9e83414f13908b4a5670d8c7e3b594df8d2eb'
			+ '8220620aae48c95bc604b303c47831853487abe0e19459901cf7afde0f014c0a'
			+ '21d3aa8b6f1cbcc0d11a9d0e3584043c5d4b5b9903f3be2cacd2276a099b7563'
			+ '12e988c8b58ed18f21aed49fc106624462b97985655ef3a99b5f1a40acde6fa5'
			+ 'b95e1498c966f5d7d0c0f8f79d598bc613d44878402ec12682512fab66a15019'
			+ 'a571f84dcc7618ab31bab4278576faca0a80e2fdf71417b2abe00fe112279184'
			+ 'e77d6d97249647f5d1408d57e16d07913241d2f725389713091de3146beaecbe'
			+ '1295948c072d0cdd7808368f2720cf8ff57acbfee6a4197c0975c53074bffd08'
			+ 'd0b578b0fdfc0bfe3fb89c3fb5a188ce4e58d468f2bc738a459189132c4c9614'
			+ '47eb30b0ef1ee7c9e2beba5a2f5f0e9288f17c0ad444f3006567cee4c5eebdfa'
			+ '12cb9fc43410c0cb63a8ade6bdd8f214764e02e946a9e0e6af64c0afe94a7190'
			+ 'a47732217485e18adbc3b4b42ba3652516b82f377f617245ed1349169b9b8e17'
			+ '5dd88922fe09cda686814bb8efcdfaf97a5c4b7862cf692e9a312a412b680c26'
			+ '7ca382259ce08262309206e8900d771855747ea7c10bbbdffe2602816bfd388d'
			+ '69dbc667e54f6df9040d831dae67549db2963f64f57501420a67740ad9866fb3'
			+ 'afb54fe4aa2aae94d8741dc34dc5477230dc07dab1e842b8c0709194e3466d21'
			+ 'd0d0e3f6d9857aba70f04c382ec2b39cfb585147a73f8492ab286a24e51f8525'
			+ 'ad4b85006243ca8224af1a357aeee12a9576b3686b1b6d56d14539a4079e698b'
			+ '26c7270fec4813aec0bd62159656d8e5cd72c24eaaabecd45b724975f28b3f86'
			+ 'c4b18c53d3ae9c58c55d1357efc8c91bba2b3046252e3cb21afabe89a1d80cd4'
			+ '1452dd5f719210fdb9e87de65d06cf1afbea4dfe6054d9a111fde6e4ac554042'
			+ '43715ebee2c4060829909bfed04db000de6bdee11b4f467311c024779b3a8e54'
			+ 'e64d330d07ae85dacc694da6c7ea623575811e3aa92790767f656c689fd27277'
			+ '3762e932832582fda68808abc6c5d87e28c34a0db2c5b6d07fb63389ab2b62d4'
			+ '15146ca0698af9c08fd10060f70f2db3ee189301a6878ca40252bc7ce612cea6'
			+ 'e9ffbbf379c796bbc5f1953e69b9223c33199b7ad24bd4d007e6680045bfb124'
			+ '0f6a1a194c60cd8a93664d7b58938a6a52023c9737de110319075346522a2113'
			+ '6cedd2f424753e6fb1d258e34fedd85b2cba2a67d31d12e25e3e8f8acf7e5deb'
			+ '499d6930efb7257c6a0fb549c06f42a99223c5af156bb0d51dc1ab49f2a87e66'
			+ '1b195391966a7ef26940d383f32fa30a8881334de578059c2e009b6ea98ebd3d'
			+ '92a879647acb2ac570aa281b08dfd5b92f55d8afe6110f947ecd5cc130ef9d92'
			+ '5bdc63c9e9d35f61311a5ff40d836a8bc2cc5d46201819f6726238d92c5ce0d0'
			+ '9f369e726a97858d9cf9c8000781f7b6a7891e10bf3cc8fa4ece616f61fb5bf9'
			+ '1a667505391115e0dd1d82e91368c4d3d199d58856fa36143bd883807862aa1f'
			+ 'e2db69cb54c8507c11740bf65103d3d24ed9d10c1a3ed58331cacd8a8d2754e8'
			+ '13d4ece63a12aca3a6f0c62b7e68df086311a7cd4bbef3cfc2a4dd016bf66dd7'
			+ '9f8a5e300c36e4f5a61dca0e0d97280fcc3980fbfff4737104f91c1e0753c070'
			+ 'fed3c2a677ab42e30da6c1bf30f7c8dfc3e5552c666cab6231d6dc4e1af19b68'
			+ 'dcfa05d576ebf42165e767aa56a447e1473710a3bb9d6b04a939926ccda8cb74'
			+ '50186377d80f16d38911c9d270549bc342a9f6e566ec804072dee58cbe7d322f'
			+ 'b9d8fff2688a8a3d1c76903cdddde38fc550ea00d7844d500acc02634d324919'
			+ '4da7af53e460132daace69b33d8b0c744233be079780d7692ce3537cb7350c85'
			+ '29cdc7ea5225c384588280afed79345d48b9985ab772e715920179a7e46caf2a'
			+ '7d572c71e9542eda8d767a7e966a6aa58b38e8665f8adc553eb13f800050fad2'
			+ '001619581ebf963020f8e494c826c6d18279f8df3eb04197af4a307f844ed372'
			+ '0b43a45c3bed1e83172616a1218ca06f30c4cfd3c30516a57355453c42ad5737'
			+ '9906216995f795514dbbe45555b5edf587732cdc856d782cac3a54d13e6b3ffc'
			+ '7c6c560f8227e25da054403c32c2e0c82683a881a9d3a3ef15a390785535a58d'
			+ 'f81618357d13792ff5d6af295c8ed03db3a907e4f9371294a2d322fb57d7334f'
			+ '7e9dca020093722e67a1b9bc6746c3389fe7508885232bc21918c9ef41e1d0ae'
			+ '92176f1fc6702403328d0824fa2cac6bc364dd2786c667edbd91732596a5bb70'
			+ 'c6b3e913b1869c7c0fd64fec11e8548c3d5f94fd5196617b2b20a663ed34da81',
		msgLenBits: 65536,
		functionName: 'ParallelHash',
		customization: 'j<E(% 31q1szp+VGK9',
		md: '4807fe2bb0a0a4e9ddfdf0c399c92f192f3bff305a1679d4820591058d1f171b'
			+ '9d34ac129217',
		outLenBits: 304,
	},
];

// ============================================================
// KMAC-128, SP 800-185 sample values
// Source: csrc.nist.gov/.../examples/KMAC_samples.pdf, samples #1, #2, #3
// Records: 3
// ============================================================

export const kmac128_appendix_a: KmacSampleVector[] = [
	{
		description: 'NIST KMAC128 sample #1 (strength=128-bit, S=\'\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '00010203',
		msgLenBits: 32,
		S: '',
		outLenBits: 256,
		expected: 'e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e',
	},
	{
		description: 'NIST KMAC128 sample #2 (strength=128-bit, S=\'My Tagged Application\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '00010203',
		msgLenBits: 32,
		S: 'My Tagged Application',
		outLenBits: 256,
		expected: '3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5',
	},
	{
		description: 'NIST KMAC128 sample #3 (strength=128-bit, S=\'My Tagged Application\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
		+ '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
		+ '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
		+ '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
		+ '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
		+ 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
		+ 'c0c1c2c3c4c5c6c7',
		msgLenBits: 1600,
		S: 'My Tagged Application',
		outLenBits: 256,
		expected: '1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230',
	},
];

// ============================================================
// KMAC-128, ACVP AFT/MVT (byte-aligned, xof=false)
// Source: ACVP-Server KMAC-128-1.0, vsId=0, byte-aligned subset of tgIds 3/4/7/8
// Records: 2
// ============================================================

export const kmac128_acvp: KmacAcvpVector[] = [
	{
		tcId: 771,
		tgId: 8,
		testType: 'MVT',
		xof: false,
		hexCustomization: true,
		key: '82feb3906afa6df1ea34fc73e876e7acf25a14b6d9756d4491759b86afb4040a'
			+ '5efe4663d89a0a597a896a1fb7d56659677bdd6a0cc607c8618b2b7453e87b54'
			+ '53b3484fd04e27d0c4207ce03dcfcfbceaef6e2a0858bea64d16b1ff6bcf7af7'
			+ '6aa7ee87915149d6a5e5c2cb6d54de138b9643cee0e5fb423bdaa11925cdb686'
			+ 'ece9351be35b522ebe4e0f049af981ee2fd7cc215566e19fc3d1e2e47f0725b4'
			+ 'ea5dc5ee430dea57b79935c184bf131dbf20204a81a0e4b1d87829ceb20ac8f3'
			+ '1093c3ae17400f4f214ec13918b917ed9f95ee48fa3548ae0bdc2f535d0ca679'
			+ 'd34d7a9cacb3b2ad681b7fca4ef08d07cc87da59839b408b2f7062caee786ba1'
			+ '191029a5c1e3747aee72e33bc0781e6ea61dcbc8adbf89fdf33c80202da1204c'
			+ '5640436d5e3425985088190d9933c7b091906c0ec5c1e15c7d88dae77cc40208'
			+ '7f7d6e8828affe132c918a8f1c0785cd23fce530aaa0cac5c86b1c5d475129da'
			+ '1735151f01ebac76c016ae8f86aac89ae52239a59f1a3e949d7073d526bf29da'
			+ '211139e5a16bf05da1844ae83467353c41431c712c4aeb511ab68af1484dfb0b'
			+ 'fee3f7bbe709dd029365ef8b6b594b2761bc2221cb28be18cd20ee7f6d83c291'
			+ '0fb641808f96f96365e799ea62b8',
		keyLenBits: 3696,
		msg: '31ce6d47249115837fd815d9b490711d801f2e5445a37203c597fbe099b86c9c'
			+ 'a8c80eba1f64830e96a150ada8b863833a4cc7c05a6bc43f888caba79fac24d0'
			+ '85be921714ab6a48df89c00ae3fb90713f9b8cbe88f25a3adf236689ad629757'
			+ 'ab34a8392aa31fc60a50b2b5a5a463ef16590a3703d0042ef8bcba3472759991'
			+ '3e66ae46eaa7cb49d3908e8d2053f69a57d9fe47f3d6bd5a7a93e1f5ecf25799'
			+ 'ded2089c3fbac815a1fd0ec12a7ec1d9b1a727ca0e78634703ee00b3bc6c47e1'
			+ '52b90ce12ca8417ea30dbf571ec0487b469d6134d4a953eab4354581396b2260'
			+ '552c8173fa077712dbfb736263187d486f3a1edfcc9c0ed32d06e9a4bb1d7a17'
			+ '7022709b09b8b5657d2dd1e27d80f19ed9009eb3839383c5c88b2baf6df440ac'
			+ 'def1e354b656490eeda2725062d65f58b55798fcca5809537726f252c6a207ef'
			+ '7e33b9dcd9a7f572fd680c8ce7fbecbaddf25174e4bfe097cebdfbacc94677f9'
			+ '2e594b4e913c4a07cb7dbbaaf0d71173d2bb993d9c3649c9814a1924aec1efb8'
			+ '13fc64f86ebe76762fedab2e8861e2e8e1aa6db8ff8af69251ba0d07b37af577'
			+ 'ab440bd2bff21d407498c792c99b838e52cd9fa3389afc1fcf23eb8cffea0ff7'
			+ '7f74c90cf034b5804ea653fca9c5b63c460cf1c37175eb7551fc0775736be6c7'
			+ '9471577fd8ca9b44901018240f4e1bd6995ef8e5b1a368d7f4a2d68b78469167'
			+ 'ca634ac49c4f9b3ef2a366da4ce017288780bc05d2b12ade35f4cf74088de7f7'
			+ 'ea65052776a2565564cb96dc829ecbc416df18603e7ccccf8ac067f3a5000989'
			+ '80e87818a42d079fe0fa819f81b59e9de77574121668e0637ea9557d42374fe6'
			+ '6a1892203bb3398bf12ec81ee04a79df3ea92af5e674a11209b4ccdeb8f9cea8'
			+ '1862eafa95dd46126a5a86b77ae9184a880e7710e06848551227fe82c6a4e578'
			+ 'e54308f89402edb5b90b5d2ec9b43a073792829e71b4ec205a7ffd8292001dc8'
			+ '894f6bb5f14fdc0aace8c4cc89a2d410aa9183e36c6fc751f8fa47710c9a9e7e'
			+ 'd7e6d19dc4e499ba75ee0e3805e51aa2f0091d317ff5af5aed2f998b0952f9bb'
			+ '21c9b1a345c519c7c202d91bcab480918551c30655bf48898a1662deac5bbc4e'
			+ '0ad8ed85779ff3b41073f1c77f3a714f0d45e6c5a104930f4f284339792a3bb3'
			+ 'c958553c048ed76b17640be9cf98b2ce4fdb08e70e86a76014f1134e0b0b181b'
			+ '5dc05f3108c12b162df54c4865a80163774f449246997329895efd2fa4056163'
			+ 'ad7092d0fb2a1d946e4e8182af30bf1221b8546c6ec68cf0905b5b26559964ae'
			+ '77fb7924bb231bccbbb258d2890384e58453c909b4d95e26954ef317f6d946c6'
			+ '210a8533164466ebc10846cdec213e837251009c6085b9fd2e8f69210eddd402'
			+ '7f44f3c887f73785f02a8f6dd78db6fe7002f5cadbc60b14d30d2a4dc9561550'
			+ '761d5aa21fae85671cdb636b9a8c0b59dd3278242d4b1fdae712770c5f536053'
			+ '9529fae2e69330e8262216fba0f2274a1989a12aa9ab7970ff40355097ac8a32'
			+ 'd6045ec1d625e27e5c21d0a7bb1f1a1d630eb9e9863757f4ebd107c8118d09f7'
			+ 'cad11abb0f8a58d3732862019f6541070947dea1a35504f1bf6e4c2ff856a6be'
			+ '23700cfd26236441af5d3e8b2817623800ff1eb84c2d67d7cf40de74cc0830b2'
			+ 'b38a18029d420627002ace0b2cd3319ee2183729085a493b72a93f2d4b656c7d'
			+ '686a5f5ab54551382827129669da800f6d2ad93885991d12e5ce47ee7b2f4e13'
			+ 'c037e5ade39fc8bc51bdc2256c2e0aba98bb5d9a782cb54d1742f97e01a2f6eb'
			+ '4c7fc5739418cacac452653ae73554de4d4990711b9b9286ab79c5ad698d0eb6'
			+ 'f8a95ac10d5703282c78350bb260c7ddf0630c1058ef94a640d2cb9741f743fa'
			+ '5d189aae1344415959e961af42d358761007a4ac886cce93586d064fb15c128d'
			+ '2878de0bd6d8e59410957c2783ec1446217cf353856b733c237186f8d952efd6'
			+ '11e49c571a7af2045b2918fba8f205de66dfa1a0322372c5cff886c9dc40be28'
			+ '91251a88cb7a26c31d2677f7304234a93a6239987a80fb2b6c68d1403e102ad2'
			+ '21483edd9c3f419f781c202e4fdf2da139c4d90612df71cf02b6c80d1a9fe03d'
			+ '55c6d65ee36e6d14694c78ec4ffee23576ecdf1e4d7f98f7a6214b0a53abebf0'
			+ '08702d3114a48d19e22786abd717f14ec11cb9068fe8ad82f7ea027187503bf0'
			+ 'f74f04414da35130f26f07fb028fe2a993d35a8f9ce2400cb17ad565d47f89e9'
			+ '22883bb9c184221bab55e8d0f55ffdcd4fd6f011395e783209c5c56fbffc85db'
			+ '40fc5bff5d327f84e494ed14154ad176ea9461595bc9e57e8898eb400807af98'
			+ '6afe1ac7d6e861b1304cda1fdc01caf505ce766f94f0d95ac331e7bee3b0d0bf'
			+ 'b3c916e03fd7456104f5493423a9af6f57cff1d8c6636180de599e1b4965a77a'
			+ '80fec88b7121c4f6a63dd2f570b8b4624c31248b2a51bd7c55870104ceec9ed6'
			+ 'ebbaedd80bfca17b5a1c2983dfb607e05e6d07e83c93356ed6d488129d1f13d0'
			+ 'c0b2ac789812cf541a611e60bf9351dd999f23e1bc5f89983385eadb51bbdd79'
			+ '7ce8173094a17f824ec447c52b68f3c1b0d9ce7b988fb9d7e2401a18941e1862'
			+ '274ac8b25501b6681abc7076376cd94d9e7ff9691d04c3449b6c314b0a9a3ebf'
			+ '3a7f3105b69140aa43ec805cd35544148b24b2d3de53e1594f7e4495abf9549a'
			+ '1944cb7b8065725052d8bcff5e13c3e002dd445e35570405fab26a28e29382ff'
			+ 'ebde6f973546f2d083e82be258dc0bbaa727282df9407988dc00c27336f5397d'
			+ 'ba15db6acd6b072a0b3e9eaee0e006bd25a11d1b103c15c6483d023c71fd0f21'
			+ '970bc25f99315bc542396a0e07c1c6df3d33704516d0897d75749b29304a6475'
			+ '4da570a6bf44f096e634ec9ab98a3be4673287d6725cc707b282a389c842f92f'
			+ 'd4249942a62d12c409e3a2ded73c0019fe646b29793899e6e817d4d109fa7989'
			+ '12c3d6baa33a48d35c000e0c43af1e8754ad8441cb0cf2aade3c7cef006fc518'
			+ 'f0e68df6c354c683a537366ce378236506d441ce13696fa0ba9a0f69bdee0a92'
			+ '6cf2846714255c957b97ab3bacad44eda63add0b02320a754da21b1fea411b51'
			+ '72e2192865ca9fe3e043001edfbc42d6b9f9abd8407d75861aea31b4083cd87c'
			+ 'b68af7ee84fee752131d8977b8255f7e56245bc3bdd1dc6ad09e264c1cb20169'
			+ 'bab9433e3b98fb15bd69a91ce8462440374e660aa59335f9c933867f13a4bbbd'
			+ '3a71bddd6697cdbc2e0157f3caa69d571d3af1d76f3cda7897a9d60855291714'
			+ '5c74c3869d427b2825d646800bcca29f3cdba92bb91731fef75b1fe1c0f29375'
			+ '8262c06d46da33c665aaefa13ad2d4b78a96fbe89f99771ce20960d108e0d314'
			+ '778153df832d3637c448c430331308572c28c193070bf6d542439b7c11f70e2a'
			+ 'db22b5422a01df4c2903f3956fb9607d8671c8160aae372dc37de0637a5f3ab7'
			+ 'de34ea93918ec9f53fcc423e38ba5323a715dc4caeec5ec5b647d1f4f61e196c'
			+ '422b4fc2dd079362be77036873ee749471d78193cb7ce22df6c79b25f1876c42'
			+ '35b62dac4fc4fb28a9a8c8911a548d516cc27b63614e226fd89e87d8303c0a86'
			+ '081ebd0140e057ed3be2e1eeebbbcc7ea0cb61fb0e7560f2b76d8da6b2360b8a'
			+ '96b44ce7d32d1dcdbe8ad9c140d9dc6545390e3bc7a13b5505902e5dae157714'
			+ 'a422c7c72011b8af07299d4acb6683e5ca3bbb2a4ab0ad5d7c6df98bdc24f75b'
			+ 'd4a427c4bfa6a0006459eb74ffb7c3fe1c0b81a5714cb8cce6866ec1121c08f2'
			+ '9e9c028e649ff04ce02c76037c93e4eb2f0ca7e41795f8d6338c63aff3812dda'
			+ '5c6808e3a3f20ac3ef993b6922ec584a36614240f6645ba780a5816f63e0e51b'
			+ '9599efd5de1b4c714c9e49723c787bb4fbc690d89dc3744c3de7ffef64566138'
			+ '0b77e19ea15411c73ae0036ab0988e7f94e5c6c419f19377389029efe2865250'
			+ '08f90bcaf7109ac18ba9c9303aacdc67d6e176b6a76a321642d9af3b169c7004'
			+ '103e178dff64600b9c6d2e4c08d650e7cc3f8b538b638e20870a2f581c362fba'
			+ 'f6d2068b93a9a662340119358aba217231cb71455667d617c9ab36a6c7950db5'
			+ 'a2b9062a4882b33d85e2ba617a58cbbeb1f7ed29ecd173fdfc4f0d47e62c45ee'
			+ '63948d5579d3691ff55e17c964d267d7f21dd20c83704a300e80fdb2a1a89b9c'
			+ 'ac1e34e12fbddc8403719a3601817df901aff082c8f10c9776bc1255576d9090'
			+ '94194be1cc6886e2a09bfd9008c0ec21d5541f323930b5f7ff004ab5a07c1f01'
			+ '01a2f7eea3534e20e129b37de80c98c071b3d2776e92328c07ee341a89670b53'
			+ '19e69da0815ed4a8cc8dc46cbcbde5341bd31cabd038e79e43784d77fb1aaea5'
			+ '95703bce41b3948e5ea3b05531760555663035380da1c454b4de5416ed334b7c'
			+ 'e3f5e2c1124b64510b2a4d948d9c7d978f3bab4797929b77314d1aa604a0b9ac'
			+ '383df2ae0d94901177cccaa918f5a1cf8458b6a6df83b9d5a3ef55a35cdc1dd6'
			+ 'd3658a2f6b01f045e18aca50683f6787f1778222768c11c26c5daffdd9729b41'
			+ '1d32e87f7d9346077b2d33f146253353ed2f16f81e3b08bce508c2b2086b7315'
			+ '7b10769b9354b7076fa05e7f49f7cb2e10b8694d88175294ce7cd4359ab6a7da'
			+ 'ac7de81154430c567d9e0f71cfd639b93d5c68b04520926422cbdf9faa34a57f'
			+ '112e5582b0088a7969af6d1b7b755fad1c7e693f36b90802ff991adfbc7505ea'
			+ 'b98be62f845538a79c9f6a4e2292fd3caa9c15b01e5e0af85ddad8e9b02618d3'
			+ 'fd90ad78b20949312f889e40b266dcd882ca05d448027a67039839cd87672f3a'
			+ 'e01cb4ff6a8007b0715eb399c50e9197a85f50df61f8f0b18f18f8b9baba8fe2'
			+ '21644f43fd8437d3aa67cd39b40a7ffc52f3881649519e2f5fb284a153b1173e'
			+ '9767a3450be38b30759a3100274f6414ba4c6ad1f92749c5a95a2689b5ad6ddb'
			+ '67f488181e3a48bdc5813d93164889853b394fc18c7e331f80c17f54a050b2b3'
			+ '2e4848b1d59f4e090df7502c47ca8629aec6d967619c23b0a65eb86c4356b515'
			+ 'ae845e9d71384c14a1b05db02ed97e382dc3aa556660388ce5baea22b4efb96a'
			+ 'a87f06c502b4ec591b3fc89928096a90806c5bfdc15d94b44a61515d91685469'
			+ '4a85b9996afea589c06bb2fa1483ed37187b8a095903f0621871c4a83eacc5ce'
			+ '3adc1c1540820c0b75b501b1c0ad250e09900a56378f46679afa1b770a1b3ec2'
			+ '1d73a83a91f6c722d2c2989f6b8b5d33e8cec37d6ee241e216ae0c08a4dfcd0e'
			+ '556c3c1de00dddcd0d793979725d15a703c057d829932e5a9089486fc3d49b0c'
			+ '3b0afd803260f43fa7ed119d3cd26b5e1dcfdd40ec091852ed6f7dd54d84ba1e'
			+ '16764bddbc3376e00143e242e61bc90d5e95f37ef3b28287e8b9b4a940f58289'
			+ '2ff7b805e0caf4114dd0f36e91010ba118becad00eea15cf7c2ba7b045c4b0f4'
			+ 'b17343f1bde1cc2865026808',
		msgLenBits: 31072,
		customizationHex: 'b20f53bec3',
		mac: '71cb6f914872a4967e736aca16389386ce147e4801e464e0415cad3aa5f3cb88',
		macLenBits: 256,
		testPassed: false,
	},
	{
		tcId: 799,
		tgId: 8,
		testType: 'MVT',
		xof: false,
		hexCustomization: true,
		key: 'f9dd43d7a5a776a76b9d1f10bfa1ae960c0c3a8b30f7be76302fc7ce22984cad'
			+ '88b3e1f2bafc5737850d48927e20d3d34718441704da7edbcffed4fcdefbb4b3'
			+ '309e309275f5af50243e66aed28e74042ca6cad74c7c4bb84657e76a4c7b75ec'
			+ 'bc1b20f324ff7911f090934f93c532b768207854e771ce50915592ef06a0e0b7'
			+ '8efa740546dd25a4fab2481acddd0ed946ee0a2d3304e6302066d149a474c339'
			+ 'aa602da19e79a6734eab59cea2efb7639f3764cad98b18bb9b127fec51734f54'
			+ '80ea098440ad10aab8e4b94bc08243a05322bdf3c94424b4e56d4eae235f5807'
			+ 'f61950e58f0b855c2a2d0efe40fd29eac1a34ca97b456dd1d0998fc6093bd7c7'
			+ 'e2f949e96c04439fcc38393615f44e753357eafb263b013f02bde9d2aa529464'
			+ '6323f38e735c42ab9f73e57c85708eba6c3a189e9f3bebd687bc46aeb0e212b1'
			+ 'b4bfa6a3aebaaf4cf68a37121188fc486c9ab5bc0449230ac7a14823a93835d6'
			+ '85f60582b8fa5421f71ce7c346b278d0e0efe7e6b997a8b9415f9e03dba768dd'
			+ '4d7dc58959dc3853806e54ac02656965a524ca111583544a7f5e5ef04dd5904b'
			+ 'c9ea29b0181df4aa01fc690de228179f50ecd86cf231c7772ddea64e863950ea'
			+ '7c37d41a05ba517e90bd43ddfa822826ace52a9dbf0c829d052e6a6a9b856745'
			+ 'da64900b4fc4857a89987975',
		keyLenBits: 3936,
		msg: '7f2c0106c94e23d5b0aaaab360c049cf18e5c72c9dc3399e4e4ae6ef79f5803a'
			+ '9269331ec02ffb67d74a0cd15f3b791e87807d591b64c7b24ac136c5b5fb1fbc'
			+ '7c09eedadfd04f953fe39064768460840f9bea99b2fc44804312ef0fc53a4a68'
			+ 'af8256c0bf88ba72192f565fe40ac53ad1fbffff64cf3fd2c9ae629a4368c595'
			+ '42756f3bbe317f0e9b4f68f1ce0d2ea6ac32788acf8cdd1ebd14f13f9755c181'
			+ '21256d13b1726c4985ce8c42edfde6bbedf9f004eae6bab08820ad2a7a05dd27'
			+ '9156efb5c91ca09c376270893d663f6b3f6c45747d53d810da372f510ea3abf6'
			+ '58caa82c682628326e6e58c3f795e7b771bcce26fc35f23a8358dcf14e0e0a8f'
			+ '25681e251db0270d9341aa708e5b68b6287d5f1933d15e77f0c6dd9034bb7418'
			+ 'dee61e604c1035d1d601f85bade20160e910acc327e87644c86b365281fd0f8b'
			+ '9d57528fbc51c6d5418702a91526e226195f8e434712703076dbb213e57658d8'
			+ 'aa0e828f081ac07753f3d59819ec207a7e1bc9dad6b99920e75aa97cc91ac917'
			+ '1f1b9535a16042e23965fde032588a20587b2dae8d78f4404323f04afdf9dd50'
			+ 'd408f0a30c78f5abca5752ca',
		msgLenBits: 3424,
		customizationHex: 'ed2e38980687d9e1d1',
		mac: '0811f1602fa4c4049a53a99920c9759274d6c3c9d997647bf19b6cc928352883'
			+ 'f8d7d8cb10e3abd0baf55e24f9a436412df8242893b322f9931b41f68d723202'
			+ '7d788a142021ddb41162ac1b5ab5afcc1abf790264705761f17f01c2b9301417'
			+ 'dd86ab3da2b5558cc0dbbdc50b86de9d76538294d0da2f65e9d6c1d2ac4eca0d'
			+ 'b3b7a6feefb94971c5919dce383eaea788bfd99e415624352c423895ec5d38ee'
			+ 'c1bee7359b0009a4e260dec8272ae3f18048d5deab7c63e03a0493e0fb3c53ad'
			+ 'f8bfa3d728173f9dc79b4d59624b66c777df217bd2259c04125e0b644e252141'
			+ '6dbd2a4517c32cfc55f7dad3e4e8d484882da4f4c53e20a9144423edf8b1c405'
			+ '4acfe5e671a827e0c65ae48506a621bd574a5d32287d2cccf10073213d1ce4ed'
			+ '39c56a4291d09e2b21230ce79341d08b7d3045e9068c93042bff2867b0e80184'
			+ '587cd18e9214d81c47a248b7f0d9c18a2ab43384ab18f302c4c31165dd2b53dc'
			+ 'a36fa30522dd17b42ca108b434d49310c8615238458fd8bf4e9462ced2d9e169'
			+ 'fecbe451430d958b9b85a84d00635396d9ba86fbf51a0e552796bcd8a2652be0'
			+ '2e4fa4118f427e5cca9015bf31ce60c219a2264b0182c6a30ac66b75c08d94c7'
			+ 'cb528d37cf4a426ad2bb8c464332043795d5748bc42fec02e079d6cba1d2',
		macLenBits: 3824,
		testPassed: true,
	},
];

// ============================================================
// KMAC-256, SP 800-185 sample values
// Source: csrc.nist.gov/.../examples/KMAC_samples.pdf, samples #4, #5, #6
// Records: 3
// ============================================================

export const kmac256_appendix_a: KmacSampleVector[] = [
	{
		description: 'NIST KMAC256 sample #4 (strength=256-bit, S=\'My Tagged Application\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '00010203',
		msgLenBits: 32,
		S: 'My Tagged Application',
		outLenBits: 512,
		expected: '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7'
		+ 'f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd',
	},
	{
		description: 'NIST KMAC256 sample #5 (strength=256-bit, S=\'\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
		+ '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
		+ '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
		+ '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
		+ '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
		+ 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
		+ 'c0c1c2c3c4c5c6c7',
		msgLenBits: 1600,
		S: '',
		outLenBits: 512,
		expected: '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691'
		+ '589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69',
	},
	{
		description: 'NIST KMAC256 sample #6 (strength=256-bit, S=\'My Tagged Application\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
		+ '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
		+ '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
		+ '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
		+ '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
		+ 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
		+ 'c0c1c2c3c4c5c6c7',
		msgLenBits: 1600,
		S: 'My Tagged Application',
		outLenBits: 512,
		expected: 'b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9'
		+ '70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965',
	},
];

// ============================================================
// KMAC-256, ACVP AFT/MVT (byte-aligned, xof=false)
// Source: ACVP-Server KMAC-256-1.0, vsId=0, byte-aligned subset of tgIds 3/4/7/8
// Records: 0
// ============================================================

export const kmac256_acvp: KmacAcvpVector[] = []; // intentionally empty, see scope statement at top of file.

// ============================================================
// KMACXOF-128, SP 800-185 sample values
// Source: csrc.nist.gov/.../examples/KMACXOF_samples.pdf, samples #1, #2, #3
// Records: 3
// ============================================================

export const kmacxof128_appendix_a: KmacSampleVector[] = [
	{
		description: 'NIST KMACXOF128 sample #1 (strength=128-bit, S=\'\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '00010203',
		msgLenBits: 32,
		S: '',
		outLenBits: 256,
		expected: 'cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35',
	},
	{
		description: 'NIST KMACXOF128 sample #2 (strength=128-bit, S=\'My Tagged Application\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '00010203',
		msgLenBits: 32,
		S: 'My Tagged Application',
		outLenBits: 256,
		expected: '31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c',
	},
	{
		description: 'NIST KMACXOF128 sample #3 (strength=128-bit, S=\'My Tagged Application\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
		+ '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
		+ '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
		+ '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
		+ '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
		+ 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
		+ 'c0c1c2c3c4c5c6c7',
		msgLenBits: 1600,
		S: 'My Tagged Application',
		outLenBits: 256,
		expected: '47026c7cd793084aa0283c253ef658490c0db61438b8326fe9bddf281b83ae0f',
	},
];

// ============================================================
// KMACXOF-128, ACVP AFT/MVT (byte-aligned, xof=true)
// Source: ACVP-Server KMAC-128-1.0, vsId=0, byte-aligned subset of tgIds 1/2/5/6
// Records: 0
// ============================================================

export const kmacxof128_acvp: KmacAcvpVector[] = []; // intentionally empty, see scope statement at top of file.

// ============================================================
// KMACXOF-256, SP 800-185 sample values
// Source: csrc.nist.gov/.../examples/KMACXOF_samples.pdf, samples #4, #5, #6
// Records: 3
// ============================================================

export const kmacxof256_appendix_a: KmacSampleVector[] = [
	{
		description: 'NIST KMACXOF256 sample #4 (strength=256-bit, S=\'My Tagged Application\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '00010203',
		msgLenBits: 32,
		S: 'My Tagged Application',
		outLenBits: 512,
		expected: '1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa9'
		+ '6faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b',
	},
	{
		description: 'NIST KMACXOF256 sample #5 (strength=256-bit, S=\'\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
		+ '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
		+ '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
		+ '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
		+ '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
		+ 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
		+ 'c0c1c2c3c4c5c6c7',
		msgLenBits: 1600,
		S: '',
		outLenBits: 512,
		expected: 'ff7b171f1e8a2b24683eed37830ee797538ba8dc563f6da1e667391a75edc02c'
		+ 'a633079f81ce12a25f45615ec89972031d18337331d24ceb8f8ca8e6a19fd98b',
	},
	{
		description: 'NIST KMACXOF256 sample #6 (strength=256-bit, S=\'My Tagged Application\')',
		key: '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f',
		keyLenBits: 256,
		msg: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
		+ '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
		+ '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
		+ '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
		+ '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
		+ 'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
		+ 'c0c1c2c3c4c5c6c7',
		msgLenBits: 1600,
		S: 'My Tagged Application',
		outLenBits: 512,
		expected: 'd5be731c954ed7732846bb59dbe3a8e30f83e77a4bff4459f2f1c2b4ecebb8ce'
		+ '67ba01c62e8ab8578d2d499bd1bb276768781190020a306a97de281dcc30305d',
	},
];

// ============================================================
// KMACXOF-256, ACVP AFT/MVT (byte-aligned, xof=true)
// Source: ACVP-Server KMAC-256-1.0, vsId=0, byte-aligned subset of tgIds 1/2/5/6
// Records: 1
// ============================================================

export const kmacxof256_acvp: KmacAcvpVector[] = [
	{
		tcId: 461,
		tgId: 5,
		testType: 'MVT',
		xof: true,
		hexCustomization: false,
		key: 'd2eb952310e51cbb2af397412c5b0ef052ff36db7e8c5673717fdd1813cc1cab'
			+ '4730e622e17c0cf943ebe21257de5e45bf8014fad229d6b90d76a01dde5fa60c'
			+ '05ef1f8ba0cd7067f90904544564ea129dbc77b9d9219b66bb87ef51e4060347'
			+ '40277641f0fc01373aed1c6e8f9240fdc88424e2a6e6347b310f87a204ab5516'
			+ '7793e78561b296c19e1ea00d9dcd764329f4fd391c7bdb27acd7f486bda055da'
			+ 'fab93b05d669f1c5be415d820ee053269645425a8550d0b399bdef53785402fb'
			+ 'a0aeeef0f30c886c4e8289ed2e74e59c2a6ddbc09cf689e9aa2e115ed6404847'
			+ '2e8bf6f37d7e937105de500f397ae1ab1cc593c19c308797a26b6e877e8d4b9f'
			+ '92c267101f0162bd2e78f0238d2c5419b590ec21dfdb0a959c16f5df3cc2e9f5'
			+ '02de3c8d93973b08e7729ca7c623ad974aaa4a68834e7dce50fba75b094930cb'
			+ '1fb7473bc49ec400f86f705caa5b914372fe286c8e09ad4a1a002c5897337857'
			+ 'ce4702586720967317d871309897cf7c533f8e81a1ff12210faf5b5a12dbd869'
			+ 'a008f479d8e5830080c96ba12bbdfa755a3e33709d1860c3c0da3eeb20173d82'
			+ '799cee930d2abb87b02c9a01c2d3fc4d9a7c714f5e52068e9c01a3936d332c1a'
			+ 'cb2e74280b95f2cc8d91c3a3a7fcc5',
		keyLenBits: 3704,
		msg: 'dfafa5d1e265e803a488749a50a7aa3f91633686ccbc51ef3fb25b4d78e9d405'
			+ '6c0703eb3875f17055a6e44a1e651b65e3f1ae56fa5689e39ade47d4d53da988'
			+ 'd292006b0c8e3140b931dd55a0ebcd8786308b2171a6976c73107969b6aba132'
			+ 'fb8436ebeca2956e1320fd92c2fcf41348fd7f7670a50c087eec0ea2fd4461b7'
			+ 'c49f5294ff168405a7fbc67eaf165881b377ae176265d24e18350171a73d6ada'
			+ '9fada91b7da88bf614e1dc42f3253e805eb5e0671f00656dbad03c8a0c99e784'
			+ '3db9a4ee97b73794dfcd17c7d38c1e55c00e0b8fc1a794449c40d2b43c6ac42c'
			+ 'a9afcf117bff8f6945a20fb34401ad8d8478f5d1c691340ccb1fed26207c36ee'
			+ '805cc8801aa3ceb5e0d121f6b45f638966f331725945887230e9b449b46f3a66'
			+ '98c412a88a1481b6eb4e164e0364f67f69a2965be3cfb3930453949b59b903f6'
			+ '1f245babdfcd2bfc4e15420cd88dc5c5850d03b8665a8bf370f175b611cfcb2d'
			+ '5befdcc92a7c8d6c5afcb56ec323857a09a66b25e75ee5fbed85276c3986f904'
			+ '8405305e08cf6bf033ea174c567979985eaf3c0ad450338b4de498966dc15771'
			+ '480be83cbbe42a46b03f751aea33df861b952d91f742106c41ec4232151c30a9'
			+ '05018036ff942d8c40344ce4bc74779016aeb29d6a5c73c842e7d0e9706b7afd'
			+ '24328f62c4f634cd3398ed6b0a525412d5b39d8f1955db9463442c346260242e'
			+ '9f573710874d43b43dcbf346f1d70d6e1c3249949919545b4316af08aa729926'
			+ 'dede4218c170451e4737a96eb01eaa134dd7a6fb86020de16ff881cc6c8bebe7'
			+ '39a4649bea5a45c32ed097a7fbc453c4e21b939659d3ca437a2d72063373efde'
			+ 'dea53204e38d2fe06d00cf5145870fe2ffb43f5b6aca8c6ca94829193bb3c3fd'
			+ '21dc2e0aa753792276fe61e63f738ba347aebaf77110bb0db0d9575cafa6dfcf'
			+ 'e70ec5d02b5691baacb16c25d83d4601a4d9c01a83ab0ce6ad5a61380d25d3e3'
			+ '2439248674307d07c83ea27df7696811116582838903090b943900a85d59f84e'
			+ '2e638e404f5866275c491e8cb6a120ae03bf9205740246b37a73deda57d950e6'
			+ 'ca591f17176bd1a46af686cfb6837e73145782ae40c2a74d7ba6ac20fcd01de2'
			+ '19d41035143506866ed3c81c50c1592793daab74bc69bbda8e334c1df13f7732'
			+ '12d69110aa124dc0cc3f18fc9d3681c8c49e60730330b9aae4bb4762f5d3c586'
			+ 'cf6552d1891dc5f34eafa57514a095d69542f0b6c6469864a81b2d70069c7071'
			+ 'b42c9c330c170ab45526ba9c9561c6122b4efe654479b36c995ee994d21b1a08'
			+ '4c3ad7dab2c12494a835307ab232c291b0008b20a4bcac8b074ff430abb2ea86'
			+ 'a06dce57f37613b76ea322f105bbbb8e8e9447bda1ba751b92ca50c6799337ca'
			+ '2636356ec05126f7bd2ddb1ad83e5658156dc3e27d11bcd6db8fa9196dd1e44a'
			+ 'bdfa2f5b13d1fc5177c4ce5d9151aa3be3bd975dddf5c55692483fbca39ebb8c'
			+ '8a6c6b82793a16adcba0d842674e1f1b4b4cb7285e6fb7297da896297ec8f24f'
			+ '0636acb06cf5879be6f5cd941e42ff2872be8495edc1c3371cd87800d5fca299'
			+ '35f684677791dacfe1a5ea21a6d402f5a96b26216128468a9d234146c56940d1'
			+ '1774682037a89398e0e5be344c615a5e1f3d6a15ceba0e9e17bc100a2abab59f'
			+ 'd93783013221321380f4db6fc65d47ae2e6b017a091a089a769b426abc148cbb'
			+ '558492930f88ca20b7732fd75484395926cc1eb7760a246ccb928afc42ea87b0'
			+ 'cb30f400b76d7a4c2277852d86d42d0097845543c458eb49854a018ad5ec973c'
			+ 'a1b5ab8184d1dd7b10e30f6254aab6cd1d5fe9da27286676b178d295e98b3031'
			+ 'd9d9d83ca14a60805e7c6c2acf9dc257dfea16051e711679f24dcbe4523cf77d'
			+ '0edeff160195b73365074b3da158c47d5d24d1e1093e10d8f0d9d1597dc688a9'
			+ 'ba0e83931a207bb1cb1f442f4a0752c4a649abdbe5b28b91711a367d468353a9'
			+ '369545f41c6ac608ffb79394cf81f3275618ddd070bf3fff029ffee1287b685f'
			+ 'b413b03d2ea9dc831a1b9b25b18e316ffb5ff9afe207bde7d3739ef9eee1239a'
			+ 'dc442300f1ee874fc7bfd82da71273a199ecc24c1645a3d714a22cb6f9a443f2'
			+ '484238242fca5cbeac0ff486dfd289ff29989e32d46cdd146953cb4dad335fbc'
			+ '46b70031129c39371e97b9f35a0d2be0efd9e9596189aa49734ac169017a5566'
			+ '034f940ab279d913f1ffbb7fb6505f2abccdc80399620cdac2b3aaebb02a37da'
			+ '166f44b938e7adb7dd83bb6d636dfc1d35719339556cd54809ccf16031b697ac'
			+ '6d1fecb26e949c50061d6f6fab15a6b413dba247d7a4f90222b34ed437b3d54d'
			+ 'f367830a210ff9d7b96bdd4e6ff8fc57a1291306048a13f0290dc2686c55bbe4'
			+ '6cdf67a76d48dd27e1a6',
		msgLenBits: 13648,
		customization: '?U',
		mac: '1a297c8e4574e79d13c5cce0419c4adca1496dcff66475444c90d1b65c40f9e4'
			+ '8e39ced927f92f2669099679c5',
		macLenBits: 360,
		testPassed: false,
	},
];
