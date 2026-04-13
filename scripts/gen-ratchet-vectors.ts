#!/usr/bin/env node
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
/**
 * Generate HKDF-SHA-256 reference vectors for the ratchet KDF constructions.
 *
 * Calls HKDF_SHA256.derive() directly — no ratchet wrapper code involved.
 * Pins KDF_SCKA_INIT and KDF_SCKA_CK parameter assignments before Phase B.
 *
 * usage: bun scripts/gen-ratchet-vectors.ts
 * output: test/vectors/ratchet_kat.ts
 */
import { init, HKDF_SHA256 } from '../src/ts/index.js';
import { sha2Wasm } from '../src/ts/sha2/embedded.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concat } from '../src/ts/utils.js';

await init({ sha2: sha2Wasm });

// ── HKDF helper ─────────────────────────────────────────────────────────────

function hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, len: number): Uint8Array {
	const h = new HKDF_SHA256();
	try {
		return h.derive(ikm, salt, info, len);
	} finally {
		h.dispose();
	}
}

// ── Protocol constants ───────────────────────────────────────────────────────

const PROTOCOL   = utf8ToBytes('leviathan-ratchet-v1');
const INFO_INIT  = concat(PROTOCOL, utf8ToBytes(' Chain Start'));
const INFO_CHAIN = concat(PROTOCOL, utf8ToBytes(' Chain Step'));
const INFO_ROOT  = concat(PROTOCOL, utf8ToBytes(' Chain Add Epoch'));

// ── Counter encoding helper ──────────────────────────────────────────────────

function encodeU64BE(n: number): Uint8Array {
	const buf = new Uint8Array(8);
	const v   = new DataView(buf.buffer);
	v.setUint32(0, Math.floor(n / 0x100000000), false);
	v.setUint32(4, n >>> 0, false);
	return buf;
}

// ── ratchetInit vectors (KDF_SCKA_INIT) ─────────────────────────────────────
// HKDF parameters per spec §7.2:
//   ikm  = sk
//   salt = 32 zero bytes
//   info = INFO_INIT (append context bytes if provided)
//   len  = 96
// Output split:
//   okm[0..32]  → nextRootKey
//   okm[32..64] → sendChainKey
//   okm[64..96] → recvChainKey

const ZERO_SALT = new Uint8Array(32);

const initInputs: { id: number; sk: Uint8Array; context?: Uint8Array }[] = [
	{ id: 0, sk: new Uint8Array(32) },
	{ id: 1, sk: new Uint8Array(32).fill(0xff) },
	{ id: 2, sk: Uint8Array.from({ length: 32 }, (_, i) => i) },
	{ id: 3, sk: new Uint8Array(32), context: utf8ToBytes('test-context') },
	{ id: 4, sk: new Uint8Array(32).fill(0xff), context: utf8ToBytes('test-context') },
	{ id: 5, sk: Uint8Array.from({ length: 32 }, (_, i) => i), context: utf8ToBytes('test-context') },
];

interface RatchetInitResult {
	id:           number;
	sk:           string;
	context:      string;
	nextRootKey:  string;
	sendChainKey: string;
	recvChainKey: string;
}

const ratchetInitResults: RatchetInitResult[] = initInputs.map(({ id, sk, context }) => {
	const info = context != null ? concat(INFO_INIT, context) : INFO_INIT;
	const okm  = hkdf(sk, ZERO_SALT, info, 96);
	return {
		id,
		sk:           bytesToHex(sk),
		context:      context != null ? bytesToHex(context) : '',
		nextRootKey:  bytesToHex(okm.slice(0, 32)),
		sendChainKey: bytesToHex(okm.slice(32, 64)),
		recvChainKey: bytesToHex(okm.slice(64, 96)),
	};
});

// ── KDFChain.step() vectors (KDF_SCKA_CK) ───────────────────────────────────
// HKDF parameters per spec §7.2:
//   ikm  = current chain key
//   salt = 32 zero bytes
//   info = concat(INFO_CHAIN, encodeU64BE(N))
//   len  = 64
// The counter starts at 1 on the first step (spec §5.2).
// Output split:
//   okm[0..32]  → nextChainKey (fed back as ikm for next step)
//   okm[32..64] → messageKey

const chainInputs: { id: number; initialCk: Uint8Array }[] = [
	{ id: 0, initialCk: new Uint8Array(32) },
	{ id: 1, initialCk: Uint8Array.from({ length: 32 }, (_, i) => i) },
];

interface KdfChainStep {
	n:            number;
	messageKey:   string;
	nextChainKey: string;
}

interface KdfChainResult {
	id:        number;
	initialCk: string;
	steps:     KdfChainStep[];
}

const kdfChainResults: KdfChainResult[] = chainInputs.map(({ id, initialCk }) => {
	const steps: KdfChainStep[] = [];
	let ck = initialCk;
	for (let n = 1; n <= 5; n++) {
		const info = concat(INFO_CHAIN, encodeU64BE(n));
		const okm  = hkdf(ck, ZERO_SALT, info, 64);
		const nextChainKey = okm.slice(0, 32);
		const messageKey   = okm.slice(32, 64);
		steps.push({
			n,
			messageKey:   bytesToHex(messageKey),
			nextChainKey: bytesToHex(nextChainKey),
		});
		ck = nextChainKey;
	}
	return {
		id,
		initialCk: bytesToHex(initialCk),
		steps,
	};
});

// ── kemRatchetDecap vectors (KDF_SCKA_RK) ───────────────────────────────────
// Uses ML-KEM-512 ACVP tcId 77 (valid decapsulation) to provide a
// deterministic sharedSecret. The HKDF step is applied directly here to
// cross-check the expected values independently of the ratchet wrapper.
//
// Note: this script cannot call kemRatchetDecap directly because it requires
// the full WASM stack (kyber + sha3 + sha2). The HKDF step is verified here
// using sha2 only, matching what kemRatchetDecap would compute given the same
// sharedSecret.

// ACVP tcId 77 fixed inputs (ML-KEM-512 valid decapsulation)
const DK_ACVP_TCID_77   = '3b5879284a33a6204c06f84bf91843cf9b23cd8256e3d23bd1012325686138f40e435275298a614d30950d98b00f59ae6a04bbc37510d4dcbe738b90530b455b048df4f4af191b59db8a3d37c83190d425d40014775b507d43a2e2204b9aa6b6241057663a782a411419f0a0e1e8a4d7f5995b197114e832c7fab5f2d69923d53a46f07c403038c29219ef228da1746ed27978d9723d09ea6d6f32856d8b5589382af4f32d2dda0eadf342ed3248eb0ccb7b9424fce6432f8a3892a24d610b9f35b7a4d63b918203bef239c07277433d8122eda503c3d596b7c670893051286044ea919bb4863ab6a7cd8d43255c099ce1db832b109cc24c1b15bca2f5383f03cc7263775ad39a90de6a1e1cbb4ee8683295353fde05478cfbb4c5249500faa9d35b264e36494f009d8cea06ac096ff3965de5980b8e8485149b6912ba7b8e935341755ac67499647391a181158f3ac719f3b36ca0624b6c6f26800904609759b0c5d4270accaa01159c4235685d1b079624576c73f498a3f9a37b5090fd6010960c3ec9d7a1d95c3749dc3e225b800d2b8f3b597090f0b83cb315b7a43fb69151ad2b2ef21c8e3d6028a650716bd96f466baec316a230232b59a97d371c3df6d2476c51c64f48271ea38aae9c8eacd1a0f9318dfbc273d382cdfc0043b0c47b35834eb2069a0e306a53826c49c7a69ae3442947c37ed01f55e9411146870da50194e778caf71a7561429d1ac02ac362fad196ce1331bf2a00001da290f2b136b92b576c2831717908682412462af101c3ed3685180112d41a73bb164553f9b79ca71f0932693a630e4209bebe7baa7aea295150b1b827716f47464204258f414bdb6c5fffc42249c782494a4268f60bc5c195ae9c1efd778cbc15af2003b3dab7336af5037bfb4eed702ec887af43eba616414914b08493d53ed9f89ec2805ea1b40b634610b458236a2aca1610565350234e9b23be27166fb8abdb441138f44e79d8541c3aae85fc553fb884cca95e6c84325df29e112b6d863444a52721f5a5a6d0db5a65564a545633cb121a927136408c16763191eb10270e6a1604b486770ab5fcca728f659556c212f9925f28493cd3c2a60ad743830769f9b387422ac46385c88f4a10d8c43764f5200e810d20ab9a7aeb5c8b100cb751c55b301976d7bd4f0a1de7d7cfbf0379cc6b9844b16749b8c6659824b65c2659a430914b322289b88d51324772c4a507cbaf240436aac23950088e41973fcc487f57bd1d14321664afc6ea2b66403c881509be445933528a4f97c2a5b86f1cbc08816484f9432241a09e16d6b6c7068f0356505227216127af9506250e59ada3ab4611d7ba4a999621241a3d8c4fe0e7cbae2492b6f44e6afca27f33940e3233f5a382549b9da2c52b9bc99a8bdc1e541b274987a5bc4a272f330f725856220961c659cd9ba534716c5a113b53cd243d5c907fd6e1b2cde69090b40314b7ca85f2185f9401fa758c3fd8ad91441a6dcb88b7350b753cc06ae5a1fbcb4df61cae1dfc7e60c28c7787654a068dd06821983aaed658c110bc19c2fc61e76caa65d9c0914887a77571b3e63cd63a437028bc03dc8f69346585d023f01465e430220607948619975fac993703cf60055d9af28eaa1a2ce412322d11497df22137380714b701dae205ef308e2eb8a1b0b09adb896bb8ab3f34f9ba2695056b7785fd51acd043cdc1919c6b0335d7e7bdd1c43693582ed5e71d534163a48c45796b43e98bcb3df47e075b8ae3e96a640ca659747b287c4714113ddccbc83d37c54022cd321409be74c331900cb17a72dc27bb6d4401d974b4e236b82f894ef5dc9a7a29091ab475d584b52d9672ddbc8d63b0bdb51554709041cc07cdee435f39463c04ba0dc2b4c085aac7822aa4ba50cd470a75c53a7c1318839df4086d8a8d3510780081112453134f15601f810895b287195866fc237669f5b212c002f62b2130952b99bac4e0ab002fa915520a715a41b1d541cb54cb7dd0291655f14fd2d0b3d802c9d6cb569fc815b69b1a0787463104a30ab34e7bd732feea3c8cc8764fe199947513889942b7c110482c9a1477348c3c3b491060a78b8299490e4dbabd22b054929ba77ee31922e1439d15b530a0c307e72c2f9c568622301dfa261c885a6f66399dc79e593486b11ff236b8367bf6864a1a596448fc251898a3c89ccd0b5511311826546e56b6967ee923e5733561d5a4bf940caac4960bf60cb769a40e396bfc370f094a00986d708ac731b420fdc11fcb071bda0786a23f80269341ae270b8ed6844b'
const KEMCT_ACVP_TCID_77 = '30991222b8ea47530f7c703d85bf4357f61f47615539781920effdf067172e32ef1ba77b21670eca074c4b2401bb591b21ca0f4bfba9f8be4a26a9de2eceaa8303a91073c0c91205daf6ddb17d35104969c5036ba722b176f6a3e6d92e1e5eddad9a6a3561f7e5338ba2b163702e297f9c6f27c5bcb7975139dff287b739d2053bbc4307946b89df3d9c963379b932ddba015a6ea396e729996f7ff573a0c24040de323e60b95b2197c89127661db35d44588e132742b62949ea45d3e8527f0b2b71295e0943f1fa1f87d3b3ef11f840b59e2bbb10aa22b687ff23d22cda109d5ce33f3527fea041579793530226009d48cae3e499fd0eccd036d04b8da21f939908e53f5bbbe41dbacaf3a7f9f5839d479ba0909f0df0b2c8cd7ae8b11f160b16eba19656744ac38d9aee3a31e698380b3b9483e3a5f3c3b3767c519acbb515706b1f192b16aa7b1e0b8178f28c65cab578368de5bd0dd5691b659293b3b212a5547e60727f69b33d3938a301572fdd931f5f71e7c647bf9cb4b3a8b294e2a17cf504319278648e59da78f0fc5bbad5abc37551c30aab853cc50df796f308ec99d56a2348954edaf7af6e4d62fa6b1bb6fac370226f47f1a91e2bc6731875c09ccbf8e635745def1a607f15ba774e7a1fce8822c07916d352bf24de6218350c5356d627411f884623496620500337654dbb8048d58db94bcd8bf18adff7eafe9dc8687156f426379ff0d57b880b8f86fd94861cf865db231b9adf9fcc53a7d8e5bec45ef2edeeaf2109f35a365c1287ac81d18ef302c9313b357870db914e2e8300440a0c44e3940fab6b35f1bc4bdf9b7a54eec634897f1f715a334e553f2aef6eccd13966364cb942ca7c91a90ee2ed924dad7f7a0907a56323ba787967f687e1c8bab45976e20ae14301139e989e4257ec9f87728f4ac56a5f0588d96908ff7dd901ac4fbd8ab336eac865377dce7c22b4e8193f17769e1c1d6a2365d21715f014e9634834eec80e4f6c97fdfda6559ba2f88f81ca57a03aed25a0d818e7823bd08713e1667815a5e4776ace6fb5658053e6dd38a01aa0aa9819802bd83e'

// ML-KEM-512 structure: dk = skCpa(768) || ek(800) || H(ek)(32) || z(32). Pull
// the embedded ek so the decap-side HKDF info binding can be computed here
// without pulling in the full kyber WASM stack.
const MLKEM512_SK_CPA_BYTES = 768;
const MLKEM512_EK_BYTES     = 800;

function u32beBytes(n: number): Uint8Array {
	const b = new Uint8Array(4);
	new DataView(b.buffer).setUint32(0, n, false);
	return b;
}

const kemDecapInputs = [
	{
		id:  0,
		rk:  new Uint8Array(32).fill(0x01),
		dk:  hexToBytes(DK_ACVP_TCID_77),
		kemCt: hexToBytes(KEMCT_ACVP_TCID_77),
		// sharedSecret k from ACVP tcId 77:
		ss:  hexToBytes('6621D11567D58EAC3CDFBEB9C69DB0E7AFC4C97C252D98B4770C5F6AF98C83DB'),
	},
];

const kemDecapOutput = kemDecapInputs.map(({ id, rk, dk, kemCt, ss }) => {
	const ownEk  = dk.slice(MLKEM512_SK_CPA_BYTES, MLKEM512_SK_CPA_BYTES + MLKEM512_EK_BYTES);
	// info = INFO_ROOT || u32be(|ek|) || ek || u32be(|ct|) || ct || u32be(0) || ""
	const info = concat(
		INFO_ROOT,
		u32beBytes(ownEk.length),  ownEk,
		u32beBytes(kemCt.length),  kemCt,
		u32beBytes(0),             new Uint8Array(0),
	);
	const okm = hkdf(ss, rk, info, 96);
	// apply decap-side slot swap to match kemRatchetDecap return shape:
	const nextRootKey  = okm.slice(0, 32);
	const recvChainKey = okm.slice(32, 64);  // kdfRoot sendChainKey → recvChainKey
	const sendChainKey = okm.slice(64, 96);  // kdfRoot recvChainKey → sendChainKey
	return { id, nextRootKey, recvChainKey, sendChainKey };
});

// print for cross-check against Python
for (const v of kemDecapOutput) {
	process.stderr.write(`kemRatchetDecap vector ${v.id}:\n`);
	process.stderr.write(`  nextRootKey:  ${bytesToHex(v.nextRootKey)}\n`);
	process.stderr.write(`  recvChainKey: ${bytesToHex(v.recvChainKey)}\n`);
	process.stderr.write(`  sendChainKey: ${bytesToHex(v.sendChainKey)}\n`);
}

// ── Emit output ──────────────────────────────────────────────────────────────

function fmtInitVector(v: RatchetInitResult): string {
	return `\t{
\t\tid: ${v.id},
\t\tsk: '${v.sk}',
\t\tcontext: '${v.context}',
\t\tnextRootKey: '${v.nextRootKey}',
\t\tsendChainKey: '${v.sendChainKey}',
\t\trecvChainKey: '${v.recvChainKey}',
\t}`;
}

function fmtChainStep(s: KdfChainStep): string {
	return `\t\t\t{
\t\t\t\tn: ${s.n},
\t\t\t\tmessageKey: '${s.messageKey}',
\t\t\t\tnextChainKey: '${s.nextChainKey}',
\t\t\t}`;
}

function fmtChainVector(v: KdfChainResult): string {
	const steps = v.steps.map(fmtChainStep).join(',\n');
	return `\t{
\t\tid: ${v.id},
\t\tinitialCk: '${v.initialCk}',
\t\tsteps: [
${steps},
\t\t],
\t}`;
}

function fmtKemDecapVector(v: {
	id: number
	nextRootKey: Uint8Array
	recvChainKey: Uint8Array
	sendChainKey: Uint8Array
}): string {
	return `\t{
\t\tid: ${v.id},
\t\trk: '0101010101010101010101010101010101010101010101010101010101010101',
\t\tdk: DK_ACVP_TCID_77,
\t\tkemCt: KEMCT_ACVP_TCID_77,
\t\tnextRootKey: '${bytesToHex(v.nextRootKey)}',
\t\trecvChainKey: '${bytesToHex(v.recvChainKey)}',
\t\tsendChainKey: '${bytesToHex(v.sendChainKey)}',
\t}`;
}

const asciiHeader = `//                  ▄▄▄▄▄▄▄▄▄▄
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
//                           ▀█████▀▀`;

console.log(`${asciiHeader}
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
\tid:           number
\tsk:           string  // hex, 32 bytes
\tcontext:      string  // hex, empty string means no context
\tnextRootKey:  string  // hex, 32 bytes
\tsendChainKey: string  // hex, 32 bytes
\trecvChainKey: string  // hex, 32 bytes
}

export interface KdfChainStep {
\tn:            number  // counter value used in this step (1-indexed)
\tmessageKey:   string  // hex, 32 bytes
\tnextChainKey: string  // hex, 32 bytes
}

export interface KdfChainVector {
\tid:        number
\tinitialCk: string        // hex, 32 bytes
\tsteps:     KdfChainStep[]
}

export const ratchetInitVectors: RatchetInitVector[] = [
${ratchetInitResults.map(fmtInitVector).join(',\n')},
];

export const kdfChainVectors: KdfChainVector[] = [
${kdfChainResults.map(fmtChainVector).join(',\n')},
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
// at dk[${MLKEM512_SK_CPA_BYTES}:${MLKEM512_SK_CPA_BYTES + MLKEM512_EK_BYTES}];
// tests must extract it from that slice before calling kemRatchetDecap.
const DK_ACVP_TCID_77 = '${DK_ACVP_TCID_77}';
const KEMCT_ACVP_TCID_77 = '${KEMCT_ACVP_TCID_77}';

export interface KemRatchetDecapVector {
\tid:           number
\trk:           string  // hex, 32 bytes
\tdk:           string  // hex, ML-KEM-512 dk — from ACVP tcId 77
\tkemCt:        string  // hex, ML-KEM-512 ciphertext — from ACVP tcId 77
\tnextRootKey:  string  // hex, 32 bytes
\trecvChainKey: string  // hex, 32 bytes
\tsendChainKey: string  // hex, 32 bytes
}

export const kemRatchetDecapVectors: KemRatchetDecapVector[] = [
${kemDecapOutput.map(fmtKemDecapVector).join(',\n')},
];
`);
