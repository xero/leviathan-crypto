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
// scripts/lib/test-groups.ts
//
// Single source of truth for unit test group compositions.
// Each group list mirrors the corresponding .github/workflows/unit-*.yml.
// CICD workflows call `bun scripts/test.ts unit:group <name>` for their
// file list and build prerequisites.

import type {BuildTarget} from './build-graph'

export interface TestGroup {
	name: string
	files: string[]
	buildTargets: BuildTarget[]
	timeoutMin: number
}

const UNIT_BASE: BuildTarget[] = ['asm', 'embed', 'embed-workers']
const UNIT_FULL: BuildTarget[] = ['asm', 'embed', 'embed-workers', 'ts']

export const UNIT_GROUPS: readonly TestGroup[] = [
	{
		name: 'core',
		buildTargets: UNIT_FULL,
		timeoutMin: 5,
		files: [
			'test/unit/init.test.ts',
			'test/unit/init/exclusivity.test.ts',
			'test/unit/init/init-race.test.ts',
			'test/unit/init/atomic-defense.test.ts',
			'test/unit/init/internal-api-stripped.test.ts',
			'test/unit/errors.test.ts',
			'test/unit/utils.test.ts',
			'test/unit/ct/compare-branch-free.test.ts',
			'test/unit/ct/module-shape.test.ts',
			'test/unit/fortuna.test.ts',
			'test/unit/fortuna/wipe-lifecycle.test.ts',
			'test/unit/fortuna/spec-conformance.test.ts',
			'test/unit/fortuna/pluggable-primitives.test.ts',
			'test/unit/fortuna/generator-hash-wipe.test.ts',
			'test/unit/loader/wasm_source.test.ts',
			'test/unit/loader/thenable-dispatch.test.ts',
			'test/unit/fortuna/generator-output-shape.test.ts',
		],
	},
	{
		name: 'serpent',
		buildTargets: UNIT_BASE,
		timeoutMin: 5,
		files: [
			'test/unit/serpent/serpent_kat.test.ts',
			'test/unit/serpent/serpent_iv.test.ts',
			'test/unit/serpent/serpent_sbox.test.ts',
			'test/unit/serpent/serpent_ctr.test.ts',
			'test/unit/serpent/serpent_cbc.test.ts',
			'test/unit/serpent/pkcs7-oracle.test.ts',
			'test/unit/serpent/pool-shared-ops.test.ts',
			'test/unit/serpent/exclusivity-preservation.test.ts',
			'test/unit/serpent/serpent_wipe.test.ts',
			'test/unit/serpent/serpent.test.ts',
			'test/unit/serpent/serpent_simd_gate.test.ts',
			'test/unit/serpent/serpent_simd_ctr.test.ts',
			'test/unit/serpent/serpent_simd_cbc_gate.test.ts',
			'test/unit/serpent/serpent_simd_cbc.test.ts',
		],
	},
	{
		name: 'chacha20',
		buildTargets: UNIT_BASE,
		timeoutMin: 5,
		files: [
			'test/unit/chacha20/chacha20.test.ts',
			'test/unit/chacha20/chacha20_simd.test.ts',
			'test/unit/chacha20/chacha20_simd_4x_gate.test.ts',
			'test/unit/chacha20/poly1305.test.ts',
			'test/unit/chacha20/chacha20poly1305.test.ts',
			'test/unit/chacha20/xchacha20.test.ts',
			'test/unit/chacha20/single-use-guard.test.ts',
			'test/unit/chacha20/aead-decrypt-wipe.test.ts',
		],
	},
	{
		name: 'stream',
		buildTargets: UNIT_BASE,
		timeoutMin: 10,
		files: [
			'test/unit/stream/header.test.ts',
			'test/unit/stream/sealstream.test.ts',
			'test/unit/stream/sealstream_xchacha_kat.test.ts',
			'test/unit/stream/sealstream_serpent_kat.test.ts',
			'test/unit/stream/sealstream_aes_kat.test.ts',
			'test/unit/stream/seal.test.ts',
			'test/unit/stream/seal_xchacha_kat.test.ts',
			'test/unit/stream/seal_serpent_kat.test.ts',
			'test/unit/stream/seal_aes_kat.test.ts',
			'test/unit/stream/xchacha20-cipher-suite.test.ts',
			'test/unit/stream/serpent-cipher-suite.test.ts',
			'test/unit/stream/aes-cipher-suite.test.ts',
			'test/unit/stream/salamander-resistance.test.ts',
			'test/unit/stream/pool.test.ts',
			'test/unit/stream/pool-terminal-on-throw.test.ts',
			'test/unit/stream/pool-byte-exact.test.ts',
			'test/unit/stream/pool-wipe-handshake.test.ts',
			'test/unit/stream/failed-state.test.ts',
			'test/unit/stream/seek-forward-only.test.ts',
		],
	},
	{
		name: 'kyber',
		buildTargets: UNIT_BASE,
		timeoutMin: 5,
		files: [
			'test/unit/kyber/ntt_simd_gate.test.ts',
			'test/unit/kyber/poly_arithmetic.test.ts',
			'test/unit/kyber/mlkem.test.ts',
			'test/unit/kyber/kyber_suite.test.ts',
			'test/unit/kyber/suite-commitment.test.ts',
			'test/unit/kyber/decap-scratch-wipe.test.ts',
			'test/unit/kyber/encap-scratch-wipe.test.ts',
			'test/unit/kyber/keygen-scratch-wipe.test.ts',
			'test/unit/kyber/sha3-scratch-wipe.test.ts',
		],
	},
	{
		name: 'hashing',
		buildTargets: UNIT_BASE,
		timeoutMin: 5,
		files: [
			'test/unit/sha2/sha224.test.ts',
			'test/unit/sha2/sha256.test.ts',
			'test/unit/sha2/sha512.test.ts',
			'test/unit/sha2/sha512_224.test.ts',
			'test/unit/sha2/sha512_256.test.ts',
			'test/unit/sha2/hmac.test.ts',
			'test/unit/sha2/hkdf.test.ts',
			'test/unit/sha3/sha3.test.ts',
			'test/unit/sha3/shake_xof.test.ts',
			'test/unit/sha3/kmac.test.ts',
		],
	},
	{
		name: 'montecarlo-cbc',
		buildTargets: UNIT_BASE,
		timeoutMin: 10,
		files: [
			'test/unit/serpent/serpent_cbc_montecarlo.test.ts',
		],
	},
	{
		name: 'montecarlo-ecb',
		buildTargets: UNIT_BASE,
		timeoutMin: 10,
		files: [
			'test/unit/serpent/serpent_montecarlo.test.ts',
		],
	},
	{
		name: 'nessie',
		buildTargets: UNIT_BASE,
		timeoutMin: 5,
		files: [
			'test/unit/serpent/serpent_nessie128.test.ts',
			'test/unit/serpent/serpent_nessie192.test.ts',
			'test/unit/serpent/serpent_nessie256.test.ts',
		],
	},
	{
		name: 'ratchet',
		buildTargets: UNIT_BASE,
		timeoutMin: 5,
		files: [
			'test/unit/ratchet/ratchet_kdf.test.ts',
			'test/unit/ratchet/kem_ratchet.test.ts',
			'test/unit/ratchet/kem-ratchet-info-binding.test.ts',
			'test/unit/ratchet/skipped_key_store.test.ts',
			'test/unit/ratchet/ratchet_keypair.test.ts',
			'test/unit/ratchet/resolve-handle-dos-mitigation.test.ts',
		],
	},
	{
		name: 'aes',
		buildTargets: UNIT_BASE,
		timeoutMin: 5,
		files: [
			'test/unit/aes/aes_transpose.test.ts',
			'test/unit/aes/aes_sbox.test.ts',
			'test/unit/aes/aes_round.test.ts',
			'test/unit/aes/aes_kat.test.ts',
			'test/unit/aes/aes_decrypt.test.ts',
			'test/unit/aes/aes_mmt.test.ts',
			'test/unit/aes/aes_cbc.test.ts',
			'test/unit/aes/aes_cbc_mmt.test.ts',
			'test/unit/aes/aes_ctr.test.ts',
			'test/unit/aes/aes_ghash.test.ts',
			'test/unit/aes/aes_gcm_seal.test.ts',
			'test/unit/aes/aes_gcm_open.test.ts',
			'test/unit/aes/aes_generator.test.ts',
		],
	},
	{
		name: 'aes-siv',
		buildTargets: UNIT_BASE,
		timeoutMin: 5,
		files: [
			'test/unit/aes/aes_polyval.test.ts',
			'test/unit/aes/aes_gcm_siv_seal.test.ts',
			'test/unit/aes/aes_gcm_siv_open.test.ts',
		],
	},
	{
		name: 'aes-mct',
		buildTargets: UNIT_BASE,
		timeoutMin: 5,
		files: [
			'test/unit/aes/aes_mct.test.ts',
			'test/unit/aes/aes_cbc_mct.test.ts',
		],
	},
	{
		name: 'mldsa',
		buildTargets: UNIT_BASE,
		timeoutMin: 5,
		files: [
			'test/unit/mldsa/reduce.test.ts',
			'test/unit/mldsa/ntt_simd_gate.test.ts',
			'test/unit/mldsa/poly_arithmetic.test.ts',
			'test/unit/mldsa/encoding.test.ts',
			'test/unit/mldsa/rounding.test.ts',
			'test/unit/mldsa/sampling.test.ts',
			'test/unit/mldsa/mldsa.test.ts',
			'test/unit/mldsa/keygen-scratch-wipe.test.ts',
			'test/unit/mldsa/sign-scratch-wipe.test.ts',
			'test/unit/mldsa/verify-scratch-wipe.test.ts',
			'test/unit/mldsa/validate-checks.test.ts',
			'test/unit/mldsa/sha3-scratch-wipe.test.ts',
			'test/unit/mldsa/sha2-scratch-wipe.test.ts',
			'test/unit/mldsa/hashvariant.test.ts',
		],
	},
]
