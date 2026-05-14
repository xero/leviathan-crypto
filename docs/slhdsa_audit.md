<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### SLH-DSA Cryptographic Audit

Audit of the `leviathan-crypto` WebAssembly SLH-DSA implementation
(AssemblyScript) against FIPS 205, covering the SHAKE-fast parameter sets
shipped in Phase 2 (SLH-DSA-SHAKE-128f, -192f, -256f) and the three PQ-only
hybrid suites (`0x30 / 0x31 / 0x32`). Every checkbox is falsifiable by
reading the cited file and confirming the invariant against the spec
reference (and, where noted, against an independent reference such as the
`slhdsa-c` codebase, which is consulted only after the round-trip gates
already pass per AGENTS.md §4).

> ### Table of Contents
> - [Buffer Layout and Parameter Selection (`src/asm/slhdsa/buffers.ts`)](#buffer-layout-and-parameter-selection-srcasmslhdsabuffersts)
> - [Keccak Substrate (`src/asm/slhdsa/keccak.ts`)](#keccak-substrate-srcasmslhdsakeccackts)
> - [Hash Family (`src/asm/slhdsa/hashes.ts`)](#hash-family-srcasmslhdsahashests)
> - [ADRS (`src/asm/slhdsa/address.ts`)](#adrs-srcasmslhdsaaddressts)
> - [WOTS+ (`src/asm/slhdsa/wots.ts`)](#wots-srcasmslhdsawotsts)
> - [FORS (`src/asm/slhdsa/fors.ts`)](#fors-srcasmslhdsaforsts)
> - [XMSS (`src/asm/slhdsa/xmss.ts`)](#xmss-srcasmslhdsaxmssts)
> - [Hypertree (`src/asm/slhdsa/hypertree.ts`)](#hypertree-srcasmslhdsahypertreets)
> - [Top-level §9 Algorithms (`src/asm/slhdsa/slh.ts`)](#top-level-9-algorithms-srcasmslhdsaslhts)
> - [WASM Public Exports (`src/asm/slhdsa/index.ts`)](#wasm-public-exports-srcasmslhdsaindexts)
> - [TS Parameter Bindings (`src/ts/slhdsa/params.ts`)](#ts-parameter-bindings-srctsslhdsaparamsts)
> - [TS Type Surface (`src/ts/slhdsa/types.ts`)](#ts-type-surface-srctsslhdsatypests)
> - [TS Validation (`src/ts/slhdsa/validate.ts`)](#ts-validation-srctsslhdsavalidatets)
> - [TS Pre-Hash Dispatcher (`src/ts/slhdsa/prehash.ts`)](#ts-pre-hash-dispatcher-srctsslhdsaprehashts)
> - [TS Sign Driver (`src/ts/slhdsa/sign.ts`)](#ts-sign-driver-srctsslhdsasignts)
> - [TS Verify Driver (`src/ts/slhdsa/verify.ts`)](#ts-verify-driver-srctsslhdsaverifyts)
> - [SlhDsaBase Public Surface (`src/ts/slhdsa/index.ts`)](#slhdsabase-public-surface-srctsslhdsaindexts)
> - [Pure-mode and Prehash-mode Suite Factories (`src/ts/sign/suites/slhdsa.ts`)](#pure-mode-and-prehash-mode-suite-factories-srctssignsuitesslhdsats)
> - [PQ-only Hybrid Suite Factory (`src/ts/sign/suites/hybrid-pq.ts`)](#pq-only-hybrid-suite-factory-srctssignsuiteshybrid-pqts)
> - [Test Coverage](#test-coverage)
> - [Cross-References](#cross-references)

| Meta | Description |
| --- | --- |
| Target: | `leviathan-crypto` WebAssembly implementation (AssemblyScript) |
| Spec: | FIPS 205 (SLH-DSA Standard, August 2024) |
| Parameter sets: | SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-256f |
| Test vectors: | NIST ACVP (`SLH-DSA-keyGen-FIPS205`, `SLH-DSA-sigGen-FIPS205`, `SLH-DSA-sigVer-FIPS205`); pin `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0` (v1.1.0.42, 2026-04-16) |
| Hybrid suites: | `MlDsa44SlhDsa128fSuite` (`0x30`), `MlDsa65SlhDsa192fSuite` (`0x31`), `MlDsa87SlhDsa256fSuite` (`0x32`) |

---

## Buffer Layout and Parameter Selection (`src/asm/slhdsa/buffers.ts`)

- [ ] `INPUT_OFFSET`, `OUT_OFFSET`, `STATE_OFFSET`, `SCRATCH_OFFSET`, `ADRS_OFFSET`, `PARAMS_OFFSET` are pinned constants and do not overlap.
- [ ] `INPUT_SIZE` is large enough to hold the maximum slhSignInternal layout (sk + M' + opt_rand) for 256f at the maximum supported `msgLen`.
- [ ] `OUT_SIZE` is at least `params.sigBytes` for the largest set (49856 bytes for 256f) with slack for the 6·n keygen output.
- [ ] `slhSetParams128f` writes `n=16, m=30, paramSet=PARAMSET_128F` into the PARAMS slot in the byte order the §5/§6/§7/§8/§9 algorithms read.
- [ ] `slhSetParams192f` writes `n=24, m=39, paramSet=PARAMSET_192F`.
- [ ] `slhSetParams256f` writes `n=32, m=49, paramSet=PARAMSET_256F`.
- [ ] `getParamN`, `getParamM`, `getParamSet` read the same bytes written by the `slhSetParams*` thunks.
- [ ] `wipeBuffers` zeros at minimum OUT, STATE, and SCRATCH regions. (INPUT wipe is the TS driver's responsibility per the documented contract in `sign.ts`.)
- [ ] `getModuleId` returns `7` (distinct from every other module).

## Keccak Substrate (`src/asm/slhdsa/keccak.ts`)

- [ ] `shake128Init()` configures rate 168 and pad byte `0x1F` (FIPS 202 §6.2 SHAKE128 domain).
- [ ] `shake256Init()` configures rate 136 and pad byte `0x1F` (FIPS 202 §6.2 SHAKE256 domain).
- [ ] `keccakAbsorbAt(src, len)` absorbs `len` bytes from address `src` with rate-mod indexing (block boundary handled by the same code path the `sha3.wasm` module uses; both modules implement FIPS 202 Algorithm 8).
- [ ] `keccakSqueezeTo(dst, outLen)` squeezes `outLen` bytes starting at `dst` and applies extra `KeccakF1600` permutations every `rate` bytes (FIPS 202 §4 Algorithm 7).
- [ ] `shakeFinal` is functionally equivalent to `keccakSqueezeTo` for the §10.2.2 fixed-output cases; if it diverges, the divergence is documented in the file.
- [ ] None of the keccak entries leak secret-derived branch decisions: all squeeze loops iterate over the public output length, not the input contents.

## Hash Family (`src/asm/slhdsa/hashes.ts`)

- [ ] `slhHashF(out, pkSeed, adrs, m1)` evaluates `SHAKE256(PK.seed || ADRS || M1, 8n)` exactly (FIPS 205 §11.2 Table 4, F).
- [ ] `slhHashH(out, pkSeed, adrs, m2)` evaluates `SHAKE256(PK.seed || ADRS || M2, 8n)` (FIPS 205 §11.2 Table 4, H).
- [ ] `slhHashTl(out, pkSeed, adrs, m, mLen)` evaluates `SHAKE256(PK.seed || ADRS || M, 8n)` with variable-length M (FIPS 205 §11.2 Table 4, T_ℓ).
- [ ] `slhPRF(out, pkSeed, skSeed, adrs)` evaluates `SHAKE256(PK.seed || ADRS || SK.seed, 8n)` (FIPS 205 §11.2 Table 4, PRF).
- [ ] `slhPRFmsg(out, prf, optRand, m, mLen)` evaluates `SHAKE256(SK.prf || opt_rand || M, 8n)` with `opt_rand` mixed in (FIPS 205 §11.2 Table 4, PRF_msg).
- [ ] `slhHmsg(out, r, pkSeed, pkRoot, m, mLen)` evaluates `SHAKE256(R || PK.seed || PK.root || M, 8m)` and outputs exactly `m` bytes for the active parameter set (FIPS 205 §11.2 Table 4, H_msg).
- [ ] `tweakableHash` internal helper absorbs in the order `PK.seed → ADRS → tail` and squeezes exactly `n` bytes. The order matches FIPS 205 §11.2 Table 4 and must not be transposed.
- [ ] Output lengths in `slhHashF / slhHashH / slhHashTl / slhPRF` read from `getParamN()`; output length in `slhHmsg` reads from `getParamM()`.

## ADRS (`src/asm/slhdsa/address.ts`)

- [ ] ADRS field-offset constants match FIPS 205 §4.2 Figure 2: `layer=0`, `tree=4..15`, `type=16`, `keypair=20`, `chain/treeHeight=24`, `hash/treeIndex=28`, with `ADRS_BYTES=32` total.
- [ ] `adrsSetLayerAddress(adrs, layer)` writes the layer value as a 4-byte big-endian integer at offset 0 (NOT as a single byte at offset 0). Spec authority FIPS 205 §4.2 Figure 2.
- [ ] `adrsSetTreeAddr(adrs, hi, mid, lo)` writes three 4-byte big-endian limbs into bytes 4..15 in that order (hi at byte 4, mid at byte 8, lo at byte 12). Cross-check against `slhdsa-c slh_adrs.h` after the round-trip gate passes.
- [ ] `adrsSetType(adrs, type)` writes a 4-byte big-endian integer at offset 16.
- [ ] `adrsSetKeyPairAddress`, `adrsSetChainAddress`, `adrsSetHashAddress`, `adrsSetTreeHeight`, `adrsSetTreeIndex` all write 4-byte big-endian values at their documented offsets.
- [ ] Getters round-trip: `adrsGetX(adrsSetX(adrs, v))` returns `v` for every X.
- [ ] `adrsClear(adrs)` zeros all 32 bytes; `adrsCopy(dst, src)` copies all 32 bytes.
- [ ] ADRS type constants match FIPS 205 §4.2 Algorithm 14 column "type": `WOTS_HASH=0, WOTS_PK=1, TREE=2, FORS_TREE=3, FORS_ROOTS=4, WOTS_PRF=5, FORS_PRF=6`.

## WOTS+ (`src/asm/slhdsa/wots.ts`)

- [ ] `LG_W = 4` and `W_MINUS_1 = 15` match FIPS 205 §11.1 (`w = 2^lg_w = 16` for all approved sets).
- [ ] `len1() = 2·n` (FIPS 205 §5 line 5.1 with `lg_w = 4`).
- [ ] `LEN2 = 3` and `len() = 2·n + 3` for all FIPS 205 SHAKE parameter sets.
- [ ] `wotsChain(out, x, i, s, pkSeed, adrs)` runs F starting from chain step `i`, advancing exactly `s` steps and updating the hash-address inside the loop (FIPS 205 §5 Algorithm 5 line 5).
- [ ] `wotsChain` stops at exactly step `i + s` and writes the resulting n-byte value to `out`; the WOTS+ public-value chain terminates at index `w − 1 = 15`.
- [ ] `wotsPkGen(outPk, skSeed, pkSeed, adrs)` produces `len` n-byte chain endpoints, hashes them with `T_len`, and stores the compressed pk at `outPk` (FIPS 205 §5 Algorithm 6).
- [ ] `wotsSign(outSig, m, skSeed, pkSeed, adrs)` invokes `base_2b(m, lg_w, len_1)`, computes the checksum per FIPS 205 §5 Algorithm 7 lines 5-8, packs the checksum via `base_2b` over the right number of digits, and emits the `len` chain results in the spec order.
- [ ] `wotsPkFromSig(outPk, sig, m, pkSeed, adrs)` reconstructs each chain to step `w − 1 − msg[i]` and `T_len`-compresses the result; output matches `wotsPkGen` for an honestly-signed message.
- [ ] `_testBase2b(out, x, b, outLen)` writes a base-2^b digit array consuming `⌈outLen · b / 8⌉` input bytes and emitting exactly `outLen` digits (FIPS 205 §4 Algorithm 4).
- [ ] WOTS working buffers `WOTS_TMP / WOTS_SK / WOTS_MSG / SK_ADRS / WOTSPK_ADRS` are inside the STATE region documented in the file header and never alias the FORS pair buffer.

## FORS (`src/asm/slhdsa/fors.ts`)

- [ ] `forsK()` returns 33 for 128f/192f and 35 for 256f (FIPS 205 §11.1 Table 2).
- [ ] `forsA()` returns 6 / 8 / 9 for 128f / 192f / 256f (FIPS 205 §11.1 Table 2).
- [ ] `forsSkGen(out, skSeed, idx, pkSeed, adrs)` derives the FORS leaf secret via `PRF(PK.seed, SK.seed, ADRS=FORS_PRF, treeIndex=idx)` (FIPS 205 §8 Algorithm 14).
- [ ] `forsNode(out, skSeed, i, z, pkSeed, adrs)` implements the FORS Merkle recursion with the `z=0` base case calling `F(PK.seed, ADRS, fors_sk)` (FIPS 205 §8 Algorithm 15 line 1) and the recursive case calling `H` over `lnode || rnode` (line 7).
- [ ] `forsSign(outSig, md, skSeed, pkSeed, adrs)` produces exactly `k` authentication paths, each path containing the leaf secret followed by `a` sibling nodes (FIPS 205 §8 Algorithm 16 line 5; sig length `k·(a+1)·n`).
- [ ] `forsPkFromSig(outPk, sig, md, pkSeed, adrs)` reconstructs the `k` tree roots and compresses them under `T_k`-style hashing with ADRS type `FORS_ROOTS` (FIPS 205 §8 Algorithm 17 line 19).
- [ ] FORS working buffers `FORS_ROOTS / FORS_LEAF / FORS_SK_ADRS / FORS_PK_ADRS / FORS_PAIR_BASE` alias the WOTS working buffers, and the recursion never simultaneously needs both (algorithms are mutually exclusive within one WASM call).
- [ ] `forsIdx` extracts the bit slice for tree `i` from `md` per FIPS 205 §8 Algorithm 16 line 4 (right-aligned binary read of the relevant `a` bits).

## XMSS (`src/asm/slhdsa/xmss.ts`)

- [ ] `xmssHPrime()` returns 3 for 128f/192f and 4 for 256f (FIPS 205 §11.1 Table 2).
- [ ] `xmssNode(out, skSeed, i, z, pkSeed, adrs)` handles the `z=0` base case by computing the WOTS+ public key via `wotsPkGen` and writing the result to `out` (FIPS 205 §6 Algorithm 9 line 1).
- [ ] `xmssNode` recursive case (`z > 0`) computes left and right children and combines with `H(PK.seed, ADRS=TREE, lnode || rnode)` (FIPS 205 §6 Algorithm 9 line 7).
- [ ] `xmssSign(outSig, m, skSeed, idx, pkSeed, adrs)` emits a `len`-element WOTS+ signature followed by `h'` sibling authentication nodes (FIPS 205 §6 Algorithm 10 sig length `(len + h')·n`).
- [ ] `xmssPkFromSig(outRoot, idx, sig, m, pkSeed, adrs)` recovers a candidate WOTS+ public key via `wotsPkFromSig`, then climbs the XMSS auth path, choosing left/right sibling order via bit `j` of `idx` at each level (FIPS 205 §6 Algorithm 11 line 6).
- [ ] `xmssSign` and `xmssPkFromSig` reset ADRS type to `WOTS_HASH` / `TREE` at the appropriate steps so the caller (`htSign` / `htVerify`) does not need to manage type bytes between calls.
- [ ] `XMSS_PAIR_BASE` lives at `STATE_OFFSET + 3072` and does not alias the WOTS or FORS working ranges.

## Hypertree (`src/asm/slhdsa/hypertree.ts`)

- [ ] `htD()` returns 22 for 128f/192f and 17 for 256f (FIPS 205 §11.1 Table 2).
- [ ] `htHPrime()` matches `xmssHPrime()` for every parameter set.
- [ ] `htSign(outSig, m, skSeed, pkSeed, idxTreeHi, idxTreeLo, idxLeaf, adrs)` walks all `d` hypertree layers, emitting one `(len + h')·n`-byte XMSS subtree signature per layer (FIPS 205 §7 Algorithm 12, signature length `(h + d·len)·n`).
- [ ] On each ascent `htSign` updates `idx_tree ← idx_tree ≫ h'` and `idx_leaf ← idx_tree & ((1≪h')−1)` so the leaf index at layer j+1 is the low `h'` bits of the layer-j subtree index (FIPS 205 §7 Algorithm 12 line 8).
- [ ] `htSign` clears `adrs` at the start (`ADRS ← toByte(0,32)` per Algorithm 12 line 1) before setting layer and tree-address.
- [ ] `htVerify(m, sig, pkSeed, idxTreeHi, idxTreeLo, idxLeaf, pkRoot, adrs)` reproduces the `d`-layer ascent, compares the final layer's recovered root against `pkRoot`, and returns 1 iff equal (FIPS 205 §7 Algorithm 13 line 13).
- [ ] `htVerify`'s final equality compare is byte-wise constant-time at the WASM level (the comparison runs over public-input bytes per FIPS 205 §3.6.2; no branch on secret-derived data sits above it).
- [ ] `HT_ROOT_OFFSET` lives at `STATE_OFFSET + 3392` and carries the XMSS root across layers without aliasing FORS / XMSS pair buffers.

## Top-level §9 Algorithms (`src/asm/slhdsa/slh.ts`)

- [ ] `slhK()` matches `forsK()` exactly; `slhA()` matches `forsA()`; `slhD()` matches `htD()`; `slhHPrime()` matches `xmssHPrime()`.
- [ ] `mdBytes()` returns `⌈k·a/8⌉` consistent with `params.m` (25, 33, 40 for 128f/192f/256f respectively).
- [ ] `slhKeygenInternal()` reads `SK.seed || SK.prf || PK.seed` from INPUT (3·n bytes), runs FIPS 205 §9.1 Algorithm 18, and writes `sk = SK.seed || SK.prf || PK.seed || PK.root` followed by `pk = PK.seed || PK.root` to OUT (4·n + 2·n = 6·n bytes).
- [ ] `slhKeygenInternal` derives `PK.root` via `xmssNode` at the top hypertree layer with the canonical ADRS (`layer = d-1`, `tree_address = 0`, `type = TREE`).
- [ ] `slhSignInternal(msgLen)` reads `sk (4·n) || M (msgLen) || opt_rand (n)` from INPUT and writes `sig = R || σ_FORS || σ_HT` to OUT (FIPS 205 §9.2 Algorithm 19, sig length `params.sigBytes`).
- [ ] `slhSignInternal` calls `slhPRFmsg(R, SK.prf, opt_rand, M, msgLen)` to derive `R`, then `slhHmsg(digest, R, PK.seed, PK.root, M, msgLen)` to derive the `m`-byte signing digest.
- [ ] `slhSignInternal` performs the digest split per FIPS 205 §9.2 Algorithm 19 lines 6-10: `md` = low `mdBytes` bytes; `tmp_idx_tree` = next `treeBytes` bytes; `tmp_idx_leaf` = final `leafBytes` bytes; `idx_tree` masked to `(h − h/d)` bits; `idx_leaf` masked to `h'` bits.
- [ ] `slhSignInternal` computes M' is NOT applied here, M' construction lives in the TS layer (`constructMPrimePure` / `constructMPrimeHash`); the WASM entry receives the M'-shaped bytes as `M`.
- [ ] `slhSignInternal` computes `Hmsg` with `PK.seed` and `PK.root` arguments in spec order (FIPS 205 §9.2 Algorithm 19 line 8: `Hmsg(R, PK.seed, PK.root, M)`).
- [ ] `slhVerifyInternal(msgLen)` reads `pk (2·n) || M (msgLen) || sig (sigBytes)` from INPUT, recomputes the signing digest, runs forsPkFromSig and htVerify, and returns 1 iff verify succeeds.
- [ ] `slhVerifyInternal` returns 0 on any internal authentication failure (not just on htVerify mismatch); intermediate failures DO NOT leak via exception or trap.

## WASM Public Exports (`src/asm/slhdsa/index.ts`)

- [ ] Re-exports cover only the offsets, parameter setters, ADRS struct, hash family, raw Keccak gates, and the top-level keygen/sign/verify entries; the `_test*` functions exist for the unit suite but are NOT mirrored in the consumer-facing `SlhDsaExports` interface.
- [ ] `wipeBuffers` is exported and runs over OUT / STATE / SCRATCH per the buffer-layout contract.
- [ ] No additional ADRS / FORS / WOTS / XMSS / hypertree intermediate accessors are exposed beyond the documented test-fixture helpers.
- [ ] Every `_test*` re-export carries an underscore prefix and a comment indicating it is a test-fixture-only export (the `_test*` namespace); none of them appear in `src/ts/slhdsa/types.ts:SlhDsaExports`.

## TS Parameter Bindings (`src/ts/slhdsa/params.ts`)

- [ ] `SLHDSA128F` constants match FIPS 205 §11.1 Table 2 (`n=16, h=66, d=22, hPrime=3, k=33, a=6, m=30, pkBytes=32, skBytes=64, sigBytes=17088, securityCategory=1`).
- [ ] `SLHDSA192F` constants match the spec (`n=24, h=66, d=22, hPrime=3, k=33, a=8, m=39, pkBytes=48, skBytes=96, sigBytes=35664, securityCategory=3`).
- [ ] `SLHDSA256F` constants match the spec (`n=32, h=68, d=17, hPrime=4, k=35, a=9, m=49, pkBytes=64, skBytes=128, sigBytes=49856, securityCategory=5`).
- [ ] Each `wasmSelector` calls the matching `slhSetParams{128f,192f,256f}` export and not a different parameter set.
- [ ] `pkBytes = 2·n` and `skBytes = 4·n` for all three sets.
- [ ] `sigBytes = (1 + k·(a+1) + h + d·len)·n` for all three sets with `len = 2·n + 3`.

## TS Type Surface (`src/ts/slhdsa/types.ts`)

- [ ] `SlhDsaExports` exposes every WASM export the TS surface relies on (`memory`, buffer-offset getters, `wipeBuffers`, parameter-set selectors, ADRS struct, hash family, raw Keccak, and the three top-level entries).
- [ ] `SlhDsaExports` does NOT include any `_test*` symbol.
- [ ] `SlhDsaKeyPair` shape matches `MlDsaKeyPair`: `{ verificationKey: Uint8Array, signingKey: Uint8Array }` with the same naming convention.
- [ ] `SlhDsaTestExports` is declared as a separate interface with all `_test*` members and is documented as test-only.

## TS Validation (`src/ts/slhdsa/validate.ts`)

- [ ] `validateContext(ctx)` throws `SigningError('sig-ctx-too-long')` when `ctx.length > 255` and a `TypeError` when ctx is not a Uint8Array.
- [ ] `validatePublicKey(pk, params)` throws `RangeError` when `pk.length !== params.pkBytes`.
- [ ] `validateSigningKey(sk, params)` throws `RangeError` when `sk.length !== params.skBytes`.
- [ ] `validateSignature(sig, params)` throws `RangeError` when `sig.length !== params.sigBytes`.
- [ ] `validateRnd(rnd, params)` throws `RangeError` when `rnd.length !== params.n` and a `TypeError` when rnd is not a Uint8Array.
- [ ] `validateMessage(M)` requires only that `M` be a Uint8Array; FIPS 205 places no length restriction on M.
- [ ] `validateDigest(digest, ph)` throws `SigningError('sig-malformed-input')` when `digest.length !== digestSize(ph)` and explicitly mentions `'sig-malformed-input'` so the verify surface can intercept and return false.

## TS Pre-Hash Dispatcher (`src/ts/slhdsa/prehash.ts`)

- [ ] `PreHashAlgorithm` enumerates exactly the 12 FIPS 205 §10.2.2 approved choices and no others.
- [ ] OID DER table maps `SHA2-224 → .04, SHA2-256 → .01, SHA2-384 → .02, SHA2-512 → .03, SHA2-512/224 → .05, SHA2-512/256 → .06, SHA3-224 → .07, SHA3-256 → .08, SHA3-384 → .09, SHA3-512 → .0A, SHAKE128 → .0B, SHAKE256 → .0C` per FIPS 205 §10.2.2 Algorithm 23 lines 10, 13, 16, 19 (plus the four NIST CSOR registrations on the same branch).
- [ ] `oid(arc)` returns a fresh 11-byte Uint8Array each call; the 10-byte DER prefix is `06 09 60 86 48 01 65 03 04 02`.
- [ ] `getOid(algo)` returns a `.slice()` of the table entry so callers cannot mutate the module-private constant.
- [ ] `digestSize` outputs 28 / 32 / 48 / 64 in line with the spec's natural digest sizes and the §10.2.2 XOF fixings (SHAKE128 → 32, SHAKE256 → 64).
- [ ] `algoNeedsSha2` is true exactly for the six `SHA2-*` algorithms; `algoNeedsSha3` is true exactly for the six `SHA3-*` and `SHAKE*` algorithms.
- [ ] `constructMPrimePure(M, ctx)` returns `0x00 || |ctx| || ctx || M`. Caller has already validated `ctx.length ≤ 255`.
- [ ] `constructMPrimeHash(digest, ph, ctx)` returns `0x01 || |ctx| || ctx || OID(ph) || digest`. Byte-identical to `src/ts/mldsa/format.ts:constructMPrimeHash` (HashML-DSA mirror).
- [ ] `preHashMessage` routes through the correct WASM hasher (`sha3` for SHA-3 / SHAKE, `sha2` for SHA-2); throws a clear `Error` when the required module is undefined rather than NPE'ing on member access.
- [ ] `preHashMessage` requests exactly `digestSize(ph)` bytes from each hasher (SHAKE128 → 32, SHAKE256 → 64).

## TS Sign Driver (`src/ts/slhdsa/sign.ts`)

- [ ] `slhSignInternalTs(x, params, sk, MPrime, optRand)` writes INPUT in the order `sk (4n) || M' (msgLen) || opt_rand (n)`.
- [ ] `slhSignInternalTs` calls `params.wasmSelector()` BEFORE `x.slhSignInternal(msgLen)` so the active parameter set is loaded into PARAMS first.
- [ ] `slhSignInternalTs` slices out `sigBytes` bytes from OUT and returns a fresh `Uint8Array`.
- [ ] `slhSignInternalTs` zeroes the full INPUT range (`sk + M' + opt_rand`) in `finally` and calls `x.wipeBuffers()` to clear OUT / STATE / SCRATCH.
- [ ] `signWithPrehash(x, params, sk, prehash, ph, ctx, optRand)` builds M' via `constructMPrimeHash` and wipes M' in `finally`.
- [ ] `signWithPrehash` never wipes `prehash` (caller-owned digest) nor `optRand` (caller-owned in derand, lib-wiped by the caller-side method).

## TS Verify Driver (`src/ts/slhdsa/verify.ts`)

- [ ] `slhVerifyInternalTs` writes INPUT in the order `pk (2n) || M' (msgLen) || sig (sigBytes)`.
- [ ] `slhVerifyInternalTs` returns `x.slhVerifyInternal(msgLen) === 1` (boolean), never throws on a wrong signature.
- [ ] `slhVerifyInternalTs` catches every unexpected WASM exception and returns `false` so the public surface stays a pure predicate.
- [ ] `slhVerifyInternalTs` zeroes INPUT and runs `x.wipeBuffers()` in `finally` for hygiene parity with the sign path.
- [ ] `verifyWithPrehash` builds M' via `constructMPrimeHash` and wipes M' in `finally`; it never wipes `prehash`.

## SlhDsaBase Public Surface (`src/ts/slhdsa/index.ts`)

- [ ] Every public method (`keygen`, `keygenDerand`, `sign`, `signDeterministic`, `signDerand`, `verify`, `signHash`, `signHashDeterministic`, `signHashDerand`, `verifyHash`, `signHashPrehashed`, `signHashPrehashedDeterministic`, `signHashPrehashedDerand`, `verifyHashPrehashed`, `dispose`) calls `_assertNotOwned('slhdsa')` before any WASM access.
- [ ] `_assertHashPrereqs(ph)` validates `ph` via `digestSize(ph)` before the category check, so widened-type callers (e.g. parsing a vector file via `as PreHashAlgorithm`) hit the "unsupported HashSLH-DSA pre-hash" RangeError rather than a downstream sha2-not-initialized error.
- [ ] `_assertHashPrereqs` enforces the FIPS 205 §10.2.2 category restriction: `SHA2-256` and `SHAKE128` throw `RangeError` when `params.securityCategory !== 1`.
- [ ] `_assertHashPrereqs` requires `init({ sha2 })` when `algoNeedsSha2(ph)` and asserts `_assertNotOwned('sha2')`.
- [ ] `_assertHashPrereqs` requires `init({ sha3 })` when `algoNeedsSha3(ph)` and asserts `_assertNotOwned('sha3')`.
- [ ] `keygenDerand` writes `seed (3n)` to INPUT, calls `slhKeygenInternal`, and slices `sk (4n)` and `pk (2n)` from OUT in that order. The 3·n-byte seed is the FIPS 205 §9.1 `SK.seed || SK.prf || PK.seed` layout.
- [ ] `keygenDerand` zeroes the 3·n input region and calls `wipeBuffers` in `finally`.
- [ ] `keygen()` allocates `randomBytes(3n)`, calls `keygenDerand`, and wipes the local seed in `finally`.
- [ ] `sign` constructs M' via `constructMPrimePure(M, ctx)` (NOT `constructMPrimeHash`).
- [ ] `sign` allocates a lib-owned `optRand = randomBytes(n)` and wipes it in `finally`.
- [ ] `signDeterministic` slices `optRand = sk.slice(2n, 3n)` (PK.seed). The slice is a copy, not a view, and is wiped in `finally`.
- [ ] `signDerand` validates `optRand.length === n` via `validateRnd` and does NOT wipe the caller-supplied `optRand`.
- [ ] `verify` returns `false` (without throwing) on wrong-length `pk` or `sig`. It throws only via `validateContext` for `ctx.length > 255`.
- [ ] `signHash` family runs `preHashMessage` to produce `PH_M`, wipes `PH_M` in `finally`, and wipes the chosen sha2 / sha3 module buffers via `wipeBuffers` in `finally`.
- [ ] `verifyHash` returns `false` (without throwing) on wrong-length `pk` or `sig`. It throws via `_assertHashPrereqs` only for caller contract violations.
- [ ] `signHashPrehashed` validates `digest.length === digestSize(ph)` via `validateDigest` (throws `SigningError('sig-malformed-input')` on mismatch); the lib does NOT wipe the caller-owned `digest`.
- [ ] `signHashPrehashed` allocates a lib-owned `optRand = randomBytes(n)` and wipes it in `finally`.
- [ ] `signHashPrehashedDeterministic` slices `optRand = sk.slice(2n, 3n)` and wipes that slice in `finally`.
- [ ] `signHashPrehashedDerand` validates `optRand.length === n` via `validateRnd` and does NOT wipe the caller-supplied buffer.
- [ ] `verifyHashPrehashed` returns `false` on wrong-length `pk` / `sig` / `digest` and only throws for caller contract violations.
- [ ] `dispose` runs `x.wipeBuffers()` inside a `try { ... } catch {}` so a teardown race never throws; the catch comment documents idempotency.
- [ ] No public method wipes caller-supplied buffers (`sk`, `M`, `ctx`, `digest`, externally-supplied `optRand`).
- [ ] Public classes `SlhDsa128f / SlhDsa192f / SlhDsa256f` each pass the matching `SLHDSA*F` const into `SlhDsaBase`.

## Pure-mode and Prehash-mode Suite Factories (`src/ts/sign/suites/slhdsa.ts`)

- [ ] `SlhdsaPureSuite` is unexported; only the named `SlhDsa{128f,192f,256f}Suite` consts produced by it are exported. Factory must remain internal so consumers cannot construct custom suites against reserved format bytes.
- [ ] `SlhdsaPrehashSuite` is unexported under the same constraint.
- [ ] Format bytes are `SlhDsa128fSuite = 0x06, SlhDsa192fSuite = 0x07, SlhDsa256fSuite = 0x08, SlhDsa128fPreHashSuite = 0x16, SlhDsa192fPreHashSuite = 0x17, SlhDsa256fPreHashSuite = 0x18` per the signaturesuite.md catalog.
- [ ] `ctxDomain` strings match `slhdsa128f-envelope-v3 / slhdsa192f-envelope-v3 / slhdsa256f-envelope-v3` (pure) and `slhdsa128f-prehash-envelope-v3 / slhdsa192f-prehash-envelope-v3 / slhdsa256f-prehash-envelope-v3` (prehash); each is ≤ 32 bytes UTF-8.
- [ ] `wasmModules` is `['slhdsa']` for pure suites and `['slhdsa', 'sha3']` for prehash suites.
- [ ] Pure-mode `sign(sk, msg, ctx)` invokes `inst.sign(sk, msg, effectiveCtx)` where `effectiveCtx = buildEffectiveCtx(ctxDomain, ctx)`.
- [ ] Pure-mode `verify(pk, msg, sig, ctx)` mirrors with `inst.verify(pk, msg, sig, effectiveCtx)`.
- [ ] Each method instantiates `new SlhDsaClass()` inside a `try { ... } finally { inst.dispose() }` block so WASM scratch is wiped on every path.
- [ ] Prehash suite `signPrehashed` belt-and-suspenders re-validates `digest.length === prehashSize` before instantiating; the underlying primitive also validates.
- [ ] Prehash suite `verifyPrehashed` returns `false` on `digest.length !== prehashSize` without instantiating the primitive.
- [ ] Prehash-mode 128f pairs with `'shake-128'` (32-byte digest) per the FIPS 205 §10.2.2 category restriction.
- [ ] Prehash-mode 192f pairs with `'shake-256'` (64-byte digest).
- [ ] Prehash-mode 256f pairs with `'shake-256'` (64-byte digest).
- [ ] `prehashAlgoToSlhdsa` translates the lowercase suite-layer enum (`'shake-128'`, `'shake-256'`, `'sha-256'`, `'sha-512'`, `'sha3-256'`, `'sha3-512'`) into the uppercase `PreHashAlgorithm` SLH-DSA expects, with an exhaustive `default` that hits `never`.

## PQ-only Hybrid Suite Factory (`src/ts/sign/suites/hybrid-pq.ts`)

- [ ] `MldsaSlhdsaHybridSuite` is unexported; only the named `MlDsa{44,65,87}SlhDsa{128f,192f,256f}Suite` consts are exported.
- [ ] Format bytes are `MlDsa44SlhDsa128fSuite = 0x30, MlDsa65SlhDsa192fSuite = 0x31, MlDsa87SlhDsa256fSuite = 0x32`.
- [ ] `ctxDomain` strings are `mldsa44-slhdsa128f-envelope-v3`, `mldsa65-slhdsa192f-envelope-v3`, `mldsa87-slhdsa256f-envelope-v3`; each is ≤ 32 bytes UTF-8.
- [ ] `wasmModules` is `['mldsa', 'sha3', 'slhdsa']` for every hybrid suite. (sha3 is present because the prehash runs through `createRunningHash` via sha3-streaming.)
- [ ] `pkSize = mldsaParams.pkBytes + slhdsaParams.pkBytes` and `skSize / sigSize` follow the same additive layout (ML-DSA half FIRST, SLH-DSA half SECOND).
- [ ] Prehash algorithm pinning: `MlDsa44SlhDsa128fSuite → shake-128 / 32`, `MlDsa65SlhDsa192fSuite → shake-256 / 64`, `MlDsa87SlhDsa256fSuite → shake-256 / 64`. (Matches the per-half FIPS 205 §10.2.2 category gate.)
- [ ] `keygen()` instantiates each primitive in its own `try { ... } finally { dispose }` block; the two key pairs are concatenated only after BOTH dispose paths have run.
- [ ] `signPrehashed` validates `digest.length === prehashSize` and `sk.length === skSize` BEFORE any WASM work; mismatches throw `SigningError('sig-malformed-input')` and `SigningError('sig-key-size')` respectively.
- [ ] `signPrehashed` slices `sk` into `skMldsa = sk.subarray(0, mldsaParams.skBytes)` and `skSlhdsa = sk.subarray(mldsaParams.skBytes)`. The subarray views do NOT copy.
- [ ] `signPrehashed` calls `mldsaInst.signHashPrehashed(skMldsa, digest, mldsaHashAlgo, effectiveCtx)` and `slhdsaInst.signHashPrehashed(skSlhdsa, digest, slhdsaHashAlgo, effectiveCtx)` with the SAME `digest` and SAME `effectiveCtx`.
- [ ] `signPrehashed` concatenates `sigMldsa || sigSlhdsa` (ML-DSA half first).
- [ ] `signPrehashed` wipes the lib-allocated `effectiveCtx` Uint8Array in `finally`; it does NOT wipe `digest` (caller-owned).
- [ ] `verifyPrehashed` short-circuits to `false` (no WASM) on `pk.length !== pkSize`, `sig.length !== sigSize`, or `digest.length !== prehashSize`.
- [ ] `verifyPrehashed` ALWAYS runs both sub-verifies regardless of the first half's result. The declaration `let mldsaOk: boolean; let slhdsaOk: boolean;` without an initial value enforces this at the type level (a TypeScript compile error if either declaration is read before its assignment).
- [ ] `verifyPrehashed` returns `mldsaOk && slhdsaOk` AFTER both sub-verifies have completed. The boolean `&&` is operating on two pre-computed values, so JavaScript's short-circuit operator has nothing to short-circuit.
- [ ] `verifyPrehashed` does NOT wipe `sigMldsa` / `sigSlhdsa` subarrays on failure (caller-owned data per the hybrid factory contract).
- [ ] `verifyPrehashed` wipes the lib-allocated `effectiveCtx` Uint8Array in `finally`.
- [ ] The streaming variants `sign(sk, msg, ctx)` and `verify(pk, msg, sig, ctx)` route through `createRunningHash(prehashAlgorithm)` to compute the digest, then forward to `signPrehashed` / `verifyPrehashed`. The hasher is disposed via `h.finalize()` (which also returns the digest) plus a belt-and-suspenders `h.dispose()` in the catch branch for the "throw before finalize" path.
- [ ] The streaming variants wipe the computed digest in `finally` after `signPrehashed` / `verifyPrehashed` returns.

## Test Coverage

- [ ] `test/unit/slhdsa/slhdsa.test.ts` covers round-trip sign / verify across all three parameter sets.
- [ ] `test/unit/slhdsa/slhdsa-acvp.test.ts` exercises the ACVP-Server v1.1.0.42 corpus pinned at `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`: 15 keyGen, 39 sigGen, 27 sigVer.
- [ ] `test/unit/slhdsa/slhdsa-wots.test.ts` cross-checks `wotsChain / wotsPkGen / wotsSign / wotsPkFromSig` via the `_test*` WASM exports.
- [ ] `test/unit/slhdsa/slhdsa-fors.test.ts` cross-checks `forsSkGen / forsNode / forsSign / forsPkFromSig`.
- [ ] `test/unit/slhdsa/slhdsa-xmss.test.ts` cross-checks `xmssNode / xmssSign / xmssPkFromSig`.
- [ ] `test/unit/slhdsa/slhdsa-hypertree.test.ts` cross-checks `htSign / htVerify`.
- [ ] `test/unit/slhdsa/slhdsa-hashes.test.ts` covers `F / H / T_ℓ / PRF / PRF_msg / H_msg` against FIPS 205 §11.2 Table 4 expectations.
- [ ] `test/unit/slhdsa/slhdsa-address.test.ts` covers every ADRS setter / getter round-trip and the BE-32 layout invariant.
- [ ] `test/unit/slhdsa/slhdsa-hashvariant.test.ts` covers HashSLH-DSA across all 12 §10.2.2 pre-hash functions with category-gate enforcement.
- [ ] `test/unit/slhdsa/slhdsa-prehashed.test.ts` covers byte-identical equivalence between `signHashDeterministic(M, ph)` and `signHashPrehashedDeterministic(H_PH(M), ph)`.
- [ ] `test/unit/slhdsa/slhdsa-validation.test.ts` covers every validate.ts throw path.
- [ ] `test/unit/slhdsa/keygen-scratch-wipe.test.ts`, `sign-scratch-wipe.test.ts`, `verify-scratch-wipe.test.ts` confirm INPUT / OUT / STATE / SCRATCH are wiped after every public operation.
- [ ] `test/unit/sign/sign-slhdsa-*.test.ts` covers the SLH-DSA suite layer (vectors, integration, suite-level error paths).
- [ ] `test/unit/sign/sign-stream-equivalence-slhdsa.test.ts` confirms `Sign.sign` / `SignStream.finalize` byte-equivalence for the slhdsa-prehash suites.
- [ ] `test/unit/sign/sign-hybrid-pq-*.test.ts` covers the three hybrid suites (vectors, integration, tamper resistance, suite layer).

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [slhdsa](./slhdsa.md) | SLH-DSA public API reference |
| [signaturesuite](./signaturesuite.md) | SignatureSuite interface; pure / prehash / hybrid catalog |
| [SECURITY.md](../SECURITY.md) | PQ-only hybrid threat model |
| [mldsa_audit](./mldsa_audit.md) | ML-DSA audit (parallel structure for the other PQ signature family) |
| [audits](./audits.md) | Project audit index |
| [architecture](./architecture.md) | Module structure, buffer layouts, build pipeline |
