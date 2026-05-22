<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### P-256 ECDSA performance, math-level optimizations

Benchmark results for substrate-level changes to P-256 scalar
multiplication and modular inverse. All changes preserve the project's
"no precomputed tables indexed by secret bits" architectural posture
(SECURITY.md §Side-channel resistance) and "register-only logic with no
data-dependent memory access on secret-derived values" rule.

> ### Table of Contents
> - [Environment](#environment)
> - [Baseline](#baseline)
> - [Change 1: Comba feSqr (rejected by measurement)](#change-1-comba-fesqr-rejected-by-measurement)
> - [Change 2: Strauss-Shamir verify](#change-2-strauss-shamir-verify)
> - [Change 3: Windowed scalarInv](#change-3-windowed-scalarinv)
> - [Combined effect](#combined-effect)
> - [What remains on the table](#what-remains-on-the-table)
> - [Cross-References](#cross-references)

---

## Environment

- **Date**: 2026-05-22
- **Hardware**: Apple Silicon, arm64
- **Runtime**: Bun 1.3.13 (JavaScriptCore)
- **WASM**: `build/p256.wasm`, instantiated once per bench process
- **Method**: 5 sequential runs per measurement, median reported; per-op
  iteration counts chosen so each measurement runs at least ~10 ms of
  wall clock to keep variance under ~3%
- **Inputs**: deterministic; same seed bytes across all measurements

This is a substrate-level micro-bench, not a browser-side end-to-end
suite. Numbers reflect the AS / WASM toolchain in JSC; absolute numbers
on V8 / SpiderMonkey will differ but the relative deltas should hold.

## Baseline

Naive Fermat scalarInv with constant-time always-compute, separate
`pointMulBase(u1, G) + pointMul(u2, Q) + pointAdd` for verify.

| op | median |
|----|--------|
| feMul        | 240 ns |
| feSqr        | 237 ns |
| feInv        | 123.3 µs |
| scalarMul    | 20.4 µs |
| scalarInv    | **10.54 ms** |
| pointAdd     | 3.63 µs |
| pointDouble  | 3.32 µs |
| pointMul     | 1.791 ms |
| pointMulBase | 1.789 ms |
| ecdsaSign    | **14.41 ms** |
| ecdsaVerify  | **14.46 ms** |

ECDSA call cost is dominated by `scalarInv`: 73% of sign, 72% of
verify. Substrate field arithmetic is small in comparison.

## Change 1: Comba feSqr (rejected by measurement)

**Hypothesis.** A dedicated squaring routine exploiting
`a_i · a_j = a_j · a_i` should compute 28 off-diagonal + 8 diagonal
partial products instead of `feMul`'s 64, saving ~30% on `feSqr`.

**Two implementations tried:**

1. Comba column accumulator with 3 × u32 lanes (96-bit running column
   sum). 28 off-diagonals computed once, added twice via `combaAdd(p);
   combaAdd(p)` pattern.
2. Schoolbook with off-diagonal symmetry: row-by-row over `i < j` only,
   then in-place left-shift to double, then 8 diagonal adds with
   constant-time carry propagation.

**Result.** Both within ±5% of `feMul(a, a)` cost, neither faster:

| op | baseline | attempt 1 | attempt 2 |
|----|----------|-----------|-----------|
| feSqr | 237 ns | 237 ns | 248 ns |
| feInv | 123.3 µs | 126.3 µs | 128.1 µs |
| pointDouble | 3.32 µs | 3.40 µs | 3.39 µs |

**Why it doesn't win.** The schoolbook inner step

```
t = pij + ai * bj + carry
```

is a 5-op pipeline (load + mul + add + store + shift). The multiply is
not the bottleneck; the load/store/carry-shift chain is. Saving 28/64
of the multiplications would save ~7-8% of `feMul` cost in theory, but
both implementations introduce structural overhead (a 3-lane carry
accumulator, or a separate phase-3 diagonal-add loop with fixed-length
constant-time carry propagation) that costs at least as much as it
saves.

For comparison, curve25519's `feSqr` does win, because its radix-2^51
representation gives 128-bit accumulator headroom that absorbs many
partial products without per-product carry propagation. P-256's
radix-2^32 saturated representation has no such headroom.

**Decision.** Rejected. The audit-surface cost of a dedicated `feSqr`
is not justified when the wall-clock saving is zero. `feSqr` remains
the one-liner `feMul(out, a, a)`.

## Change 2: Strauss-Shamir verify

**Implementation.** New export `pointMulDoubleVerify(u1, u2, Q, out)`
in `src/asm/p256/scalar_mult.ts`. Interleaves the two ladders of
`[u1]G + [u2]Q` into a single 256-iteration loop:

- 4-entry table `T = {O, Q, G, G+Q}` materialised once before the loop
  (G + Q is computed by one `pointAdd`)
- Per bit pair `(b1, b2)`: one shared `pointDouble`, one conditional
  `pointAdd` of `T[2·b1 | b2]`; skip when both bits are zero

`ecdsaVerify` replaces its `pointMulBase + pointMul + pointAdd`
triplet with a single call. The 4-entry table is indexed by PUBLIC
verify-input bits, not by any secret-derived value, so it remains
outside the architectural prohibition on secret-bit-indexed tables.
The function explicitly does not satisfy constant-time discipline
across the bit-pair selector; verify is already non-CT across reject
branches by design (see [asm_p256.md §Verify timing](./asm_p256.md#verify-timing)).

**Result.** 5-run median, baseline → after change 2:

| op | baseline | after | delta |
|----|----------|-------|-------|
| ecdsaVerify | 14.46 ms | 12.09 ms | **−16.4%** |
| ecdsaSign | 14.41 ms | (unchanged) | ~0% |
| pointMul | 1.79 ms | 1.78 ms | -0.7% |
| pointMulBase | 1.79 ms | 1.78 ms | -0.6% |

Larger than the original 13% estimate because the bench's `ecdsaVerify`
also captures pointAffinify / scalarReduce overhead that I had lumped
into "scalar mult portion"; actual savings versus the replaced cost
are ~50% of the replaced cost, which is ~16% of verify wall-clock.

## Change 3: Windowed scalarInv

**Implementation.** Replaced naive square-and-multiply in `scalarInv`
with fixed-window-4 exponentiation over the PUBLIC exponent (n-2):

- Precompute 15-entry table `a^1..a^15` at FIELD_TMP slots 16..30
  (free during scalarInv; only `point.ts` uses these slots and is not
  on this call path).
- Scan `(n-2)` MSB-first as 64 4-bit windows. Per window: 4 unconditional
  squarings + 1 conditional multiply (skipped when the window value is 0).

Constant-time discipline preserved:

- The branch on `win == 0` is on PUBLIC exponent bits (n-2 is a fixed
  constant from SP 800-186 §3.2.1.3).
- The table lookup index `(win - 1) * 32` is also derived from public
  exponent bits; no secret-bit-driven memory access.
- The table CONTENTS are derived from the secret `a`, but every entry
  is computed unconditionally in a fixed order. The architectural
  prohibition is on secret-bit-indexed access patterns; public-bit-indexed
  access to secret-derived storage is the same shape as Strauss-Shamir's
  4-entry table in `pointMulDoubleVerify`.

**Result.** 5-run median, baseline → after change 3 (cumulative with #2):

| op | baseline | after #2 | after #3 | total delta |
|----|----------|----------|----------|-------------|
| scalarInv | 10.54 ms | 10.08 ms | **6.49 ms** | **−38.4%** |
| ecdsaSign | 14.41 ms | 13.99 ms | **10.41 ms** | **−27.7%** |
| ecdsaVerify | 14.46 ms | 12.09 ms | **8.41 ms** | **−41.8%** |

**Why the win is bigger than my pre-implementation estimate (13%).**
The OLD scalarInv ran unconditional `scalarMul(tmp, acc, aCopy)` on
every iteration and committed via constant-time mask-select on the bit.
That is ~512 scalarMul-equivalents (256 squarings + 256 unconditional
multiplies). The NEW windowed version, branching on PUBLIC exponent
bits, lands at 14 precompute + 256 squarings + (64 windows × 56/64
non-zero) multiplies = ~326 scalarMul-equivalents.

```
saving = (512 - 326) / 512 ≈ 36%
```

That matches the measured 38%. The under-estimate happened because I
counted "naive Fermat = 256 squarings + 128 multiplies" rather than
"constant-time naive Fermat = 256 squarings + 256 multiplies".

The branch-on-public-bit is the load-bearing move. Constant-time
discipline on a SECRET exponent forces always-compute, which doubles
the multiply count. Public exponents can branch freely.

## Combined effect

5-run median, baseline → after both changes:

| op | baseline | after #2 + #3 | delta |
|----|----------|---------------|-------|
| feMul | 240 ns | 240 ns | -0.0% |
| feSqr | 237 ns | 236 ns | -0.3% |
| feInv | 123.3 µs | 122.4 µs | -0.7% |
| scalarMul | 20.4 µs | 19.9 µs | -2.2% |
| scalarInv | 10.54 ms | 6.49 ms | **−38.4%** |
| pointAdd | 3.63 µs | 3.62 µs | -0.4% |
| pointDouble | 3.32 µs | 3.30 µs | -0.4% |
| pointMul | 1.79 ms | 1.77 ms | -1.0% |
| pointMulBase | 1.79 ms | 1.78 ms | -0.5% |
| **ecdsaSign** | **14.41 ms** | **10.41 ms** | **−27.7%** |
| **ecdsaVerify** | **14.46 ms** | **8.41 ms** | **−41.8%** |

WASM binary growth: `build/p256.wasm` 19,084 → 19,376 bytes (+292
bytes, +1.5%). gzip-embedded delta: 6.1 → 6.2 KB.

## What remains on the table

After #2 + #3:

| component of cost | wall-clock | % of sign | % of verify |
|-------------------|------------|-----------|-------------|
| scalarInv | 6.49 ms | 62% | 77% |
| pointMul / pointMulBase | 1.78 ms / 1.78 ms | 17% | 21% |
| other (SHA, HMAC-DRBG, scalarMul, etc.) | ~2.1 ms | 21% | ~2% |

`scalarInv` still dominates. The remaining 6.49 ms is the cost of 256
scalar squarings plus 56 scalar multiplies plus the 14-entry
precompute. Each scalar op is byte-level (32-byte BE schoolbook) so
no constant-factor optimization on the substrate squaring (rejected in
change 1) would help.

The next-tier change would be **Bernstein-Yang safegcd** for
`scalarInv` (eprint 2019/266), which computes `a^-1 mod n` in
constant-time via a 743-divstep iteration without modular squarings.
Estimated speedup: ~5x over the current windowed implementation,
landing both sign and verify around 6 ms wall-clock. Not pursued in
this round; the audit-surface cost is significantly larger than #2 + #3
combined and merits a dedicated effort.

A note on what was investigated and explicitly NOT pursued:

- **SIMD field arithmetic**: rejected at module inception. The HMV
  §2.4.1 Solinas reduction does not lane-pack; AS `v128` does not
  expose paired `64×64 → 128`. See
  [asm_p256.md §SIMD posture](./asm_p256.md#simd-posture).
- **Comba feSqr**: rejected by measurement (this doc, change 1).
- **RCB mixed addition** (a = -3, Z₂ = 1): saves only 1 generic feMul
  per add in the projective RCB representation (not the 4-5 from the
  textbook Jacobian + affine quote). With pointMul / pointMulBase at
  ~1.8 ms each, the wall-clock saving would be ~256 feMul × 240 ns ≈
  60 µs per ladder, ~3% of pointMul. Not worth the audit cost of a
  second `pointAddMixed` variant.

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [asm_p256](./asm_p256.md) | WASM API reference, RCB formulas, Solinas reduction |
| [ecdsa](./ecdsa.md) | TypeScript wrapper class |
| [architecture](./architecture.md) | Module structure, side-channel posture |
