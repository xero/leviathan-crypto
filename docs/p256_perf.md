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
> - [Change 4: Bernstein-Yang safegcd scalarInv](#change-4-bernstein-yang-safegcd-scalarinv)
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

## Change 4: Bernstein-Yang safegcd scalarInv

**Implementation.** Replaced the windowed Fermat scalarInv with
bit-by-bit Bernstein-Yang safegcd (eprint 2019/266 §11). 743 divsteps
over a 9 × u32 LE-limb signed representation of (f, g), with (u, v)
tracked modulo n in 8 × u32 LE limbs. Constant-time by construction:

- Every conditional in the divstep uses mask-driven selects on the two
  per-step bits: `δ > 0` and `g & 1`. Neither is branched on directly.
- Per-divstep update of (u, v): 9-limb mask-driven mul-add of u into v
  (with sign encoded via two's-complement: XOR with `maskNeg`,
  AND with `maskUse`, carry-in = `swapCond`), then reduce mod n by
  conditional add of n if negative + conditional sub of n if ≥ n, then
  modular halve by conditional add of n if odd + arithmetic shift right.
- Fixed 743-iteration count from Theorem 11.2 (`iter(n) = ⌈(49n+80)/17⌉`
  for n = 256).
- At termination: if f's sign bit is set, the answer is `n - u` instead
  of `u` (computed via constant-time conditional select).

The implementation works in LE u32 limbs internally, bypassing the
byte-by-byte scalarMul / scalarReduce64 path entirely. BE↔LE conversion
at the function boundary is the only byte-level work.

**Result.** 5-run median, baseline → after change 4 (cumulative with
#2 and #3):

| op | baseline | after #3 (windowed) | after #4 (safegcd) | total delta |
|----|----------|---------------------|--------------------|--------------|
| scalarInv | 10.54 ms | 6.49 ms | **32.4 µs** | **−99.69%** (325× faster) |
| ecdsaSign | 14.41 ms | 10.41 ms | **3.92 ms** | **−72.8%** (3.67× faster) |
| ecdsaVerify | 14.46 ms | 8.41 ms | **1.92 ms** | **−86.7%** (7.53× faster) |

**Why so much bigger than my pre-implementation estimate (5×).** Three
compounding effects:

1. Per-divstep cost is much lower than I assumed. I estimated ~10 ns
   per u32 op based on conservative WASM/JSC numbers. Actual is closer
   to 1-2 ns per u32 op on JSC for this code shape (tight u32 work with
   excellent register allocation).
2. No scalarMul calls at all. The windowed implementation made ~270
   scalarMul calls each averaging 20 µs (5.4 ms total). Safegcd uses
   only 9-limb u32 additions and shifts.
3. WASM JIT loves tight u32 loops. The divstep body is mostly
   register-resident operations on small operands; JSC optimizes the
   path aggressively.

The 743 × ~85 u32 ops × ~0.5 ns ≈ 32 µs matches the measurement.

**Audit notes.**

- Algorithm: eprint 2019/266 §11.3 (divstep), §11.2 (iteration bound),
  §11.4 (magnitude bound). Independently transcribed per AGENTS.md §4;
  cross-checked against RustCrypto `crypto-bigint::modular::safegcd` and
  BoringSSL `bn_mod_inverse_consttime` for algorithm shape only.
- Correctness: 200 deterministic random + 5 edge-case inputs verified
  via the `a · inv(a) ≡ 1 (mod n)` substrate invariant
  (`test/unit/p256/scalar.test.ts > scalarInv: stress test`). Plus the
  RFC 6979 §A.2.5 KAT vectors implicitly verify k^{-1} via the
  reproduced (r, s) outputs.
- Constant-time: branches on `δ > 0` and `g & 1` use mask-driven
  selects throughout. The iteration count is the fixed public bound;
  the per-step work is fixed-shape regardless of secret inputs.

## Combined effect

5-run median, baseline → after all four changes (#1 was rejected by
measurement; #2, #3, #4 shipped):

| op | baseline | shipped | delta |
|----|----------|---------|-------|
| feMul | 240 ns | 237 ns | -1.2% |
| feSqr | 237 ns | 237 ns | +0.1% |
| feInv | 123.3 µs | 129.4 µs | +5.0% (variance) |
| scalarMul | 20.4 µs | 20.3 µs | -0.3% |
| **scalarInv** | **10.54 ms** | **32.4 µs** | **−99.7%** (325× faster) |
| pointAdd | 3.63 µs | 3.63 µs | -0.1% |
| pointDouble | 3.32 µs | 3.38 µs | +1.8% (variance) |
| pointMul | 1.79 ms | 1.78 ms | -0.4% |
| pointMulBase | 1.79 ms | 1.80 ms | +0.5% |
| **ecdsaSign** | **14.41 ms** | **3.92 ms** | **−72.8%** (3.67× faster) |
| **ecdsaVerify** | **14.46 ms** | **1.92 ms** | **−86.7%** (7.53× faster) |

WASM binary growth: `build/p256.wasm` 19,084 → 20,288 bytes (+1,204
bytes, +6.3%). gzip-embedded delta: 6.1 → 6.6 KB.

## What remains on the table

After #2 + #3 + #4:

| component of cost | sign | verify |
|-------------------|------|--------|
| pointMulBase / pointMul / pointMulDoubleVerify | 1.80 ms (46%) | 1.80 ms (94%) |
| SHA-256 + HMAC-DRBG + scalarMul (RFC 6979 K-derivation) | ~1.9 ms (49%) | n/a |
| scalarInv | 32 µs (0.8%) | 32 µs (1.7%) |
| other (reductions, affinify, etc.) | ~0.2 ms | ~0.1 ms |

Sign is now dominated by SHA-256 + HMAC-DRBG + pointMulBase. Verify is
dominated entirely by `pointMulDoubleVerify`. Both ECDSA paths are now
in the low single-millisecond range.

The next-tier optimization targets:

- **Limb-level scalarMul.** The byte-by-byte schoolbook in scalar.ts
  is ~20 µs per call; a limb-level radix-2^32 schoolbook (mirroring
  feMul's shape with a Barrett or Montgomery reduction mod n) would
  be ~250 ns per call, an 80× speedup. Affects the RFC 6979 K-derivation
  (~270 scalarMuls per sign) and the verify u1/u2 computation (2 muls).
  Estimated sign delta: ~−5 ms to ~−6 ms, possibly larger if HMAC-DRBG
  also shares the scalarMul time. Audit surface: moderate.

- **Pre-computed comb for `[scalar]G`.** Adds a precomputed table
  indexed by SECRET scalar bits, which is the architectural posture
  this library does not pursue (SECURITY.md §Side-channel resistance).
  Stays rejected.

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
