<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Benchmarks

SIMD performance results across V8, SpiderMonkey, and JavaScriptCore.

---

| Benchmark | Description |
|---|---|
| [serpent_simd_bench](./serpent_simd_bench.md) | Serpent-256 CTR and CBC-decrypt, scalar vs 4-wide SIMD across all three engines |
| [chacha_simd_bench](./chacha_simd_bench.md) | ChaCha20 4-wide inter-block parallelism, scalar vs SIMD, including documented negative result for intra-block approach |
| [p256_perf](./p256_perf.md) | ECDSA-P256 math-level optimizations: Strauss-Shamir verify, windowed-then-safegcd scalarInv, Comba feSqr investigated and rejected by measurement. ecdsaSign -73%, ecdsaVerify -87% versus baseline. |

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |