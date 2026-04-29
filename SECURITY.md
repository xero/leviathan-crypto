# Leviathan Crypto Library Security Policy

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="Leviathan logo" width="100" align="left">

- **[Security Posture](#security-posture)**
- **[Cryptanalytic Audits](#cryptanalytic-audits)**
- **[Supported Versions](#supported-versions)**
- **[Vulnerability Reporting](#reporting-a-vulnerability)**

---

## Security posture

[leviathan-crypto](https://leviathan.3xi.club/) is a cryptography library. Security shapes every layer of the stack.

### Algorithm correctness

Every primitive in this library was implemented by hand in AssemblyScript against the authoritative specification: [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) for SHA-2, [FIPS 202](https://csrc.nist.gov/publications/detail/fips/202/final) for SHA-3, [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) for ML-KEM, [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) for ChaCha20-Poly1305, [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) for HMAC, [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) for HKDF, and the original [Serpent-256 specification](https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf) with S-box reference. No algorithm came from an existing implementation. The spec is the source of truth.

All implementations verify against published known-answer test vectors from NIST, RFC appendices, NESSIE, and the Argon2 reference suite. Test vectors are immutable; if an implementation produces incorrect output, we fix the code and never adjust the vectors to match.

### Side-channel resistance

Serpent's S-boxes use Boolean gate circuits with no table lookups, no data-dependent memory access, and no data-dependent branches. Every bit processes unconditionally on every block. This is the most timing-safe cipher approach available in WASM, where JIT optimization can otherwise introduce observable timing variation.

Security-sensitive comparisons (MAC verification, padding validation) use [`constantTimeEqual`](https://github.com/xero/leviathan-crypto/wiki/utils#constanttimeequal), backed by a dedicated WASM SIMD module. The v128 XOR accumulate with branch-free scalar tail reduction eliminates JIT short-circuiting and speculative optimization as side-channel vectors. The function requires WebAssembly SIMD and throws a branded error on runtimes without it, matching the library-wide SIMD requirement. WASM comparison memory gets wiped after every call.

### WASM execution model

All cryptographic computation runs in WebAssembly, isolated outside the JavaScript JIT. WASM execution is deterministic and not subject to JIT speculation or optimization. Each primitive family compiles to its own isolated binary with its own linear memory. Key material in the Serpent module cannot interact with memory in the SHA-3 module, even in principle. A dedicated WASM module handles constant-time comparison with its own single-page memory that is wiped after every call.

Serpent and ChaCha20 modules require WebAssembly SIMD (v128 instructions). `init()` and `initModule()` perform a SIMD preflight check and throw a clear error on runtimes without support. SIMD has been a baseline feature of all major browsers and runtimes since 2021. SHA-2 and SHA-3 modules run on any WASM-capable runtime.

The kyber module requires WebAssembly SIMD for NTT and polynomial arithmetic (v128 instructions). The SIMD preflight check applies on `init()` alongside serpent and chacha20. Its linear memory is independent from all other modules. Kyber's constant-time path (FO transform decapsulation) uses dedicated `ct_verify` and `ct_cmov` functions implemented in the kyber WASM binary; comparison never passes through JavaScript.

Stateful classes (`SHAKE128/256`, `ChaCha20`, `SerpentCtr`, `SerpentCbc`, `MlKem*`) enforce module exclusivity at runtime. A live instance holds an exclusivity token on its backing WASM module; constructing a second instance against the same module throws until the first is disposed. Cross-module operations (kyber decapsulate invoking sha3 hashing) assert non-ownership of the modules they touch before writing to them, preventing silent re-initialization of a live sponge or cipher state.

### Memory hygiene

Every public cryptographic operation zeros its secret and secret-derived scratch before returning. Across all three ML-KEM operations (`keygen`, `encapsulate`, `decapsulate`), no kyber secret or secret-derived data persists in kyber or sha3 linear memory between operations. The CPA secret key, per-message noise polynomials, raw message bytes, PRF output buffers, and FO re-encryption intermediates all get wiped at the operation boundary. AEAD authentication failures wipe the full keystream block and the Poly1305 one-time subkey. Fortuna's `stop()` is a complete teardown: generator key, generator counter, all 32 pool-hash chain values, and a `wipeBuffers()` call on every WASM module the chosen generator and hash touched. Stream constructions (`SealStream`/`OpenStream`) transition to a terminal `'failed'` state on any mid-operation throw, wiping derived keys before the exception propagates.

This wipe discipline defends against a narrow but concrete threat: an adversary with read access to WASM linear memory between operations. JS-side memory disclosure, host CPU side channels (cache, branch predictor, speculative execution beyond what WASM neuters), and physical device access remain out of scope; those are the runtime's and the hardware's responsibility.

Key-validation helpers (`checkEncapsulationKey`, `checkDecapsulationKey`) operate on public material only and require no wipe. They are side-effect-free with respect to module state.

### Authenticated encryption by default

Raw unauthenticated cipher modes (`SerpentCbc`, `SerpentCtr`, `ChaCha20`) and stateless caller-managed-nonce primitives (`ChaCha20Poly1305`, `XChaCha20Poly1305`) are exposed for power users but are not the recommended entry point. The primary API surfaces (`Seal`, `SealStream`, `OpenStream`, `SealStreamPool`, and `KyberSuite`) are authenticated by construction with internally managed nonces.

All streaming constructions satisfy the _Cryptographic Doom Principle_.

**SealStream/OpenStream with SerpentCipher.** Encrypt-then-MAC (SerpentCbc + HMAC-SHA256). The HMAC tag is compared against the expected tag via `constantTimeEqual` — backed by the dedicated WASM SIMD CT module — and that compare is the unconditional gate into the CBC WASM decrypt path; decryption is unreachable until the gate clears. HKDF key derivation with the stream nonce and counter-nonce domain separation extends this guarantee to full stream integrity.

**SealStream/OpenStream with XChaCha20Cipher.** XChaCha20-Poly1305 AEAD per chunk. The Poly1305 tag is compared against the expected tag via `constantTimeEqual` — backed by the dedicated WASM SIMD CT module — before any call to the chacha20 WASM decrypt path. On authentication failure, the full chunk output buffer is wiped and plaintext bytes never return. Counter nonces with TAG_DATA/TAG_FINAL final-flag domain separation ensure reorder, splice, truncation, and cross-stream substitution all fail AEAD verification before decryption.

**SealStreamPool.** Delegates per-chunk AEAD to isolated Web Workers. Each worker holds its own derived subkey and WASM instance. Any authentication error marks the pool dead, rejects all pending operations, requests that each worker zero its in-memory key material, and terminates workers after a short ACK window. Main-thread copies of the derived keys and master key are zeroed synchronously. No retry, no partial results.

The stateless AEADs (`ChaCha20Poly1305`, `XChaCha20Poly1305`) enforce strict single-use; any throw from `encrypt()` (including length validation errors on `key` or `nonce`) terminates the instance. A retry with valid arguments always raises the single-use guard rather than potentially reusing a nonce. Consumers allocate a fresh AEAD per message.

### Key-material lifecycle

`SkippedKeyStore.resolve` returns a transactional `ResolveHandle` rather than a raw key. The caller settles the handle via `commit()` on successful decryption (the key is wiped) or `rollback()` on authentication failure (the key returns to the store under its counter, so a subsequent legitimate delivery at the same counter can still decrypt). This closes a delete-on-retrieval DoS where an adversary injecting a garbage ciphertext at a valid counter would otherwise consume that counter's cached key before the legitimate message arrived. A `FinalizationRegistry` wipes the key best-effort if a handle is GC'd unsettled.

`SkippedKeyStore` splits its work budget into `maxCacheSize` (memory bound, default 100) and `maxSkipPerResolve` (per-message HKDF work bound, default 50). A malicious header with a very high counter cannot force unbounded HKDF derivations on the receiver; eviction is O(1) via insertion-order iteration.

`OpenStream.seek(index)` only moves forward. Backward seeks would reuse an already-consumed per-chunk counter nonce against a new ciphertext, permitting plaintext replay against a stale opener. The call throws rather than silently reusing the nonce.

### Dependency management

This library has zero runtime dependencies by design. `sideEffects: false` is enforced in `package.json`. Argon2id integration is documented as an _optional_ external dependency. See: [leviathan-crypto/wiki/argon2id](https://github.com/xero/leviathan-crypto/wiki/argon2id).

Build toolchain dependencies use exact version locks in `bun.lock`. GitHub Actions workflows use [SHA-pinned action references](https://github.com/xero/leviathan-crypto/blob/main/scripts/pin-actions.ts) throughout with no floating tags. Supply chain integrity is a first-class concern for a cryptography library.

### Explicit initialization

No class silently auto-initializes. The [`init()`](https://github.com/xero/leviathan-crypto/wiki/init) gate is mandatory and explicit, giving you full control over when WASM modules load and ensuring no hidden initialization costs or race conditions. Classes throw immediately if used before initialization rather than failing silently.

### Agentic development contracts

All AI-assisted development on this repository operates under a strict agentic contract defined in [AGENTS.md](https://github.com/xero/leviathan-crypto/blob/main/AGENTS.md). The contract enforces spec authority over planning documents, immutable test vectors, gate discipline before extending any test suite, independent algorithm derivation from published standards, and constant-time and wipe requirements for all security-sensitive code paths. Agents are explicitly prohibited from guessing cryptographic values or resolving spec ambiguities silently.

The contract has been verified against Claude, GitHub Copilot (VS Code), OpenHands, Kilo Code, Cursor, Windsurf, and Aider. Configuration files for each are in the repository and all route to [AGENTS.md](https://github.com/xero/leviathan-crypto/blob/main/AGENTS.md) as the single source of authority.

---

## Cryptanalytic audits

All primitives undergo periodic cryptographic implementation reviews. See the [audit index](https://github.com/xero/leviathan-crypto/wiki/audits) for a full summary.

| Primitive | Audit description |
| --- | --- |
| [serpent_audit](https://github.com/xero/leviathan-crypto/wiki/serpent_audit) | Correctness verification, side-channel analysis, cryptanalytic attack paper review |
| [chacha_audit](https://github.com/xero/leviathan-crypto/wiki/chacha_audit) | XChaCha20-Poly1305 correctness, Poly1305 field arithmetic, HChaCha20 nonce extension, post-auth-fail wipe hygiene |
| [sha2_audit](https://github.com/xero/leviathan-crypto/wiki/sha2_audit) | SHA-256/512/384 correctness, HMAC and HKDF composition, constant verification |
| [sha3_audit](https://github.com/xero/leviathan-crypto/wiki/sha3_audit) | Keccak permutation correctness, θ/ρ/π/χ/ι step verification, round constant derivation |
| [hmac_audit](https://github.com/xero/leviathan-crypto/wiki/hmac_audit) | HMAC-SHA256/512/384 construction, key processing, RFC 4231 vector coverage |
| [hkdf_audit](https://github.com/xero/leviathan-crypto/wiki/hkdf_audit) | HKDF extract-then-expand, info field domain separation, stream key derivation |
| [kyber_audit](https://github.com/xero/leviathan-crypto/wiki/kyber_audit) | ML-KEM FIPS 203 correctness (§7.2/§7.3 direct coefficient-range validation), NTT/Montgomery/Barrett verification, FO transform CT analysis, per-op memory hygiene across keygen/encap/decap, ACVP validation |
| [stream_audit](https://github.com/xero/leviathan-crypto/wiki/stream_audit) | Streaming AEAD composition, counter nonce binding, final-chunk detection, key wipe paths, `'failed'` terminal state |
| [ratchet_audit](https://github.com/xero/leviathan-crypto/wiki/ratchet_audit) | SPQR KDF primitives: HKDF parameter assignments with full transcript binding (peerEk, kemCt, context), wipe coverage, counter encoding, direction slot alignment, transactional `ResolveHandle` DoS mitigation |

### Serpent-256 security margin research

The security margin of Serpent-256 has been independently researched and documented. The best known attack on the full 32-round cipher, _biclique cryptanalysis_, achieves a complexity of 2²⁵⁵·¹⁹ with 2⁴ chosen ciphertexts. This provides less than one bit of advantage over exhaustive key search and has zero practical impact. Independent research conducted against this implementation improved on the published result by −0.20 bits through systematic parameter search, confirming no structural weakness beyond what the published literature describes.

See: [xero/BicliqueFinder/biclique_research.md](https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md)

---

## Supported versions

Every fix is documented in the full [CHANGELOG](https://github.com/xero/leviathan-crypto/blob/main/CHANGELOG). Each version below links to the release notes documenting its fixes.

| Version | Status | Summary |
| --- | --- | --- |
| [v2.1.x](https://github.com/xero/leviathan-crypto/blob/main/CHANGELOG#v2-1-0-XXXX-XX-XX) | ✓ supported | Adds SPQR post-quantum KEM ratchet primitives |
| [v2.0.x](https://github.com/xero/leviathan-crypto/blob/main/CHANGELOG#v2-0-1-2026-04-10) | ✗ superseded | FIPS 203 key validation, per-op wipe hygiene, padding-oracle closure, and ratchet DoS mitigation. Upgrade to v2.1.x |
| [v1.x](https://github.com/xero/leviathan-crypto/blob/main/CHANGELOG#v2-0-0-2026-04-10) | ✗ deprecated | Multiple partial-wipe and auth-handling issues. Upgrade to v2.1.x |

> [!CAUTION]
> v2.0.0 has a known silent-corruption bug. `SealStreamPool` with `SerpentCipher` silently produces corrupt plaintext with no authentication error on decrypt for inputs ≥ 65536 bytes. See [v2.0.1 release notes](https://github.com/xero/leviathan-crypto/blob/main/CHANGELOG#v2-0-1-2026-04-10) and update to the latest version immediately.

---

## Reporting a vulnerability

> [!IMPORTANT]
> Do not open a public issue for security vulnerabilities.

### Private advisory (preferred)

Use GitHub's private vulnerability reporting form: [https://github.com/xero/leviathan-crypto/security/advisories/new](https://github.com/xero/leviathan-crypto/security/advisories/new)

This opens a private channel between you and the maintainer, and you will receive a response promptly. If the vulnerability is confirmed, we collaborate to fully understand the issue, including a review of proposed fixes, so you can track and validate firsthand. Before any public advisory publishes, we agree on a coordinated disclosure timeline. After disclosure, you are encouraged to publish your own write-up, blog post, or research notes for full hacker scene credit.

### Direct contact

If you prefer direct contact:

- **Email:** x﹫xero.style · PGP: [0xAC1D0000](https://0w.nz/pgp.pub)
- **Matrix:** x0﹫rx.haunted.computer

> [!NOTE]
> Encrypted communication is welcome and preferred for sensitive reports.

### In scope

- Authentication bypass in AEAD constructions
- Key material exposure or improper zeroing
- Incorrect entropy or CSPRNG weaknesses in Fortuna
- Side-channel vulnerabilities (timing, memory access patterns)
- Correctness bugs in cryptographic implementations (wrong output against test vectors)
- Platform-specific behavioral differences (WASM execution, binary output, or timing characteristics that differ across operating systems or CPU architectures)
- Supply chain issues (dependency tampering, workflow compromise)
- Improper scope of exported symbols

### Out of scope

- Vulnerabilities in third-party packages not maintained by this project. This includes optional peer dependencies such as argon2id. Report those directly to their maintainers.
- Issues requiring physical access to the user's device
- Theoretical attacks with no practical exploit path (complexity improvements that remain computationally infeasible)
- Issues in the demo applications that do not affect the core library. Open an issue in [leviathan-demos](https://github.com/xero/leviathan-demos/) instead.

