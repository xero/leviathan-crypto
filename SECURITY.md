# Leviathan Crypto Library Security Policy

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="Leviathan logo" width="100" align="left">

- **[Supported Versions](#supported-versions)**
- **[Reporting a Vulnerability](#reporting-a-vulnerability)**
- **[Security Posture](#security-posture)**
- **[Cryptanalytic Audits](#cryptanalytic-audits)**
- **[Signature Threat Models](#signature-threat-models)**
  - **[PQ-only Hybrid](#pq-only-hybrid-signature-threat-model)**
  - **[Classical+PQ Hybrid](#classicalpq-hybrid-signature-threat-model)**

---

## Supported versions

Every fix is documented in the full [CHANGELOG](https://github.com/xero/leviathan-crypto/blob/main/CHANGELOG). Each version below links to the release notes documenting its fixes.

| Version | Status | Summary |
| --- | --- | --- |
| [v3.0.x](https://github.com/xero/leviathan-crypto/blob/main/CHANGELOG#v3-0-0) | ✓ supported | Serpent public byte-order convention flipped to NIST natural order (wire-format break against v2); ChaCha salamander defense; AES-128/192/256 raw block cipher; PQ + classical signature catalog (ML-DSA, SLH-DSA, Ed25519, ECDSA-P256, PQ-only and classical+PQ hybrids); BLAKE3 hash family; C2SP-conformant merkle log substrate (`MerkleLog`, `MerkleVerifier`) |
| [v2.1.x](https://github.com/xero/leviathan-crypto/blob/main/CHANGELOG#v2-1-0-XXXX-XX-XX) | ✗ deprecated | Seal with ChaCha vulnerable to Salamander attacks (Serpent unaffected). Upgrade to v3.0.x; note the Serpent wire-format break |
| [v2.0.x](https://github.com/xero/leviathan-crypto/blob/main/CHANGELOG#v2-0-1-2026-04-10) | ✗ deprecated | FIPS 203 key validation, per-op wipe hygiene, padding-oracle closure, and ratchet DoS mitigation. Upgrade to v3.0.x |
| [v1.x](https://github.com/xero/leviathan-crypto/blob/main/CHANGELOG#v2-0-0-2026-04-10) | ✗ deprecated | Multiple partial-wipe and auth-handling issues. Upgrade to v3.0.x |

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

---

## Security posture

[leviathan-crypto](https://leviathan.3xi.club/) is a cryptography library. Security shapes every layer of the stack.

### Algorithm correctness

Every primitive in this library was implemented by hand in AssemblyScript against the authoritative specification: [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) for SHA-2, [FIPS 202](https://csrc.nist.gov/publications/detail/fips/202/final) for SHA-3, [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) for ML-KEM, [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) for ML-DSA, [FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) for SLH-DSA, [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) for ChaCha20-Poly1305, [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) for HMAC, [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) for HKDF, the [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs) for BLAKE3 (hash, keyed_hash, derive_key), and the original [Serpent-256 specification](https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf) with S-box reference. No algorithm came from an existing implementation. The spec is the source of truth.

All implementations verify against published known-answer test vectors from NIST, RFC appendices, NESSIE (Serpent test vectors), and the Argon2 reference suite. Test vectors are immutable; if an implementation produces incorrect output, we fix the code and never adjust the vectors to match.

ML-KEM produces its 32-byte shared secret directly from a SHA-3 output rather than from a big-integer encoding, so the construction is structurally immune to the leading-zero-trim timing leak that affected TLS-DH(E) (Raccoon attack).

### Authenticator robustness (key-committing AEAD)

The seal layer is key-committing across all supported cipher suites. SerpentCipher achieves this natively. HMAC-SHA-256 over the chunk authenticator binds the message to the MAC key under SHA-256 collision resistance, so two distinct keys cannot produce the same tag for distinct messages. XChaCha20Cipher relies on Poly1305, which is not key-committing on its own, so the seal v3 wire format adds an explicit 32-byte commitment to the preamble. The commitment is derived from the master key via HKDF-SHA-256 alongside the encryption key. `OpenStream` and `SealStreamPool` verify the commitment against the receiver's derived value in constant time before any chunk is processed; a wrong key fails fast with `AuthenticationError` carrying the discriminator string `commitment-xchacha20`, before the Poly1305 tag is consulted.

AESGCMSIVCipher uses the same HtE construction as XChaCha20Cipher modulo the cipher backend: AES-256-GCM-SIV's POLYVAL-based MAC is not key-committing on its own (same posture as Poly1305), so the seal v3 wire format adds the same explicit 32-byte commitment. The HKDF info string is `aes-gcm-siv-sealstream-v3` and the discriminator on a wrong-key open is `commitment-aes-gcm-siv`. The construction is byte-equivalent to the XChaCha20 path modulo the cipher backend; the same Salamander regression suite covers both.

This closes the Invisible Salamanders attack surface (Albrecht, Degabriele, Janson, Struck, RWC 2019) for any higher-level construction built on the seal primitive. Multi-recipient envelope encryption, group messaging with sender keys, and multi-tenant data warehouses get this property without adding their own commitment scheme.

Both XChaCha20 v3 and AES-GCM-SIV v3 HKDF info strings incorporate the full 20-byte header. Tampering with `formatEnum`, the framed flag, the nonce, or `chunkSize` produces different keys and fails the AEAD on the first chunk, rather than relying on indirect detection through chunk-boundary mismatch.

### Side-channel resistance

Serpent's S-boxes use Boolean gate circuits with no table lookups, no data-dependent memory access, and no data-dependent branches. Every bit processes unconditionally on every block. This is the most timing-safe cipher approach available in WASM, where JIT optimization can otherwise introduce observable timing variation.

Security-sensitive comparisons (MAC verification, padding validation) use [`constantTimeEqual`](https://github.com/xero/leviathan-crypto/wiki/utils#constanttimeequal), backed by a dedicated WASM SIMD module. The v128 XOR accumulate with branch-free scalar tail reduction eliminates JIT short-circuiting and speculative optimization as side-channel vectors. The function requires WebAssembly SIMD and throws a branded error on runtimes without it, matching the library-wide SIMD requirement. WASM comparison memory gets wiped after every call.

### WASM execution model

All cryptographic computation runs in WebAssembly. WASM bytecode has defined deterministic semantics at the spec level, same input, same output, no undefined behavior, and is compiled by the runtime's WASM JIT (V8 Liftoff/TurboFan, SpiderMonkey Cranelift, JSC OMG) to native code with predictable instruction selection. This eliminates the JS-level timing oracles that motivate constant-time crypto, JIT deopts, hidden-class transitions, GC pauses, string interning, and exposes the cipher to the same constant-time-coding discipline that native crypto follows. CPU-level side channels (cache timing on secret-dependent loads, branch prediction, speculative execution) are out of scope and remain the runtime's and the hardware's responsibility. Each primitive family compiles to its own isolated binary with its own linear memory. Key material in the Serpent module cannot interact with memory in the SHA-3 module, even in principle. A dedicated WASM module handles constant-time comparison with its own single-page memory that is wiped after every call.

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

**SealStream/OpenStream with SerpentCipher.** Encrypt-then-MAC (SerpentCbc + HMAC-SHA256). The HMAC tag is compared against the expected tag via `constantTimeEqual`, backed by the dedicated WASM SIMD CT module, and that compare is the unconditional gate into the CBC WASM decrypt path; decryption is unreachable until the gate clears. HKDF key derivation with the stream nonce and counter-nonce domain separation extends this guarantee to full stream integrity.

**SealStream/OpenStream with XChaCha20Cipher.** XChaCha20-Poly1305 AEAD per chunk. The Poly1305 tag is compared against the expected tag via `constantTimeEqual`, backed by the dedicated WASM SIMD CT module, before any call to the chacha20 WASM decrypt path. On authentication failure, the full chunk output buffer is wiped and plaintext bytes never return. Counter nonces with TAG_DATA/TAG_FINAL final-flag domain separation ensure reorder, splice, truncation, and cross-stream substitution all fail AEAD verification before decryption.

**SealStream/OpenStream with AESGCMSIVCipher.** AES-256-GCM-SIV (RFC 8452) AEAD per chunk, nonce-misuse-resistant authenticated encryption with a 16-byte tag. The SIV tag is compared against the recomputed expected tag via `constantTimeEqual`, backed by the dedicated WASM SIMD CT module, before plaintext is returned. On authentication failure, `sivWipeOnFail()` zeroes the unauthenticated plaintext at CHUNK_PT_OFFSET before the throw, so the plaintext bytes never become reachable from JavaScript. Counter nonces with TAG_DATA/TAG_FINAL final-flag domain separation extend the same reorder/splice/truncation/cross-stream substitution guarantees that XChaCha20Cipher provides.

**SealStreamPool.** Delegates per-chunk AEAD to isolated Web Workers. Each worker holds its own derived subkey and WASM instance. Any authentication error marks the pool dead, rejects all pending operations, requests that each worker zero its in-memory key material, and terminates workers after a short ACK window. Main-thread copies of the derived keys and master key are zeroed synchronously. No retry, no partial results.

The stateless AEADs (`ChaCha20Poly1305`, `XChaCha20Poly1305`) enforce strict single-use; any throw from `encrypt()` (including length validation errors on `key` or `nonce`) terminates the instance. A retry with valid arguments always raises the single-use guard rather than potentially reusing a nonce. Consumers allocate a fresh AEAD per message.

### Key-material lifecycle

`SkippedKeyStore.resolve` returns a transactional `ResolveHandle` rather than a raw key. The caller settles the handle via `commit()` on successful decryption (the key is wiped) or `rollback()` on authentication failure (the key returns to the store under its counter, so a subsequent legitimate delivery at the same counter can still decrypt). This closes a delete-on-retrieval DoS where an adversary injecting a garbage ciphertext at a valid counter would otherwise consume that counter's cached key before the legitimate message arrived. A `FinalizationRegistry` wipes the key best-effort if a handle is GC'd unsettled.

`SkippedKeyStore` splits its work budget into `maxCacheSize` (memory bound, default 100) and `maxSkipPerResolve` (per-message HKDF work bound, default 50). A malicious header with a very high counter cannot force unbounded HKDF derivations on the receiver; eviction is O(1) via insertion-order iteration.

`OpenStream.seek(index)` only moves forward. Backward seeks would reuse an already-consumed per-chunk counter nonce against a new ciphertext, permitting plaintext replay against a stale opener. The call throws rather than silently reusing the nonce.

### Signature surface threat model

The sign module (`Sign`, `SignStream`, `VerifyStream`, and the six ML-DSA SignatureSuite consts) is built on the same disciplines that protect the seal layer: required-customization construction, constant-time comparison on attacker-supplied bytes, wipe-on-failure, and runtime exclusivity guards on shared WASM state.

**Cross-suite domain separation via `ctxDomain`.** Every SignatureSuite carries a built-in `{scheme}-envelope-v3` (or `{scheme}-prehash-envelope-v3`) string. The suite wraps the caller's user_ctx into an effective ctx of the form `lengthPrefix(suite.ctxDomain) || lengthPrefix(user_ctx)` before handing the ctx to the underlying primitive. A signature produced under `MlDsa65Suite` cannot accidentally validate against `MlDsa65PreHashSuite` even with identical `(sk, msg, user_ctx)`, the M' transcripts differ at the very first bytes. The factory enforces `ctxDomain ≤ 32 bytes`; per-call `user_ctx ≤ 255 bytes` (FIPS 204 §3.6.1 native ctx cap) throws `SigningError('sig-ctx-too-long')`. `buildEffectiveCtx` enforces a second check on the combined output length so the effective per-call user_ctx ceiling on `buildEffectiveCtx`-using suites is `253 - len(ctxDomain)`, keeping the combined effective_ctx inside the FIPS 204 255-byte cap. Composite suites (the classical+PQ hybrids at `0x20`-`0x23`) bind ctx through the M' construction directly and enforce the full 255-byte cap inline; the discriminator is uniform across both check sites.

**Hedged signing by default.** The ML-DSA suites route `suite.sign` to `MlDsaBase.sign`, the FIPS 204 §3.4 recommended hedged variant: a fresh 32-byte `rnd` is sampled per call from `crypto.getRandomValues`, so two signatures over the same `(sk, msg, ctx)` differ. Hedged signing remains unforgeable under fault attacks that bias the rejection-sampling stream, the failure mode that deterministic ML-DSA is vulnerable to. The deterministic and externally-randomized (CAVP-style) variants live on the underlying primitive, not on the suite; suites do not expose them.

**Constant-time ctx comparison in the envelope and stream parsers.** `Sign.verify` and `VerifyStream` compare the caller-supplied ctx against the wire-format ctx via `constantTimeEqual` from `src/ts/utils.ts`, never `===` on `Uint8Array`. A wrong ctx and a wrong signature are indistinguishable to a timing observer.

**Wipe hygiene across both stream classes.** `SignStream` holds the SHA3-256 / SHA3-512 running prehash; `finalize()` and `dispose()` zero the hasher state via the underlying `SHA3_*Stream.dispose()` wipe. `VerifyStream` additionally buffers payload chunks for the post-finalize length-known verify pass; on auth failure inside `finalize()` the collected chunks are wiped before the `SigningError` propagates, so partial payload bytes never leak through a thrown error path. Caller-owned signing keys, verification keys, and messages are not wiped by the lib, those remain the caller's responsibility under the same memory-hygiene contract that applies to AEAD keys.

**Concurrency posture.** `SignStream` and `VerifyStream` hold an exclusive ownership token on the `sha3` WASM module from construction until `finalize()` or `dispose()`. Concurrent use of `Sign.sign` on a prehash suite during a live `SignStream`, or vice versa, throws the same `_acquireModule` exclusivity error that protects SHAKE128 from clobber. The sign layer supports single-threaded use only; concurrent multi-signer use cases will ship when the underlying primitive offers worker-pool variants.

### Dependency management

This library has zero runtime dependencies by design. `sideEffects: false` is enforced in `package.json`. Argon2id integration is documented as an _optional_ external dependency. See: [leviathan-crypto/wiki/argon2id](https://github.com/xero/leviathan-crypto/wiki/argon2id).

Build toolchain dependencies use exact version locks in `bun.lock`. GitHub Actions workflows use [SHA-pinned action references](https://github.com/xero/leviathan-crypto/blob/main/scripts/pin-actions.ts) throughout with no floating tags. Supply chain integrity is a first-class concern for a cryptography library.

Decoy packages cover common typosquat variants (missing hyphens, character transpositions, and common misspellings) of `leviathan-crypto` on npm. Each declares the real `leviathan-crypto` as an optional peer dependency and runs a post-install script that loudly warns the user with the correct package name and install command, preempting the typosquat attack class ahead of any observed exploitation.

### Explicit initialization

No class silently auto-initializes. The [`init()`](https://github.com/xero/leviathan-crypto/wiki/init) gate is mandatory and explicit, giving you full control over when WASM modules load and ensuring no hidden initialization costs or race conditions. Classes throw immediately if used before initialization rather than failing silently.

### Agentic development contracts

All AI-assisted development on this repository operates under a strict agentic contract defined in [AGENTS.md](https://github.com/xero/leviathan-crypto/blob/main/AGENTS.md). The contract enforces spec authority over planning documents, immutable test vectors, gate discipline before extending any test suite, independent algorithm derivation from published standards, and constant-time and wipe requirements for all security-sensitive code paths. Agents are explicitly prohibited from guessing cryptographic values or resolving spec ambiguities silently.

The contract has been verified against Claude, GitHub Copilot (VS Code), OpenHands, Kilo Code, Cursor, Windsurf, and Aider. Configuration files for each are in the repository and all route to [AGENTS.md](https://github.com/xero/leviathan-crypto/blob/main/AGENTS.md) as the single source of authority.

A separate `CLAUDE_consumer.md` ships alongside the library, compressing the API surface, design restrictions, and recommended workflows into a map an AI assistant can use when a consumer asks for help writing or reviewing code that uses leviathan-crypto. It does for consumer-side AI work what `AGENTS.md` does for contributor-side AI work.

---

## Cryptanalytic audits

All primitives undergo periodic cryptographic implementation reviews. See the [audit index](https://github.com/xero/leviathan-crypto/wiki/audits) for a full summary.

| Primitive | Audit description |
| --- | --- |
| [serpent_audit](https://github.com/xero/leviathan-crypto/wiki/serpent_audit) | Correctness verification, side-channel analysis, cryptanalytic attack paper review |
| [chacha_audit](https://github.com/xero/leviathan-crypto/wiki/chacha_audit) | XChaCha20-Poly1305 correctness, Poly1305 field arithmetic, HChaCha20 nonce extension, post-auth-fail wipe hygiene |
| [sha2_audit](https://github.com/xero/leviathan-crypto/wiki/sha2_audit) | SHA-256/512/384 correctness, HMAC and HKDF composition, constant verification |
| [sha3_audit](https://github.com/xero/leviathan-crypto/wiki/sha3_audit) | Keccak permutation correctness, θ/ρ/π/χ/ι step verification, round constant derivation |
| [blake3_audit](https://github.com/xero/leviathan-crypto/wiki/blake3_audit) | BLAKE3 §2.2 compress / §2.1 compress4 / §2.3 chunk machine / §2.4 subtree stack / §2.5 root + XOF / §2.6 keyed_hash / §2.7 derive_key correctness, lane-parallel SIMD equivalence, XOF snapshot lifecycle, per-class wipe discipline |
| [hmac_audit](https://github.com/xero/leviathan-crypto/wiki/hmac_audit) | HMAC-SHA256/512/384 construction, key processing, RFC 4231 vector coverage |
| [hkdf_audit](https://github.com/xero/leviathan-crypto/wiki/hkdf_audit) | HKDF extract-then-expand, info field domain separation, stream key derivation |
| [kyber_audit](https://github.com/xero/leviathan-crypto/wiki/kyber_audit) | ML-KEM FIPS 203 correctness (§7.2/§7.3 direct coefficient-range validation), NTT/Montgomery/Barrett verification, FO transform CT analysis, per-op memory hygiene across keygen/encap/decap, ACVP validation |
| [stream_audit](https://github.com/xero/leviathan-crypto/wiki/stream_audit) | Streaming AEAD composition, counter nonce binding, final-chunk detection, key wipe paths, `'failed'` terminal state |
| [ratchet_audit](https://github.com/xero/leviathan-crypto/wiki/ratchet_audit) | SPQR KDF primitives: HKDF parameter assignments with full transcript binding (peerEk, kemCt, context), wipe coverage, counter encoding, direction slot alignment, transactional `ResolveHandle` DoS mitigation |

### Serpent-256 security margin research

The security margin of Serpent-256 has been independently researched and documented. The best known attack on the full 32-round cipher, _biclique cryptanalysis_, achieves a complexity of 2²⁵⁵·¹⁹ with 2⁴ chosen ciphertexts. This provides less than one bit of advantage over exhaustive key search and has zero practical impact. Independent research conducted against this implementation improved on the published result by −0.20 bits through systematic parameter search, confirming no structural weakness beyond what the published literature describes.

See: [xero/BicliqueFinder/biclique_research.md](https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md)

---

## Signature threat models

Two hybrid signature families ship with different adversary models. PQ-only hybrids (`0x30`-`0x32`) pair ML-DSA with SLH-DSA for assumption diversity between two PQ families. Classical+PQ hybrids (`0x20`-`0x23`) pair ML-DSA with Ed25519 or ECDSA-P256 for ecosystem interop during PQ migration. The sections below cover what each defends against and what it does not.

### PQ-only hybrid signature threat model

Three PQ-only hybrid suites (`MlDsa44SlhDsa128fSuite`, `MlDsa65SlhDsa192fSuite`, `MlDsa87SlhDsa256fSuite`, format bytes `0x30` / `0x31` / `0x32`) pair ML-DSA (lattice-based, FIPS 204) with SLH-DSA (hash-based, FIPS 205) at the matching NIST security category and emit a single combined signature that binds both primitives to the same prehash digest and the same effective ctx. The composite encoding lives in [signaturesuite.md](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#pq-only-hybrid-composite-encoding); the threat model below covers what this design defends against and what it does not.

**What this defends against.** A break in one post-quantum family while the other holds. The combined signature is secure iff at least one half remains unbroken.

- If ML-DSA falls to a lattice cryptanalysis advance, the SLH-DSA half holds. An attacker cannot forge the SLH-DSA half without breaking SHAKE: Grover's quadratic speedup leaves SHAKE256 with approximately 128 bits of security against quantum preimage search, well above the 96-bit floor implied by FIPS 205's category-3 design margin.
- If SLH-DSA falls (a SHAKE256 weakness or a structural break in the hypertree construction), the ML-DSA half holds. ML-DSA's M-LWE reduction still applies because the lattice algorithm operates on a parameter set whose security has not been compromised.
- An attacker who forges one half still needs to forge the other, or possess the other half's secret key, before the combined signature verifies. Standard CMA bound applies to the unbroken half regardless of what is known about the broken half.

**What this does NOT defend against.** A universal cryptographically-relevant quantum computer that breaks lattice and hash-based primitives simultaneously, a discovery that one of the two primitives is fundamentally broken under classical attack (the broken half offers no protection in that case and only the other half's security applies). Neither half of the hybrid is classical, so Shor's algorithm does not apply; the hybrid is PQ-only by design.

**Difference from classical+PQ hybrids (`0x20`-`0x23`, see below).** Classical hybrids exist for ecosystem interop during PQ migration: they bind ML-DSA to Ed25519 or ECDSA-P256 so a receiver with only classical verifier support can still consume the signature. Classical hybrids defend against the case where PQ cryptanalysis has not panned out and the classical primitive carries the security. They do NOT defend against a quantum adversary, because Shor's algorithm breaks the classical half. PQ-only hybrids invert that trade: both halves are quantum-resistant, neither is classical, neither offers interop with pre-PQ verifiers. Different threat models, different designs, different encodings. The library does NOT use the IETF composite-sigs draft for the PQ-only pairs because composite-sigs targets classical+PQ; the PQ-only encoding here is leviathan-defined per [signaturesuite.md](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#pq-only-hybrid-composite-encoding).

**Domain separation.** Each hybrid suite carries a unique `ctxDomain` (`mldsa44-slhdsa128f-envelope-v3`, `mldsa65-slhdsa192f-envelope-v3`, `mldsa87-slhdsa256f-envelope-v3`). Both halves of a single hybrid see the same `effective_ctx`, so a sig produced for one hybrid cannot reuse against another. Cross-suite forgery (an ML-DSA half from a standalone `MlDsa44Suite` masquerading as the ML-DSA half of hybrid `0x30`) is prevented because the `effective_ctx` differs at the byte level. Cross-hybrid forgery (the ML-DSA half from `0x30` reused inside `0x31`) is prevented by the same mechanism. No per-half suffix is required because ML-DSA pk and SLH-DSA pk are distinct artifacts: a sig produced for one primitive cannot accidentally verify under the other's pk.

**Constant-time discipline.** `verifyPrehashed` always runs both sub-verifies regardless of intermediate outcomes. The reference implementation declares the two boolean results without initial values so neither is readable until both sub-verifies have completed; the trailing `mldsa_ok AND slhdsa_ok` is a boolean reduction over precomputed values, not a short-circuit operation. Total verify work is the sum of the two sub-verifies regardless of which (if either) fails, so a timing observer cannot distinguish an ML-DSA failure from an SLH-DSA failure. Each sub-verify is itself constant-time on attacker-supplied bytes per its FIPS contract. The audit checklist in [docs/slhdsa_audit.md](https://github.com/xero/leviathan-crypto/wiki/slhdsa_audit) enforces this discipline at the source level.

**No reduction to weakest link.** Both sub-signers receive the SAME prehash digest and the SAME `effective_ctx`. An attacker who forges one half cannot weaken the other by manipulating the digest; the digest is computed once by the caller (or by the streaming layer) and passed unchanged to both `signHashPrehashed` calls. The combined signature is bound to a single `(digest, ctx)` pair, so an attacker faces two independent forgery problems against the same input rather than a chained construction where compromising the outer half compromises the inner.

**Concurrency model.** Single-threaded. A live `SignStream` over a hybrid suite holds the `mldsa`, `sha3`, and `slhdsa` WASM modules exclusively from construction until `finalize()` or `dispose()`. Concurrent `Sign.sign` calls on the same hybrid suite throw the same `_acquireModule` exclusivity error that protects every other stateful WASM consumer. Worker-pool variants for hybrid signing land alongside the underlying primitives' worker support.

### Classical+PQ hybrid signature threat model

The four composite classical+PQ hybrid suites (`MlDsa44Ed25519Suite`, `MlDsa65Ed25519Suite`, `MlDsa44EcdsaP256Suite`, `MlDsa65EcdsaP256Suite`, format bytes `0x20` / `0x21` / `0x22` / `0x23`) implement `draft-ietf-lamps-pq-composite-sigs` Composite ML-DSA. Each suite pairs ML-DSA (lattice-based, FIPS 204) with a classical signature primitive (Ed25519 per RFC 8032 §5.1 or ECDSA-P256 per FIPS 186-5 §6 + SP 800-186 §3.2.1.3) and emits a single combined signature that binds both halves to the same M' construction. The composite encoding lives in [signaturesuite.md](https://github.com/xero/leviathan-crypto/wiki/signaturesuite#classicalpq-hybrid-composite-encoding); the threat model below covers what this design defends against and what it does not.

**Combiner type.** Parallel signature combiner per composite-sigs §9: both halves verify independently over the same M'. The combined signature is EUF-CMA secure (existential unforgeability under chosen-message attack) if either component remains EUF-CMA secure — an attacker who cannot forge under one half cannot produce a composite signature on a never-signed message. Strong unforgeability (sEUF-CMA, the "no second valid signature on an already-signed message" property) holds across the composite only when both halves are sEUF-CMA and their wire encodings are non-malleable; see the §"ECDSA-half high-S normalisation" paragraph below for the per-suite breakdown of which composites land on which side of that line.

**What this defends against.** A break in one component while the other holds.

- If ML-DSA falls to a lattice cryptanalysis advance under classical attack, the classical half (Ed25519 or ECDSA-P256) holds. The classical primitives are not affected by lattice cryptanalysis.
- If a flaw is found in the classical primitive under classical attack (an elliptic-curve weakness, an RFC 8032 / FIPS 186-5 implementation pitfall the library managed to avoid), the ML-DSA half holds because lattice cryptanalysis offers no shortcut against a classical-curve weakness.

**What this does NOT defend against.** A CRQC (cryptographically-relevant quantum computer) that runs Shor's algorithm against the classical curve. Both Ed25519 and ECDSA-P256 fall to Shor in polynomial time once a sufficiently large quantum computer exists. The ML-DSA half still holds in that world, but a parallel combiner accepts as valid any signature where BOTH halves verify; an attacker who forges the classical half (trivial under Shor) plus already-knows the ML-DSA secret key (a separate compromise) defeats the composite. Pick the [PQ-only hybrids](#pq-only-hybrid-signature-threat-model) (`0x30`-`0x32`) when the threat model assumes a future CRQC.

**Domain separation via `M'`.** The composite-sigs §3.2 `M' = Prefix || Label || len(ctx) || ctx || PH(M)` construction binds each suite uniquely. The 32-byte ASCII Prefix (`CompositeAlgorithmSignatures2025`) fixes the combiner family; the per-suite Label fixes the specific OID. Cross-suite forgery is prevented at the byte level by the Label differentiation; a signature produced under `MlDsa44Ed25519Suite` does NOT verify as the ML-DSA half of any other suite because the M' construction bound to that signature carries the suite-specific Label.

The caller-supplied `user_ctx` is bound through the M' construction, not through `buildEffectiveCtx`. Wrapping ctx with a leviathan-specific `{ctxDomain}|{user_ctx}` framing inside M' would produce a wire incompatible with every other Composite ML-DSA implementation. Per-call `user_ctx ≤ 255 bytes` (composite-sigs §3.2 step 1) is enforced inline; the discriminator on overflow is the library-wide `SigningError('sig-ctx-too-long')`.

**Constant-time discipline.** `verifyPrehashed` always runs both sub-verifies regardless of intermediate outcomes. Composite-sigs §3.3 explicitly permits early-fail on the ML-DSA verify ("no private keys are involved in a signature verification, there are no timing attacks to consider"); the library declines that permission for parity with the [PQ-only hybrid](#pq-only-hybrid-signature-threat-model) posture and for defence-in-depth against side-channel observers. The reference implementation declares `mldsaOk` and `tradOk` without initial values so neither is readable until both sub-verifies have completed; the trailing AND is a boolean reduction over precomputed values, not a short-circuit. Total verify work is the sum of the two sub-verifies regardless of which half (if either) fails. For the ECDSA hybrids, DER decode failure on the trad-half also folds into `tradOk = false` rather than propagating an exception, so a malformed trad-half does not short-circuit the ML-DSA verify either.

**Hedged signing posture.** Both halves are hedged-by-default.

- ML-DSA half hedged per FIPS 204 §3.7 recommendation (`rnd = randomBytes(32)` mixed into the rejection-sampling state per sign).
- ECDSA half hedged per `draft-irtf-cfrg-det-sigs-with-noise-05` §4 (`rnd = randomBytes(32)` mixed into the K derivation per sign). Pure-deterministic RFC 6979 §3.2 is available on the standalone `EcdsaP256` class for callers who need it; the composite suites do not expose that knob.
- Ed25519 half deterministic by construction per RFC 8032 §5.1.6 (`r = SHA-512(prefix || M)`); no rnd to hedge. This is a property of the spec, not a policy choice.

The composite signature is therefore non-deterministic for both ECDSA suites and the ML-DSA half of the Ed25519 suites. Two `sign` calls on the same `(sk, msg, ctx)` produce different composite signatures; both verify under the same composite pk.

**Secret-key handling.** Composite sk is `mldsaSeed (32) || tradSk` per composite-sigs §4.2. The 32-byte ML-DSA seed is the only ML-DSA material carried on the wire; the expanded ML-DSA signing key is re-derived per sign via `keygenDerand` (FIPS 204 §6.1 `KeyGen_internal`), lives in WASM scratch for the duration of one sign call, and is wiped on every exit path. One extra ML-DSA keygen per sign (roughly 5-15 ms depending on parameter set) is the price of the seed-only sk encoding the draft mandates. The classical sk half is the standard primitive encoding: 32-byte raw seed for Ed25519, 51-byte DER `ECPrivateKey` per RFC 5915 §3 for ECDSA-P256. Standalone-suite sk handling is unchanged.

**ECDSA-half high-S normalisation.** Composite-sigs is silent on low-S enforcement. The Appendix E reference vectors include high-S cases that the standalone strict-S `EcdsaP256.verify` would reject. The composite verify path normalises high-S signatures to their equivalent low-S form via `s ← (n - s)` before calling `EcdsaP256.verify` (FIPS 186-5 §6.5 accepts both s and n - s under the same pk; the math is symmetric in s ↔ n - s). This preserves interop with the spec's reference vectors without weakening the standalone `EcdsaP256Suite`'s strict-S posture for callers not on the composite path.

The asymmetric posture is emit-strict, verify-lenient: leviathan-produced composite signatures are always low-S (the WASM-side `ecdsaSign` runs FIPS 186-5 §6.5 / RFC 6979 §3.5 normalisation before DER encoding), but the verify side accepts both. Considered in isolation the ECDSA half on the composite-verify path is EUF-CMA, not sEUF-CMA, because the s ↔ n - s symmetry lets an attacker holding a valid composite signature produce a second composite (re-encoded with the high-S equivalent of the ECDSA half) that also verifies. This is a real consequence at the composite level: 0x22 / 0x23 are sEUF-CMA only if the ECDSA half is sEUF-CMA, which it is not under the lenient verify policy. Applications that require sEUF-CMA — Bitcoin-style transaction IDs, Signal-style "this signature uniquely identifies the message", anything that uses a signature as a non-malleable commitment — should use `MlDsa44Ed25519Suite` / `MlDsa65Ed25519Suite` (0x20 / 0x21, sEUF-CMA via RFC 8032 §5.1.7 strict verify on the Ed25519 half) or the standalone `EcdsaP256Suite` (0x02, sEUF-CMA via strict low-S). EUF-CMA — the standard "can't forge a signature on a message the signer never signed" guarantee — holds across all four composite suites and is what most signing use cases actually need.

**Concurrency model.** Single-threaded. A live `SignStream` over a classical+PQ hybrid suite holds the underlying WASM modules exclusively from construction until `finalize()` or `dispose()`. Concurrent `Sign.sign` calls on the same hybrid suite throw the same `_acquireModule` exclusivity error that protects every other stateful WASM consumer.
