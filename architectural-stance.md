# leviathan-crypto: Architectural Stance

> [!NOTE]
> The architectural posture of leviathan-crypto: what the library defends, how each layer composes, and the threats it does not address. Canonical source for v3 onward.

---

> ### Table of Contents
>
> - [Architectural overview](#architectural-overview)
> - [Constant-time at the algorithm level](#constant-time-at-the-algorithm-level)
> - [Cryptanalytic margin](#cryptanalytic-margin)
> - [Implementation discipline](#implementation-discipline)
>     - [Agentic development contracts](#agentic-development-contracts)
>     - [Defended attacks (runtime)](#defended-attacks-runtime)
>     - [Defended attacks (distribution)](#defended-attacks-distribution)
> - [Threat model](#threat-model)
> - [WebAssembly is the deployment vehicle](#webassembly-is-the-deployment-vehicle)
> - [Where defense ends](#where-defense-ends)
> - [The honest comparison](#the-honest-comparison)

---

## Architectural overview

**Zero runtime dependencies.** No npm graph to audit. No supply chain attack surface. Argon2id is the one optional integration, documented separately and consumer-installed. **Tree-shakeable.** Import only what you use. Subpath exports let bundlers exclude everything else. **Side-effect free.** Nothing runs on import. [`init()`](https://github.com/xero/leviathan-crypto/wiki/init) is explicit and asynchronous.

**Cipher Triptych.** Leviathan provides three ciphers. The implementations all use a round structure that runs as a bitsliced Boolean circuit implemented as register-only logic with no S-box lookup tables. Each compiles to an independent v128 SIMD optimized WebAssembly module, with isolated linear memory, preventing cross-module memory access by design. Every operation zeroes key material on exit, including on failure.

**[Serpent-256](https://github.com/xero/leviathan-crypto/wiki/serpent_reference): maximum paranoia.** 32 rounds of eight different 4-bit S-boxes, each bitsliced as a Boolean circuit with no table lookups. An ouroboros devouring every bit, in every block, through every round.

**[XChaCha20-Poly1305](https://github.com/xero/leviathan-crypto/wiki/chacha_reference): precise elegance.** 20 rounds of add-rotate-XOR alternating column and diagonal quarter-rounds, choreography without S-boxes or cache-timing leakage. A dance closing with Poly1305's unconditional forgery bound.

**[AES-256-GCM-SIV](https://github.com/xero/leviathan-crypto/wiki/aes): industry standard, sharpened.** 14 rounds bitsliced into Boolean gates with tower-field S-box with no table lookups. A fresh POLYVAL key per nonce leaves GHASH-key recovery with no target.

**Below the cipher suites sit two hash primitive families:** SHA-2 (SHA-256/384/512 with HMAC and HKDF variants) and SHA-3 (SHA3-256/512 and SHAKE128/256). The round permutations are constant-time by algorithm design: pure bit operations with no S-box lookups and no data-dependent branches. SHA-2 powers the seal layer's HKDF key derivation and Serpent's HMAC authentication. SHA-3 is the Keccak sponge ML-KEM relies on internally.

**Above the cipher suites sits a cipher-agnostic AEAD layer:** `Seal`, `SealStream`, `OpenStream`, and `SealStreamPool`. Each takes a `CipherSuite` at construction, and the seal layer handles key derivation, nonce management, and authentication. `Seal` covers one-shot encryption for data that fits in memory. `SealStream` and `OpenStream` handle chunked data too large to buffer. WASM instances are single-threaded by design, so `SealStreamPool` distributes chunks across Web Workers to reach multi-core throughput. Any authentication failure kills the pool. Pending operations reject, workers zero their keys and terminate, and the master copies zero synchronously. No retry, no partial results. All four share one wire format. A `Seal` blob is structurally a single-chunk `SealStream` output, and `OpenStream` decrypts it interchangeably.

**ML-KEM is the post-quantum key encapsulation mechanism.** `KyberSuite` is a fourth `CipherSuite` factory that wraps an ML-KEM parameter set around any of the three ciphers above. The result satisfies the same `CipherSuite` interface and slots into `Seal`, `SealStream`, `OpenStream`, and `SealStreamPool` unchanged. ML-KEM is a lattice-based key encapsulation mechanism with three security levels: ML-KEM-512, ML-KEM-768, and ML-KEM-1024. Constant-time comparisons for the Fujisaki-Okamoto transform run within the Kyber WASM module, so secret-derived comparisons never cross to JavaScript. The 32-byte shared secret never crosses the wire. It also derives directly from a SHA-3 output rather than a big-integer encoding, so the leading-zero-trim timing leak that hit TLS-DH(E) (the Raccoon attack) has no structural analog here.

**ML-DSA is the post-quantum signature peer.** `MlDsa44`, `MlDsa65`, and `MlDsa87` are FIPS 204 lattice-based signatures at NIST security categories 2, 3, and 5. The ring arithmetic, NTT, and rejection-sampling kernels are constant-time at the algorithm level, and the c̃ comparison in verify routes through the same SIMD `ct.equal` primitive used elsewhere in the library. Signing is hedged by default. HashML-DSA wraps the same Sign and Verify primitives with a per-function OID DER prefix and a 0x01 domain-separator byte for cross-protocol separation. All FIPS 204 hard checks land at runtime, including the three HintBitUnpack malformed-input checks added in §D.3.

**Fortuna is the library's CSPRNG.** It collects entropy from platform-specific sources (browser input events, timing jitter, Node.js process stats, plus `crypto.getRandomValues()` as a baseline), distributes it across 32 independent pools, and reseeds an internal generator built on a cipher-as-PRF construction. The generator key is replaced after every `get()` call, so state compromise at time T cannot reveal any output produced before T. The primitive pair is pluggable, mirroring `CipherSuite`'s extension-point pattern: any of the three ciphers above plugs into the generator, paired with either SHA-256 or SHA3-256 for hashing.

**Above the seal layer sits the ratchet module:** KDF primitives from Signal's Sparse Post-Quantum Ratchet (SPQR), the post-quantum extension of the Double Ratchet protocol. `ratchetInit` bootstraps the root and chain keys from an out-of-band shared secret. `KDFChain` advances a symmetric chain key and derives per-message keys with forward secrecy. `kemRatchetEncap` and `kemRatchetDecap` perform the ML-KEM ratchet step for post-compromise security. `SkippedKeyStore` caches message keys for out-of-order delivery; cached keys return through a transactional handle that commits on auth success and rolls back on failure, so a garbage ciphertext at a valid counter cannot consume the legitimate message's slot. The store also bounds memory and per-message HKDF work, so a malicious header with a high counter cannot force unbounded derivations. These are primitives, not a full session: state machines, message counters, header format, and epoch orchestration are application concerns. Consumers compose them with their own transport for forward-secret protocols whose needs outgrow one-shot AEAD.

**Alongside the WASM-backed primitives ships a utility tier.** No `init()` call required, every utility function works immediately on import. Pure-TypeScript encoding converters handle hex, base64, and the common byte-format round-trips. `wipe` and `xor` modules cover byte-buffer zeroing and exclusive OR logical operations. The `ct` module is the constant-time path. It carries its own dedicated WebAssembly binary that compiles synchronously, with a zero-copy v128 SIMD XOR-accumulate kernel. `ct.equal()` is the library's recommended path for any equality check on secret material.

**Implementation discipline is its own pillar.** Every cipher, hash, and KEM derives independently from its authoritative spec, never ported from another implementation. Known-answer test vectors come from spec authors, and cross-checks run against multiple independent reference implementations. The test suite covers unit tests at the primitive level plus end-to-end tests across three browser engines (Chromium, Firefox, WebKit) and Node.js. Detailed reference documentation ships at the [project wiki](https://github.com/xero/leviathan-crypto/wiki).

---

## Constant-time at the algorithm level

**Each of these implementations is constant-time at the algorithm level.** The same code in C, Rust, or hand-typed assembly would have the same property. WebAssembly does not buy that; the implementation does. ML-KEM extends the same principle to post-quantum: the Fujisaki-Okamoto re-encryption uses dedicated `ct_verify` and `ct_cmov` primitives implemented in WASM that never pass through JavaScript.

**The exception is the GHASH multiplier inside AES-GCM and AES-GCM-SIV's POLYVAL backend.** Both use a 256-byte 4-bit-windowed multiplication table indexed by secret-derived state. This is the same posture as BoringSSL, OpenSSL, and RustCrypto on hardware without PCLMULQDQ. WebAssembly does not currently expose carry-less multiply, so a fully table-free GHASH or POLYVAL is not implementable in this environment without unacceptable throughput cost. The library documents the leak surface, mitigates it with per-message authentication keys (the POLYVAL key in AES-GCM-SIV derives per nonce from the master, not fixed across the session), and recommends the AEAD `seal` family over the lower-level `AESGCM` primitive.

---

## Cryptanalytic margin

**Serpent-256 is verified at 32 rounds with a wide margin.** The cipher placed second to Rijndael in the AES competition, rated higher on security margin and timing side-channel resistance but lower on 2001-era performance; that gap no longer matters on modern hardware. The best mathematical attack on the full cipher is biclique cryptanalysis at 2²⁵⁵·²¹ time with 2⁸⁸ chosen ciphertexts, less than one bit faster than exhaustive key search. Independent research against this implementation improved the published result by −0.20 bits, confirming no structural weakness beyond what the literature describes ([BicliqueFinder](https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md)). Reduced-round attacks reach 12 rounds (multidimensional linear), leaving a 20-round security margin, wider than AES-256's. No practical attack on full Serpent-256 is known.

**ChaCha20-Poly1305 has a 13-round margin.** The AEAD is IETF-standardized (RFC 8439) and descends from Salsa20 in the eSTREAM portfolio; it outperforms AES in software on platforms without hardware acceleration. The best published distinguisher reaches 7 of 20 rounds (Shi et al. 2012, differential-linear) and requires infeasible data; nothing further is published. Poly1305 forgery is bounded at ⌈l/16⌉/2¹⁰⁶ per message. XChaCha20's 192-bit nonce shifts the 50% collision boundary to 2⁹⁶ messages, beyond any realistic deployment. ChaCha20 is deployed at scale across TLS 1.3, WireGuard, Signal, and Android full-disk encryption with no known practical weaknesses in the full-round construction.

**AES-256-GCM-SIV has the narrowest published margin of the three** *but remains intact in practice.* The best mathematical attack on the full cipher is biclique cryptanalysis (Bogdanov, Khovratovich, & Rechberger 2011) at 2²⁵⁴·⁴ time with 2⁴⁰ chosen plaintexts, roughly 0.6 bits below exhaustive key search; differential and linear distinguishers bounded by the AES wide-trail strategy do not approach the full 14 rounds. The 2009 Biryukov-Khovratovich related-key boomerang reaches full AES-256 in 2⁹⁹·⁵ time but assumes attacker-chosen key relationships that AEAD use under independent KDF outputs does not provide. GCM-SIV adds nonce-misuse resistance over AES-GCM (RFC 8452, Gueron & Lindell 2015), so under nonce reuse an attacker learns only whether two encryptions shared identical inputs, with no key recovery and no universal forgery. AES is deployed at scale across TLS, IPsec, SSH, and FIPS-validated systems with no known practical weaknesses.

---

## Implementation discipline

**Every primitive derives independently from its authoritative specification.** FIPS 180-4, FIPS 197, FIPS 202, FIPS 203, RFC 8439, RFC 8452, RFC 2104, RFC 5869, and the original Serpent paper. None is ported from an existing implementation. Published known-answer-test vectors (NIST CAVP, NESSIE, RFC appendices, and ACVP) are immutable. When an implementation produces wrong output, the implementation gets fixed and the vectors stay. New tests do not extend the surface until the existing surface gates green.

**Every primitive family has a gate test.** The gate is the simplest authoritative vector for that primitive, annotated `// GATE` and required to pass before any other test in the family runs. KAT files in `test/vectors/` come from spec authors directly (FIPS, RFC, ACVP, NIST CAVP, NESSIE), or `scripts/gen-*-vectors.ts` generates them as regression vectors. CI validates corpus integrity against SHA256SUMS on every run. Cross-implementation verification works in layers: the `verify-vectors` Rust crate ([vector_audit.md](./vector_audit.md)) re-runs every KAT against a parallel Rust implementation, leviathan's TypeScript reference provides a second independent codebase, and external tools (OpenSSL, Python hashlib, Node.js crypto) cross-check primitives where parallel implementations exist.

**Memory hygiene.** Every public cryptographic operation wipes its secret-derived scratch on the way out, including failure paths. AEAD authentication failures wipe before the exception propagates. Stateless AEADs are strict single-use; any throw from `encrypt()` terminates the instance. Stateful classes hold an exclusivity token on their backing WASM module. Cross-module operations assert non-ownership of the modules they touch. The high-level API surfaces (`Seal`, `SealStream`, `OpenStream`, `SealStreamPool`, and `KyberSuite`) are authenticated by default with internally-managed nonces. The unauthenticated raw modes ship for power users and are not the recommended entry point.

**All streaming constructions satisfy the _Cryptographic Doom Principle_.** The MAC compare is the unconditional gate into the decrypt path. Serpent and XChaCha20 use verify-then-decrypt. The implementation checks the tag before materializing any plaintext. AES-GCM-SIV uses verify-then-release. The tag is a function of the plaintext, so the SIV construction reconstructs the plaintext in WASM linear memory, then recomputes and compares the tag in constant time. On mismatch, the implementation wipes the WASM-side plaintext before the throw, and only slices the plaintext across the WASM-to-JavaScript boundary after the auth check. In either path, forged ciphertext never reaches the caller as plaintext.

**The seal layer is key-committing across all three suites.** Serpent gets it natively from HMAC-SHA-256. XChaCha20 and AES-GCM-SIV add an explicit 32-byte commitment derived from the master key via HKDF-SHA-256 alongside the encryption key. The library verifies the commitment in constant time before processing any chunk. A wrong key fails fast, ahead of any call to Poly1305 or POLYVAL. The HKDF info string incorporates the full 20-byte header, so tampering with the format enum, framing flag, nonce, or chunk size produces different keys and fails on the first chunk. This closes the Invisible Salamanders attack surface for any higher-level construction built on the seal primitive.

### Agentic development contracts

**All AI-assisted development on this repository operates under a strict agentic contract** defined in [AGENTS.md](https://github.com/xero/leviathan-crypto/blob/main/AGENTS.md). Configs for Claude, GitHub Copilot, OpenHands, Kilo Code, Cursor, Windsurf, and Aider all route to that file as the single source of authority. The contract enforces spec authority over planning documents, immutable test vectors, gate discipline before any test-suite extension, independent algorithm derivation from published standards, and constant-time and wipe requirements for all security-sensitive code paths. The contract explicitly prohibits agents from guessing cryptographic values or resolving spec ambiguities silently.

**Consumer agent guidance.** A `CLAUDE_consumer.md` file ships alongside the library, compressing the API surface, design restrictions, and recommended workflows into a map an AI assistant can use when a consumer asks for help writing or reviewing code that uses leviathan-crypto. It does for consumer-side AI work what `AGENTS.md` does for contributor-side AI work.

### Defended attacks (runtime)

The architectural defenses above compose into protection against specific named attacks and DoS classes. The inventory below pairs each threat with its mechanism.

**Invisible Salamanders.** AEADs without key commitment allow ciphertexts to authenticate under multiple keys, enabling multi-recipient envelope forgery and similar attacks. The seal layer commits to the key across all three suites, via HMAC-SHA-256 for Serpent and a 32-byte HKDF commitment for XChaCha20 and AES-GCM-SIV.

**Raccoon.** TLS-DH(E)'s leading-zero-trim timing leak exploited a big-integer shared secret encoding. ML-KEM derives its 32-byte shared secret directly from a SHA-3 output, eliminating the structural analog.

**HintBitUnpack malformed-input forgery.** The FIPS 204 IPD draft was vulnerable to a SUF-CMA forgery via crafted hint encodings: an attacker could produce two distinct signature byte strings that both verified under the same `(vk, M, ctx)`. FIPS 204 §D.3 added three malformed-input checks to Algorithm 21 (lines 4, 9, 17). HintBitUnpack returns -1 from WASM on any failure, and `verify` short-circuits to false before any further decoding.

**Cross-protocol signature confusion.** A signature produced under pure ML-DSA could otherwise be replayed against a HashML-DSA verifier on the same key, or vice versa, enabling cross-protocol forgery. FIPS 204 §3.6.4 prefixes M' with 0x00 for pure mode and 0x01 plus the per-function OID DER bytes for HashML-DSA. A `signHash` signature will not verify under `verify` on the same key, regardless of message or context.

**Fault attacks on deterministic signing.** A computational fault during deterministic signature generation can leak partial signing-key state to an attacker who can repeatedly trigger the fault and observe outputs. Hedged signing per FIPS 204 §3.4 mixes 32 fresh RBG bytes into ρ'' on every call, so two signatures over identical inputs differ. The hedged path is the recommended default; `signDeterministic` and `signDerand` ship with the §3.4 caveat documented at the call site.

**Sign-loop denial of service.** Without a bound, ML-DSA's rejection-sampling loop could hang the signing thread on inputs that fail every iteration. The implementation bounds the loop at 1000 iterations (FIPS 204 Appendix C minimum: 814) and throws a deterministic error on exceedance after wiping all scratch via `try/finally`. ρ'' = H(K ‖ rnd ‖ μ) requires K, so an attacker without the signing key cannot bias the iteration count.

**AES-GCM nonce-reuse universal forgery.** Reusing a nonce under AES-GCM exposes the GHASH authentication subkey, enabling tag forgery for every past and future message under the affected key. AES-GCM-SIV derives the POLYVAL authentication key per nonce from the master (RFC 8452 §4), so even a recovered per-message key reveals nothing about other messages.

**T-table cache-timing key recovery.** Software AES with T-table or S-box lookups indexes memory at every round on plaintext XOR key, letting an attacker who shares cache with the encrypt operation recover the key. The bitsliced kernel has no AES tables in linear memory and no key-dependent memory accesses inside SubBytes, ShiftRows, MixColumns, or AddRoundKey.

**Delete-on-retrieval DoS.** Garbage ciphertext at a valid skipped-key counter can consume the legitimate message's cached key. `SkippedKeyStore` returns cached keys through a transactional handle that commits on auth success and rolls back on failure.

**Counter-flood DoS.** A malicious header with a very high counter can force unbounded HKDF derivations on the receiver. `SkippedKeyStore` bounds both memory and per-message HKDF work.

**Backward-seek nonce reuse.** Reusing a consumed counter nonce against new ciphertext exposes plaintext to XOR cancellation. `OpenStream.seek` only moves forward; backward seeks throw rather than reuse the nonce.

**Header tampering.** Tampering with format enum, framing flag, nonce, or chunk size could pass undetected at the format layer. The HKDF info string incorporates the full 20-byte header, so any tampered byte produces different keys and fails the AEAD on the first chunk.

**Cross-stream substitution, reorder, splice, truncation.** These stream-level attacks mix ciphertext between streams or rearrange chunks within a stream. Counter nonces with TAG_DATA/TAG_FINAL final-flag domain separation make all four fail AEAD verification before decryption.

**Pool failure isolation.** A worker-level auth failure could leak partial results back to the caller. `SealStreamPool` kills the pool on the first failure: pending operations reject, workers zero their keys and terminate, and master copies zero synchronously.

**Verify-then-release plaintext leak.** AES-GCM-SIV's tag depends on the plaintext, so the construction must reconstruct plaintext before MAC verification. The implementation reconstructs in WASM linear memory, constant-time compares the tag, and wipes the WASM-side plaintext before any throw, so bytes never cross to JavaScript on auth failure.

### Defended attacks (distribution)

**Typosquatting.** Misspellings or punctuation variants of `leviathan-crypto` on npm could otherwise install attacker-controlled code under a believable name. Decoy packages cover common typosquat variants (missing hyphens, character transpositions, and common misspellings); each declares the real `leviathan-crypto` as an optional peer dependency and runs a post-install script that loudly warns the user with the correct package name and install command.

---

## Threat model

The architecture above commits to a specific threat model. Three adversary classes act at different layers, a shared set of trust assumptions underlies all three, and a framing constraint bounds the whole.

**Runtime adversary.** This adversary has full chosen-ciphertext capability at the API surface, runs concurrent JavaScript in the same browser context, and reads WASM linear memory at any operation boundary. The library commits to AEAD confidentiality and integrity under correctly-generated keys, key commitment across all three suites, nonce-misuse resistance for AES-GCM-SIV, per-operation key wipes on success and failure paths, module-isolated linear memory, and forward-secret plus post-compromise primitives for session protocols built on the ratchet. The [defended attacks (runtime)](#defended-attacks-runtime) inventory enumerates the specific threats. CPU-level side channels (Spectre-class, cache-timing on secret-dependent loads, branch prediction, speculative execution), JavaScript heap inspectors (intern pools, eval injection, prototype pollution), and physical access (DPA, EM analysis, fault injection) stay out of scope; [where defense ends](#where-defense-ends) covers the disclaim in detail.

**Construction adversary.** Spec drift enters through contributor mistakes, ported-from-another-implementation errors, or AI-assisted guesses and unstated assumptions. Defenses include independent derivation from authoritative spec, immutable KAT vectors with SHA256SUMS integrity validated in CI, gate discipline before any test-suite extension, cross-implementation verification across the `verify-vectors` Rust crate plus the TypeScript reference plus external tools, and the [agentic development contracts](#agentic-development-contracts) for AI-assisted work.

**Distribution adversary.** Typosquat variants of `leviathan-crypto` on npm could otherwise install attacker-controlled code under a believable name. Decoy packages claim common variants preemptively, ahead of any observed attack; the [defended attacks (distribution)](#defended-attacks-distribution) section describes the mechanism. Compromise of the npm registry itself, and any supply-chain compromise downstream of the registry, stay out of scope.

**Trust assumptions.** Across all three axes the model assumes a faithful WebAssembly runtime, a working CSPRNG, the browser's same-origin and sandbox boundaries, and npm publishing pipeline integrity. Keys must be properly generated; Argon2id, if used, must be consumer-installed. Consumer code must use the API as documented, with the published [wiki](https://github.com/xero/leviathan-crypto/wiki) and supporting documentation.

**Framing constraint.** The whole model lives inside a JavaScript runtime. Side-channel resistance comparable to a native binary with hand-tuned instruction scheduling is not promised; the [honest comparison](#the-honest-comparison) section is explicit about this trade-off.

---

## WebAssembly is the deployment vehicle

The runtime compiles WASM bytecode to native machine code through its WASM JIT. V8 uses Liftoff and TurboFan; SpiderMonkey uses Baseline and Cranelift; JavaScriptCore uses BBQ and OMG. *There is no ahead-of-time path in mainstream engines today.*

**What makes the compiled output more predictable than equivalent JavaScript is not the absence of a JIT but the structure of the input.** Typed bytecode has no hidden-class transitions and no SMI/HeapNumber switching. Structured control flow has no computed gotos and no `eval`. There is no polymorphism-driven specialization, no deoptimization, no GC pauses, no string interning, and no shape changes mid-execution. The JS-level timing oracles that motivate constant-time-coding discipline (type guards, deopts, hidden classes, and intern pools) do not exist for WASM. WASM exposes the cipher to the same constant-time-coding discipline that native crypto follows.

**WASM linear memory is a buffer the library owns and wipes at operation boundaries.** JavaScript heap allocations leak copies into intern pools, nursery fragments, and old-space; WASM does not. Each cryptographic module compiles to its own isolated binary with its own linear memory. Code in the SHA-3 module cannot address key material in the Serpent module, even in principle. The only host-side bridge is the TypeScript orchestration layer, which sees inputs and outputs but never raw secret state.

---

## Where defense ends

**WebAssembly is not constant time at the CPU level.** The native code the WASM JIT emits runs on a real CPU with a real branch predictor, real cache hierarchy, and real speculative execution. WebAssembly itself has no language-level constant-time guarantee in its specification; the spec defines semantics, not timing. *WASM does not protect against Spectre-class side channels.*

**The browser sandbox restricts JavaScript-side measurement primitives that an in-page attacker would otherwise use to instrument these channels.** SharedArrayBuffer requires COOP/COEP headers; `performance.now()` is throttled; the cross-origin attacker has limited reach. The channels themselves remain. They are the runtime's and the hardware's responsibility.

**Cycle-equivalent timing across hardware is out of scope.** Different CPUs have different multiply latencies, cache geometries, and speculation behaviors. WASM does not equalize them. Defense against power analysis, electromagnetic emissions, fault injection, or physical device access is not in this library's threat model.

**The defended threat is concrete.** An adversary with read access to WASM linear memory between operations cannot recover key material from previously-completed operations. Authentication failures cannot disclose plaintext to JavaScript callers. Tampered headers, reordered chunks, spliced streams, and cross-stream substitutions fail authentication before decryption. Backward seeks on a decrypting stream throw rather than reuse a consumed counter nonce against new ciphertext. A wrong key under the seal API fails before the AEAD ever runs. Forged ciphertext never returns plaintext bytes to the caller.

**The undefended threats are equally concrete.** JavaScript-side memory disclosure from heap-snapshot exfiltration, eval injection, or prototype pollution is the runtime's responsibility. Host CPU side channels (cache timing on secret-dependent loads, branch prediction, and speculative execution) are the hardware's. Physical device access is the deployment's. Supply chain compromise downstream of the npm registry is the consumer's. None of these is what the library claims to address.

---

## The honest comparison

**leviathan-crypto is for cryptography that runs inside a JavaScript runtime.** Within that constraint, this library offers the strongest posture available: algorithm-level constant-time ciphers, per-operation wipe hygiene, module-isolated linear memory, and predictable JIT-lowered native code.

**But the constraints matter.** The JavaScript runtime is a weaker side-channel environment than a native binary with hand-tuned instruction scheduling, no matter the strength of the cryptographic algorithms used. Leviathan is for pure web deployments. If side-channel resistance is critical to your threat model and you're already shipping native code, a native crypto implementation is a better choice.

*Our cipher choices, implementation discipline, and deployment vehicle compose into leviathan-crypto, a library that ships disciplined cryptography to the browser. Each one alone is not the security claim. Together, they are.*
