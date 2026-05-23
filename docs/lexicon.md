<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### Cryptography Lexicon

A reference glossary for readers new to cryptography. Covers foundational terms, context-specific meanings, the leviathan-crypto sealing layer, and post-quantum concepts.

> ### Table of Contents
> - [Core Terminology](#core-terminology)
> - [Context-Specific Terms](#context-specific-terms)
> - [Sealing Layer](#sealing-layer)
> - [Post-Quantum](#post-quantum)
> - [Signature Layer](#signature-layer)
> - [Session Layer](#session-layer)
> - [BLAKE3](#blake3)

---

## Core Terminology

**Plaintext.** The original, readable data before encryption.

**Key.** A secret value that controls a cryptographic operation. Without it, the operation cannot be reversed. leviathan-crypto uses 256-bit (32-byte) symmetric keys.

**Entropy.** A measure of unpredictability. A 256-bit random key has 256 bits of entropy; there is no pattern an attacker can exploit. Keys derived from weak passwords without a KDF have low entropy and are vulnerable to brute force.

**Cipher.** An algorithm that transforms data using a key. Without the key, the transformation cannot be reversed.

**Block cipher.** An algorithm that encrypts data in fixed-size chunks. Serpent operates on 128-bit blocks. Block ciphers require a mode of operation to handle messages longer than one block.

**Stream cipher.** A cipher that operates on a continuous sequence of bytes rather than fixed-size blocks. ChaCha20 is a stream cipher.

**Ciphertext.** The encrypted output of a cipher, which is unreadable without the correct key.

**Nonce.** A value that must never repeat for a given key. Reusing a nonce with the same key can expose plaintext or enable forgery. Nonces are typically generated randomly.

**IV (Initialization Vector).** A nonce used to randomize the first block of a block cipher mode such as CBC. It prevents identical plaintexts from producing identical ciphertexts.

**Padding.** Extra bytes added to a message to reach a block boundary. CBC mode applies a standard padding scheme (PKCS#7) before encryption and strips it after decryption.

**Hash function.** A one-way function that maps arbitrary input to a fixed-size digest. Hash functions serve as building blocks for MACs, KDFs, and CSPRNGs.

**Digest.** The fixed-size output of a hash function, also called a hash. Any change to the input, however small, produces a completely different digest.

**Salt.** Random data mixed into a key derivation function. It ensures two derivations from the same password produce different keys. A salt is not secret and can be stored alongside the derived output.

**HMAC (Hash-based Message Authentication Code).** A MAC built from a hash function and a secret key. It proves both integrity and authenticity. Only a party holding the key could have produced it.

**Tag (authentication tag).** A short value appended to ciphertext that proves the data has not been tampered with. The tag is computed from the key, ciphertext, and any additional data. Tag verification must run in constant time.

**KDF (Key Derivation Function).** A function that produces keys from a secret input. HKDF expands existing key material. Argon2 and scrypt are KDFs designed to slow brute-force attacks on passwords.

**HKDF (HMAC-based Key Derivation Function).** A KDF that derives one or more strong keys from a single secret. leviathan-crypto uses HKDF to derive per-stream encryption and MAC keys from a master key and a random nonce.

**Subkey derivation.** Generating a new key from an existing one for a specific purpose. It limits the impact of a compromise. Knowing one subkey gives an attacker nothing about the others. leviathan-crypto derives fresh encryption and MAC subkeys per stream via HKDF.

**AEAD (Authenticated Encryption with Associated Data).** An encryption mode that provides both confidentiality and integrity. Ciphertext reveals nothing about the plaintext, and any tampering is detected. AEAD is the standard approach for symmetric encryption. XChaCha20-Poly1305 and Serpent-256-CBC+HMAC are both AEAD schemes.

**Primitive.** A low-level cryptographic building block: a cipher, hash function, or MAC. Applications rarely use primitives directly; they compose them into higher-level constructions like AEAD schemes.

**XOF (Extendable Output Function).** A hash-like function that produces an arbitrarily long output stream rather than a fixed-size digest. SHAKE128 and SHAKE256 are XOFs built on SHA-3. They are useful for key derivation and stream generation.

**CSPRNG (Cryptographically Secure Pseudo-Random Number Generator).** A random number generator whose output is indistinguishable from true randomness and cannot be predicted from past output. leviathan-crypto ships Fortuna, a well-studied CSPRNG construction.

**Test vector.** A known-good set of inputs and their expected output, used to verify a cryptographic implementation is correct. The term comes from test engineering, not mathematics. leviathan-crypto ships 415 unit tests built on published and independently derived test vectors.

---

## Context-Specific Terms

**Mode.** A cipher mode of operation specifies how a block cipher handles messages longer than one block. ECB is the simplest mode but is insecure for most data. CTR turns a block cipher into a stream cipher. CBC chains blocks together. Each mode has different security properties and appropriate use cases.

**Authenticated.** In cryptography, "authenticated" does not mean "logged in." It means the data has been verified as untampered. An authentication tag proves no bytes were modified in transit. An unauthenticated cipher like raw CBC encrypts data but does not detect tampering.

**Wire format.** The exact byte layout of data as it travels between systems. leviathan-crypto defines a precise wire format for sealed streams: a 20-byte header followed by authenticated chunks. Both sides must agree on this layout to communicate.

**Sealing and opening.** Sealing is authenticated encryption. It encrypts and authenticates in one step, producing a self-contained blob that reveals tampering on decryption. Opening is the reverse. leviathan-crypto provides `Seal.encrypt` and `Seal.decrypt` for one-shot use, and `SealStream` with `OpenStream` for chunked data.

**Overhead.** The bytes an encryption scheme adds beyond the plaintext. This includes the nonce, authentication tag, header, and any padding. XChaCha20-Poly1305 adds 40 bytes per message (24-byte nonce, 16-byte tag). Streaming adds a 20-byte preamble plus per-chunk tags.

**Preamble.** The bytes at the start of a sealed stream, sent before any ciphertext. The preamble contains the format identifier, a random 16-byte HKDF salt, and the chunk size. The recipient reads it first to initialize the opener. For KEM suites, the preamble also carries the encapsulated shared secret.

**Chunk.** A fixed-size segment of a stream, encrypted and authenticated independently. A tampered chunk is rejected immediately without decrypting any following chunks. The default chunk size in leviathan-crypto is 65,536 bytes.

**Session.** A cryptographic context shared between two parties over time. In the sealing layer, a session is single-use: a `SealStream` encrypts exactly one message, and calling `finalize()` zeroes its keys. In a ratchet-based messenger, a session is long-lived and spans many messages, with keys advancing after each one. Both usages mean "a bounded context with its own key material," but their lifetimes differ.

**Derive.** In cryptography, to derive a key means to produce it from another secret via a KDF. It does not mean class inheritance. Derived keys are cryptographically independent: knowing one does not help an attacker find others.

**Wipe / zeroize.** To overwrite a buffer containing secret data with zeros before releasing it. The garbage collector does not guarantee zeroing, and memory may be readable after deallocation in some environments. `wipe(key)` zeroes a `Uint8Array` in place.

**Dispose.** The act of zeroing and releasing key material held in WASM memory. Calling `.dispose()` writes zeros over the key buffer before freeing it. Without this step, key bytes may persist in memory. Garbage collection does not zero memory.

**Constant-time equality.** Comparing two values in a fixed amount of time, regardless of their contents. JavaScript's `===` short-circuits on the first differing byte, leaking information about where values diverge. Use `constantTimeEqual(a, b)` when comparing secrets, MACs, or keys.

---

## Sealing Layer

**Cipher suite.** A named bundle pairing a cipher with its authentication scheme, key sizes, and wire format identifier. leviathan-crypto provides `SerpentCipher` (Serpent-256-CBC + HMAC-SHA-256) and `XChaCha20Cipher` (XChaCha20-Poly1305). Both plug into `Seal`, `SealStream`, and `SealStreamPool`.

**One-shot vs. streaming.** One-shot (`Seal`) loads the entire message into memory, encrypts it as a single chunk, and returns the result. Streaming (`SealStream` / `OpenStream`) processes data in fixed-size chunks and authenticates each independently. Use streaming when the message is too large to buffer or arrives incrementally.

**Stream isolation.** Each `SealStream` generates a fresh random 16-byte nonce on construction. Two streams sharing the same master key derive independent subkeys via HKDF with different salts and cannot interfere with each other.

**Counter binding.** Each chunk's nonce encodes a monotonically increasing counter. An attacker cannot reorder, duplicate, or replay chunks without triggering a counter mismatch, which fails authentication. Counter binding is a core property of the STREAM construction used by leviathan-crypto.

**Final-chunk detection.** The last chunk in a stream uses a distinct nonce flag (`TAG_FINAL`) rather than `TAG_DATA`. If an attacker truncates the stream by dropping the final chunk, the opener detects that it never received a chunk marked final and rejects the message.

**Framing / framed mode.** In framed mode (`{ framed: true }`), each encrypted chunk gets a 4-byte big-endian length prefix. This makes a stream of concatenated chunks self-delimiting. A reader can extract chunk boundaries from the data itself. Omit framing when the transport already provides message boundaries, such as WebSocket frames or IPC messages.

**AAD (Additional Authenticated Data).** Data that is authenticated alongside ciphertext but not encrypted. It binds a chunk to external context such as sequence numbers or routing metadata, without including that data in the encrypted payload. Both sides must supply identical AAD or decryption fails.

**Single-use stream.** A `SealStream` encrypts exactly one message. After `finalize()`, the derived keys are immediately zeroed and the stream cannot seal any further data. Create a new instance for each message.

**Pool.** `SealStreamPool` distributes chunk encryption across multiple Web Workers, each with its own WASM instance and a copy of the derived keys. It is useful for large files where single-threaded throughput is a bottleneck. Any failure is fatal. The pool is destroyed on error and must be recreated for the next operation.

**AuthenticationError.** The exception thrown when an authentication tag does not match, meaning the ciphertext was modified, the key is wrong, or the AAD differs. Never use output from a decryption that throws this error. The stream layer zeroes output buffers before throwing.

---

## Post-Quantum

**Post-quantum cryptography.** Cryptographic algorithms designed to resist attacks from quantum computers. Quantum computers running Shor's algorithm can break RSA, ECDH, and other schemes based on integer factorization or discrete logarithms. Symmetric ciphers and hash functions remain secure with larger key sizes.

**Lattice-based cryptography.** A family of post-quantum algorithms whose security rests on the hardness of problems involving high-dimensional geometric lattices, such as Learning With Errors. ML-KEM is a lattice-based scheme. No known quantum algorithm solves these problems efficiently.

**KEM (Key Encapsulation Mechanism).** A public-key scheme for establishing a shared secret. The sender uses the recipient's public key to encapsulate a randomly chosen secret into a ciphertext. The recipient uses their private key to decapsulate and recover the same secret. Both parties then use this secret as a symmetric key.

**Encapsulation key.** The public key in a KEM scheme. It is shared openly. Senders use it to encapsulate a shared secret. In leviathan-crypto, `kem.keygen()` returns `{ encapsulationKey, decapsulationKey }`.

**Decapsulation key.** The private key in a KEM scheme. The recipient keeps it secret and uses it to recover the shared secret from the ciphertext produced by encapsulation. It is never transmitted.

**ML-KEM / Kyber.** The NIST post-quantum KEM standard (FIPS 203, formerly known as Kyber). It produces a 32-byte shared secret suitable for use as a symmetric key. leviathan-crypto provides `MlKem512`, `MlKem768`, and `MlKem1024`, corresponding to NIST security levels 1, 3, and 5.

**Parameter set.** ML-KEM comes in three variants that trade key and ciphertext size for security margin. ML-KEM-512 has the smallest keys; ML-KEM-1024 has the largest and the highest security level. ML-KEM-768 is the recommended default, offering a conservative security margin with reasonable key sizes.

**Hybrid construction.** A scheme that combines a post-quantum KEM with a classical symmetric cipher. The KEM establishes a shared secret; that secret keys a symmetric cipher (XChaCha20-Poly1305 or Serpent-256) for the actual data. Security holds as long as either component remains unbroken. `KyberSuite` implements this pattern and plugs directly into `Seal` and `SealStream`.

---

## Signature Layer

**Digital signature.** A short value that proves a specific message was authorized by the holder of a specific private key. Anyone with the matching public key can verify the signature. Provides authenticity, integrity, and non-repudiation. Distinct from a MAC, which uses one shared secret rather than a public-private key pair.

**Public key / private key.** An asymmetric key pair. The private key signs and stays secret. The public key verifies and ships openly. FIPS 204 and FIPS 205 use `verificationKey` for the public half and `signingKey` for the private half; the leviathan-crypto APIs use `pk` and `sk` for the same two objects.

**Verification.** Checking that a signature is valid for a given message and public key. The verify function returns a boolean: valid or invalid. It never returns a partial result, a probability, or "maybe."

**Signing context (ctx).** A per-call domain separation string bound into the signature computation. Two signatures over the same message produced under different contexts are different signatures and cannot be substituted for each other. Used to scope a signing key to a protocol, a version, or a purpose. Capped at 255 bytes per FIPS 204 §3.6.1, native ctx encoding.

**Domain separation.** Distinguishing one signing context, scheme, or version from another by mixing a unique tag into the signature computation. Prevents a signature produced for context A from verifying as a signature for context B even under the same key. Every leviathan-crypto suite carries a built-in `ctxDomain` string (e.g. `ed25519-prehash-envelope-v3`); `buildEffectiveCtx` wraps the per-call `user_ctx` with this domain before handing it to the underlying primitive.

**Pure mode.** A signing mode that runs the signature computation over the full message bytes rather than over a prehash. Pure-mode signing cannot stream the message in chunks. Pure Ed25519, pure ML-DSA, and pure SLH-DSA all support this. Pure suites in this library implement `SignatureSuite` only and are rejected by `SignStream` at the type level.

**Prehashed signing.** A signing mode that hashes the message to a fixed-size digest before the signature computation. The digest is part of the signed input, so verifiers must use the same hash function. Prehashing lets signers and verifiers stream arbitrarily large inputs without buffering, which pure-mode cannot do. Each scheme's prehash variant binds to a specific hash function: Ed25519ph uses SHA-512 per RFC 8032 §5.1.7, signature verification; HashML-DSA permits twelve hashes per FIPS 204 §5.4.1; HashSLH-DSA pairs hashes with security categories per FIPS 205 §10.2.2. Prehash variants in this library satisfy `StreamableSignatureSuite` and plug into `SignStream` / `VerifyStream`.

**Deterministic signing.** A signing mode where the same `(sk, msg)` pair always produces the same signature byte-for-byte. Pure Ed25519 is intrinsically deterministic per RFC 8032 §5.1.6, signature generation. Pure ECDSA is intrinsically randomized, but RFC 6979 §3.2, generation of k, specifies a deterministic K derivation that makes ECDSA reproducible. Deterministic signing is reproducible and free of RNG dependencies, but vulnerable to fault-injection attacks that perturb the signing computation while K stays fixed.

**Hedged signing.** A signing mode that mixes deterministic K derivation with fresh per-call randomness, defending against both poor RNGs and fault-injection attacks that target a fixed deterministic K. `EcdsaP256Suite` and the PQ signature suites hedge by default; the underlying `EcdsaP256` class can drop down to pure RFC 6979 determinism on demand. `draft-irtf-cfrg-det-sigs-with-noise-05` §4, Hedged-Deterministic Nonce Generation, formalizes the construction.

**Format byte / suite byte.** The 1-byte wire identifier at the start of every v3 signature envelope. Identifies which `SignatureSuite` produced the envelope so verifiers can dispatch to the right verify logic. The catalog at `src/ts/sign/catalog.ts` reserves a fixed byte per shipped suite; consumers cannot mint custom suites with reserved bytes.

**Signature envelope.** The v3 wire format produced by `Sign.sign` and `SignStream.finalize`: `suite_byte || ctx_len || ctx || payload_len || payload || sig`. The same bytes are accepted by `Sign.verify` and `VerifyStream`. The envelope carries everything a verifier needs to dispatch and authenticate, including the raw `user_ctx` (never `effective_ctx`).

**Lattice-based signature.** A signature scheme whose security rests on the hardness of lattice problems such as Module-LWE. ML-DSA (FIPS 204, formerly Dilithium) is NIST's standardized lattice signature. Post-quantum. Public keys and signatures are in the kilobyte range. See [Post-Quantum](#post-quantum) for the broader category.

**Hash-based signature.** A signature scheme whose security rests entirely on the second-preimage and collision resistance of a hash function. SLH-DSA (FIPS 205, formerly SPHINCS+) is NIST's standardized hash-based signature. Post-quantum, stateless, with the most conservative security argument of any standardized signature. Signatures are large, 8-50 kilobytes depending on parameter set. Internally a stateless variant of XMSS, layered as a hypertree of one-time WOTS+ signatures over FORS leaves.

**Hypertree.** The multi-layer tree of one-time signatures inside SLH-DSA, FIPS 205 §7. Each non-leaf node signs the public key of the node below it; the bottom leaf signs a FORS commitment to the message digest. The hypertree is what lets SLH-DSA produce many signatures from one keypair without per-message state.

**WOTS+ (Winternitz One-Time Signature Plus).** The one-time signature scheme used as a leaf in SLH-DSA's hypertree, FIPS 205 §5, WOTS+. Each WOTS+ instance signs at most one message; the hypertree chains WOTS+ leaves upward so the keypair can produce many signatures without rolling state.

**FORS (Forest of Random Subsets).** The hash-tree signature scheme at the bottom of SLH-DSA's hypertree, FIPS 205 §8. FORS signs the message digest itself; the WOTS+ leaves above it sign FORS public keys.

**Composite signature / hybrid signature.** A signature that combines two underlying signature schemes so that forging requires breaking both. The leviathan-crypto catalog ships three PQ-only hybrids (ML-DSA + SLH-DSA at matching security categories) and four classical+PQ hybrids (ML-DSA + Ed25519 or ECDSA-P256). Verification runs both component verifies; a hybrid signature is valid only when both halves verify. Wire format is `sig_a || sig_b` with no length prefixes. `draft-ietf-lamps-pq-composite-sigs` §3.2, signature generation, formalizes the construction.

**Fault-injection defense.** Re-deriving the public key from the secret key during signing and comparing it to a caller-supplied `pk`. Detects glitches that flipped bits during the signing computation. The direct `Ed25519.sign(sk, pk, M)` and `EcdsaP256.sign(sk, pk, M)` class entry points include this cross-check; the suite-layer factories skip it because deriving `pk` inside the same call from the same potentially-faulted module collapses the defense to no defense. See `_signInternalPk` in `src/ts/ed25519/index.ts` and `src/ts/ecdsa/index.ts`.

**Low-S normalization.** A canonicalization step for ECDSA signatures. For every valid `(r, s)` an equivalent `(r, n - s)` also verifies, which means raw ECDSA signatures are malleable. Low-S enforcement requires `s <= n/2` so the canonical half is unique. `EcdsaP256.sign` normalizes on the signer side, and `EcdsaP256.verify` rejects high-S on the verifier side. RFC 6979 §3.5, alternate description of the signature generation step.

**Transparency log.** An append-only Merkle tree of signed entries that exposes inclusion proofs (a specific entry exists in the log at size N) and consistency proofs (the log at size M is a prefix of the log at size N). Operators publish signed tree heads; verifiers and witnesses check them. RFC 6962 (Certificate Transparency) and Sigsum are well-known instances. `MerkleLog`, `MerkleVerifier`, and `SignedLog` provide the substrate.

**Inclusion proof.** A short list of sibling hashes that lets a verifier reconstruct the Merkle root for a tree of given size from a single leaf. If the reconstructed root matches the operator's signed tree head, the entry is proven to be in the log. Sub-linear in the tree size.

**Consistency proof.** A short list of node hashes that lets a verifier confirm a larger tree is an append-only extension of a smaller tree. Both tree heads must verify against the proof. Sub-linear in the tree size.

**Signed tree head (STH).** A signed commitment to the current Merkle root and tree size. The log operator signs the STH; verifiers check the signature before trusting the root for inclusion or consistency proofs.

**Cosignature.** A second signature over a signed tree head, produced by a witness who has seen the STH. Cosignatures aggregate independent observations of the log so verifiers do not need to trust a single operator. c2sp.org/tlog-cosignature defines the wire format.

**Checkpoint.** A textual encoding of a signed tree head plus optional metadata, in the line-oriented format used by Sigsum and the Go ecosystem's tlog. Body lines carry the origin string, tree size, and root hash; signature lines carry the operator and cosigner signatures.

---

## Session Layer

**Forward secrecy.** The property that past ciphertext remains secure even if the long-term key is compromised later. A session with forward secrecy derives a fresh per-message key from an evolving state and immediately zeroes the old one. An attacker who steals today's device cannot decrypt yesterday's messages.

**Post-compromise security.** Post-compromise security complements forward secrecy. After a compromise, the session eventually heals on its own as fresh key material mixes in. An attacker who captures a key at one moment cannot decrypt messages sent after the next ratchet step. Forward secrecy protects the past; post-compromise security protects the future.

**Ratchet.** A mechanism that advances a secret in one direction so old values cannot be recovered from new ones. Each step derives the next state from the current one and discards the previous. Ratchets are how a session achieves forward secrecy. Once a message key has been used and the ratchet steps forward, the key cannot be recomputed.

**Double Ratchet.** A session construction that layers two ratchets. A symmetric chain ratchet derives a new message key for every message. An asymmetric ratchet mixes fresh KEM output into the root key at session boundaries. The symmetric side gives you forward secrecy within a chain. The asymmetric side gives you post-compromise security across chains. leviathan-crypto's ratchet module implements the KDF primitives for a Signal-like Double Ratchet, using ML-KEM as the asymmetric component. You may see this construction called the Sparse Post-Quantum Ratchet or SPQR. The result is the full Double-Ratchet session-security story against an adversary with a quantum computer.

**Root key.** The long-lived secret at the top of a ratchet hierarchy. Each asymmetric ratchet step derives a new root key from the previous root key and a fresh KEM output, then splits the result into send and receive chain keys. The root key is never used to encrypt a message directly; it only seeds the chains.

**Chain / chain key.** The per-direction symmetric ratchet. A chain key advances via HKDF with each message: one step produces the next chain key (for the following message) and a message key (for the current message). A session has separate send and receive chains so the two parties advance independently.

**Message key.** The single-use key derived from a chain key to encrypt exactly one message. After the message is encrypted or decrypted, the key is zeroed. Message keys are never transmitted; both parties derive them locally from their chain state.

**Epoch.** A segment of a session bounded by root-key advances. Messages within one epoch share a chain; a new epoch starts when the asymmetric ratchet produces a new KEM output and derives a fresh root key. Epochs are the unit at which post-compromise healing happens.

**Skipped message keys.** Message keys for messages that haven't arrived yet. When a message arrives out of order (message 5 before message 3), the receiver advances its chain through the missing counters, saves the intermediate keys in a bounded cache, and decrypts the out-of-order message. When the delayed messages arrive, their cached keys are used once and immediately zeroed. `SkippedKeyStore` manages this cache with configurable bounds on both memory and per-message work.

---


## BLAKE3

The terms below are specific to BLAKE3 and its tree-mode design. They
crop up in the BLAKE3 spec, in `docs/blake3.md`, `docs/asm_blake3.md`,
and the BLAKE3 audit doc, and across the AssemblyScript source under
`src/asm/blake3/`.

**CV (chaining value).** The 32-byte (8 × u32 little-endian) state
that threads through BLAKE3's compression function. The starting CV
is the BLAKE3 IV in default-mode hash, the 32-byte key in keyed_hash,
and the context_chain_value in derive_key pass 2 (BLAKE3 §2.3 Modes).
Each compress takes a CV in and emits the next CV as the first 32
bytes of its 64-byte output.

**Chunk.** In BLAKE3, a chunk is exactly 1024 bytes of input (BLAKE3
§2.4). Each chunk runs through its own §2.4 chunk machine to produce
a 32-byte chunk CV. Chunks are the leaves of the §2.5 binary tree.
Inputs ≤ 1024 bytes are single-chunk and apply the ROOT flag on the
chunk's final compress (§2.4 single-chunk root case); larger inputs
go through the tree assembly.

**Subtree / parent.** The §2.5 tree-assembly node. A parent is a
compress over two child CVs (`left || right`) with the PARENT flag.
A subtree is a balanced binary tree of chunks merged via parent
compresses. The queue-per-level discipline (leviathan, see tree.ts)
defers merges until a level's queue reaches 8 entries; the topmost
merge during finalize is the §2.5 root parent, which carries
`PARENT | ROOT`.

**Root compress.** The final compress in any BLAKE3 hash. Always
carries the ROOT flag. For single-chunk inputs, the chunk's last
compress is the root (§2.4 single-chunk root case); for multi-chunk
inputs, the topmost parent merge is the root (§2.5). The root
compress emits 64 bytes, and additional XOF bytes come from re-firing
the root compress with an incremented counter.

**XOF (Extendable Output Function).** A hash that emits arbitrary-
length output. BLAKE3's §2.6 squeeze takes the root-compress input,
captures it as a snapshot, and re-fires the compress with an
incrementing counter to lift 64-byte blocks off the snapshot. The
leviathan binding exposes this via `BLAKE3OutputReader`. See also the
generic XOF entry in [Core Terminology](#core-terminology).

**DERIVE_KEY_CONTEXT / DERIVE_KEY_MATERIAL.** The two §2.3 derive_key mode flags.
DERIVE_KEY_CONTEXT rides every compress in pass 1 (hashing the
context string with the BLAKE3 IV as the starting CV).
DERIVE_KEY_MATERIAL rides every compress in pass 2 (hashing the key
material with the pass-1 output as the starting CV). The two flags
are distinct power-of-two bits per BLAKE3 §2.2 Table 3.

**compress1 / compress4.** BLAKE3 SIMD width nomenclature. `compress1`
(named `compress` in the source) is the v128-internal single-block
compress that runs one v128 op per state-update step across the four
state rows. `compress4` (named `compress4` in the source) is the
v128-external lane-parallel compress that runs four independent
single-block compressions in parallel, with lane K of every v128 op
corresponding to compress K. The reference BLAKE3 implementations
ship up to `compress16` on AVX-512 hosts; leviathan ships
`compress1` and `compress4` because WebAssembly SIMD is fixed at 128
bits.

**ROOT_STATE_* (XOF snapshot).** The four memory slots in the BLAKE3
WASM buffer layout (`ROOT_STATE_CV`, `ROOT_STATE_MSG`,
`ROOT_STATE_BLEN`, `ROOT_STATE_FLAGS`) that capture the root-compress
input bytes immediately before the root compress fires. The TS
`BLAKE3OutputReader` and the WASM `squeezeXofBlock` export re-fire
the root compress from this snapshot with an incrementing counter to
produce additional 64-byte XOF blocks.

---

## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project documentation index |
| [architecture](./architecture.md) | Repository structure, build and CI, WASM modules, public API, test suite, and security posture |
| [authenticated encryption](./aead.md) | `Seal`, `SealStream`, `OpenStream`: cipher-agnostic AEAD APIs using a `CipherSuite` such as `SerpentCipher` or `XChaCha20Cipher` |
| [ciphersuite](./ciphersuite.md) | `SerpentCipher`, `XChaCha20Cipher`, `KyberSuite`, and the `CipherSuite` interface |
| [signing](./signing.md) | `Sign`, `SignStream`, `VerifyStream`: scheme-agnostic signing layer |
| [signaturesuite](./signaturesuite.md) | `SignatureSuite` interface and the shipped suite catalog (ML-DSA, SLH-DSA, Ed25519, ECDSA-P256, hybrids) |
| [kyber](./kyber.md) | ML-KEM key encapsulation, parameter sets, and key management |
| [ratchet](./ratchet.md) | Double Ratchet KDF primitives: `ratchetInit`, `KDFChain`, `kemRatchetEncap`/`kemRatchetDecap`, `SkippedKeyStore` |
| [serpent](./serpent.md) | Serpent-256 raw primitives |
| [chacha20](./chacha20.md) | ChaCha20 raw primitives |
| [blake3](./blake3.md) | BLAKE3 default-mode hash, keyed_hash, derive_key, and XOF reader |
| [exports](./exports.md) | Complete export reference |
| [init](./init.md) | WASM loading and `WasmSource` |
