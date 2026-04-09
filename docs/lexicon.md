# Cryptography Lexicon

> [!NOTE]
> A reference glossary for readers new to cryptography. Covers foundational terms, context-specific meanings, the leviathan-crypto sealing layer, and post-quantum concepts.

---

> ### Table of Contents
> - [Core Terminology](#core-terminology)
> - [Context-Specific Terms](#context-specific-terms)
> - [Sealing Layer](#sealing-layer)
> - [Post-Quantum](#post-quantum)

---

## Core Terminology

**Plaintext.** The original, readable data before encryption.

**Key.** A secret value that controls a cryptographic operation. Without it, the operation cannot be reversed. leviathan-crypto uses 256-bit (32-byte) symmetric keys.

**Entropy.** A measure of unpredictability. A 256-bit random key has 256 bits of entropy; there is no pattern an attacker can exploit. Keys derived from weak passwords without a KDF have low entropy and are vulnerable to brute force.

**Cipher.** An algorithm that transforms data using a key. Without the key, the transformation cannot be reversed.

**Block cipher.** An algorithm that encrypts data in fixed-size chunks. Serpent operates on 128-bit blocks. Block ciphers require a mode of operation to handle messages longer than one block.

**Stream cipher.** A cipher that operates on a continuous sequence of bytes rather than fixed-size blocks. ChaCha20 is a stream cipher.

**Ciphertext.** The encrypted output of a cipher. Unreadable without the correct key.

**Nonce.** A value that must never repeat for a given key. Reusing a nonce with the same key can expose plaintext or enable forgery. Nonces are typically generated randomly.

**IV (Initialization Vector).** A nonce used to randomize the first block of a block cipher mode such as CBC. It prevents identical plaintexts from producing identical ciphertexts.

**Padding.** Extra bytes added to a message to reach a block boundary. CBC mode applies a standard padding scheme (PKCS#7) before encryption and strips it after decryption.

**Hash function.** A one-way function that maps arbitrary input to a fixed-size digest. Hash functions serve as building blocks for MACs, KDFs, and CSPRNGs.

**Digest.** The fixed-size output of a hash function, also called a hash. Any change to the input, however small, produces a completely different digest.

**Salt.** Random data mixed into a key derivation function. It ensures two derivations from the same password produce different keys. A salt is not secret and can be stored alongside the derived output.

**HMAC (Hash-based Message Authentication Code).** A MAC built from a hash function and a secret key. It proves both integrity and authenticity: only a party with the key could have produced it.

**Tag (authentication tag).** A short value appended to ciphertext that proves the data has not been tampered with. The tag is computed from the key, ciphertext, and any additional data. Tag verification must run in constant time.

**KDF (Key Derivation Function).** A function that produces keys from a secret input. HKDF expands existing key material. Argon2 and scrypt are KDFs designed to slow brute-force attacks on passwords.

**HKDF (HMAC-based Key Derivation Function).** A KDF that derives one or more strong keys from a single secret. leviathan-crypto uses HKDF to derive per-stream encryption and MAC keys from a master key and a random nonce.

**Subkey derivation.** Generating a new key from an existing one for a specific purpose. It limits the impact of a compromise: knowing one subkey gives an attacker nothing about the others. leviathan-crypto derives fresh encryption and MAC subkeys per stream via HKDF.

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

**Sealing and opening.** Sealing is authenticated encryption: encrypt and authenticate in one step, producing a self-contained blob that reveals tampering on decryption. Opening is the reverse. leviathan-crypto provides `Seal.encrypt` and `Seal.decrypt` for one-shot use, and `SealStream` with `OpenStream` for chunked data.

**Overhead.** The bytes an encryption scheme adds beyond the plaintext. This includes the nonce, authentication tag, header, and any padding. XChaCha20-Poly1305 adds 40 bytes per message (24-byte nonce, 16-byte tag). Streaming adds a 20-byte preamble plus per-chunk tags.

**Preamble.** The bytes at the start of a sealed stream, sent before any ciphertext. The preamble contains the format identifier, a random 16-byte HKDF salt, and the chunk size. The recipient reads it first to initialize the opener. For KEM suites, the preamble also carries the encapsulated shared secret.

**Chunk.** A fixed-size segment of a stream, encrypted and authenticated independently. A tampered chunk is rejected immediately without decrypting any following chunks. The default chunk size in leviathan-crypto is 65,536 bytes.

**Session.** A single-use cryptographic context. A `SealStream` is single-use: once `finalize()` is called, the keys are zeroed. Each message requires a new stream. Reusing a stream would risk nonce collision.

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

**Framing / framed mode.** In framed mode (`{ framed: true }`), each encrypted chunk gets a 4-byte big-endian length prefix. This makes a stream of concatenated chunks self-delimiting: a reader can extract chunk boundaries from the data itself. Omit framing when the transport already provides message boundaries, such as WebSocket frames or IPC messages.

**AAD (Additional Authenticated Data).** Data that is authenticated alongside ciphertext but not encrypted. It binds a chunk to external context such as sequence numbers or routing metadata, without including that data in the encrypted payload. Both sides must supply identical AAD or decryption fails.

**Single-use stream.** A `SealStream` encrypts exactly one message. After `finalize()`, the derived keys are immediately zeroed and the stream cannot seal any further data. Create a new instance for each message.

**Pool.** `SealStreamPool` distributes chunk encryption across multiple Web Workers, each with its own WASM instance and a copy of the derived keys. It is useful for large files where single-threaded throughput is a bottleneck. Any failure is fatal: the pool is destroyed on error and must be recreated for the next operation.

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

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [authenticated encryption](./aead.md) — `Seal`: one-shot AEAD over any `CipherSuite`
> - [ciphersuite](./ciphersuite.md) — `SerpentCipher`, `XChaCha20Cipher`, `KyberSuite`, and the `CipherSuite` interface
> - [kyber](./kyber.md) — ML-KEM key encapsulation, parameter sets, and key management
> - [serpent](./serpent.md) — Serpent-256 raw primitives
> - [chacha20](./chacha20.md) — ChaCha20 raw primitives
> - [exports](./exports.md) — complete export reference
> - [init](./init.md) — WASM loading and `WasmSource`
