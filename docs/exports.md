<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### All Exports

Complete reference for every public export in leviathan-crypto, grouped by module. Follow the module links for deeper documentation on each class.

> ### Table of Contents
> - [Initialization](#initialization)
> - [Serpent-256](#serpent-256)
> - [AES](#aes)
> - [Stream](#stream)
> - [Sign](#sign)
> - [Errors](#errors)
> - [XChaCha20 / Poly1305](#xchacha20--poly1305)
> - [SHA-2](#sha-2)
> - [SHA-3](#sha-3)
> - [Keccak (alias for SHA-3)](#keccak-alias-for-sha-3)
> - [BLAKE3](#blake3)
> - [Ed25519 / X25519 (Curve25519 family)](#ed25519--x25519-curve25519-family)
> - [ML-KEM (Post-quantum KEM)](#ml-kem-post-quantum-kem)
> - [ML-DSA (Post-quantum signatures)](#ml-dsa-post-quantum-signatures)
> - [SLH-DSA (Post-quantum signatures)](#slh-dsa-post-quantum-signatures)
> - [Fortuna CSPRNG](#fortuna-csprng)
> - [Ratchet (Sparse Post-Quantum Ratchet KDF)](#ratchet-sparse-post-quantum-ratchet-kdf)
> - [Types](#types)
> - [Utilities](#utilities)

---

## Initialization

Root barrel `leviathan-crypto`. No module required.

| Export | Kind | Description |
|--------|------|-------------|
| `init` | function | Load and cache WASM modules. `init(sources: Partial<Record<Module, WasmSource>>)`. |
| `isInitialized` | function | `isInitialized(mod: Module): boolean`. Returns `true` if the given module has been loaded. Useful for diagnostic checks. |
| `Module` | type | `'serpent' \| 'chacha20' \| 'sha2' \| 'sha3' \| 'keccak' \| 'kyber' \| 'aes' \| 'mldsa' \| 'slhdsa' \| 'blake3' \| 'curve25519'`. The top-level `init()` additionally accepts `'ed25519'` and `'x25519'` as aliases that resolve to the `curve25519` slot. |
| `WasmSource` | type | Union of all accepted WASM loading strategies. See below. |

**`WasmSource`** accepted by every init function:

| Value | Strategy |
|-------|----------|
| `string` | Decode gzip+base64 embedded blob |
| `URL` | `fetch` + `instantiateStreaming` |
| `ArrayBuffer` | Compile from raw WASM bytes |
| `Uint8Array` | Compile from raw WASM bytes |
| `WebAssembly.Module` | Instantiate pre-compiled module |
| `Response` | `instantiateStreaming` from fetch response |
| `Promise<Response>` | `instantiateStreaming` from deferred fetch |

See [init.md](./init.md) for full loading documentation.

---

## Serpent-256

Requires `init({ serpent: serpentWasm, sha2: sha2Wasm })` for authenticated classes, `init({ serpent: serpentWasm })` for raw modes.
Subpath: `leviathan-crypto/serpent`. See [serpent.md](./serpent.md).

| Export | Kind | Description |
|--------|------|-------------|
| `serpentInit` | function | Module-scoped init. `serpentInit(source: WasmSource)` loads only serpent. |
| `SerpentCipher` | const | `CipherSuite` for Serpent-256 CBC+HMAC-SHA-256. `keygen()` → 32-byte key. `formatEnum: 0x02`, `keySize: 32`, `tagSize: 32`, `padded: true`. Used with `Seal`, `SealStream`, `OpenStream`. |
| `Serpent` | class | Serpent-256 ECB block cipher. `loadKey()`, `encryptBlock()`, `decryptBlock()`. Unauthenticated. |
| `SerpentCtr` | class | Serpent-256 CTR mode. `beginEncrypt()`, `encryptChunk()`, `beginDecrypt()`, `decryptChunk()`. Unauthenticated. |
| `SerpentCbc` | class | Serpent-256 CBC mode with PKCS7 padding. `encrypt(key, iv, plaintext)`, `decrypt(key, iv, ciphertext)`. Unauthenticated. |

---

## AES

Bitsliced AES-128/192/256 (FIPS 197) over WebAssembly SIMD, with CBC and CTR mode wrappers (SP 800-38A §6.2, §6.5), AES-GCM authenticated encryption (SP 800-38D §7), and AES-GCM-SIV nonce-misuse-resistant authenticated encryption (RFC 8452). The raw block cipher (`AES`) is the building block; `AESCbc` and `AESCtr` are unauthenticated direct mode access; `AESGCM` and `AESGCMSIV` are authenticated AEADs with a fixed 128-bit tag.

| Export | Kind | Description |
|--------|------|-------------|
| `aesInit` | function | Module-scoped init. `aesInit(source: WasmSource)` loads only aes. |
| `AES` | class | AES ECB block cipher. `loadKey(key)` (16, 24, or 32 byte keys), `encryptBlock(plaintext)`, `decryptBlock(ciphertext)` (FIPS 197 §5.3.5 Equivalent Inverse Cipher). Unauthenticated. Atomic, does not hold module exclusivity. |
| `AESCbc` | class | AES CBC mode (SP 800-38A §6.2) with PKCS7 padding (RFC 5652 §6.3). `encrypt(key, iv, plaintext)`, `decrypt(key, iv, ciphertext)`. **Unauthenticated.** requires `{ dangerUnauthenticated: true }` opt-in; pair with HMAC (Encrypt-then-MAC) or use `Seal` with `SerpentCipher`/`XChaCha20Cipher` instead. SIMD CBC decrypt; scalar CBC encrypt (chaining is sequential by definition). Stateful, holds the AES module exclusively until `dispose()`. |
| `AESCtr` | class | AES CTR mode (SP 800-38A §6.5). `loadKey(key)`, `setNonce(nonce)`, `encrypt(plaintext)` / `decrypt(ciphertext)`. Counter is 128-bit big-endian (SP 800-38A Appendix B.1, matches §F.5 worked examples). **Unauthenticated.** pair with HMAC or use an authenticated cipher instead. SIMD via the bitsliced 8-block kernel. Stateful, counter advances across calls; reset with `setNonce`. |
| `AESGCM` | class | AES-GCM authenticated encryption (SP 800-38D §7). `seal(key, iv, aad, pt)` returns `ciphertext \|\| tag` (128-bit tag); `open(key, iv, aad, sealed)` verifies and returns plaintext, throws `RangeError('authentication failed')` on any verification failure. 12-byte (96-bit) IV is the recommended fast path; variable-length IVs trigger the GHASH-on-IV slow path per §7.1 step 2. AAD up to 64 KiB; PT up to 64 KiB per single call (chunked iteration internally for larger inputs). Tag length fixed at 128 bits. Stateful, holds the AES module exclusively until `dispose()`. |
| `AESGCMSIV` | class | AES-GCM-SIV nonce-misuse-resistant authenticated encryption (RFC 8452). Constructor takes a 16-byte (AES-128) or 32-byte (AES-256) key, AES-192 is **not** supported (RFC 8452 §6 only defines AES-128/256 variants). `seal(nonce, plaintext, aad?)` returns `ciphertext \|\| tag`; `open(nonce, sealed, aad?)` returns plaintext, throws `AuthenticationError('siv')` on any verification failure. Nonce must be exactly 12 bytes. AAD ≤ 64 KiB; plaintext ≤ 64 KiB per call (single-shot only, larger messages will use a future streaming SIV variant). Tag verification routes through `constantTimeEqual` in the dedicated `ct` WASM module. Atomic. |
| `AESGenerator` | const | `Generator` const for `Fortuna`. AES-256 ECB counter-mode PRF (Practical Cryptography §9.4, the spec-canonical Fortuna generator). `keySize: 32`, `blockSize: 16`, `counterSize: 16`. Requires `init({ aes })`. Re-exported from the root barrel. |
| `AESGCMSIVCipher` | const | `CipherSuite` for AES-256-GCM-SIV (RFC 8452). `keygen()` returns a 32-byte master key. `formatEnum: 0x04`, `keySize: 32`, `tagSize: 16`, `commitmentSize: 32`, `padded: false`. Used with `Seal`, `SealStream`, `OpenStream`, `SealStreamPool`, and `KyberSuite`. Requires `init({ aes, sha2 })`. HtE explicit-commitment construction matches `XChaCha20Cipher`, closes the Invisible Salamanders attack surface for AES-GCM-SIV's POLYVAL-based MAC. |

---

## Stream

Cipher-agnostic streaming encryption using the STREAM construction.
Subpath: `leviathan-crypto/stream`. See [aead.md](./aead.md).

| Export | Kind | Description |
|--------|------|-------------|
| `Seal` | class (static) | One-shot AEAD. `Seal.encrypt(suite, key, plaintext)` / `Seal.decrypt(suite, key, blob)`. Works with any `CipherSuite` including `KyberSuite`. Never instantiated. |
| `SealStream` | class | Cipher-agnostic streaming encryption (STREAM construction). `push(chunk)`, `finalize(chunk)`, `toTransformStream()`. |
| `OpenStream` | class | Cipher-agnostic streaming decryption. `pull(chunk)`, `finalize(chunk)`, `seek(index)`, `toTransformStream()`. |
| `SealStreamPool` | class | Parallel batch seal/open via Web Workers. `SealStreamPool.create(cipher, key, opts)` static factory. |
| `CipherSuite` | interface | Cipher-specific logic injected into SealStream/OpenStream. Implementations: `XChaCha20Cipher`, `SerpentCipher`, `AESGCMSIVCipher`, `KyberSuite`. See [ciphersuite.md](./ciphersuite.md). |
| `DerivedKeys` | interface | Opaque key material returned by `CipherSuite.deriveKeys()`. |
| `SealStreamOpts` | type | Options for SealStream: `chunkSize?`, `framed?`. |
| `PoolOpts` | type | Options for SealStreamPool: `wasm`, `workers?`, `chunkSize?`, `framed?`, `jobTimeout?`. |
| `HEADER_SIZE` | const | Stream header size in bytes (20). |
| `CHUNK_MIN` | const | Minimum chunk size (1024). |
| `CHUNK_MAX` | const | Maximum chunk size (16777215, u24 max). |
| `FLAG_FRAMED` | const | Header byte 0 framed flag (0x80). |
| `TAG_DATA` | const | Counter nonce final flag for data chunks (0x00). |
| `TAG_FINAL` | const | Counter nonce final flag for final chunk (0x01). |

---

## Sign

Cipher-agnostic signature envelope and streaming layer over the v3 SignatureSuite abstraction.
Subpath: `leviathan-crypto/sign`. See [signaturesuite.md](./signaturesuite.md).

| Export | Kind | Description |
|--------|------|-------------|
| `Sign` | class (static) | One-shot signature envelope. `Sign.sign(suite, sk, msg, ctx)`, `Sign.verify(suite, pk, blob, ctx)`, `Sign.signDetached(suite, sk, msg, ctx)`, `Sign.verifyDetached(suite, pk, msg, sig, ctx)`, `Sign.peek(blob, suite)`. Never instantiated. |
| `SignStream` | class | Streaming signature production over a `StreamableSignatureSuite`. `new SignStream(suite, sk, ctx)`, `update(chunk)`, `finalize()`, `dispose()`. `finalize()` returns wire bytes byte-identical to `Sign.sign` for the same inputs. |
| `VerifyStream` | class | Streaming signature consumption over a `StreamableSignatureSuite`. `new VerifyStream(suite, pk, ctx)`, `update(chunk)`, `finalize()` returns verified payload or throws `SigningError`. Buffered payload chunks are wiped on auth failure. |
| `SignatureSuite` | interface | Suite contract for all signature schemes. Fields: `formatEnum`, `formatName`, `ctxDomain`, `pkSize`, `skSize`, `sigSize`, `wasmModules`. Methods: `sign(sk, msg, ctx)`, `verify(pk, msg, sig, ctx)`, `keygen()`. |
| `StreamableSignatureSuite` | interface | `SignatureSuite` extension for suites usable with `SignStream`/`VerifyStream`. Adds `prehashAlgorithm`, `prehashSize`, `signPrehashed(sk, digest, ctx)`, `verifyPrehashed(pk, digest, sig, ctx)`. |
| `PrehashAlgorithm` | type | Union of the six prehash function identifiers used across the catalog: `'sha-256' \| 'sha-512' \| 'sha3-256' \| 'sha3-512' \| 'shake-128' \| 'shake-256'`. |
| `Ed25519Suite` | const | Pure Ed25519 SignatureSuite (RFC 8032 §5.1.6, signature generation). `formatEnum: 0x01`, `ctxDomain: 'ed25519-envelope-v3'`. Rejects non-empty user_ctx with `SigningError('sig-ctx-unsupported')`. Requires `init({ ed25519 })`. |
| `Ed25519PreHashSuite` | const | Ed25519ph StreamableSignatureSuite (RFC 8032 §5.1.7, signature verification, dom2 prehash). `formatEnum: 0x11`, `ctxDomain: 'ed25519-prehash-envelope-v3'`, `prehashAlgorithm: 'sha-512'`. Requires `init({ ed25519, sha2 })`. |
| `MlDsa44Suite` | const | Pure ML-DSA-44 SignatureSuite. `formatEnum: 0x03`, `ctxDomain: 'mldsa44-envelope-v3'`. Requires `init({ mldsa, sha3 })`. |
| `MlDsa65Suite` | const | Pure ML-DSA-65 SignatureSuite. `formatEnum: 0x04`, `ctxDomain: 'mldsa65-envelope-v3'`. Requires `init({ mldsa, sha3 })`. |
| `MlDsa87Suite` | const | Pure ML-DSA-87 SignatureSuite. `formatEnum: 0x05`, `ctxDomain: 'mldsa87-envelope-v3'`. Requires `init({ mldsa, sha3 })`. |
| `MlDsa44PreHashSuite` | const | ML-DSA-44 + SHA3-256 prehash StreamableSignatureSuite. `formatEnum: 0x13`, `ctxDomain: 'mldsa44-prehash-envelope-v3'`. Requires `init({ mldsa, sha3 })`. |
| `MlDsa65PreHashSuite` | const | ML-DSA-65 + SHA3-256 prehash StreamableSignatureSuite. `formatEnum: 0x14`, `ctxDomain: 'mldsa65-prehash-envelope-v3'`. Requires `init({ mldsa, sha3 })`. |
| `MlDsa87PreHashSuite` | const | ML-DSA-87 + SHA3-512 prehash StreamableSignatureSuite. `formatEnum: 0x15`, `ctxDomain: 'mldsa87-prehash-envelope-v3'`. Requires `init({ mldsa, sha3 })`. |
| `SlhDsa128fSuite` | const | Pure SLH-DSA-SHAKE-128f SignatureSuite. `formatEnum: 0x06`, `ctxDomain: 'slhdsa128f-envelope-v3'`. Requires `init({ slhdsa })`. |
| `SlhDsa192fSuite` | const | Pure SLH-DSA-SHAKE-192f SignatureSuite. `formatEnum: 0x07`, `ctxDomain: 'slhdsa192f-envelope-v3'`. Requires `init({ slhdsa })`. |
| `SlhDsa256fSuite` | const | Pure SLH-DSA-SHAKE-256f SignatureSuite. `formatEnum: 0x08`, `ctxDomain: 'slhdsa256f-envelope-v3'`. Requires `init({ slhdsa })`. |
| `SlhDsa128fPreHashSuite` | const | SLH-DSA-SHAKE-128f + SHAKE128(32) prehash StreamableSignatureSuite. `formatEnum: 0x16`, `ctxDomain: 'slhdsa128f-prehash-envelope-v3'`. Requires `init({ slhdsa, sha3 })`. |
| `SlhDsa192fPreHashSuite` | const | SLH-DSA-SHAKE-192f + SHAKE256(64) prehash StreamableSignatureSuite. `formatEnum: 0x17`, `ctxDomain: 'slhdsa192f-prehash-envelope-v3'`. Requires `init({ slhdsa, sha3 })`. |
| `SlhDsa256fPreHashSuite` | const | SLH-DSA-SHAKE-256f + SHAKE256(64) prehash StreamableSignatureSuite. `formatEnum: 0x18`, `ctxDomain: 'slhdsa256f-prehash-envelope-v3'`. Requires `init({ slhdsa, sha3 })`. |
| `MlDsa44SlhDsa128fSuite` | const | PQ-only hybrid StreamableSignatureSuite composing ML-DSA-44 + SLH-DSA-128f (NIST cat-2 + cat-1). `formatEnum: 0x30`, `ctxDomain: 'mldsa44-slhdsa128f-envelope-v3'`. Composite `pk = pk_mldsa \|\| pk_slhdsa`, `sig = sig_mldsa \|\| sig_slhdsa`, ML-DSA-first, no length prefixes. Prehash SHAKE128(32). Requires `init({ mldsa, sha3, slhdsa })`. |
| `MlDsa65SlhDsa192fSuite` | const | PQ-only hybrid StreamableSignatureSuite composing ML-DSA-65 + SLH-DSA-192f (cat-3 + cat-3). `formatEnum: 0x31`, `ctxDomain: 'mldsa65-slhdsa192f-envelope-v3'`. Prehash SHAKE256(64). Requires `init({ mldsa, sha3, slhdsa })`. |
| `MlDsa87SlhDsa256fSuite` | const | PQ-only hybrid StreamableSignatureSuite composing ML-DSA-87 + SLH-DSA-256f (cat-5 + cat-5). `formatEnum: 0x32`, `ctxDomain: 'mldsa87-slhdsa256f-envelope-v3'`. Prehash SHAKE256(64). Requires `init({ mldsa, sha3, slhdsa })`. |

---

## Errors

| Export | Kind | Description |
|--------|------|-------------|
| `AuthenticationError` | class | Thrown on AEAD auth failure. Extends `Error`. Constructor takes cipher name string. |
| `SigningError` | class | Thrown on signature contract violations and verification failures from the v3 sign module. Extends `Error`. Constructor takes a stable `discriminator` string plus optional message. Discriminators span suite, envelope, and stream layers (see [signaturesuite.md](./signaturesuite.md)). |
| `KeyAgreementError` | class | Thrown by `X25519.dh` when the peer public key produces an all-zero shared secret (small-order point per RFC 7748 §6.1, Curve25519). Extends `Error`. Branch on `err instanceof KeyAgreementError` to distinguish this from a caller-side contract violation. |

---

## XChaCha20 / Poly1305

Requires `init({ chacha20: chacha20Wasm })` or subpath `chacha20Init()`.
Subpath: `leviathan-crypto/chacha20`. See [chacha20.md](./chacha20.md).

| Export | Kind | Description |
|--------|------|-------------|
| `chacha20Init` | function | Module-scoped init. `chacha20Init(source: WasmSource)` loads only chacha20. |
| `XChaCha20Poly1305` | class | XChaCha20-Poly1305 AEAD. 24-byte nonce. `encrypt()` returns single `Uint8Array` (ct‖tag), `decrypt()` accepts same format. Single-use encrypt guard. |
| `XChaCha20Cipher` | const | `CipherSuite` for XChaCha20-Poly1305. `keygen()` → 32-byte key. `formatEnum: 0x03`, `keySize: 32`, `tagSize: 16`, `commitmentSize: 32`, `padded: false`. Used with `Seal`, `SealStream`, `OpenStream`. |
| `ChaCha20Poly1305` | class | ChaCha20-Poly1305 AEAD (RFC 8439). 12-byte nonce. `encrypt()` returns single `Uint8Array` (ct‖tag), `decrypt()` accepts same format. Single-use encrypt guard. |
| `ChaCha20` | class | ChaCha20 stream cipher (RFC 8439). `beginEncrypt()`, `encryptChunk()`. Unauthenticated. |
| `Poly1305` | class | Poly1305 one-time MAC (RFC 8439). `mac(key, msg)`. |

---

## SHA-2

Requires `init({ sha2: sha2Wasm })` or subpath `sha2Init(source)`.
Subpath: `leviathan-crypto/sha2`. See [sha2.md](./sha2.md).

| Export | Kind | Description |
|--------|------|-------------|
| `sha2Init` | function | Module-scoped init. `sha2Init(source: WasmSource)` loads only sha2. |
| `SHA224` | class | SHA-224 hash (FIPS 180-4 §6.3, §5.3.2 IV). `hash(msg)` returns 28 bytes. |
| `SHA256` | class | SHA-256 hash (FIPS 180-4). `hash(msg)` returns 32 bytes. |
| `SHA384` | class | SHA-384 hash (FIPS 180-4). `hash(msg)` returns 48 bytes. |
| `SHA512` | class | SHA-512 hash (FIPS 180-4). `hash(msg)` returns 64 bytes. |
| `SHA512_224` | class | SHA-512/224 hash (FIPS 180-4 §6.7.1, §5.3.6.1 IV). `hash(msg)` returns 28 bytes. |
| `SHA512_256` | class | SHA-512/256 hash (FIPS 180-4 §6.7.2, §5.3.6.2 IV). `hash(msg)` returns 32 bytes. |
| `HMAC_SHA256` | class | HMAC-SHA256 (RFC 2104). `hash(key, msg)` returns 32 bytes. |
| `HMAC_SHA384` | class | HMAC-SHA384 (RFC 2104). `hash(key, msg)` returns 48 bytes. |
| `HMAC_SHA512` | class | HMAC-SHA512 (RFC 2104). `hash(key, msg)` returns 64 bytes. |
| `HKDF_SHA256` | class | HKDF with HMAC-SHA256 (RFC 5869). `derive(ikm, salt, info, length)`. |
| `HKDF_SHA512` | class | HKDF with HMAC-SHA512 (RFC 5869). `derive(ikm, salt, info, length)`. |

---

## SHA-3

Requires `init({ sha3: sha3Wasm })` or subpath `sha3Init(source)`.
Subpath: `leviathan-crypto/sha3`. See [sha3.md](./sha3.md).

| Export | Kind | Description |
|--------|------|-------------|
| `sha3Init` | function | Module-scoped init. `sha3Init(source: WasmSource)` loads only sha3. |
| `SHA3_224` | class | SHA3-224 hash (FIPS 202). `hash(msg)` returns 28 bytes. |
| `SHA3_256` | class | SHA3-256 hash (FIPS 202). `hash(msg)` returns 32 bytes. |
| `SHA3_384` | class | SHA3-384 hash (FIPS 202). `hash(msg)` returns 48 bytes. |
| `SHA3_512` | class | SHA3-512 hash (FIPS 202). `hash(msg)` returns 64 bytes. |
| `SHA3_256Stream` | class | Incremental SHA3-256. `update(chunk)`, `finalize()` returns 32 bytes. Holds the sha3 module exclusively from construction until `finalize()` or `dispose()`. |
| `SHA3_512Stream` | class | Incremental SHA3-512. `update(chunk)`, `finalize()` returns 64 bytes. Holds the sha3 module exclusively from construction until `finalize()` or `dispose()`. |
| `SHAKE128` | class | SHAKE128 XOF (FIPS 202). Unbounded output. `hash(msg, outputLength)`, `absorb(msg)`, `squeeze(n)`, `reset()`. |
| `SHAKE256` | class | SHAKE256 XOF (FIPS 202). Unbounded output. `hash(msg, outputLength)`, `absorb(msg)`, `squeeze(n)`, `reset()`. |
| `SHAKE128Stream` | class | Fixed-output streaming SHAKE128. `new SHAKE128Stream(outputLen)`, `update(chunk)`, `finalize()` returns exactly `outputLen` bytes and disposes. Holds the sha3 module exclusively from construction until `finalize()` or `dispose()`. Substrate for `createRunningHash('shake-128')` in the sign layer. |
| `SHAKE256Stream` | class | Fixed-output streaming SHAKE256. Same shape as `SHAKE128Stream`. Substrate for `createRunningHash('shake-256')`. |
| `CSHAKE128` | class | cSHAKE128 customizable XOF (SP 800-185 §3). `new CSHAKE128(customization)`, `hash(msg, outputLength)`, `absorb(msg)`, `squeeze(n)`, `reset()`. Throws if customization is empty (use SHAKE128 instead). |
| `CSHAKE256` | class | cSHAKE256 customizable XOF (SP 800-185 §3). Same shape as CSHAKE128 with the 256-bit-strength rate. |
| `KMAC128` | class | KMAC128 keyed Keccak MAC, fixed-output (SP 800-185 §4). `new KMAC128(key, outLen, customization)`, `update(chunk)`, `finalize()`, `mac(msg)`, static `verify(tag, key, msg, customization)` (throws `AuthenticationError('kmac128')` on mismatch). |
| `KMAC256` | class | KMAC256 keyed Keccak MAC, fixed-output (SP 800-185 §4). Same shape as KMAC128 with `AuthenticationError('kmac256')` discriminator. |
| `KMACXOF128` | class | KMAC128 in XOF mode (SP 800-185 §4.3.1). `new KMACXOF128(key, customization)`, `update(chunk)`, `squeeze(n)`, `mac(msg, outLen)`. No static `verify`, caller squeezes a fixed length and uses `constantTimeEqual`. |
| `KMACXOF256` | class | KMAC256 in XOF mode (SP 800-185 §4.3.1). Same shape as KMACXOF128. |

---

## Keccak (alias for SHA-3)

`'keccak'` is an alias for `'sha3'`. Same WASM binary, same instance slot.
Both `init({ sha3: sha3Wasm })` and `init({ keccak: keccakWasm })` load the same module.
Provided so Kyber/ML-KEM consumers can use the semantically correct primitive name.
Subpath: `leviathan-crypto/keccak`.

| Export | Kind | Description |
|--------|------|-------------|
| `keccakInit` | function | Alias init. `keccakInit(source: WasmSource)` loads the sha3 WASM slot via the keccak alias. |
| `SHA3_224` | class | Re-exported from `leviathan-crypto/sha3`. |
| `SHA3_256` | class | Re-exported from `leviathan-crypto/sha3`. |
| `SHA3_384` | class | Re-exported from `leviathan-crypto/sha3`. |
| `SHA3_512` | class | Re-exported from `leviathan-crypto/sha3`. |
| `SHAKE128` | class | Re-exported from `leviathan-crypto/sha3`. |
| `SHAKE256` | class | Re-exported from `leviathan-crypto/sha3`. |
| `CSHAKE128` | class | Re-exported from `leviathan-crypto/sha3`. |
| `CSHAKE256` | class | Re-exported from `leviathan-crypto/sha3`. |
| `KMAC128` | class | Re-exported from `leviathan-crypto/sha3`. |
| `KMAC256` | class | Re-exported from `leviathan-crypto/sha3`. |
| `KMACXOF128` | class | Re-exported from `leviathan-crypto/sha3`. |
| `KMACXOF256` | class | Re-exported from `leviathan-crypto/sha3`. |

---

## BLAKE3

Requires `init({ blake3: blake3Wasm })` or subpath `blake3Init(source)`. v128 SIMD required (the module ships a v128-internal `compress` and a v128-external lane-parallel `compress4`, no scalar fallback).
Subpath: `leviathan-crypto/blake3`. See [blake3.md](./blake3.md).

| Export | Kind | Description |
|--------|------|-------------|
| `blake3Init` | function | Module-scoped init. `blake3Init(source: WasmSource)` loads only blake3. |
| `BLAKE3` | class | One-shot default-mode hash (BLAKE3 §2.3 `hash`). `hash(msg, outLen?)` returns `outLen` bytes (default 32, max 1024 per call; use the streaming class plus `finalizeXof()` for unbounded output). Atomic, does not hold module exclusivity. |
| `BLAKE3Stream` | class | Incremental default-mode hash. `update(chunk)`, `finalize(outLen?)` returns up to 1024 bytes and disposes; `finalizeXof()` returns a `BLAKE3OutputReader` for unbounded output. Holds the blake3 module exclusively from construction until `finalize()` / `finalizeXof()` / `dispose()`. |
| `BLAKE3KeyedHash` | class | One-shot keyed_hash (BLAKE3 §2.3 `keyed_hash`). `hash(key, msg, outLen?)` requires a 32-byte key; output behaviour matches `BLAKE3.hash`. Atomic. |
| `BLAKE3KeyedHashStream` | class | Incremental keyed_hash. Constructor takes the 32-byte key; otherwise identical to `BLAKE3Stream`. Holds the blake3 module exclusively until disposed. |
| `BLAKE3DeriveKey` | class | One-shot derive_key (BLAKE3 §2.3 `derive_key`, two-pass). `derive(context, keyMaterial, outLen?)`: pass 1 hashes the context string with `DERIVE_KEY_CONTEXT`; pass 2 hashes `keyMaterial` with `DERIVE_KEY_MATERIAL` under the context CV. Atomic. |
| `BLAKE3DeriveKeyStream` | class | Incremental derive_key. Constructor takes the context string; `update(chunk)` feeds key material; `finalize(outLen?)` / `finalizeXof()` as above. Holds the blake3 module exclusively until disposed. |
| `BLAKE3OutputReader` | class | Unbounded XOF reader returned by any streaming class's `finalizeXof()`. `read(n)` lifts the next `n` bytes off the §2.6 root-state snapshot via the WASM `squeezeXofBlock` export; holds module exclusivity until `dispose()`. |
| `BLAKE3Hash` | const | `HashFn` const wrapping `BLAKE3.hash` at the default 32-byte digest size. Compatible with the `Fortuna` accumulator slot alongside `SHA256Hash` and `SHA3_256Hash`. `outputSize: 32`, `wasmModules: ['blake3']`. Requires `init({ blake3 })`. |

---

## Ed25519 / X25519 (Curve25519 family)

Requires `init({ ed25519: curve25519Wasm })` (or equivalently `init({ x25519: curve25519Wasm })`, or `init({ curve25519: curve25519Wasm })`). Both aliases resolve to the same `curve25519` WASM module, which hosts the Ed25519 (RFC 8032) and X25519 (RFC 7748) substrates plus an embedded SHA-512. Scalar (no SIMD); works on every WASM-capable runtime regardless of SIMD support.

Subpaths: `leviathan-crypto/ed25519` and `leviathan-crypto/x25519`. See [ed25519.md](./ed25519.md) and [x25519.md](./x25519.md). The `Ed25519PreHashSuite` envelope path additionally requires `init({ sha2: sha2Wasm })` because the message-taking and streaming SHA-512 hashers drive the sha2 module.

| Export | Kind | Description |
|--------|------|-------------|
| `ed25519Init` | function | Module-scoped init. `ed25519Init(source: WasmSource)` loads the curve25519 WASM under the `curve25519` slot. |
| `x25519Init` | function | Module-scoped init. `x25519Init(source: WasmSource)` loads the curve25519 WASM under the `curve25519` slot. Calling either `ed25519Init` or `x25519Init` enables both `Ed25519` and `X25519`. |
| `Ed25519` | class | Ed25519 classical signer (RFC 8032 §5.1, Ed25519). `keygen()`, `keygenDerand(seed)`, `sign(sk, pk, M)`, `signPrehashed(sk, pk, digest, ctx?)`, `verify(pk, M, sig)`, `verifyPrehashed(pk, digest, ctx, sig)`, `dispose()`. Strict verification per FIPS 186-5 §7.6.4, Verification. The sign methods include a fault-injection cross-check; see [ed25519.md](./ed25519.md#fault-injection-defense). |
| `X25519` | class | X25519 classical Diffie-Hellman (RFC 7748 §5, The X25519 and X448 Functions). `keygen()`, `keygenDerand(sk)`, `dh(sk, peerPk)`, `dispose()`. `dh` throws `KeyAgreementError` on an all-zero shared secret (small-order peer pk per RFC 7748 §6.1, Curve25519). |
| `Ed25519KeyPair` | type | `{ publicKey: Uint8Array, secretKey: Uint8Array }`. Both 32 bytes; `secretKey` is the RFC 8032 §5.1.5, key generation, seed. |
| `X25519KeyPair` | type | `{ publicKey: Uint8Array, secretKey: Uint8Array }`. Both 32 bytes; `secretKey` is opaque 32 random bytes (not pre-clamped). |
| `Ed25519Suite` | const | Pure Ed25519 `SignatureSuite` (RFC 8032 §5.1.6, signature generation). `formatEnum: 0x01`, `ctxDomain: 'ed25519-envelope-v3'`, `pkSize: 32`, `skSize: 32`, `sigSize: 64`. Rejects non-empty user_ctx with `SigningError('sig-ctx-unsupported')`. Requires `init({ ed25519 })`. |
| `Ed25519PreHashSuite` | const | Ed25519ph `StreamableSignatureSuite` (RFC 8032 §5.1.7, signature verification, dom2(F=1, ctx) prehash). `formatEnum: 0x11`, `ctxDomain: 'ed25519-prehash-envelope-v3'`, `prehashAlgorithm: 'sha-512'`, `prehashSize: 64`, `pkSize: 32`, `skSize: 32`, `sigSize: 64`. Plugs into `SignStream` / `VerifyStream`. Requires `init({ ed25519, sha2 })`. |
| `KeyAgreementError` | class | Thrown by `X25519.dh` when the resulting shared secret is all-zero, indicating a small-order peer public key. Extends `Error`. Branch on `err instanceof KeyAgreementError` to distinguish this from a caller-side contract violation. |

---

## ML-KEM (Post-quantum KEM)

Requires `init({ kyber: kyberWasm, sha3: sha3Wasm })`.
Subpath: `leviathan-crypto/kyber`. See [kyber.md](./kyber.md).

| Export | Kind | Description |
|--------|------|-------------|
| `kyberInit` | function | Module-scoped init. `kyberInit(source: WasmSource)` loads only kyber WASM. |
| `MlKemBase` | class | Abstract base class for all ML-KEM variants. Holds `params: KyberParams`. Not normally instantiated directly. Use `MlKem512`, `MlKem768`, or `MlKem1024`. |
| `MlKem512` | class | ML-KEM-512. k=2, η₁=3. `keygen()`, `encapsulate(ek)`, `decapsulate(dk, c)`, `checkEncapsulationKey(ek)`, `checkDecapsulationKey(dk)`. |
| `MlKem768` | class | ML-KEM-768. k=3, η₁=2. Recommended default. Same API as MlKem512. |
| `MlKem1024` | class | ML-KEM-1024. k=4, η₁=2. Same API as MlKem512. |
| `KyberSuite` | function | Factory. `KyberSuite(kem, innerCipher)` → `CipherSuite & { keygen(): KyberKeyPair }`. Wraps `MlKemBase` + `CipherSuite` into a hybrid KEM+AEAD suite for use with `Seal`, `SealStream`, `OpenStream`. |
| `KyberKeyPair` | type | `{ encapsulationKey: Uint8Array, decapsulationKey: Uint8Array }` |
| `KyberEncapsulation` | type | `{ ciphertext: Uint8Array, sharedSecret: Uint8Array }` |
| `KyberParams` | type | Parameter set configuration (k, η₁, η₂, dᵤ, dᵥ, byte sizes). |
| `MLKEM512` | const | Parameter set for ML-KEM-512. |
| `MLKEM768` | const | Parameter set for ML-KEM-768. |
| `MLKEM1024` | const | Parameter set for ML-KEM-1024. |

> [!NOTE]
> `ntt_scalar` and `invntt_scalar` are scalar NTT references exported for SIMD gate tests. They are not part of the public API.

---

## ML-DSA (Post-quantum signatures)

Requires `init({ mldsa: mldsaWasm, sha3: sha3Wasm })`. HashML-DSA with a
SHA-2 family pre-hash additionally requires `init({ sha2: sha2Wasm })`;
SHA-3 / SHAKE pre-hashes reuse the existing `sha3` module.
Subpath: `leviathan-crypto/mldsa`. See [mldsa.md](./mldsa.md).

ML-DSA classes ship pure-ML-DSA `keygen` / `keygenDerand` / `sign` /
`signDeterministic` / `signDerand` / `verify` and the HashML-DSA pre-hash
counterparts `signHash` / `signHashDeterministic` / `signHashDerand` /
`verifyHash` (FIPS 204 §5.4 Algorithms 4 & 5).

| Export | Kind | Description |
|--------|------|-------------|
| `mldsaInit` | function | Module-scoped init. `mldsaInit(source: WasmSource)` loads only the mldsa WASM. |
| `MlDsaBase` | class | Abstract base class for all ML-DSA variants. Holds `params: MlDsaParams`. Not normally instantiated directly, use `MlDsa44`, `MlDsa65`, or `MlDsa87`. |
| `MlDsa44` | class | ML-DSA-44 (k=4, ℓ=4, η=2; NIST category 2). `keygen()`, `keygenDerand(xi)`, `sign(sk, M, ctx?)`, `signDeterministic(sk, M, ctx?)`, `signDerand(sk, M, ctx, rnd)`, `verify(vk, M, sig, ctx?)`, `signHash(sk, M, ph, ctx?)`, `signHashDeterministic(sk, M, ph, ctx?)`, `signHashDerand(sk, M, ph, ctx, rnd)`, `verifyHash(vk, M, sig, ph, ctx?)`, `signHashPrehashed(sk, digest, ph, ctx?)`, `signHashPrehashedDeterministic(sk, digest, ph, ctx?)`, `signHashPrehashedDerand(sk, digest, ph, ctx, rnd)`, `verifyHashPrehashed(vk, digest, sig, ph, ctx?)`, `dispose()`. |
| `MlDsa65` | class | ML-DSA-65 (k=6, ℓ=5, η=4; NIST category 3). Recommended default. Same API as `MlDsa44`. |
| `MlDsa87` | class | ML-DSA-87 (k=8, ℓ=7, η=2; NIST category 5). Same API as `MlDsa44`. |
| `MlDsaKeyPair` | type | `{ verificationKey: Uint8Array, signingKey: Uint8Array }` (FIPS 204 pkEncode / skEncode). |
| `MlDsaParams` | type | Parameter-set configuration (k, ℓ, η, τ, λ, γ₁, γ₂, ω, β, byte sizes). |
| `PreHashAlgorithm` | type | Tagged union of approved HashML-DSA pre-hash functions: `'SHA2-224'`, `'SHA2-256'`, `'SHA2-384'`, `'SHA2-512'`, `'SHA2-512/224'`, `'SHA2-512/256'`, `'SHA3-224'`, `'SHA3-256'`, `'SHA3-384'`, `'SHA3-512'`, `'SHAKE128'`, `'SHAKE256'`. SHAKE128 is fixed at 256-bit / SHAKE256 at 512-bit output per FIPS 204 §5.4.1. |
| `MLDSA44` | const | Parameter set for ML-DSA-44. |
| `MLDSA65` | const | Parameter set for ML-DSA-65. |
| `MLDSA87` | const | Parameter set for ML-DSA-87. |

---

## SLH-DSA (Post-quantum signatures)

Requires `init({ slhdsa: slhdsaWasm })`. HashSLH-DSA with a SHA-2 family
pre-hash additionally requires `init({ sha2: sha2Wasm })`; HashSLH-DSA
with a SHA-3 or SHAKE pre-hash additionally requires
`init({ sha3: sha3Wasm })`. Pure-mode SLH-DSA needs neither, the slhdsa
WASM module embeds its own Keccak permutation for the internal
F / H / T_l / PRF / PRFmsg / Hmsg primitives.
Subpath: `leviathan-crypto/slhdsa`. See [slhdsa.md](./slhdsa.md).

SLH-DSA classes ship pure-SLH-DSA `keygen` / `keygenDerand` / `sign` /
`signDeterministic` / `signDerand` / `verify` and the HashSLH-DSA
pre-hash counterparts `signHash` / `signHashDeterministic` /
`signHashDerand` / `verifyHash`, plus the caller-supplied-prehash
variants `signHashPrehashed` / `signHashPrehashedDeterministic` /
`signHashPrehashedDerand` / `verifyHashPrehashed` (FIPS 205 §10.2.2
Algorithm 23 / §10.3 Algorithm 25).

| Export | Kind | Description |
|--------|------|-------------|
| `slhdsaInit` | function | Module-scoped init. `slhdsaInit(source: WasmSource)` loads only the slhdsa WASM. |
| `SlhDsaBase` | class | Abstract base class for all SLH-DSA variants. Holds `params: SlhDsaParams`. Not normally instantiated directly, use `SlhDsa128f`, `SlhDsa192f`, or `SlhDsa256f`. |
| `SlhDsa128f` | class | SLH-DSA-SHAKE-128f (n=16, h=66, d=22, h'=3, a=6, k=33, lg(w)=4; NIST category 1). pk 32 B, sk 64 B, sig 17088 B. Same method surface as `SlhDsa192f`. |
| `SlhDsa192f` | class | SLH-DSA-SHAKE-192f (n=24, h=66, d=22, h'=3, a=8, k=33, lg(w)=4; NIST category 3). pk 48 B, sk 96 B, sig 35664 B. `keygen()`, `keygenDerand(seed)`, `sign(sk, M, ctx?)`, `signDeterministic(sk, M, ctx?)`, `signDerand(sk, M, optRand, ctx?)`, `verify(pk, M, sig, ctx?)`, `signHash(sk, M, ph, ctx?)`, `signHashDeterministic(sk, M, ph, ctx?)`, `signHashDerand(sk, M, ph, optRand, ctx?)`, `verifyHash(pk, M, sig, ph, ctx?)`, `signHashPrehashed(sk, digest, ph, ctx?)`, `signHashPrehashedDeterministic(sk, digest, ph, ctx?)`, `signHashPrehashedDerand(sk, digest, ph, optRand, ctx?)`, `verifyHashPrehashed(pk, digest, sig, ph, ctx?)`, `dispose()`. |
| `SlhDsa256f` | class | SLH-DSA-SHAKE-256f (n=32, h=68, d=17, h'=4, a=9, k=35, lg(w)=4; NIST category 5). pk 64 B, sk 128 B, sig 49856 B. Same API as `SlhDsa192f`. |
| `SlhDsaKeyPair` | type | `{ verificationKey: Uint8Array, signingKey: Uint8Array }` (FIPS 205 pkEncode / skEncode). |
| `SlhDsaParams` | type | Parameter-set configuration (n, h, d, h', a, k, lg(w), securityCategory, byte sizes, paramSet name, wasmSelector). |
| `SLHDSA128F` | const | Parameter set for SLH-DSA-SHAKE-128f. |
| `SLHDSA192F` | const | Parameter set for SLH-DSA-SHAKE-192f. |
| `SLHDSA256F` | const | Parameter set for SLH-DSA-SHAKE-256f. |

---

## Fortuna CSPRNG

Takes a `Generator` and a `HashFn` at create time. Required `init()` modules depend on which pair you pass; valid combinations are listed in [fortuna.md](./fortuna.md).

| Export | Kind | Description |
|--------|------|-------------|
| `Fortuna`            | class    | Fortuna CSPRNG (Ferguson & Schneier). `Fortuna.create({ generator, hash })` static factory; `get(n)`, `addEntropy()`, `stop()`. |
| `AESGenerator`       | const    | `Generator` const for `Fortuna`. AES-256 PRF in counter mode (Practical Cryptography §9.4, the spec-canonical generator). Requires `init({ aes })`. Re-exported from `'leviathan-crypto/aes'`. |
| `SerpentGenerator`   | const    | `Generator` const for `Fortuna`. Serpent-256 PRF in counter mode. Requires `init({ serpent })`. Re-exported from `'leviathan-crypto/serpent'`. |
| `ChaCha20Generator`  | const    | `Generator` const for `Fortuna`. ChaCha20 PRF with fixed zero nonce. Requires `init({ chacha20 })`. Re-exported from `'leviathan-crypto/chacha20'`. |
| `SHA256Hash`         | const    | `HashFn` const for `Fortuna`. Stateless SHA-256. Requires `init({ sha2 })`. Re-exported from `'leviathan-crypto/sha2'`. |
| `SHA3_256Hash`       | const    | `HashFn` const for `Fortuna`. Stateless SHA3-256. Requires `init({ sha3 })`. Re-exported from `'leviathan-crypto/sha3'`. |
| `Generator`          | type     | Interface implemented by `AESGenerator`, `SerpentGenerator`, and `ChaCha20Generator`. |
| `HashFn`             | type     | Interface implemented by `SHA256Hash`, `SHA3_256Hash`, and `BLAKE3Hash`. |

---

## Ratchet (Sparse Post-Quantum Ratchet KDF)

`ratchetInit`, `KDFChain`, `ratchetReady` require `init({ sha2: sha2Wasm })`.
`kemRatchetEncap`, `kemRatchetDecap` additionally require `init({ kyber: kyberWasm, sha3: sha3Wasm })`.
Subpath: `leviathan-crypto/ratchet`. See [ratchet.md](./ratchet.md).

| Export | Kind | Description |
|--------|------|-------------|
| `ratchetInit` | function | `ratchetInit(sk, context?)`, derives initial root key, send chain key, and receive chain key from a 32-byte shared secret (`KDF_SCKA_INIT`). Returns `RatchetInitResult`. |
| `KDFChain` | class | Stateful symmetric ratchet chain (`KDF_SCKA_CK`). `new KDFChain(ck)`, `step()` → 32-byte message key, `stepWithCounter()` → `{ key, counter }`, `dispose()`. |
| `SkippedKeyStore` | class | MKSKIPPED cache for a single `KDFChain` (DR spec §3.2/§3.5). `new SkippedKeyStore({ maxCacheSize?, maxSkipPerResolve? })`. `resolve(chain, counter)` → `ResolveHandle`, call `handle.commit()` on successful decrypt, `handle.rollback()` on auth failure. `advanceToBoundary(chain, pn)`, `size`, `wipeAll()`. Requires `sha2`. |
| `RatchetKeypair` | class | Single-use ek/dk lifecycle for one KEM ratchet step. `new RatchetKeypair(kem)`, `readonly ek`, `decap(kem, rk, kemCt, context?)`, `dispose()`. Requires `sha2`, `kyber`, `sha3`. |
| `kemRatchetEncap` | function | `kemRatchetEncap(kem, rk, peerEk, context?)`, encapsulation side of a KEM ratchet step (`KDF_SCKA_RK`). Returns `KemEncapResult` including `kemCt` to transmit to peer. |
| `kemRatchetDecap` | function | `kemRatchetDecap(kem, rk, dk, kemCt, ownEk, context?)`, decapsulation side of a KEM ratchet step. `ownEk` is the local party's encapsulation key, bound into the HKDF info string alongside `peerEk` and `kemCt` as defense-in-depth on top of the KEM FO transform. Returns `KemDecapResult` with chain key slots swapped to match Bob's perspective. |
| `ratchetReady` | function | `ratchetReady(): boolean`, returns `true` if `sha2` has been initialized. |
| `RatchetInitResult` | type | `{ nextRootKey, sendChainKey, recvChainKey }`, all 32-byte `Uint8Array` fields. |
| `KemEncapResult` | type | `{ nextRootKey, sendChainKey, recvChainKey, kemCt }`, three 32-byte keys plus the ML-KEM ciphertext. |
| `KemDecapResult` | type | `{ nextRootKey, sendChainKey, recvChainKey }`, all 32-byte `Uint8Array` fields. Slots are swapped relative to the encap side. |
| `RatchetMessageHeader` | interface | `{ epoch, counter, pn?, kemCt? }`, canonical message header shape. `pn` and `kemCt` present only on the first message of a new epoch. |
| `MlKemLike` | interface | Structural interface satisfied by `MlKem512`, `MlKem768`, `MlKem1024`. Used as the `kem` parameter type for `kemRatchetEncap`/`kemRatchetDecap`/`RatchetKeypair`. |
| `ResolveHandle` | interface | Return type of `SkippedKeyStore.resolve()`. `readonly key`, 32-byte message key (throws after settlement). `commit()`, wipes key, marks settled (call on successful decrypt). `rollback()`, returns key to store, marks settled (call on auth failure). Double-settle throws. |

---

## Types

No `init()` required. See [types.md](./types.md).

| Export | Kind | Description |
|--------|------|-------------|
| `Hash` | interface | `hash(msg): Uint8Array`, `dispose()` |
| `KeyedHash` | interface | `hash(key, msg): Uint8Array`, `dispose()` |
| `Blockcipher` | interface | `encrypt(block): Uint8Array`, `decrypt(block): Uint8Array`, `dispose()` |
| `Streamcipher` | interface | `encrypt(msg): Uint8Array`, `decrypt(msg): Uint8Array`, `dispose()` |
| `AEAD` | interface | `encrypt(msg, aad?): Uint8Array`, `decrypt(ciphertext, aad?): Uint8Array`, `dispose()` |

---

## Utilities

No `init()` required. See [utils.md](./utils.md).

| Export | Kind | Description |
|--------|------|-------------|
| `hexToBytes` | function | Hex string to `Uint8Array`. Accepts `0x` prefix, uppercase/lowercase. Throws `RangeError` on odd-length input. |
| `bytesToHex` | function | `Uint8Array` to lowercase hex string. |
| `utf8ToBytes` | function | UTF-8 string to `Uint8Array`. |
| `bytesToUtf8` | function | `Uint8Array` to UTF-8 string. |
| `base64ToBytes` | function | Base64/base64url string to `Uint8Array`. Returns `undefined` on invalid input. |
| `bytesToBase64` | function | `Uint8Array` to base64 string. Pass `url=true` for base64url. |
| `constantTimeEqual` | function | Constant-time byte-array equality. Runs entirely inside a dedicated WASM SIMD module (v128 XOR-accumulate with branch-free reduction) to eliminate JIT timing leaks. Throws a branded error on runtimes without WebAssembly SIMD; no JS fallback. Returns `false` immediately on length mismatch. Throws `RangeError` if either input exceeds `CT_MAX_BYTES`. |
| `CT_MAX_BYTES` | const | Maximum input size for `constantTimeEqual` per side (32768 bytes, one 64 KiB WASM page split between two buffers). |
| `wipe` | function | Zero a typed array in place. |
| `xor` | function | XOR two equal-length `Uint8Array`s, returns new array. |
| `concat` | function | Concatenate one or more `Uint8Array`s into a new array. Variadic. |
| `randomBytes` | function | Cryptographically secure random bytes via Web Crypto API. |
| `hasSIMD` | function | Returns `true` if the runtime supports WebAssembly SIMD. Cached after first call. Used internally for CTR/CBC-decrypt and ChaCha20 dispatch. Exported for informational use. |

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |

