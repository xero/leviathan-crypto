<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### All Exports

Complete reference for every public export in leviathan-crypto, grouped by module. Follow the module links for deeper documentation on each class.

> ### Table of Contents
> - [Initialization](#initialization)
> - [Serpent-256](#serpent-256)
> - [Stream](#stream)
> - [Errors](#errors)
> - [XChaCha20 / Poly1305](#xchacha20--poly1305)
> - [SHA-2](#sha-2)
> - [SHA-3](#sha-3)
> - [Keccak (alias for SHA-3)](#keccak-alias-for-sha-3)
> - [ML-KEM (Post-quantum KEM)](#ml-kem-post-quantum-kem)
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
| `Module` | type | `'serpent' \| 'chacha20' \| 'sha2' \| 'sha3' \| 'keccak' \| 'kyber'` |
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

## Stream

Cipher-agnostic streaming encryption using the STREAM construction.
Subpath: `leviathan-crypto/stream`. See [aead.md](./aead.md).

| Export | Kind | Description |
|--------|------|-------------|
| `Seal` | class (static) | One-shot AEAD. `Seal.encrypt(suite, key, plaintext)` / `Seal.decrypt(suite, key, blob)`. Works with any `CipherSuite` including `KyberSuite`. Never instantiated. |
| `SealStream` | class | Cipher-agnostic streaming encryption (STREAM construction). `push(chunk)`, `finalize(chunk)`, `toTransformStream()`. |
| `OpenStream` | class | Cipher-agnostic streaming decryption. `pull(chunk)`, `finalize(chunk)`, `seek(index)`, `toTransformStream()`. |
| `SealStreamPool` | class | Parallel batch seal/open via Web Workers. `SealStreamPool.create(cipher, key, opts)` static factory. |
| `CipherSuite` | interface | Cipher-specific logic injected into SealStream/OpenStream. Implementations: `XChaCha20Cipher`, `SerpentCipher`, `KyberSuite`. See [ciphersuite.md](./ciphersuite.md). |
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

## Errors

| Export | Kind | Description |
|--------|------|-------------|
| `AuthenticationError` | class | Thrown on AEAD auth failure. Extends `Error`. Constructor takes cipher name string. |

---

## XChaCha20 / Poly1305

Requires `init({ chacha20: chacha20Wasm })` or subpath `chacha20Init()`.
Subpath: `leviathan-crypto/chacha20`. See [chacha20.md](./chacha20.md).

| Export | Kind | Description |
|--------|------|-------------|
| `chacha20Init` | function | Module-scoped init. `chacha20Init(source: WasmSource)` loads only chacha20. |
| `XChaCha20Poly1305` | class | XChaCha20-Poly1305 AEAD. 24-byte nonce. `encrypt()` returns single `Uint8Array` (ct‖tag), `decrypt()` accepts same format. Single-use encrypt guard. |
| `XChaCha20Cipher` | const | `CipherSuite` for XChaCha20-Poly1305. `keygen()` → 32-byte key. `formatEnum: 0x01`, `keySize: 32`, `tagSize: 16`, `padded: false`. Used with `Seal`, `SealStream`, `OpenStream`. |
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
| `SHA256` | class | SHA-256 hash (FIPS 180-4). `hash(msg)` returns 32 bytes. |
| `SHA384` | class | SHA-384 hash (FIPS 180-4). `hash(msg)` returns 48 bytes. |
| `SHA512` | class | SHA-512 hash (FIPS 180-4). `hash(msg)` returns 64 bytes. |
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
| `SHAKE128` | class | SHAKE128 XOF (FIPS 202). Unbounded output. `hash(msg, outputLength)`, `absorb(msg)`, `squeeze(n)`, `reset()`. |
| `SHAKE256` | class | SHAKE256 XOF (FIPS 202). Unbounded output. `hash(msg, outputLength)`, `absorb(msg)`, `squeeze(n)`, `reset()`. |

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

## Fortuna CSPRNG

Takes a `Generator` and a `HashFn` at create time. Required `init()` modules depend on which pair you pass; valid combinations are listed in [fortuna.md](./fortuna.md).

| Export | Kind | Description |
|--------|------|-------------|
| `Fortuna`            | class    | Fortuna CSPRNG (Ferguson & Schneier). `Fortuna.create({ generator, hash })` static factory; `get(n)`, `addEntropy()`, `stop()`. |
| `SerpentGenerator`   | const    | `Generator` const for `Fortuna`. Serpent-256 PRF in counter mode. Requires `init({ serpent })`. Re-exported from `'leviathan-crypto/serpent'`. |
| `ChaCha20Generator`  | const    | `Generator` const for `Fortuna`. ChaCha20 PRF with fixed zero nonce. Requires `init({ chacha20 })`. Re-exported from `'leviathan-crypto/chacha20'`. |
| `SHA256Hash`         | const    | `HashFn` const for `Fortuna`. Stateless SHA-256. Requires `init({ sha2 })`. Re-exported from `'leviathan-crypto/sha2'`. |
| `SHA3_256Hash`       | const    | `HashFn` const for `Fortuna`. Stateless SHA3-256. Requires `init({ sha3 })`. Re-exported from `'leviathan-crypto/sha3'`. |
| `Generator`          | type     | Interface implemented by `SerpentGenerator` and `ChaCha20Generator`. |
| `HashFn`             | type     | Interface implemented by `SHA256Hash` and `SHA3_256Hash`. |

---

## Ratchet (Sparse Post-Quantum Ratchet KDF)

`ratchetInit`, `KDFChain`, `ratchetReady` require `init({ sha2: sha2Wasm })`.
`kemRatchetEncap`, `kemRatchetDecap` additionally require `init({ kyber: kyberWasm, sha3: sha3Wasm })`.
Subpath: `leviathan-crypto/ratchet`. See [ratchet.md](./ratchet.md).

| Export | Kind | Description |
|--------|------|-------------|
| `ratchetInit` | function | `ratchetInit(sk, context?)` — derives initial root key, send chain key, and receive chain key from a 32-byte shared secret (`KDF_SCKA_INIT`). Returns `RatchetInitResult`. |
| `KDFChain` | class | Stateful symmetric ratchet chain (`KDF_SCKA_CK`). `new KDFChain(ck)`, `step()` → 32-byte message key, `stepWithCounter()` → `{ key, counter }`, `dispose()`. |
| `SkippedKeyStore` | class | MKSKIPPED cache for a single `KDFChain` (DR spec §3.2/§3.5). `new SkippedKeyStore({ maxCacheSize?, maxSkipPerResolve? })`. `resolve(chain, counter)` → `ResolveHandle` — call `handle.commit()` on successful decrypt, `handle.rollback()` on auth failure. `advanceToBoundary(chain, pn)`, `size`, `wipeAll()`. Requires `sha2`. |
| `RatchetKeypair` | class | Single-use ek/dk lifecycle for one KEM ratchet step. `new RatchetKeypair(kem)`, `readonly ek`, `decap(kem, rk, kemCt, context?)`, `dispose()`. Requires `sha2`, `kyber`, `sha3`. |
| `kemRatchetEncap` | function | `kemRatchetEncap(kem, rk, peerEk, context?)` — encapsulation side of a KEM ratchet step (`KDF_SCKA_RK`). Returns `KemEncapResult` including `kemCt` to transmit to peer. |
| `kemRatchetDecap` | function | `kemRatchetDecap(kem, rk, dk, kemCt, ownEk, context?)` — decapsulation side of a KEM ratchet step. `ownEk` is the local party's encapsulation key, bound into the HKDF info string alongside `peerEk` and `kemCt` as defense-in-depth on top of the KEM FO transform. Returns `KemDecapResult` with chain key slots swapped to match Bob's perspective. |
| `ratchetReady` | function | `ratchetReady(): boolean` — returns `true` if `sha2` has been initialized. |
| `RatchetInitResult` | type | `{ nextRootKey, sendChainKey, recvChainKey }` — all 32-byte `Uint8Array` fields. |
| `KemEncapResult` | type | `{ nextRootKey, sendChainKey, recvChainKey, kemCt }` — three 32-byte keys plus the ML-KEM ciphertext. |
| `KemDecapResult` | type | `{ nextRootKey, sendChainKey, recvChainKey }` — all 32-byte `Uint8Array` fields. Slots are swapped relative to the encap side. |
| `RatchetMessageHeader` | interface | `{ epoch, counter, pn?, kemCt? }` — canonical message header shape. `pn` and `kemCt` present only on the first message of a new epoch. |
| `MlKemLike` | interface | Structural interface satisfied by `MlKem512`, `MlKem768`, `MlKem1024`. Used as the `kem` parameter type for `kemRatchetEncap`/`kemRatchetDecap`/`RatchetKeypair`. |
| `ResolveHandle` | interface | Return type of `SkippedKeyStore.resolve()`. `readonly key` — 32-byte message key (throws after settlement). `commit()` — wipes key, marks settled (call on successful decrypt). `rollback()` — returns key to store, marks settled (call on auth failure). Double-settle throws. |

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

