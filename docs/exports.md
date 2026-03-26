# All Exports

Complete reference for every public export in leviathan-crypto, grouped by module.
For deeper documentation on each class follow the module links.

---

## Initialization

Root barrel `leviathan-crypto` — no module required.

| Export | Kind | Description |
|--------|------|-------------|
| `init` | function | Load and cache WASM modules. Dispatches to per-module init functions. |
| `Module` | type | `'serpent' \| 'chacha20' \| 'sha2' \| 'sha3'` |
| `Mode` | type | `'embedded' \| 'streaming' \| 'manual'` |
| `InitOpts` | type | Options for `init()`: `wasmUrl`, `wasmBinary` |

See [init.md](./init) for full loading mode documentation.

---

## Serpent-256

Requires `init(['serpent', 'sha2'])` for authenticated classes, `init(['serpent'])` for raw modes.
Subpath: `leviathan-crypto/serpent` — see [serpent.md](./serpent).

| Export | Kind | Description |
|--------|------|-------------|
| `serpentInit` | function | Module-scoped init. `serpentInit(mode?, opts?)` loads only serpent. |
| `SerpentSeal` | class | Authenticated encryption: Serpent-CBC + HMAC-SHA256. `encrypt(key, plaintext)`, `decrypt(key, ciphertext)`. 64-byte key. |
| `SerpentStream` | class | Chunked one-shot AEAD for large payloads. `seal(key, plaintext, chunkSize?)`, `open(key, ciphertext)`. 32-byte key. |
| `SerpentStreamPool` | class | Worker-pool wrapper for `SerpentStream`. Parallelises chunk encryption across isolated WASM instances. `SerpentStreamPool.create(opts?)` static factory. |
| `SerpentStreamSealer` | class | Incremental streaming AEAD: seal one chunk at a time. `header()`, `seal(plaintext)`, `final(plaintext)`, `dispose()`. 64-byte key. |
| `SerpentStreamOpener` | class | Incremental streaming AEAD: open one chunk at a time. `open(chunk)`, `dispose()`. Initialized from sealer `header()` output. |
| `Serpent` | class | Serpent-256 ECB block cipher. `loadKey()`, `encryptBlock()`, `decryptBlock()`. Unauthenticated. |
| `SerpentCtr` | class | Serpent-256 CTR mode. `beginEncrypt()`, `encryptChunk()`, `beginDecrypt()`, `decryptChunk()`. Unauthenticated. |
| `SerpentCbc` | class | Serpent-256 CBC mode with PKCS7 padding. `encrypt(key, iv, plaintext)`, `decrypt(key, iv, ciphertext)`. Unauthenticated. |
| `StreamPoolOpts` | type | Options for `SerpentStreamPool.create()`: worker count. |

---

## XChaCha20 / Poly1305

Requires `init(['chacha20'])` or subpath `chacha20Init()`.
Subpath: `leviathan-crypto/chacha20` — see [chacha20.md](./chacha20), [chacha20_pool.md](./chacha20_pool).

| Export | Kind | Description |
|--------|------|-------------|
| `chacha20Init` | function | Module-scoped init. `chacha20Init(mode?, opts?)` loads only chacha20. |
| `XChaCha20Poly1305` | class | XChaCha20-Poly1305 AEAD. 24-byte nonce. `encrypt(key, nonce, plaintext, aad?)`, `decrypt(key, nonce, ciphertext, aad?)`. |
| `XChaCha20Poly1305Pool` | class | Worker-pool wrapper for `XChaCha20Poly1305`. `XChaCha20Poly1305Pool.create(opts?)` static factory. |
| `ChaCha20Poly1305` | class | ChaCha20-Poly1305 AEAD (RFC 8439). 12-byte nonce. `encrypt(key, nonce, plaintext, aad?)`, `decrypt(key, nonce, ciphertext, aad?)`. |
| `ChaCha20` | class | ChaCha20 stream cipher (RFC 8439). `beginEncrypt()`, `encryptChunk()`. Unauthenticated. |
| `Poly1305` | class | Poly1305 one-time MAC (RFC 8439). `mac(key, msg)`. |
| `PoolOpts` | type | Options for `XChaCha20Poly1305Pool.create()`: worker count, worker script URL. |

---

## SHA-2

Requires `init(['sha2'])` or subpath `sha2Init()`.
Subpath: `leviathan-crypto/sha2` — see [sha2.md](./sha2).

| Export | Kind | Description |
|--------|------|-------------|
| `sha2Init` | function | Module-scoped init. `sha2Init(mode?, opts?)` loads only sha2. |
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

Requires `init(['sha3'])` or subpath `sha3Init()`.
Subpath: `leviathan-crypto/sha3` — see [sha3.md](./sha3).

| Export | Kind | Description |
|--------|------|-------------|
| `sha3Init` | function | Module-scoped init. `sha3Init(mode?, opts?)` loads only sha3. |
| `SHA3_224` | class | SHA3-224 hash (FIPS 202). `hash(msg)` returns 28 bytes. |
| `SHA3_256` | class | SHA3-256 hash (FIPS 202). `hash(msg)` returns 32 bytes. |
| `SHA3_384` | class | SHA3-384 hash (FIPS 202). `hash(msg)` returns 48 bytes. |
| `SHA3_512` | class | SHA3-512 hash (FIPS 202). `hash(msg)` returns 64 bytes. |
| `SHAKE128` | class | SHAKE128 XOF (FIPS 202). Unbounded output. `hash(msg, outputLength)`, `absorb(msg)`, `squeeze(n)`, `reset()`. |
| `SHAKE256` | class | SHAKE256 XOF (FIPS 202). Unbounded output. `hash(msg, outputLength)`, `absorb(msg)`, `squeeze(n)`, `reset()`. |

---

## Fortuna CSPRNG

Requires `init(['serpent', 'sha2'])` — see [fortuna.md](./fortuna).

| Export | Kind | Description |
|--------|------|-------------|
| `Fortuna` | class | Fortuna CSPRNG (Ferguson & Schneier). `Fortuna.create()` static factory, `get(n)`, `addEntropy()`, `stop()`. |

---

## Types

No `init()` required — see [types.md](./types).

| Export | Kind | Description |
|--------|------|-------------|
| `Hash` | interface | `hash(msg): Uint8Array`, `dispose()` |
| `KeyedHash` | interface | `hash(key, msg): Uint8Array`, `dispose()` |
| `Blockcipher` | interface | `encrypt(block): Uint8Array`, `decrypt(block): Uint8Array`, `dispose()` |
| `Streamcipher` | interface | `encrypt(msg): Uint8Array`, `decrypt(msg): Uint8Array`, `dispose()` |
| `AEAD` | interface | `encrypt(msg, aad?): Uint8Array`, `decrypt(ciphertext, aad?): Uint8Array`, `dispose()` |

---

## Utilities

No `init()` required — see [utils.md](./utils).

| Export | Kind | Description |
|--------|------|-------------|
| `hexToBytes` | function | Hex string to `Uint8Array`. Accepts `0x` prefix, uppercase/lowercase. |
| `bytesToHex` | function | `Uint8Array` to lowercase hex string. |
| `utf8ToBytes` | function | UTF-8 string to `Uint8Array`. |
| `bytesToUtf8` | function | `Uint8Array` to UTF-8 string. |
| `base64ToBytes` | function | Base64/base64url string to `Uint8Array`. Returns `undefined` on invalid input. |
| `bytesToBase64` | function | `Uint8Array` to base64 string. Pass `url=true` for base64url. |
| `constantTimeEqual` | function | Constant-time byte-array equality (XOR-accumulate, no early return). |
| `wipe` | function | Zero a typed array in place. |
| `xor` | function | XOR two equal-length `Uint8Array`s, returns new array. |
| `concat` | function | Concatenate two `Uint8Array`s, returns new array. |
| `randomBytes` | function | Cryptographically secure random bytes via Web Crypto API. |
