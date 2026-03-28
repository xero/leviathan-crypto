[![Version](https://img.shields.io/github/package-json/version/xero/leviathan-crypto?labelColor=33383e&logo=npm&&logoColor=979da4&color=6e2aa5)](https://github.com/xero/leviathan-crypto/releases/latest) [![GitHub repo size](https://img.shields.io/github/repo-size/xero/leviathan-crypto?labelColor=262a2e&logo=googlecontaineroptimizedos&logoColor=979da4&color=6e2aa5)](https://github.com/xero/leviathan-crypto/) [![test suite](https://github.com/xero/leviathan-crypto/actions/workflows/test-suite.yml/badge.svg)](https://github.com/xero/leviathan-crypto/actions/workflows/test-suite.yml) [![wiki](https://github.com/xero/leviathan-crypto/actions/workflows/wiki.yml/badge.svg)](https://github.com/xero/leviathan-crypto/wiki)

![side-effect free](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-side-effect-free.svg) ![tree-shakeable](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-tree-shakable.svg) ![zero dependencies](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-zero-dependancies.svg) [![MIT Licensed](https://github.com/xero/leviathan-crypto/raw/main/docs/badge-mit-license.svg)](https://github.com/xero/text0wnz/blob/main/LICENSE)

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="Leviathan logo" width="400" >

# Leviathan-Crypto

> Web cryptography built on Serpent-256 paranoia and XChaCha20-Poly1305 elegance.

**Serpent-256 is the cipher for those who distrust consensus.** In 2001, when NIST selected AES, Serpent actually received more first-place security votes from the evaluation committee. However, it lost because the competition also considered performance on hardware embedded systems, which are no longer representative of the environments for which we develop software. Serpent's designers made no compromises: thirty-two rounds, S-boxes implemented using pure Boolean logic gates without table lookups, and every bit processed for each block. You use Serpent not because a committee recommended it, but because you trust the cryptanalysis. The current best attack on the full thirty-two-round Serpent-256 achieves 2²⁵⁵·¹⁹ — less than one bit below the brute-force ceiling, and strictly impractical. This includes our own independent research, which improved upon the published result. See [`serpent_audit.md`](https://github.com/xero/leviathan-crypto/wiki/serpent_audit).

**XChaCha20-Poly1305 is the cipher for those who appreciate design that has nothing to hide.** Daniel Bernstein built ChaCha20 as a twenty-round ARX construction: add, rotate, and XOR, in a precise choreography that simply doesn't have the attack surface that table-based ciphers do. It has no S-boxes, no cache-timing leakage, and requires no hardware acceleration to be fast. Poly1305 adds a final layer of security: a one-time authenticator with an unconditional forgery bound, mathematically guaranteed regardless of attacker compute power. XChaCha20-Poly1305 is the construction you reach for when you want an AEAD whose security proof you can actually read without a PhD. See [`chacha_audit.md`](https://github.com/xero/leviathan-crypto/wiki/chacha_audit).

The tension between these two approaches constitutes the library's core identity. Serpent embodies defiance, ChaCha embodies elegance, yet both arrive at the same place: constant-time, side-channel resistant implementations, independently audited against their specifications. They represent two design philosophies that do not agree on anything, except the answer.

**WebAssembly provides a correctness layer.** Each primitive compiles into its own isolated binary, executing outside the JavaScript JIT. This prevents speculative optimization from affecting key material and ensures that data-dependent timing vulnerabilities do not cross the boundary.

**TypeScript acts as the ergonomics layer.** Fully typed classes, explicit `init()` gates, input validation, and authenticated compositions ensure primitives are connected correctly.

---

#### **Zero Dependencies.**
With no npm dependency graph to audit, the supply chain attack surface is eliminated.

#### **Tree-shakeable.**
Import only the cipher(s) you intend to use. Subpath exports allow bundlers to exclude everything else.

#### **Side-effect Free.**
Nothing runs upon import. Initialization via `init()` is explicit and asynchronous.


## Installation

```bash
# use bun
bun i leviathan-crypto
# or npm
npm install leviathan-crypto
```

> **Note:** The Serpent and ChaCha20 modules require a runtime with WebAssembly SIMD support. This has been a feature of all major browsers and runtimes since 2021. All other primitives (SHA-2, SHA-3, Poly1305) run on any WASM-capable runtime.

---

## Demos

**`lvthn-web`** [ [demo](https://leviathan.3xi.club/web) · [source](https://github.com/xero/leviathan-demos/tree/main/lvthn-web) · [readme](https://github.com/xero/leviathan-demos/blob/main/lvthn-web/README.md) ]

A browser encryption tool in a single, self-contained HTML file. Encrypt text or files using Serpent-256-CBC and Argon2id key derivation, then share the armored output. No server, installation, or network connection required after initial load. The code in is written to be read. The Encrypt-then-MAC construction, HMAC input (header with HMAC field zeroed + ciphertext), and Argon2id parameters are all intentional examples worth reading.

**`lvthn-chat`** [ [demo](https://leviathan.3xi.club/chat) · [source](https://github.com/xero/leviathan-demos/tree/main/lvthn-chat) · [readme](https://github.com/xero/leviathan-demos/blob/main/lvthn-chat/README.md) ]

End-to-end encrypted chat featuring two-party messaging over X25519 key exchange and XChaCha20-Poly1305 message encryption. The relay server functions as a dumb WebSocket pipe that never sees plaintext. Each message incorporates sequence numbers, which allows the system to detect and reject replayed messages from an attacker. The demo deconstructs the protocol step by step, with visual feedback for both injection and replays.

**`lvthn-cli`** [ [npm](https://www.npmjs.com/package/lvthn) · [source](https://github.com/xero/leviathan-demos/tree/main/lvthn-cli) · [readme](https://github.com/xero/leviathan-demos/blob/main/lvthn-cli/README.md) ]

File encryption CLI. Supports both Serpent-256 and XChaCha20-Poly1305, selectable via the `--cipher` flag. A single keyfile is compatible with both ciphers; the header byte determines decryption automatically. Encryption and decryption distribute 64KB chunks across a worker pool sized to hardwareConcurrency. Each worker owns an isolated WASM instance with no shared memory between workers.

```sh
bun i -g lvthn # or npm slow mode
lvthn keygen --armor -o my.key
cat secret.txt | lvthn encrypt -k my.key --armor > secret.enc
```
*[`lvthncli-serpent`](https://github.com/xero/leviathan-demos/tree/main/lvthncli-serpent) and [`lvthncli-chacha`](https://github.com/xero/leviathan-demos/tree/main/lvthncli-chacha) are additional educational tools: structurally identical to the main CLI tool, each implementing only a single cipher. By comparing the two, you can pinpoint the exact changes that occur when primitives are swapped; these are limited to `src/pool.ts` and `src/worker.ts`.*

---

## Primitives

| Classes                                                                   | Module            | Auth    | Notes                                                                                                |
| ------------------------------------------------------------------------- | ----------------- | ------- | ---------------------------------------------------------------------------------------------------- |
| `SerpentSeal`                                                             | `serpent`, `sha2` | **Yes** | Authenticated encryption: Serpent-CBC + HMAC-SHA256. Recommended for most use cases.                 |
| `SerpentStream`, `SerpentStreamPool`                                      | `serpent`, `sha2` | **Yes** | Chunked one-shot AEAD for large payloads. Pool variant parallelises across workers.                  |
| `SerpentStreamSealer`, `SerpentStreamOpener`                              | `serpent`, `sha2` | **Yes** | Incremental streaming AEAD: seal and open one chunk at a time without buffering the full message.    |
| `SerpentStreamEncoder`, `SerpentStreamDecoder`                            | `serpent`, `sha2` | **Yes** | Length-prefixed framing over SerpentStreamSealer/Opener for flat byte streams (files, buffered TCP). |
| `Serpent`, `SerpentCtr`, `SerpentCbc`                                     | `serpent`         | **No**  | Raw ECB, CTR, CBC modes. Unauthenticated — pair with HMAC-SHA256 for authentication.                 |
| `XChaCha20Poly1305`, `ChaCha20Poly1305`                                   | `chacha20`        | **Yes** | AEAD — RFC 8439. XChaCha20 recommended (192-bit nonce).                                              |
| `ChaCha20`                                                                | `chacha20`        | **No**  | Raw stream cipher. Unauthenticated — use with `Poly1305` for authentication.                         |
| `Poly1305`                                                                | `chacha20`        | **No**  | One-time MAC — RFC 8439. Use via the AEAD classes unless you have a specific reason not to.          |
| `SHA256`, `SHA384`, `SHA512`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512` | `sha2`            | -       | FIPS 180-4, RFC 2104                                                                                 |
| `HKDF_SHA256`, `HKDF_SHA512`                                              | `sha2`            | -       | Key derivation — RFC 5869. Extract-and-expand over HMAC.                                             |
| `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`    | `sha3`            | -       | FIPS 202                                                                                             |
| `Fortuna`                                                                 | `fortuna`         | -       | Fortuna CSPRNG (Ferguson & Schneier). Requires `Fortuna.create()`.                                   |

> [!IMPORTANT]
> All cryptographic computation runs in WASM (AssemblyScript), isolated outside the JavaScript JIT. The TypeScript layer provides the public API with input validation, type safety, and developer ergonomics.

> [!WARNING]
> `SerpentCtr` and `SerpentCbc` are **unauthenticated** cipher modes. They provide confidentiality but not integrity or authenticity. An attacker can modify ciphertext without detection. For authenticated Serpent encryption use `SerpentSeal` or `SerpentStreamSealer`. When using CBC/CTR directly, pair with `HMAC_SHA256` using the Encrypt-then-MAC pattern.

---

## Quick Start

### Authenticated encryption with Serpent

```typescript
import { init, SerpentSeal, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key = randomBytes(64)  // 64-byte key (encKey + macKey)

const seal = new SerpentSeal()

// Encrypt and authenticate
const ciphertext = seal.encrypt(key, plaintext)

// Decrypt and verify (throws on tamper)
const decrypted = seal.decrypt(key, ciphertext)

seal.dispose()
```

### Authenticated encryption with XChaCha20-Poly1305

```typescript
import { init, XChaCha20Poly1305, randomBytes } from 'leviathan-crypto'

await init(['chacha20'])

const key   = randomBytes(32)  // 32-byte key
const nonce = randomBytes(24)  // 24-byte nonce (XChaCha20 extended nonce)

const chacha = new XChaCha20Poly1305()

// Encrypt and authenticate
const ciphertext = chacha.encrypt(key, nonce, plaintext)

// Decrypt and verify (throws on tamper)
const decrypted = chacha.decrypt(key, nonce, ciphertext)

chacha.dispose()
```

For more examples, including streaming, chunking, hashing, and key derivation, see the [examples page](https://github.com/xero/leviathan-crypto/wiki/examples).

---

## Loading Modes

```typescript
// Embedded (default): zero-config, base64-encoded WASM inline
await init(['serpent', 'sha3'])

// Streaming: uses instantiateStreaming for performance
await init(['serpent'], 'streaming', { wasmUrl: '/assets/wasm/' })

// Manual: provide your own binary
await init(['serpent'], 'manual', { wasmBinary: { serpent: myBuffer } })
```

### Tree-shaking with subpath imports

Each cipher ships as its own subpath export. A bundler with tree-shaking support and `"sideEffects": false` will exclude every module you don't import:

```typescript
// Only serpent.wasm ends up in your bundle
import { serpentInit, SerpentSeal } from 'leviathan-crypto/serpent'
await serpentInit()

// Only chacha20.wasm ends up in your bundle
import { chacha20Init, XChaCha20Poly1305 } from 'leviathan-crypto/chacha20'
await chacha20Init()
```

| Subpath                     | Entry point                |
| --------------------------- | -------------------------- |
| `leviathan-crypto`          | `./dist/index.js`          |
| `leviathan-crypto/serpent`  | `./dist/serpent/index.js`  |
| `leviathan-crypto/chacha20` | `./dist/chacha20/index.js` |
| `leviathan-crypto/sha2`     | `./dist/sha2/index.js`     |
| `leviathan-crypto/sha3`     | `./dist/sha3/index.js`     |

---

## Documentation

| Document     | MD/Wiki                                                                                       | Description                                                      |
| ------------ | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| architecture | [▼](./docs/architecture.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/architecture) | Architecture overview, build pipeline, module relationships      |
| test-suite   | [▼](./docs/test-suite.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/test-suite)     | Test suite structure, vector corpus, gate discipline             |
| security     | [▼](./SECURITY.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/security_policy)       | Project security policy covering posture, disclosure, and scopes |

### API Surface

| Module       | MD/Wiki                                                                                       | Description                                                                                                                                                           |
| ------------ | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| serpent      | [▼](./docs/serpent.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/serpent)           | Serpent-256 TypeScript API (`SerpentSeal`, `SerpentStream`, `SerpentStreamPool`, `SerpentStreamSealer`, `SerpentStreamOpener`, `Serpent`, `SerpentCtr`, `SerpentCbc`) |
| asm_serpent  | [▼](./docs/asm_serpent.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/asm_serpent)   | Serpent-256 WASM implementation (bitslice S-boxes, key schedule, CTR/CBC)                                                                                             |
| chacha20     | [▼](./docs/chacha20.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/chacha20)         | ChaCha20/Poly1305 TypeScript API (`ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`)                                                                    |
| asm_chacha   | [▼](./docs/asm_chacha.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/asm_chacha)     | ChaCha20/Poly1305 WASM implementation (quarter-round, HChaCha20)                                                                                                      |
| sha2         | [▼](./docs/sha2.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/sha2)                 | SHA-2 TypeScript API (`SHA256`, `SHA512`, `SHA384`, `HMAC_SHA256`, `HMAC_SHA512`, `HMAC_SHA384`)                                                                      |
| asm_sha2     | [▼](./docs/asm_sha2.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/asm_sha2)         | SHA-2 WASM implementation (compression functions, HMAC)                                                                                                               |
| sha3         | [▼](./docs/sha3.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/sha3)                 | SHA-3 TypeScript API (`SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`)                                                                         |
| asm_sha3     | [▼](./docs/asm_sha3.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/asm_sha3)         | SHA-3 WASM implementation (Keccak-f[1600], sponge construction)                                                                                                       |
| fortuna      | [▼](./docs/fortuna.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/fortuna)           | Fortuna CSPRNG (forward secrecy, 32 entropy pools)                                                                                                                    |
| init         | [▼](./docs/init.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/init)                 | `init()` API and WASM loading modes                                                                                                                                   |
| utils        | [▼](./docs/utils.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/utils)               | Encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes`                                                                                                          |
| types        | [▼](./docs/types.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/types)               | TypeScript interfaces (`Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD`)                                                                                    |

### Utilities

These helpers are available immediately on import with no `init()` required.

| Function                     | MD/Wiki                                                                                                             | Description                                                    |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `hexToBytes(hex)`            | [▼](./docs/utils.md#hextobytes) · [¶](https://github.com/xero/leviathan-crypto/wiki/utils#hextobytes)               | Hex string to `Uint8Array` (accepts uppercase, `0x` prefix)    |
| `bytesToHex(bytes)`          | [▼](./docs/utils.md#bytestohex) · [¶](https://github.com/xero/leviathan-crypto/wiki/utils#bytestohex)               | `Uint8Array` to lowercase hex string                           |
| `utf8ToBytes(str)`           | [▼](./docs/utils.md#utf8tobytes) · [¶](https://github.com/xero/leviathan-crypto/wiki/utils#utf8tobytes)             | UTF-8 string to `Uint8Array`                                   |
| `bytesToUtf8(bytes)`         | [▼](./docs/utils.md#bytestoutf8) · [¶](https://github.com/xero/leviathan-crypto/wiki/utils#bytestoutf8)             | `Uint8Array` to UTF-8 string                                   |
| `base64ToBytes(b64)`         | [▼](./docs/utils.md#base64tobytes) · [¶](https://github.com/xero/leviathan-crypto/wiki/utils#base64tobytes)         | Base64/base64url string to `Uint8Array` (undefined on invalid) |
| `bytesToBase64(bytes, url?)` | [▼](./docs/utils.md#bytestobase64) · [¶](https://github.com/xero/leviathan-crypto/wiki/utils#bytestobase64)         | `Uint8Array` to base64 string (url=true for base64url)         |
| `constantTimeEqual(a, b)`    | [▼](./docs/utils.md#constanttimeequal) · [¶](https://github.com/xero/leviathan-crypto/wiki/utils#constanttimeequal) | Constant-time byte comparison (XOR-accumulate)                 |
| `wipe(data)`                 | [▼](./docs/utils.md#wipe) · [¶](https://github.com/xero/leviathan-crypto/wiki/utils#wipe)                           | Zero a typed array in place                                    |
| `xor(a, b)`                  | [▼](./docs/utils.md#xor) · [¶](https://github.com/xero/leviathan-crypto/wiki/utils#xor)                             | XOR two equal-length `Uint8Array`s                             |
| `concat(a, b)`               | [▼](./docs/utils.md#concat) · [¶](https://github.com/xero/leviathan-crypto/wiki/utils#concat)                       | Concatenate two `Uint8Array`s                                  |

### Algorithm correctness and verifications

| Primitive     | MD/Wiki                                                                                         | Description                                                                            |
| ------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| serpent_audit | [▼](./docs/serpent_audit.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/serpent_audit) | Correctness verification, side-channel analysis, cryptanalytic paper review            |
| chacha_audit  | [▼](./docs/chacha_audit.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/chacha_audit)   | XChaCha20-Poly1305 correctness, Poly1305 field arithmetic, HChaCha20 nonce extension   |
| sha2_audit    | [▼](./docs/sha2_audit.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/sha2_audit)       | SHA-256/512/384 correctness, HMAC and HKDF composition, constant verification          |
| sha3_audit    | [▼](./docs/sha3_audit.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/sha3_audit)       | Keccak permutation correctness, θ/ρ/π/χ/ι step verification, round constant derivation |
| hmac_audit    | [▼](./docs/hmac_audit.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/hmac_audit)       | HMAC-SHA256/512/384 construction, key processing, RFC 4231 vector coverage             |
| hkdf_audit    | [▼](./docs/hkdf_audit.md) · [¶](https://github.com/xero/leviathan-crypto/wiki/hkdf_audit)       | HKDF extract-then-expand, info field domain separation, SerpentStream key derivation   |

>[!NOTE]
> Additional documentation available in [./docs](./docs/README.md) and on the [project wiki](https://github.com/xero/leviathan-crypto/wiki/).

---

## License

leviathan is written under the [MIT license](http://www.opensource.org/licenses/MIT).

```
                ▄▄▄▄▄▄▄▄▄▄
         ▄████████████████████▄▄
      ▄██████████████████████ ▀████▄
    ▄█████████▀▀▀     ▀███████▄▄███████▌
   ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌
   ████████      ███▀▀     ████▀  █▀ █▀
   ███████▌    ▀██▀         ██
    ███████   ▀███           ▀██ ▀█▄
     ▀██████   ▄▄██            ▀▀  ██▄
       ▀█████▄   ▄██▄             ▄▀▄▀
          ▀████▄   ▄██▄
            ▐████   ▐███
     ▄▄██████████    ▐███         ▄▄
  ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███
 ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀
████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄
█████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄███▀
▀██████▀             ▀████▄▄▄████▀
                        ▀█████▀
```
