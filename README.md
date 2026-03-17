[![MIT Licensed](https://img.shields.io/github/license/xero/text0wnz?logo=wikiversity&logoColor=979da4&labelColor=262a2e&color=b1a268)](https://github.com/xero/text0wnz/blob/main/LICENSE)
[![Version](https://img.shields.io/github/package-json/version/xero/leviathan-crypto?labelColor=33383e&logo=npm&&logoColor=979da4&color=6e2aa5)](https://github.com/xero/leviathan-crypto/releases/latest)
[![GitHub repo size](https://img.shields.io/github/repo-size/xero/leviathan-crypto?labelColor=262a2e&logo=googlecontaineroptimizedos&logoColor=979da4&color=6e2aa5)](https://github.com/xero/leviathan-crypto/)
[![test suite](https://github.com/xero/leviathan-crypto/actions/workflows/test-suite.yml/badge.svg)](https://github.com/xero/leviathan-crypto/actions/workflows/test-suite.yml)
[![wiki](https://github.com/xero/leviathan-crypto/actions/workflows/wiki.yml/badge.svg)](https://github.com/xero/leviathan-crypto/wiki)

<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="Leviathan logo" width="400">

# Leviathan-Crypto: Serpent-256 & XChaCha20-Poly1305 Cryptography for the Web

Serpent-256, the most conservative AES finalist, employs 32 rounds and a
maximum security margin, built to withstand future cryptanalytic advancements.
Paired with the streamlined brilliance of ChaCha20-Poly1305, and complemented
by SHA-2 and SHA-3. Two design philosophies, four cryptographic primitives,
integrated into one coherent API.

**WebAssembly (WASM) serves as the correctness layer.** It features spec-driven and
vector-verified AssemblyScript implementations of Serpent-256, ChaCha20/Poly1305,
SHA-2, and SHA-3. Each cryptographic primitive is compiled into its own isolated
binary, executing outside the JavaScript JIT. This ensures no speculative
optimization affects key material and eliminates data-dependent timing
vulnerabilities from table lookups.

**TypeScript acts as the ergonomics layer.** Fully typed classes, explicit
`init()` gates, input validation, and authenticated compositions
([`SerpentSeal`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentseal),
[`SerpentStream`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentstream),
[`SerpentStreamSealer`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentstreamsealer--serpentstreamopener))
ensure primitives are connected correctly, simplifying development and ensuring
correctness. Advanced users retain the ability to directly access the raw block
cipher classes.

## Why Serpent-256

Serpent-256, an AES finalist, received more first-place security votes than
Rijndael from the NIST evaluation committee. It was designed with a larger
security margin: 32 rounds compared to AES's 10, 12, or 14.

While Serpent won on security margin, AES (Rijndael) ultimately won the
competition due to its  performance. Rijndael was selected because speed
was paramount for the hardware and embedded targets NIST was optimizing for
in 2001. However, for software running on modern hardware where milliseconds
of encryption latency are acceptable, this tradeoff is no longer as relevant.

**Security Margin.** Serpent has been a target of cryptanalytic research
since the AES competition. The current state-of-the-art is as follows:

- **Best known reduced-round attack:**
    - multidimensional linear cryptanalysis reaching 12 of 32 rounds (Nguyen,
      Wu & Wang, ACISP 2011), less than half the full cipher, requiring 2¹¹⁸
      known plaintexts and 2²²⁸·⁸ time.
    - Multidimensional linear cryptanalysis reaches 12 of 32 rounds (Nguyen,
      Wu & Wang, ACISP 2011), less than half the full cipher. This requires
      2¹¹⁸ known plaintexts and 2²²⁸·⁸ time. [source](https://personal.ntu.edu.sg/wuhj/research/publications/2011_ACISP_MLC.pdf) & [mirror](https://archive.is/6pwMM)
- **Best known full-round attack:**
    - biclique cryptanalysis of full 32-round Serpent-256 (de Carvalho & Kowada,
      SBSeg 2020), time complexity 2²⁵⁵·²¹, only 0.79 bits below the 256-bit
      brute-force ceiling of 2²⁵⁶, and requires 2⁸⁸ chosen ciphertexts, making
      it strictly less practical than brute force. For comparison, the analogous
      biclique attack on full-round AES-256 (Bogdanov et al., 2011) reaches
      2²⁵⁴·⁴. Serpent-256 is marginally harder to attack by this method than AES-256.
    - Biclique cryptanalysis of full 32-round Serpent-256 (de Carvalho & Kowada,
      SBSeg 2020) has a time complexity of 2²⁵⁵·²¹, only 0.79 bits below the 256-bit
      brute-force ceiling of 2²⁵⁶. It requires 2⁸⁸ chosen ciphertexts, making it
      strictly less practical than brute force. For comparison, the analogous biclique
      attack on full-round AES-256 (Bogdanov et al., 2011) reaches 2²⁵⁴·⁴.
      Serpent-256 is marginally harder to attack by this method than AES-256. [source](https://sol.sbc.org.br/index.php/sbseg/article/view/19225/19054) & [mirror](https://archive.is/ZZjrT)
    - Our independent research improved the published result by
      −0.20 bits through systematic search over v position, biclique nibble
      selection, and nabla pair. the best configuration (K31/K17, delta nibble 0,
      nabla nibble 10, v = state 66 nibbles 8+9) achieves 2²⁵⁵·¹⁹ with only 2⁴
      chosen ciphertexts. The K17 nabla result is a new finding not present in
      the published papers.
    - Our independent research improved the published result by −0.20 bits through
      systematic search over v position, biclique nibble selection, and nabla pair.
      The best configuration (K31/K17, delta nibble 0, nabla nibble 10, v = state
      66 nibbles 8+9) achieves 2²⁵⁵·¹⁹ with only 2⁴ chosen ciphertexts. The K17 nabla
      result is a new finding not present in the published papers. [`biclique_research`](https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md)

See: [`serpent_audit.md`](https://github.com/xero/leviathan-crypto/wiki/serpent_audit)
for the full analysis.

**Implementation.** Implementation: Serpent's S-boxes are implemented as Boolean gate
circuits, meaning there are no table lookups, data-dependent memory access, or
data-dependent branches. Every bit is processed unconditionally on every block.
This approach provides the most timing-safe cipher implementation available in a
JavaScript runtime, where JIT optimization can otherwise introduce observable
timing variations.

**Key Size:** The default API only supports 256-bit keys. The absence of 128 or
192-bit variants mitigates the risk of key-size downgrade attacks.

## Primitives

| Classes | Module | Auth | Notes |
|---------|--------|------|-------|
| `SerpentSeal` | `serpent`, `sha2` | **Yes** | Authenticated encryption: Serpent-CBC + HMAC-SHA256. Recommended for most use cases. |
| `SerpentStream`, `SerpentStreamPool` | `serpent`, `sha2` | **Yes** | Chunked one-shot AEAD for large payloads. Pool variant parallelises across workers. |
| `SerpentStreamSealer`, `SerpentStreamOpener` | `serpent`, `sha2` | **Yes** | Incremental streaming AEAD: seal and open one chunk at a time without buffering the full message. |
| `SerpentStreamEncoder`, `SerpentStreamDecoder` | `serpent`, `sha2` | **Yes** | Length-prefixed framing over SerpentStreamSealer/Opener for flat byte streams (files, buffered TCP). |
| `Serpent`, `SerpentCtr`, `SerpentCbc` | `serpent` | **No** | Raw ECB, CTR, CBC modes. Pair with HMAC-SHA256 for authentication. |
| `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305` | `chacha20` | Yes (AEAD) | RFC 8439 |
| `SHA256`, `SHA384`, `SHA512`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512` | `sha2` | -- | FIPS 180-4, RFC 2104 |
| `HKDF_SHA256`, `HKDF_SHA512` | `sha2` | -- | Key derivation: RFC 5869. Extract-and-expand over HMAC. |
| `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` | `sha3` | -- | FIPS 202 |
| `Fortuna` | `fortuna` | -- | Fortuna CSPRNG (Ferguson & Schneier). Requires `Fortuna.create()`. |

>[!IMPORTANT]
> All cryptographic computation runs in WASM (AssemblyScript), isolated outside the JavaScript JIT.
> The TypeScript layer provides the public API with input validation, type safety, and developer ergonomics.

## Quick Start

### Authenticated encryption with Serpent (recommended)

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

### Incremental streaming AEAD

Use `SerpentStreamSealer` when data arrives chunk by chunk and you cannot
buffer the full message before encrypting.

```typescript
import { init, SerpentStreamSealer, SerpentStreamOpener, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key = randomBytes(64)

// Seal side
const sealer = new SerpentStreamSealer(key, 65536)
const header = sealer.header()       // transmit to opener before any chunks

const chunk0 = sealer.seal(data0)    // exactly chunkSize bytes
const chunk1 = sealer.seal(data1)
const last   = sealer.final(tail)    // any size up to chunkSize; wipes key on return

// Open side
const opener = new SerpentStreamOpener(key, header)

const pt0 = opener.open(chunk0)
const pt1 = opener.open(chunk1)
const ptN = opener.open(last)        // detects final chunk; wipes key on return

// Reordering, truncation, and cross-stream splicing all throw on open()
```

### Large payload chunking

```typescript
import { init, SerpentStream, randomBytes } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const key = randomBytes(32)  // 32-byte key (HKDF handles expansion internally)

const stream = new SerpentStream()
const ciphertext = stream.seal(key, largePlaintext)   // default 64KB chunks
const decrypted  = stream.open(key, ciphertext)

stream.dispose()
```

### Fortuna CSPRNG

```typescript
import { init, Fortuna } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const fortuna = await Fortuna.create()
const random = fortuna.get(32)  // 32 random bytes

fortuna.stop()
```

### Hashing with SHA-3

```typescript
import { init, SHA3_256 } from 'leviathan-crypto'

await init(['sha3'])

const hasher = new SHA3_256()
const digest = hasher.hash(new TextEncoder().encode('hello'))
// digest is a 32-byte Uint8Array

hasher.dispose()
```

## Utilities

These helpers are available immediately on import: no `init()` required.

| Function | Description |
|----------|-------------|
| `hexToBytes(hex)` | Hex string to `Uint8Array` (accepts uppercase, `0x` prefix) |
| `bytesToHex(bytes)` | `Uint8Array` to lowercase hex string |
| `utf8ToBytes(str)` | UTF-8 string to `Uint8Array` |
| `bytesToUtf8(bytes)` | `Uint8Array` to UTF-8 string |
| `base64ToBytes(b64)` | Base64/base64url string to `Uint8Array` (undefined on invalid) |
| `bytesToBase64(bytes, url?)` | `Uint8Array` to base64 string (url=true for base64url) |
| `constantTimeEqual(a, b)` | Constant-time byte comparison (XOR-accumulate) |
| `wipe(data)` | Zero a typed array in place |
| `xor(a, b)` | XOR two equal-length `Uint8Array`s |
| `concat(a, b)` | Concatenate two `Uint8Array`s |
| `randomBytes(n)` | Cryptographically secure random bytes via Web Crypto |

## Authentication Warning

`SerpentCtr` and `SerpentCbc` are **unauthenticated** cipher modes. They provide
confidentiality but not integrity or authenticity. An attacker can modify
ciphertext without detection.

>[!TIP]
> **For authenticated Serpent encryption:** use [`SerpentSeal`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentseal) or [`SerpentStreamSealer`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentstreamsealer--serpentstreamopener)
>
> **Using Serpent CBC/CTR directly:** pair with `HMAC_SHA256` using the Encrypt-then-MAC pattern

>[!NOTE]
> **[`SerpentStream`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentstream) and [`SerpentStreamSealer`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentstreamsealer--serpentstreamopener)
> inherently satisfy the Cryptographic Doom Principle.** Message Authentication Code (MAC)
> verification is the mandatory check on every `open()` call; decryption is impossible until
> this verification succeeds. Per-chunk HKDF key derivation, using position-bound info,
> extends this protection to stream integrity. Reordering, truncation, and cross-stream
> substitution are all detected at the MAC layer, preventing any plaintext from being
> produced in such cases. [Full analysis.](https://github.com/xero/leviathan-crypto/wiki/serpent_audit#24-serpentstream-encrypt-then-mac-and-the-cryptographic-doom-principle)

## Installation

```bash
# use bun
bun i leviathan-crypto
# or npm
npm install leviathan-crypto
```

## Loading Modes

```typescript
// Embedded (default): zero-config, base64-encoded WASM inline
await init(['serpent', 'sha3'])

// Streaming: uses instantiateStreaming for performance
await init(['serpent'], 'streaming', { wasmUrl: '/assets/wasm/' })

// Manual: provide your own binary
await init(['serpent'], 'manual', { wasmBinary: { serpent: myBuffer } })
```

## Documentation

**Full API documentation:** [./docs](./docs/README.md)

| Module | Description |
|--------|-------------|
| [serpent.md](./docs/serpent.md) | Serpent-256 TypeScript API (`SerpentSeal`, `SerpentStream`, `SerpentStreamPool`, `SerpentStreamSealer`, `SerpentStreamOpener`, `Serpent`, `SerpentCtr`, `SerpentCbc`) |
| [asm_serpent.md](./docs/asm_serpent.md) | Serpent-256 WASM implementation (bitslice S-boxes, key schedule, CTR/CBC) |
| [chacha20.md](./docs/chacha20.md) | ChaCha20/Poly1305 TypeScript API (`ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`) |
| [asm_chacha.md](./docs/asm_chacha.md) | ChaCha20/Poly1305 WASM implementation (quarter-round, HChaCha20) |
| [sha2.md](./docs/sha2.md) | SHA-2 TypeScript API (`SHA256`, `SHA512`, `SHA384`, `HMAC_SHA256`, `HMAC_SHA512`, `HMAC_SHA384`) |
| [asm_sha2.md](./docs/asm_sha2.md) | SHA-2 WASM implementation (compression functions, HMAC) |
| [sha3.md](./docs/sha3.md) | SHA-3 TypeScript API (`SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`) |
| [asm_sha3.md](./docs/asm_sha3.md) | SHA-3 WASM implementation (Keccak-f[1600], sponge construction) |
| [fortuna.md](./docs/fortuna.md) | Fortuna CSPRNG (forward secrecy, 32 entropy pools) |
| [init.md](./docs/init.md) | `init()` API and WASM loading modes |
| [utils.md](./docs/utils.md) | Encoding helpers, `constantTimeEqual`, `wipe`, `randomBytes` |
| [types.md](./docs/types.md) | TypeScript interfaces (`Hash`, `KeyedHash`, `Blockcipher`, `Streamcipher`, `AEAD`) |
| [architecture.md](./docs/architecture.md.md) | Architecture overview, build pipeline, module relationships |
| [test-suite.md](./test-suite.md) | Test suite structure, vector corpus, gate discipline |

## License
leviathan is written under the [MIT license](http://www.opensource.org/licenses/MIT).

```
  ██     ▐█████ ██     ▐█▌  ▄█▌   ███▌ ▀███████▀▄██▌  ▐█▌  ███▌    ██▌   ▓▓
 ▐█▌     ▐█▌    ▓█     ▐█▌  ▓██  ▐█▌██    ▐█▌   ███   ██▌ ▐█▌██    ▓██   ██
 ██▌     ░███   ▐█▌    ██   ▀▀   ██ ▐█▌   ██   ▐██▌   █▓  ▓█ ▐█▌  ▐███▌  █▓
 ██      ██     ▐█▌    █▓  ▐██  ▐█▌  █▓   ██   ▐██▄▄ ▐█▌ ▐█▌  ██  ▐█▌██ ▐█▌
▐█▌     ▐█▌      ██   ▐█▌  ██   ██   ██  ▐█▌   ██▀▀████▌ ██   ██  ██ ▐█▌▐█▌
▐▒▌     ▐▒▌      ▐▒▌  ██   ▒█   ██▀▀▀██▌ ▐▒▌   ▒█    █▓░ ▒█▀▀▀██▌ ▒█  ██▐█
█▓ ▄▄▓█ █▓ ▄▄▓█   ▓▓ ▐▓▌  ▐▓▌  ▐█▌   ▐▒▌ █▓   ▐▓▌   ▐▓█ ▐▓▌   ▐▒▌▐▓▌  ▐███
▓██▀▀   ▓██▀▀      ▓█▓█   ▐█▌  ▐█▌   ▐▓▌ ▓█   ▐█▌   ▐█▓ ▐█▌   ▐▓▌▐█▌   ██▓
                    ▓█         ▄▄▄▄▄▄▄▄▄▄            ▀▀        ▐█▌▌▌
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

       Serpent256 & Xchacha20-Poly1305 Cryptography for the Web
```
