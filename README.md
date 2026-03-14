<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="Leviathan logo" width="400">

# leviathan - Serpent-256 Cryptography for the Web

### Serpent256 paranoia & ChaCha20 elegance

Serpent-256 The most conservative AES finalist, 32 rounds, maximum security margin, built to outlast
cryptanalytic progress — alongside the streamlined brilliance of ChaCha20-Poly1305.
SHA-2 and SHA-3 rounding it out. Two philosophies, four primitives, one coherent API.

**WASM is the correctness layer.** Spec-driven, vector-verified AssemblyScript
implementations of `Serpent-256`, `ChaCha20/Poly1305`, `SHA-2`, `SHA-3`. Each
primitive compiled to its own isolated binary, running outside the JavaScript JIT.
No speculative optimization touching key material. No data-dependent timing from table lookups.

**TypeScript is the ergonomics layer.** Fully typed classes, explicit `init()`
gates, input validation, and authenticated compositions ([`SerpentSeal`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentseal), [`SerpentStream`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentstream),
[`SerpentStreamSealer`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentstreamsealer--serpentstreamopener)) that wire the primitives together correctly so you don't have to.
While power users can still utilize the raw block cipher classes directly.

## Why Serpent-256

Serpent-256 is the AES finalist that received more first-place security votes than Rijndael from the NIST evaluation committee, and was designed with a larger security margin by construction: 32 rounds versus AES's 10/12/14.

AES (Rijndael) won the competition on performance. Serpent won on security margin. Rijndael was selected because speed mattered for the hardware and embedded targets NIST was optimising for in 2001. For software running on modern hardware where milliseconds of encryption latency are acceptable, that tradeoff no longer applies.

**Security margin.** Serpent has been a target of cryptanalytic research
since the AES competition. The current state of the art:

- **Best known reduced-round attack:**
    - multidimensional linear cryptanalysis reaching 12 of 32 rounds (Nguyen,
      Wu & Wang, ACISP 2011), less than half the full cipher, requiring 2¹¹⁸
      known plaintexts and 2²²⁸·⁸ time.
    - [source](https://personal.ntu.edu.sg/wuhj/research/publications/2011_ACISP_MLC.pdf) & [mirror](https://archive.is/6pwMM)
- **Best known full-round attack:**
    - biclique cryptanalysis of full 32-round Serpent-256 (de Carvalho & Kowada,
      SBSeg 2020), time complexity 2²⁵⁵·²¹, only 0.79 bits below the 256-bit
      brute-force ceiling of 2²⁵⁶, and requires 2⁸⁸ chosen ciphertexts, making
      it strictly less practical than brute force. For comparison, the analogous
      biclique attack on full-round AES-256 (Bogdanov et al., 2011) reaches
      2²⁵⁴·⁴. Serpent-256 is marginally harder to attack by this method than AES-256.
        - [source](https://sol.sbc.org.br/index.php/sbseg/article/view/19225/19054) & [mirror](https://archive.is/ZZjrT)
    - Our independent research improved the published result by
      −0.20 bits through systematic search over v position, biclique nibble
      selection, and nabla pair. the best configuration (K31/K17, delta nibble 0,
      nabla nibble 10, v = state 66 nibbles 8+9) achieves 2²⁵⁵·¹⁹ with only 2⁴
      chosen ciphertexts. The K17 nabla result is a new finding not present in
      the published papers.
        - [`biclique_research.md`](https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md)

See: [`serpent_audit.md`](https://github.com/xero/leviathan-crypto/wiki/serpent_audit)
for the full analysis.

**Implementation.** Serpent's S-boxes are implemented as Boolean gate
circuits: no table lookups, no data-dependent memory access, no
data-dependent branches. Every bit is processed unconditionally on every
block. This is the most timing-safe cipher implementation approach
available in a JavaScript runtime, where JIT optimisation can otherwise
introduce observable timing variation.

**Key size.** 256-bit keys only in the default API.

_No 128 or 192-bit variants mitigates key-size downgrade risk._

## Primitives

| Module | Classes | Auth | Notes |
|--------|---------|------|-------|
| `serpent`, `sha2` | `SerpentSeal` | **Yes** | Authenticated encryption: Serpent-CBC + HMAC-SHA256. Recommended for most use cases. |
| `serpent`, `sha2` | `SerpentStream`, `SerpentStreamPool` | **Yes** | Chunked one-shot AEAD for large payloads. Pool variant parallelises across workers. |
| `serpent`, `sha2` | `SerpentStreamSealer`, `SerpentStreamOpener` | **Yes** | Incremental streaming AEAD: seal and open one chunk at a time without buffering the full message. |
| `serpent` | `Serpent`, `SerpentCtr`, `SerpentCbc` | **No** | Raw ECB, CTR, CBC modes. Pair with HMAC-SHA256 for authentication. |
| `chacha20` | `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305` | Yes (AEAD) | RFC 8439 |
| `sha2` | `SHA256`, `SHA384`, `SHA512`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512` | -- | FIPS 180-4, RFC 2104 |
| `sha3` | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256` | -- | FIPS 202 |
| `fortuna` | `Fortuna` | -- | Fortuna CSPRNG (Ferguson & Schneier). Requires `Fortuna.create()`. |

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
> **[`SerpentStream`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentstream) and [`SerpentStreamSealer`](https://github.com/xero/leviathan-crypto/wiki/serpent#serpentstreamsealer--serpentstreamopener) satisfy the Cryptographic Doom Principle
> by construction.** MAC verification is the unconditional gate on every `open()` call,
> decryption is unreachable until it clears. Per-chunk HKDF key derivation with
> position-bound info extends this to stream integrity: reordering, truncation, and
> cross-stream substitution are all caught at the MAC layer before any plaintext is
> produced. [Full analysis.](https://github.com/xero/leviathan-crypto/wiki/serpent_audit#24-serpentstream-encrypt-then-mac-and-the-cryptographic-doom-principle)

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
                Serpent256 Cryptography for the Web
```
