<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="Leviathan logo" width="400">

# leviathan - Serpent-256 Cryptography for the Web

A TypeScript cryptographic library built around **Serpent-256**; the AES
finalist that received more first-place security votes than Rijndael from
the NIST evaluation committee, and was designed with a larger security
margin by construction: 32 rounds versus AES's 10/12/14.

For applications where throughput is not the primary constraint (e.g. file
encryption, key derivation, secure storage, etc) Serpent-256 is the stronger
choice. leviathan makes it practical for web and server-side TypeScript.

## Why Serpent-256

AES (Rijndael) won the competition on performance. Serpent won on security
margin. The NIST evaluation committee's own analysis gave Serpent more
first-place security votes, Rijndael was selected because speed mattered
for the hardware and embedded targets NIST was optimising for in 2001.

For software running on modern hardware where milliseconds of encryption
latency are acceptable, that tradeoff no longer applies.

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

See: [`serpent_audit.md`](https://github.com/xero/leviathan-crypto/wiki/serpent_audit) & [`biclique_research.md`](https://github.com/xero/BicliqueFinder/blob/main/biclique-research.md) for the full analysis.

**Implementation.** Serpent's S-boxes are implemented as Boolean gate
circuits: no table lookups, no data-dependent memory access, no
data-dependent branches. Every bit is processed unconditionally on every
block. This is the most timing-safe cipher implementation approach
available in a JavaScript runtime, where JIT optimisation can otherwise
introduce observable timing variation.

**Key size.** 256-bit keys only in the default API.

_No 128 or 192-bit variants mitigates key-size downgrade risk._

## Primitives

| Module     | Classes                                                                   | Auth       | Notes                                                         |
| ---------- | ------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------- |
| `serpent`  | `Serpent`, `SerpentCtr`, `SerpentCbc`                                     | **No**     | ECB, CTR, CBC modes. Pair with HMAC or use XChaCha20Poly1305. |
| `chacha20` | `ChaCha20`, `Poly1305`, `ChaCha20Poly1305`, `XChaCha20Poly1305`           | Yes (AEAD) | RFC 8439                                                      |
| `sha2`     | `SHA256`, `SHA384`, `SHA512`, `HMAC_SHA256`, `HMAC_SHA384`, `HMAC_SHA512` | —          | FIPS 180-4, RFC 2104                                          |
| `sha3`     | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`    | —          | FIPS 202                                                      |
| `serpent`, `sha2` | `Fortuna`                                                          | —          | Fortuna CSPRNG (Ferguson & Schneier). Requires `Fortuna.create()`. |

>[!IMPORTANT]
> All cryptographic computation runs in WASM (AssemblyScript), isolated outside the JavaScript JIT.
> The TypeScript layer provides the public API with input validation, type safety, and developer ergonomics.

## Quick Start

```typescript
import { init, SerpentCbc, HMAC_SHA256 } from 'leviathan-crypto'

// Load the modules you need (once, at startup)
await init(['serpent', 'sha2'])

// Encrypt with CBC (unauthenticated — must add MAC)
const cipher = new SerpentCbc()
cipher.loadKey(key)      // 16, 24, or 32 bytes
const ct = cipher.encrypt(plaintext, iv)

// Always pair unauthenticated modes with Encrypt-then-MAC
const mac = new HMAC_SHA256()
mac.init(macKey)
mac.update(ct)
const tag = mac.final()

// Clean up key material
cipher.dispose()
mac.dispose()
```

### Authenticated Encryption (recommended)

```typescript
import { init, XChaCha20Poly1305 } from 'leviathan-crypto'

await init(['chacha20'])

const cipher = new XChaCha20Poly1305()
const key   = crypto.getRandomValues(new Uint8Array(32))
const nonce = crypto.getRandomValues(new Uint8Array(24))

// Encrypt (returns ciphertext || 16-byte tag)
const ct = cipher.encrypt(key, nonce, plaintext)

// Decrypt (verifies tag, throws on tamper)
const pt = cipher.decrypt(key, nonce, ct)

cipher.dispose()
```

### Fortuna CSPRNG

```typescript
import { init, Fortuna } from 'leviathan-crypto'

await init(['serpent', 'sha2'])

const fortuna = await Fortuna.create()
const random = fortuna.get(32)  // 32 random bytes

// Optional: custom reseed interval
const fast = await Fortuna.create({ msPerReseed: 0 })

// Clean up when done
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

These helpers are available immediately on import — no `init()` required.

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

```typescript
import { randomBytes, XChaCha20Poly1305, init } from 'leviathan-crypto'

await init(['chacha20'])

const key   = randomBytes(32)
const nonce = randomBytes(24)

const cipher = new XChaCha20Poly1305()
const ct = cipher.encrypt(key, nonce, plaintext)
cipher.dispose()
```

## Authentication Warning

`SerpentCtr` and `SerpentCbc` are **unauthenticated** cipher modes. They provide
confidentiality but not integrity or authenticity. An attacker can modify
ciphertext without detection.

For authenticated encryption, use `XChaCha20Poly1305`. If Serpent CBC/CTR is
required, pair it with `HMAC_SHA256` using the Encrypt-then-MAC pattern.

## Installation

```bash
# use bun
bun i leviathan-crypto
# or npm
npm install leviathan-crypto
```

## Loading Modes

```typescript
// Embedded (default) — zero-config, base64-encoded WASM inline
await init(['serpent', 'sha3'])

// Streaming — uses instantiateStreaming for performance
await init(['serpent'], 'streaming', { wasmUrl: '/assets/wasm/' })

// Manual — provide your own binary
await init(['serpent'], 'manual', { wasmBinary: { serpent: myBuffer } })
```

## Documentation

**Full API documentation:** [./docs](./docs/README.md)

| Module | Description |
|--------|-------------|
| [serpent.md](./docs/serpent.md) | Serpent-256 TypeScript API (`Serpent`, `SerpentCtr`, `SerpentCbc`) |
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
| [api.md](./docs/api.md) | Architecture overview, build pipeline, module relationships |
| [serpent_reference.md](./docs/serpent_reference.md) | Serpent-256 algorithm specification and known attacks |
| [serpent_audit.md](./docs/serpent_audit.md) | Serpent-256 security audit results |

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
