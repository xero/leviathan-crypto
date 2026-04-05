# Encoding utilities, comparison functions, and random byte generation

## Overview

Pure TypeScript utilities that ship alongside the WASM-backed primitives. These functions have **no `init()` dependency** -- they work immediately on import, without loading any WASM module.

The module covers four areas:

- **Encoding** -- hex, UTF-8, and base64 conversions between strings and `Uint8Array`
- **Security** -- constant-time comparison and secure memory wiping
- **Byte manipulation** -- XOR and concatenation of byte arrays
- **Random** -- cryptographically secure random byte generation

---

## Security Notes

**`constantTimeEqual`** uses a WASM SIMD module when available to remove the JS JIT compiler from the timing picture, falling back to an XOR-accumulate loop on older runtimes. Use this function whenever you compare MACs, hashes, authentication tags, or any secret-derived values. **Never** use `===`, `Buffer.equals`, or manual loop-with-break for security comparisons — those leak timing information that can be exploited to recover secrets. Inputs are limited to [`CT_MAX_BYTES`](#ct_max_bytes) (32768 bytes) per side.

The length check in `constantTimeEqual` is _not_ constant-time, because array length is non-secret in all standard protocols. If your use case treats length as secret, you must pad to equal length before comparing.

**`wipe`** zeroes a typed array in-place. Call it on keys, plaintext buffers, and any other sensitive data as soon as you are done with them. JavaScript's garbage collector does not guarantee timely or complete erasure of memory.

**`randomBytes`** delegates to `crypto.getRandomValues` (Web Crypto API), which is cryptographically secure in all modern browsers and Node.js 19+. It does not fall back to `Math.random` or any insecure source.

The encoding functions (`hexToBytes`, `bytesToHex`, `utf8ToBytes`, `bytesToUtf8`, `base64ToBytes`, `bytesToBase64`) perform no security-sensitive operations.

---

## API Reference

### hexToBytes

```typescript
hexToBytes(hex: string): Uint8Array
```

Converts a hex string to a `Uint8Array`. Accepts lowercase or uppercase characters. An optional `0x` or `0X` prefix is stripped automatically. Throws `RangeError` on odd-length input.

---

### bytesToHex

```typescript
bytesToHex(bytes: Uint8Array): string
```

Converts a `Uint8Array` to a lowercase hex string (no prefix).

---

### utf8ToBytes

```typescript
utf8ToBytes(str: string): Uint8Array
```

Encodes a JavaScript string as UTF-8 bytes using the platform `TextEncoder`.

---

### bytesToUtf8

```typescript
bytesToUtf8(bytes: Uint8Array): string
```

Decodes UTF-8 bytes to a JavaScript string using the platform `TextDecoder`.

---

### base64ToBytes

```typescript
base64ToBytes(b64: string): Uint8Array | undefined
```

Decodes a base64 or base64url string to a `Uint8Array`. Handles padded, unpadded, and legacy `%3d` padding. Unpadded base64url input is accepted (RFC 4648 §5). Returns `undefined` if the input is not valid base64 (e.g., illegal characters or `rem=1` length).

---

### bytesToBase64

```typescript
bytesToBase64(bytes: Uint8Array, url?: boolean): string
```

Encodes a `Uint8Array` to a base64 string. Pass `url = true` for base64url (RFC 4648 §5 — uses `-` and `_` instead of `+` and `/`, no padding characters). Defaults to standard base64.

---

### constantTimeEqual

```typescript
constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean
```

Returns `true` if `a` and `b` contain identical bytes. Returns `false` immediately if the arrays differ in length (length is non-secret in all standard protocols).

When WebAssembly SIMD is available the comparison runs inside a WASM module, removing the JS JIT compiler from the timing picture — speculative optimisation and branch prediction inside the engine cannot short-circuit the loop. On runtimes without SIMD support the function falls back to an XOR-accumulate loop in JavaScript, which is best-effort but not a hardware-level guarantee. The overall posture is **best-available constant-time**, not a cryptographic proof of timing safety.

Maximum input size is [`CT_MAX_BYTES`](#ct_max_bytes) (32768 bytes) per side. Throws `RangeError` if either array exceeds this limit.

This function is exported specifically to support consumers working with the lower-level unauthenticated primitives or building custom authenticated protocols on top of the hashing and KDF APIs. Three common cases where you need it:

- **Encrypt-then-MAC with `SerpentCbc` or `SerpentCtr`** — if you use the `dangerUnauthenticated` primitive directly and compute your own HMAC-SHA256 tag, compare that tag with `constantTimeEqual`. See the [example below](#encrypt-then-mac-with-serpentcbc).
- **Argon2id key verification** — when re-deriving an Argon2id hash to verify a passphrase, the final comparison must be constant-time. See [argon2id.md](./argon2id.md#password-hashing-and-verification) for the full example.
- **Custom HMAC protocols** — any protocol where you derive a MAC with `HMAC_SHA256`/`HMAC_SHA512` and compare it against a received value. See [examples.md](./examples.md#hmac-sha256-message-authentication) for a complete example.

---

### CT_MAX_BYTES

```typescript
const CT_MAX_BYTES: 32768
```

Maximum input size accepted by [`constantTimeEqual`](#constanttimeequal) per side, in bytes. Reflects the physical layout of the WASM comparison module: one 64 KiB page of linear memory split equally between the two input buffers (32 KiB each).

In practice the largest comparison performed anywhere in this library is a 32-byte HMAC-SHA-256 tag. This limit only matters for custom protocols that compare unusually large values. Use this constant to guard your own inputs programmatically rather than hardcoding the magic number:

```typescript
import { constantTimeEqual, CT_MAX_BYTES } from 'leviathan-crypto'

if (a.length > CT_MAX_BYTES || b.length > CT_MAX_BYTES) {
  throw new RangeError(`comparison input exceeds CT_MAX_BYTES (${CT_MAX_BYTES})`)
}
const match = constantTimeEqual(a, b)
```

---

### wipe

```typescript
wipe(data: Uint8Array | Uint16Array | Uint32Array): void
```

Zeroes a typed array in-place by calling `fill(0)`. Use this to clear keys, plaintext, or any sensitive material when you are done with it.

---

### xor

```typescript
xor(a: Uint8Array, b: Uint8Array): Uint8Array
```

Returns a new `Uint8Array` where each byte is `a[i] ^ b[i]`. Both arrays must have the same length; throws `RangeError` if they differ.

---

### concat

```typescript
concat(...arrays: Uint8Array[]): Uint8Array
```

Concatenate one or more `Uint8Array`s into a new array.

---

### randomBytes

```typescript
randomBytes(n: number): Uint8Array
```

Returns `n` cryptographically secure random bytes via the Web Crypto API (`crypto.getRandomValues`).

---

### hasSIMD

```typescript
hasSIMD(): boolean
```

Returns `true` if the current runtime supports WebAssembly SIMD (the `v128`
type and associated operations). The result is computed once on first call by
validating a minimal v128 WASM module, then cached for subsequent calls.

This function is called internally by `SerpentCtr.encryptChunk`,
`SerpentCbc.decrypt`, and `ChaCha20.encryptChunk` to select the fast SIMD path
at runtime. It is exported for informational purposes — you do not need to call
it yourself. SIMD dispatch is fully automatic.

Supported in all modern browsers and Node.js 16+. Returns `false` in older
environments, which fall back silently to the scalar path.

---

## Usage Examples

### Converting between formats

```typescript
import { hexToBytes, bytesToHex, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'

// Hex round-trip
const bytes = hexToBytes('deadbeef')
console.log(bytesToHex(bytes)) // "deadbeef"

// 0x prefix is accepted
const prefixed = hexToBytes('0xCAFE')
console.log(bytesToHex(prefixed)) // "cafe"

// UTF-8 round-trip
const encoded = utf8ToBytes('hello world')
console.log(bytesToUtf8(encoded)) // "hello world"
```

---

### Base64 encoding and decoding

```typescript
import { bytesToBase64, base64ToBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'

const data = utf8ToBytes('leviathan-crypto')
const b64 = bytesToBase64(data)
console.log(b64) // "bGV2aWF0aGFuLWNyeXB0bw=="

// base64url variant (safe for URLs and filenames, no padding)
const b64url = bytesToBase64(data, true)
console.log(b64url) // "bGV2aWF0aGFuLWNyeXB0bw"

// Decoding (accepts both standard and url variants)
const decoded = base64ToBytes(b64)
if (decoded) console.log(bytesToUtf8(decoded)) // "leviathan-crypto"
```

---

### Encrypt-then-MAC with SerpentCbc

If you use `SerpentCbc` or `SerpentCtr` directly with `{ dangerUnauthenticated: true }`, you are responsible for authentication. The correct pattern is Encrypt-then-MAC: encrypt first, then compute HMAC-SHA256 over the ciphertext, and use `constantTimeEqual` to verify on decrypt.

```typescript
import {
  init, SerpentCbc, HMAC_SHA256,
  constantTimeEqual, randomBytes, wipe, concat,
} from 'leviathan-crypto'
import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'

await init({ serpent: serpentWasm, sha2: sha2Wasm })

const encKey = randomBytes(32)
const macKey = randomBytes(32)
const iv     = randomBytes(16)

// ── Encrypt ──────────────────────────────────────────────────────────────────

const cbc = new SerpentCbc({ dangerUnauthenticated: true })
const ct  = cbc.encrypt(encKey, iv, plaintext)
cbc.dispose()

// MAC covers iv || ct so the IV is authenticated too
const hmac = new HMAC_SHA256()
const tag  = hmac.hash(macKey, concat(iv, ct))
hmac.dispose()

const envelope = concat(iv, ct, tag)  // store or transmit this

// ── Decrypt ──────────────────────────────────────────────────────────────────

const receivedIv  = envelope.subarray(0, 16)
const receivedCt  = envelope.subarray(16, envelope.length - 32)
const receivedTag = envelope.subarray(envelope.length - 32)

const hmac2      = new HMAC_SHA256()
const expectedTag = hmac2.hash(macKey, concat(receivedIv, receivedCt))
hmac2.dispose()

// ALWAYS verify before decrypting — never decrypt unauthenticated ciphertext
if (!constantTimeEqual(expectedTag, receivedTag)) {
  wipe(expectedTag)
  throw new Error('Authentication failed')
}

const cbc2 = new SerpentCbc({ dangerUnauthenticated: true })
const pt   = cbc2.decrypt(encKey, receivedIv, receivedCt)
cbc2.dispose()
wipe(expectedTag)
```

> [!NOTE]
> `Seal` with `SerpentCipher` does all of this for you — key derivation, IV handling, Encrypt-then-MAC, and constant-time verification — with no manual steps. The pattern above is only relevant if you need direct access to the raw `SerpentCbc` primitive.

---

### Generating random keys and nonces

```typescript
import { randomBytes } from 'leviathan-crypto'

const key = randomBytes(32)   // 256-bit symmetric key
const nonce = randomBytes(24) // 192-bit nonce for XChaCha20
const iv = randomBytes(16)    // 128-bit IV for Serpent-CBC
```

---

### Wiping sensitive data after use

```typescript
import { randomBytes, wipe } from 'leviathan-crypto'

const key = randomBytes(32)

// ... use the key for encryption / decryption ...

// When done, zero the key material so it does not linger in memory
wipe(key)
// key is now all zeroes
```

---

### XOR and concatenation

```typescript
import { xor, concat, randomBytes } from 'leviathan-crypto'

const a = randomBytes(16)
const b = randomBytes(16)

// XOR two equal-length arrays
const xored = xor(a, b)

// Concatenate two arrays
const combined = concat(a, b)
console.log(combined.length) // 32
```

---

## Error Conditions

| Function | Condition | Behavior |
|---|---|---|
| `hexToBytes` | Odd-length string | Throws `RangeError` |
| `hexToBytes` | Invalid hex characters | Bytes decode as `NaN` -> `0` |
| `base64ToBytes` | Invalid length or characters | Returns `undefined` |
| `constantTimeEqual` | Arrays differ in length | Returns `false` immediately |
| `constantTimeEqual` | Either array exceeds `CT_MAX_BYTES` | Throws `RangeError` |
| `xor` | Arrays differ in length | Throws `RangeError` |
| `randomBytes` | `crypto` not available | Throws (runtime-dependent) |
| `hasSIMD` | `WebAssembly` not available | Returns `false` |

---

> ## Cross-References
>
> - [index](./README.md) — Project Documentation index
> - [architecture](./architecture.md) — architecture overview, module relationships, buffer layouts, and build pipeline
> - [serpent](./serpent.md) — Serpent modes consume keys from `randomBytes`; wrappers use `wipe` and `constantTimeEqual`
> - [chacha20](./chacha20.md) — ChaCha20/Poly1305 classes use `randomBytes` for nonce generation
> - [sha2](./sha2.md) — SHA-2 and HMAC classes; output often converted with `bytesToHex`
> - [sha3](./sha3.md) — SHA-3 and SHAKE classes; output often converted with `bytesToHex`
> - [argon2id](./argon2id.md) — passphrase-based encryption; uses `constantTimeEqual` for hash verification
> - [examples](./examples.md) — full HMAC-SHA256 custom protocol example using `constantTimeEqual`
> - [types](./types.md) — public interfaces whose implementations rely on these utilities
> - [test-suite](./test-suite.md) — test suite structure and vector corpus
