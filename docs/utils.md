# utils.md -- Encoding utilities, comparison functions, and random byte generation

## Overview

Pure TypeScript utilities that ship alongside the WASM-backed primitives. These functions have **no `init()` dependency** -- they work immediately on import, without loading any WASM module.

The module covers four areas:

- **Encoding** -- hex, UTF-8, and base64 conversions between strings and `Uint8Array`
- **Security** -- constant-time comparison and secure memory wiping
- **Byte manipulation** -- XOR and concatenation of byte arrays
- **Random** -- cryptographically secure random byte generation

---

## Security Notes

**`constantTimeEqual`** uses an XOR-accumulate pattern with no early return on byte mismatch. Use this function whenever you compare MACs, hashes, authentication tags, or any secret-derived values. **Never** use `===`, `Buffer.equals`, or manual loop-with-break for security comparisons -- those leak timing information that can be exploited to recover secrets.

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

Converts a hex string to a `Uint8Array`. Accepts lowercase or uppercase characters. An optional `0x` or `0X` prefix is stripped automatically. If the hex string has an odd number of characters, a trailing `0` is appended before decoding.

### bytesToHex

```typescript
bytesToHex(bytes: Uint8Array): string
```

Converts a `Uint8Array` to a lowercase hex string (no prefix).

### utf8ToBytes

```typescript
utf8ToBytes(str: string): Uint8Array
```

Encodes a JavaScript string as UTF-8 bytes using the platform `TextEncoder`.

### bytesToUtf8

```typescript
bytesToUtf8(bytes: Uint8Array): string
```

Decodes UTF-8 bytes to a JavaScript string using the platform `TextDecoder`.

### base64ToBytes

```typescript
base64ToBytes(b64: string): Uint8Array | undefined
```

Decodes a base64 or base64url string to a `Uint8Array`. Base64url characters (`-`, `_`, `%3d`) are normalized to standard base64 before decoding. Returns `undefined` if the input is not valid base64 (e.g., incorrect length or illegal characters).

### bytesToBase64

```typescript
bytesToBase64(bytes: Uint8Array, url?: boolean): string
```

Encodes a `Uint8Array` to a base64 string. Pass `url = true` to get base64url encoding (uses `-` and `_` instead of `+` and `/`, and `%3d` instead of `=`). Defaults to standard base64.

### constantTimeEqual

```typescript
constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean
```

Returns `true` if `a` and `b` contain identical bytes. Uses XOR-accumulate with no early return on mismatch. Returns `false` immediately if the arrays differ in length (length is non-secret).

### wipe

```typescript
wipe(data: Uint8Array | Uint16Array | Uint32Array): void
```

Zeroes a typed array in-place by calling `fill(0)`. Use this to clear keys, plaintext, or any sensitive material when you are done with it.

### xor

```typescript
xor(a: Uint8Array, b: Uint8Array): Uint8Array
```

Returns a new `Uint8Array` where each byte is `a[i] ^ b[i]`. Both arrays must have the same length; throws `RangeError` if they differ.

### concat

```typescript
concat(a: Uint8Array, b: Uint8Array): Uint8Array
```

Returns a new `Uint8Array` containing `a` followed by `b`.

### randomBytes

```typescript
randomBytes(n: number): Uint8Array
```

Returns `n` cryptographically secure random bytes via the Web Crypto API (`crypto.getRandomValues`).

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

### Base64 encoding and decoding

```typescript
import { bytesToBase64, base64ToBytes, utf8ToBytes, bytesToUtf8 } from 'leviathan-crypto'

const data = utf8ToBytes('leviathan-crypto')
const b64 = bytesToBase64(data)
console.log(b64) // "bGV2aWF0aGFuLWNyeXB0bw=="

// base64url variant (safe for URLs and filenames)
const b64url = bytesToBase64(data, true)
console.log(b64url) // "bGV2aWF0aGFuLWNyeXB0bw%3d%3d"

// Decoding (accepts both standard and url variants)
const decoded = base64ToBytes(b64)
if (decoded) console.log(bytesToUtf8(decoded)) // "leviathan-crypto"
```

### Secure MAC comparison

```typescript
import { constantTimeEqual } from 'leviathan-crypto'

// After computing a MAC over received data, compare it to the expected tag.
// NEVER use === or .every() for this -- timing leaks enable forgery attacks.
const computedMac: Uint8Array = hmac.hash(key, message)
const receivedMac: Uint8Array = getTagFromNetwork()

if (!constantTimeEqual(computedMac, receivedMac)) {
  throw new Error('Authentication failed: MAC mismatch')
}
```

### Generating random keys and nonces

```typescript
import { randomBytes } from 'leviathan-crypto'

const key = randomBytes(32)   // 256-bit symmetric key
const nonce = randomBytes(24) // 192-bit nonce for XChaCha20
const iv = randomBytes(16)    // 128-bit IV for Serpent-CBC
```

### Wiping sensitive data after use

```typescript
import { randomBytes, wipe } from 'leviathan-crypto'

const key = randomBytes(32)

// ... use the key for encryption / decryption ...

// When done, zero the key material so it does not linger in memory
wipe(key)
// key is now all zeroes
```

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
| `hexToBytes` | Odd-length string | Trailing `0` appended (no error) |
| `hexToBytes` | Invalid hex characters | Bytes decode as `NaN` -> `0` |
| `base64ToBytes` | Length not a multiple of 4 | Returns `undefined` |
| `base64ToBytes` | Invalid characters | Returns `undefined` |
| `constantTimeEqual` | Arrays differ in length | Returns `false` immediately |
| `xor` | Arrays differ in length | Throws `RangeError` |
| `randomBytes` | `crypto` not available | Throws (runtime-dependent) |

---

## Cross-References

- [serpent.md](./serpent.md) -- Serpent block cipher and modes that consume keys generated by `randomBytes`
- [testing.md](./testing.md) -- Test suite documentation
