# Argon2id -- Memory-Hard Password Hashing and Key Derivation

> A memory-hard password hashing function that resists GPU and ASIC brute-force
> attacks, backed by a dedicated WASM module with SIMD acceleration where available.

---

## Overview

Password hashing is the last line of defense when a database is breached. If an
attacker obtains a table of hashed passwords, the hash function determines how
expensive it is to recover each plaintext. Traditional hash functions -- even
iterated ones like PBKDF2 -- are fast on GPUs and custom hardware (ASICs).
An attacker with a few thousand dollars of GPU hardware can test billions of
PBKDF2-SHA256 candidates per second. bcrypt improves on this with a 4 KiB memory
requirement that limits GPU parallelism, but 4 KiB is trivial by modern standards.

Argon2 was the winner of the Password Hashing Competition (PHC, 2013--2015),
selected from 24 submissions after two years of public analysis. It was designed
specifically to be **memory-hard** -- meaning that computing the hash requires not
just CPU time but a large block of memory that cannot be traded away. An attacker
who tries to use less memory must perform exponentially more computation, making
GPU and ASIC attacks economically impractical.

Argon2 comes in three variants: Argon2d (data-dependent memory access, resists
GPU attacks but vulnerable to side-channel attacks), Argon2i (data-independent
memory access, resists side-channel attacks but weaker against GPU attacks), and
**Argon2id** (a hybrid that uses Argon2i for the first pass and Argon2d for
subsequent passes, combining both defenses). RFC 9106 recommends Argon2id as the
primary choice for password hashing, and it is the only variant this library
implements.

Why memory-hardness matters: a function that requires 64 MiB of RAM per hash
evaluation means that a GPU with 8 GiB of VRAM can only run ~128 evaluations in
parallel, regardless of how many shader cores it has. Compare this to PBKDF2,
where the same GPU can run millions of evaluations in parallel because each one
needs negligible memory. The cost asymmetry between defender (who hashes one
password at login) and attacker (who hashes billions of candidates) is what makes
memory-hard functions effective.

leviathan-crypto implements Argon2id as a standalone WASM module with optional
SIMD acceleration. You must call `init()` to load the module before creating an
instance.

---

## Security Notes

- **Memory hardness** -- Argon2id requires a configurable amount of memory
  (default: 19 MiB for INTERACTIVE, 64 MiB for SENSITIVE) that must be filled
  sequentially during hashing. This memory cannot be reduced without a
  superlinear increase in computation time, making parallel brute-force on GPUs
  and ASICs economically prohibitive.

- **OWASP presets rationale** -- The INTERACTIVE preset (19456 KiB, 2 passes,
  1 thread) targets interactive login flows where latency matters -- it completes
  in roughly 200--500 ms on modern hardware while still requiring ~19 MiB of
  memory per evaluation. The SENSITIVE preset (65536 KiB, 3 passes, 4 threads)
  targets high-value secrets -- master passwords, encryption keys -- where
  higher latency is acceptable in exchange for stronger resistance. These values
  align with OWASP recommendations for password storage.

- **Why not PBKDF2** -- PBKDF2 has no memory requirement. Its security relies
  entirely on iteration count, and GPUs can evaluate it thousands of times faster
  than CPUs per watt. Argon2id with even modest memory parameters provides orders
  of magnitude more resistance to hardware-accelerated attacks than PBKDF2 at any
  practical iteration count.

- **Salt storage requirements** -- Every call to `hash()` and `deriveKey()`
  generates a random salt if one is not provided. The salt **must** be stored
  alongside the hash or ciphertext -- without the original salt, the hash cannot
  be recomputed and verification will fail. Salts are not secret, but they must
  be unique per password.

- **Constant-time verification** -- `verify()` compares the computed hash against
  the expected hash using a constant-time XOR-accumulate pattern. There is no
  early return on mismatch. This prevents timing side-channel attacks that could
  leak information about which bytes of the hash matched.

- **Parameter storage** -- When using `deriveKey()` for encryption key derivation,
  the returned `salt` and `params` must be stored alongside the ciphertext. Both
  are required to re-derive the same key. If either is lost, the key cannot be
  reconstructed and the ciphertext is unrecoverable.

---

## API Reference

### Presets

Three presets are exported as constants:

| Preset | `memoryCost` | `timeCost` | `parallelism` | `saltLength` | `hashLength` | Use case |
|--------|-------------|-----------|---------------|-------------|-------------|----------|
| `ARGON2ID_INTERACTIVE` | 19456 KiB | 2 | 1 | 16 | 32 | Login forms, interactive auth |
| `ARGON2ID_SENSITIVE` | 65536 KiB | 3 | 4 | 16 | 32 | Master passwords, high-value secrets |
| `ARGON2ID_DERIVE` | 19456 KiB | 2 | 1 | 16 | 32 | Key derivation (always 32-byte output) |

`ARGON2ID_DERIVE` uses the same parameters as `ARGON2ID_INTERACTIVE` but always
produces a 32-byte output, matching the key size expected by symmetric ciphers
like Serpent-256 and XChaCha20-Poly1305.

All presets conform to the `Argon2idParams` interface:

```typescript
interface Argon2idParams {
	memoryCost: number
	timeCost: number
	parallelism: number
	saltLength: number
	hashLength: number
}
```

---

### `init(mode?, opts?)`

Initialize the Argon2id WASM module. Must be called before `Argon2id.create()`.

```typescript
import { init } from 'leviathan-crypto'

// Embedded mode (default) -- uses bundled WASM binaries
await init(['argon2id'])

// Manual mode -- provide your own WASM binaries
await init(['argon2id'], {
	argon2id: {
		simdBinary: simdWasmBytes,
		noSimdBinary: fallbackWasmBytes
	}
})
```

The `opts` parameter accepts an `ArgonOpts` object:

```typescript
interface ArgonOpts {
	simdBinary?: Uint8Array | ArrayBuffer
	noSimdBinary?: Uint8Array | ArrayBuffer
}
```

The module detects SIMD support at load time and uses the SIMD-accelerated binary
when available, falling back to the scalar binary otherwise. Both binaries produce
identical output -- SIMD affects only performance.

**Streaming mode is not supported.** Argon2id requires the full password in memory
and does not support incremental input. Passing a streaming option will throw.

---

### `isArgon2idInitialized()`

Check whether the Argon2id module has been loaded.

```typescript
isArgon2idInitialized(): boolean
```

Returns `true` if `init(['argon2id'])` has completed successfully, `false`
otherwise. Use this to guard against calling `Argon2id.create()` before the
module is ready.

---

### `Argon2id.create()`

Static async factory. Returns a `Promise<Argon2id>`.

```typescript
static async create(): Promise<Argon2id>
```

Throws if `init(['argon2id'])` has not been called. Direct construction with
`new Argon2id()` is not possible -- the constructor is private. Always use
`Argon2id.create()`.

---

### `hash(password, salt?, params?)`

Hash a password using Argon2id.

```typescript
hash(
	password: string | Uint8Array,
	salt?: Uint8Array,
	params?: Argon2idParams
): Promise<Argon2idResult>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password` | `string \| Uint8Array` | -- | The password to hash. Strings are UTF-8 encoded. |
| `salt` | `Uint8Array` | random | A unique salt. If omitted, a random salt of `params.saltLength` bytes is generated. |
| `params` | `Argon2idParams` | `ARGON2ID_INTERACTIVE` | Hashing parameters. |

Returns an `Argon2idResult`:

```typescript
interface Argon2idResult {
	hash: Uint8Array
	salt: Uint8Array
	params: Argon2idParams
}
```

The returned `salt` and `params` must be stored alongside the hash. Both are
required for `verify()` to recompute the hash.

---

### `verify(password, hash, salt, params?)`

Verify a password against a previously computed hash. Returns `true` if the
password matches, `false` otherwise.

```typescript
verify(
	password: string | Uint8Array,
	hash: Uint8Array,
	salt: Uint8Array,
	params?: Argon2idParams
): Promise<boolean>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password` | `string \| Uint8Array` | -- | The candidate password to verify. |
| `hash` | `Uint8Array` | -- | The stored hash from a previous `hash()` call. |
| `salt` | `Uint8Array` | -- | The stored salt from a previous `hash()` call. |
| `params` | `Argon2idParams` | `ARGON2ID_INTERACTIVE` | Must match the params used during hashing. |

The comparison is **constant-time** -- the function examines every byte of the
hash regardless of where the first mismatch occurs. This prevents timing
side-channel attacks.

---

### `deriveKey(passphrase, salt?, keyLength?)`

Derive a symmetric encryption key from a passphrase using Argon2id.

```typescript
deriveKey(
	passphrase: string | Uint8Array,
	salt?: Uint8Array,
	keyLength?: number
): Promise<{ key: Uint8Array; salt: Uint8Array; params: Argon2idParams }>
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `passphrase` | `string \| Uint8Array` | -- | The passphrase to derive a key from. |
| `salt` | `Uint8Array` | random | A unique salt. If omitted, a random salt is generated. |
| `keyLength` | `number` | `32` | Output key length in bytes. Defaults to 32 (256 bits). |

Returns an object containing the derived `key`, the `salt` used, and the `params`
applied.

**Critical: callers MUST store the returned `salt` AND `params` alongside the
ciphertext.** Both are required to re-derive the same key for decryption. If
either value is lost, the key cannot be reconstructed and the ciphertext becomes
permanently unrecoverable. The salt is not secret -- it can be stored in
plaintext next to the ciphertext -- but it must be preserved.

Uses `ARGON2ID_DERIVE` parameters by default, which always produces a 32-byte
key suitable for Serpent-256 or XChaCha20-Poly1305.

---

## Usage Examples

### Password hashing -- registration

```typescript
import { init, Argon2id } from 'leviathan-crypto'

await init(['argon2id'])
const argon = await Argon2id.create()

// Hash the user's password. A random salt is generated automatically.
const result = await argon.hash(userPassword)

// Store all three values in the database.
// The hash alone is useless without the salt and params.
db.storeCredentials(userId, {
	hash: result.hash,
	salt: result.salt,
	params: result.params
})
```

### Password verification -- login

```typescript
import { init, Argon2id } from 'leviathan-crypto'

await init(['argon2id'])
const argon = await Argon2id.create()

// Retrieve the stored credential
const stored = db.getCredentials(userId)

// Verify the candidate password against the stored hash.
// Constant-time comparison -- no timing leaks.
const valid = await argon.verify(
	candidatePassword,
	stored.hash,
	stored.salt,
	stored.params
)

if (!valid) {
	throw new Error('Invalid credentials')
}
```

### Key derivation for Serpent encryption

```typescript
import { init, Argon2id, Serpent } from 'leviathan-crypto'

await init(['argon2id', 'serpent'])
const argon = await Argon2id.create()

// Derive a 256-bit key from a passphrase.
// IMPORTANT: store the salt and params alongside the ciphertext.
const { key, salt, params } = await argon.deriveKey(passphrase)

// Encrypt with the derived key
const serpent = new Serpent()
const ciphertext = serpent.encrypt(key, plaintext)

// Store everything needed for decryption
const envelope = {
	ciphertext,
	kdf: { salt, params }   // required to re-derive the key
}

// Later -- decryption
const stored = loadEnvelope()
const { key: decryptKey } = await argon.deriveKey(
	passphrase,
	stored.kdf.salt
)
const plaintext = serpent.decrypt(decryptKey, stored.ciphertext)
```

### Using the SENSITIVE preset for high-value secrets

```typescript
import { init, Argon2id, ARGON2ID_SENSITIVE } from 'leviathan-crypto'

await init(['argon2id'])
const argon = await Argon2id.create()

// Use the SENSITIVE preset for master passwords or recovery keys.
// This uses 64 MiB of memory and 3 passes -- slower, but significantly
// more resistant to hardware-accelerated brute-force.
const result = await argon.hash(masterPassword, undefined, ARGON2ID_SENSITIVE)

db.storeMasterCredential(userId, {
	hash: result.hash,
	salt: result.salt,
	params: result.params
})
```

---

## Error Conditions

| Condition | What happens |
|-----------|-------------|
| `init()` not called | `Argon2id.create()` throws: `leviathan-crypto: call init(['argon2id']) before using Argon2id` |
| `new Argon2id()` | Compile-time error -- the constructor is private. TypeScript will not allow it. |
| Streaming mode requested | `init()` throws -- Argon2id does not support streaming. The full password must be provided at once. |
| Empty password | `hash()` throws -- a zero-length password is not permitted. |
| Salt too short | `hash()` throws -- the salt must be at least 8 bytes (RFC 9106 minimum). |
| `memoryCost` too low | `hash()` throws -- the memory cost must be at least 8 KiB (8 * parallelism, per RFC 9106). |
| `timeCost` too low | `hash()` throws -- the time cost must be at least 1. |
| `parallelism` too low | `hash()` throws -- the parallelism must be at least 1. |
| `verify()` hash length mismatch | Returns `false` -- if the recomputed hash length differs from the stored hash, verification fails (constant-time). |
| WASM memory allocation failure | `hash()` throws -- the requested `memoryCost` exceeds the available WASM linear memory. |

---

## Cross-References

- [serpent.md](./serpent.md): Serpent-256 TypeScript API (pair with `deriveKey()` for passphrase-based encryption)
- [chacha20.md](./chacha20.md): XChaCha20-Poly1305 TypeScript API (pair with `deriveKey()` for authenticated encryption)
- [fortuna.md](./fortuna.md): CSPRNG for generating random salts when none is provided
- [sha2.md](./sha2.md): SHA-256 and SHA-512 (used internally by Argon2id for compression)
- [init.md](./init.md): Module initialization API
- [types.md](./types.md): Shared type definitions including `Argon2idParams` and `Argon2idResult`
