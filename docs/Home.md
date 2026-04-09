```
  ██     ▐█████ ██     ▐█▌  ▄█▌   ███▌ ▀███████▀▄██▌  ▐█▌  ███▌    ██▌   ▓▓
 ▐█▌     ▐█▌    ▓█     ▐█▌  ▓██  ▐█▌██    ▐█▌   ███   ██▌ ▐█▌██    ▓██   ██
 ██▌     ░███   ▐█▌    ██   ▀▀   ██ ▐█▌   ██   ▐██▌   █▓  ▓█ ▐█▌  ▐███▌  █▓
 ██      ██     ▐█▌    █▓  ▐██  ▐█▌  █▓   ██   ▐██▄▄ ▐█▌ ▐█▌  ██  ▐█▌██ ▐█▌
▐█▌     ▐█▌      ██   ▐█▌  ██   ██   ██  ▐█▌   ██▀▀████▌ ██   ██  ██ ▐█▌▐█▌
▐▒▌     ▐▒▌      ▐▒▌  ██   ▒█   ██▀▀▀██▌ ▐▒▌   ▒█    █▓░ ▒█▀▀▀██▌ ▒█  ██▐█
█▓ ▄▄▓█ █▓ ▄▄▓█   ▓▓ ▐▓▌  ▐▓▌  ▐█▌   ▐▒▌ █▓   ▐▓▌   ▐▓█ ▐▓▌   ▐▒▌▐▓▌  ▐███
▓██▀▀   ▓██▀▀      ▓█▓█   ▐█▌  ▐█▌   ▐▓▌ ▓█   ▐█▌   ▐█▓ ▐█▌   ▐▓▌▐█▌   ██▓
                    ▓█                               ▀▀        ▐█▌▌▌
```

# Leviathan Crypto Library

> [!NOTE]
> A zero-dependency WebAssembly cryptography library. Two ciphers, opposite philosophies, same security properties.

```bash
npm install leviathan-crypto
# or
bun add leviathan-crypto
```

No bundler is required. See [CDN usage](./cdn.md).

---

## AEAD

[`Seal`](./aead.md#api-reference), [`SealStream`](./aead.md#sealstream),
[`OpenStream`](./aead.md#openstream), and [`SealStreamPool`](./aead.md#sealstreampool)
are the primary API for authenticated encryption in leviathan-crypto.
They are cipher-agnostic: you pass a [`CipherSuite`](./ciphersuite.md) object
at construction and the implementation handles key derivation, nonce
management, and authentication for you.

**The classes form a natural progression:**
- [Seal](./aead.md#api-reference) handles data that fits in memory (>~66k).
- [SealStream](./aead.md#sealstream) and [OpenStream](./aead.md#openstream) handle
  data that arrives in chunks or is too large to buffer.
- [SealStreamPool](./aead.md#sealstreampool) parallelizes the chunked approach
  across Web Workers.

All four produce and consume the same [wire format](./aead.md#wire-format), so a
Seal blob can be opened by OpenStream and vice versa.

---

## Find the right tool

| **_I want to..._** | |
|---|---|
| Encrypt data | [`Seal`](./aead.md#seal) with [`SerpentCipher`](./serpent.md#serpentcipher) or [`XChaCha20Cipher`](./chacha20.md#xchacha20cipher) |
| Encrypt a stream or large file | [`SealStream`](./aead.md#sealstream) to encrypt, [`OpenStream`](./aead.md#openstream) to decrypt |
| Encrypt in parallel | [`SealStreamPool`](./aead.md#sealstreampool) distributes chunks across Web Workers |
| Add post-quantum security | [`KyberSuite`](./kyber.md#kybersuite) wraps [`MlKem512`](./kyber.md#parameter-sets), [`MlKem768`](./kyber.md#parameter-sets), or [`MlKem1024`](./kyber.md#parameter-sets) with any cipher suite |
| Hash data | [`SHA256`](./sha2.md#sha256), [`SHA384`](./sha2.md#sha384), [`SHA512`](./sha2.md#sha512), [`SHA3_256`](./sha3.md#sha3_256), [`SHA3_512`](./sha3.md#sha3_512), [`SHAKE256`](./sha3.md#shake256) ... |
| Authenticate a message | [`HMAC_SHA256`](./sha2.md#hmac_sha256), [`HMAC_SHA384`](./sha2.md#hmac_sha384), or [`HMAC_SHA512`](./sha2.md#hmac_sha512) |
| Derive keys | [`HKDF_SHA256`](./sha2.md#hkdf_sha256) or [`HKDF_SHA512`](./sha2.md#hkdf_sha512) |
| Generate random bytes | [`Fortuna`](./fortuna.md#api-reference) for forward-secret generation, [`randomBytes`](./utils.md#randombytes) for one-off use |
| Compare secrets safely | [`constantTimeEqual`](./utils.md#constanttimeequal) uses a WASM SIMD path to prevent timing attacks |
| Work with bytes | [`hexToBytes`](./utils.md#hextobytes), [`bytesToHex`](./utils.md#bytestohex), [`wipe`](./utils.md#wipe), [`xor`](./utils.md#xor), [`concat`](./utils.md#concat) ... |

*For raw primitives, low-level cipher access, and ASM internals see the [full API reference](./index.md).*

> [!TIP]
> New to crypto? We have a lot of technical jargon. Checkout the [lexicon](./lexicon.md)
> if you need a glossary of cryptographic terminology.
