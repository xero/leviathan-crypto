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

A zero-dependency WebAssembly cryptography library for TypeScript, featuring
the paranoia of Serpent-256 and the elegance of XChaCha20-Poly1305, with
SHA-2/3, HMAC, HKDF, and Fortuna CSPRNG included. All cryptographic computation
runs in WASM, outside the JavaScript JIT, behind a strictly typed API built on
vector-verified primitives.

---

## Install
```bash
npm install leviathan-crypto
# or
bun add leviathan-crypto
```

No bundler? Load directly from a CDN. See: [CDN usage](cdn.md).

## Quick Start
```typescript
import { init, Seal, XChaCha20Cipher, SerpentCipher } from 'leviathan-crypto'
import { chacha20Wasm } from 'leviathan-crypto/chacha20/embedded'
import { serpentWasm }  from 'leviathan-crypto/serpent/embedded'
import { sha2Wasm }     from 'leviathan-crypto/sha2/embedded'

await init({ chacha20: chacha20Wasm, serpent: serpentWasm, sha2: sha2Wasm })

// XChaCha20-Poly1305 (recommended — IETF standard, fast)
const key  = XChaCha20Cipher.keygen()
const blob = Seal.encrypt(XChaCha20Cipher, key, plaintext)
const pt   = Seal.decrypt(XChaCha20Cipher, key, blob)

// Serpent-256 CBC+HMAC (cipher diversity / defense in depth)
const skey  = SerpentCipher.keygen()
const sblob = Seal.encrypt(SerpentCipher, skey, plaintext)
const spt   = Seal.decrypt(SerpentCipher, skey, sblob)
```

See [examples](examples.md) for streaming, chunking, hashing, key derivation, and both ciphers.

## Demos

| Name | Link | Code | Docs | Description |
| ---- | ---- | ---- | ---- | ----------- |
| **`lvthn-web`**  | [▼](https://leviathan.3xi.club/web)      | [🛈](https://github.com/xero/leviathan-demos/tree/main/web)  | [¶](https://github.com/xero/leviathan-demos/blob/main/web/README.md)  | Encrypt text or files using Serpent-256-CBC and Argon2id key derivation from a single local HTML file, with armored output. No server, installation, or network connection required after initial load. |
| **`lvthn-chat`** | [▼](https://leviathan.3xi.club/chat)     | [🛈](https://github.com/xero/leviathan-demos/tree/main/chat) | [¶](https://github.com/xero/leviathan-demos/blob/main/chat/README.md) | End-to-end encrypted chat over X25519 key exchange and XChaCha20-Poly1305. Relay server functions as a dumb WebSocket pipe and never sees plaintexts. |
| **`lvthn-cli`**  | [▼](https://www.npmjs.com/package/lvthn) | [🛈](https://github.com/xero/leviathan-demos/tree/main/lvthn-cli)  | [¶](https://github.com/xero/leviathan-demos/blob/main/lvthn-cli/README.md)  | File encryption CLI supporting both Serpent-256 and XChaCha20-Poly1305 via `--cipher`. Keyfiles are compatible across both ciphers; the header byte determines decryption automatically. |

## [Full Documentation Index](README.md)
