<img src="https://github.com/xero/leviathan-crypto/raw/main/docs/logo.svg" alt="logo" width="120" align="left" margin="10">

### CDN Usage

leviathan-crypto is published to npm and mirrored on [unpkg](https://unpkg.com). All `WasmSource` types work directly from the CDN with no install or bundler required.

> ### Table of Contents
> - [Embedded mode (Zero config)](#embedded-mode-zero-config)
> - [URL-based loading](#url-based-loading)
> - [Manual loading (fetch + ArrayBuffer)](#manual-loading-fetch--arraybuffer)
> - [Import maps](#import-maps)

> [!IMPORTANT]
> **Version pinning.** The CDN examples below use unversioned URLs, which unpkg resolves to the latest published release. This is convenient for development and quick experimentation. For production, pin to a specific version (e.g. `@2.1.0`) so a future release can't change behaviour without warning. The SRI example below pins explicitly because the integrity hash is bytes-specific — never combine SRI with `@latest` or an unversioned URL.

---

## Embedded mode (Zero config)

Import the embedded blobs alongside the main library. WASM is baked into the JS
as gzip+base64, so there are no extra network requests beyond the module files
themselves.

```html
<script type="module">
  import { init, Seal, SerpentCipher } from 'https://unpkg.com/leviathan-crypto/dist/index.js'
  import { serpentWasm } from 'https://unpkg.com/leviathan-crypto/dist/serpent/embedded.js'
  import { sha2Wasm }    from 'https://unpkg.com/leviathan-crypto/dist/sha2/embedded.js'

  await init({ serpent: serpentWasm, sha2: sha2Wasm })

  const key       = SerpentCipher.keygen()
  const blob      = Seal.encrypt(SerpentCipher, key, new TextEncoder().encode('hello from the browser'))
  const decrypted = Seal.decrypt(SerpentCipher, key, blob)

  console.log(new TextDecoder().decode(decrypted))
</script>
```

Subpath imports also work with full URLs:

```html
<script type="module">
  import { serpentInit, SerpentCipher } from 'https://unpkg.com/leviathan-crypto/dist/serpent/index.js'
  import { serpentWasm } from 'https://unpkg.com/leviathan-crypto/dist/serpent/embedded.js'

  await serpentInit(serpentWasm)
  // ...
</script>
```

---

## URL-based loading

Pass a `URL` pointing at the `.wasm` file on the CDN. The browser uses
`WebAssembly.compileStreaming` to compile the binary while it downloads.

```html
<script type="module">
  import { init, SHA256 } from 'https://unpkg.com/leviathan-crypto/dist/index.js'

  await init({
    sha2: new URL('https://unpkg.com/leviathan-crypto/dist/sha2.wasm')
  })

  const sha    = new SHA256()
  const digest = sha.hash(new TextEncoder().encode('hello'))
  console.log(digest)
  sha.dispose()
</script>
```

The server must respond with `Content-Type: application/wasm`.

**WASM filenames by module:**

| Module     | File            |
|------------|-----------------|
| `serpent`  | `serpent.wasm`  |
| `chacha20` | `chacha20.wasm` |
| `sha2`     | `sha2.wasm`     |
| `sha3`     | `sha3.wasm`     |
| `kyber`    | `kyber.wasm`    |

---

## Manual loading (fetch + ArrayBuffer)

Fetch the WASM binary yourself and pass the `ArrayBuffer` directly. Useful when
you want to cache the binary, load from a custom endpoint, or verify integrity
before instantiation.

```html
<script type="module">
  import { init, Seal, XChaCha20Cipher } from 'https://unpkg.com/leviathan-crypto@2.1.0/dist/index.js'
  import { sha2Wasm } from 'https://unpkg.com/leviathan-crypto@2.1.0/dist/sha2/embedded.js'

  const res = await fetch('https://unpkg.com/leviathan-crypto@2.1.0/dist/chacha20.wasm', {
    // SRI requires version + hash to be paired — both update together.
    integrity: 'sha384-...'
  })
  const binary = new Uint8Array(await res.arrayBuffer())

  await init({ chacha20: binary, sha2: sha2Wasm })

  const key       = XChaCha20Cipher.keygen()
  const blob      = Seal.encrypt(XChaCha20Cipher, key, new TextEncoder().encode('manual mode'))
  const plaintext = Seal.decrypt(XChaCha20Cipher, key, blob)

  console.log(new TextDecoder().decode(plaintext))
</script>
```

> [!TIP]
> The `integrity` option is standard SRI ([Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)).
> The browser verifies the hash before resolving the response, and throws a network error if it doesn't match.

---

## Import maps

Browsers don't read `package.json` exports, so bare specifiers like
`import { init } from 'leviathan-crypto'` don't work without an import map.
If you want the same import style as the npm docs, add one before your module scripts:

```html
<script type="importmap">
{
  "imports": {
    "leviathan-crypto":                    "https://unpkg.com/leviathan-crypto/dist/index.js",
    "leviathan-crypto/serpent":            "https://unpkg.com/leviathan-crypto/dist/serpent/index.js",
    "leviathan-crypto/serpent/embedded":   "https://unpkg.com/leviathan-crypto/dist/serpent/embedded.js",
    "leviathan-crypto/chacha20":           "https://unpkg.com/leviathan-crypto/dist/chacha20/index.js",
    "leviathan-crypto/chacha20/embedded":  "https://unpkg.com/leviathan-crypto/dist/chacha20/embedded.js",
    "leviathan-crypto/sha2":               "https://unpkg.com/leviathan-crypto/dist/sha2/index.js",
    "leviathan-crypto/sha2/embedded":      "https://unpkg.com/leviathan-crypto/dist/sha2/embedded.js",
    "leviathan-crypto/sha3":               "https://unpkg.com/leviathan-crypto/dist/sha3/index.js",
    "leviathan-crypto/sha3/embedded":      "https://unpkg.com/leviathan-crypto/dist/sha3/embedded.js",
    "leviathan-crypto/stream":             "https://unpkg.com/leviathan-crypto/dist/stream/index.js"
  }
}
</script>

<script type="module">
  import { init, Seal, SerpentCipher } from 'leviathan-crypto'
  import { serpentWasm } from 'leviathan-crypto/serpent/embedded'
  import { sha2Wasm }    from 'leviathan-crypto/sha2/embedded'
  // identical to the npm usage docs from here
</script>
```

> [!IMPORTANT]
> The import map must appear before any `<script type="module">` that uses bare
> specifiers. Import maps are [supported in all modern browsers](https://caniuse.com/import-maps)
> (Chrome 89+, Firefox 108+, Safari 16.4+).

---


## Cross-References

| Document | Description |
| -------- | ----------- |
| [index](./README.md) | Project Documentation index |
| [architecture](./architecture.md) | architecture overview, module relationships, buffer layouts, and build pipeline |
| [lexicon](./lexicon.md) | Glossary of cryptographic terms |
| [examples](./examples.md) | Code examples for every primitive |

