# Leviathan Crypto Library: CDN Usage

> [!NOTE]
> leviathan-crypto is published to npm and mirrored on [unpkg](https://unpkg.com).
> All three [WASM loading modes](./init.md#usage-examples) work directly from the
> CDN — no install, no bundler.

---

## Embedded mode (recommended)

The default. WASM is baked into the JS as base64, so there are no extra network
requests beyond the module files themselves. Zero config.

```html
<script type="module">
  import { init, SerpentSeal, randomBytes } from 'https://unpkg.com/leviathan-crypto@1.3.0/dist/index.js'

  await init(['serpent', 'sha2'])

  const key        = randomBytes(64)
  const seal       = new SerpentSeal()
  const ciphertext = seal.encrypt(key, new TextEncoder().encode('hello from the browser'))
  const decrypted  = seal.decrypt(key, ciphertext)

  console.log(new TextDecoder().decode(decrypted))
  seal.dispose()
</script>
```

Subpath imports also work with full URLs:

```html
<script type="module">
  import { serpentInit, SerpentSeal } from 'https://unpkg.com/leviathan-crypto@1.3.0/dist/serpent/index.js'

  await serpentInit()
  // ...
</script>
```

---

## Streaming mode

Uses [`WebAssembly.instantiateStreaming`](./loader.md#loadstreaming) to compile
WASM directly from the network response — more efficient than the embedded base64
path for performance-sensitive applications. Pass `wasmUrl` pointing at the
directory containing the `.wasm` files.

```html
<script type="module">
  // can point at unpkg or your own CDN
  import { init, SHA256 } from 'https://unpkg.com/leviathan-crypto@1.3.0/dist/index.js'

  await init(['sha2'], 'streaming', {
    wasmUrl: 'https://unpkg.com/leviathan-crypto@1.3.0/dist/'
  })

  const sha    = new SHA256()
  const digest = sha.hash(new TextEncoder().encode('hello'))
  console.log(digest)
  sha.dispose()
</script>
```

[`init()`](./init.md) appends the module's filename to `wasmUrl` automatically.
WASM filenames by module:

| Module     | File            |
|------------|-----------------|
| `serpent`  | `serpent.wasm`  |
| `chacha20` | `chacha20.wasm` |
| `sha2`     | `sha2.wasm`     |
| `sha3`     | `sha3.wasm`     |

---

## Manual mode

Fetch the WASM binary yourself and hand it to [`init()`](./init.md#manual-mode-full-control).
Maximum control — useful when you want to cache the binary, load from a custom
endpoint, or verify integrity before instantiation.

```html
<script type="module">
  // can point at unpkg or your own CDN
  import { init, XChaCha20Poly1305, randomBytes } from 'https://unpkg.com/leviathan-crypto@1.3.0/dist/index.js'

  const res    = await fetch('https://unpkg.com/leviathan-crypto@1.3.0/dist/chacha20.wasm')
  const binary = await res.arrayBuffer()

  await init(['chacha20'], 'manual', {
    wasmBinary: { chacha20: binary }
  })

  const aead      = new XChaCha20Poly1305()
  const key       = randomBytes(32)
  const nonce     = randomBytes(24)
  const sealed    = aead.encrypt(key, nonce, new TextEncoder().encode('manual mode'))
  const plaintext = aead.decrypt(key, nonce, sealed)

  console.log(new TextDecoder().decode(plaintext))
  aead.dispose()
</script>
```

See [`InitOpts.wasmBinary`](./init.md#types) for the full manual mode API.

---

## Optional: cleaner imports with an import map

Browsers don't read `package.json` exports — bare specifiers like
`import { init } from 'leviathan-crypto'` don't work without an import map.
If you want the same import style as the npm docs, define one in `<head>`:

```html
<script type="importmap">
{
  "imports": {
    "leviathan-crypto":          "https://unpkg.com/leviathan-crypto@1.3.0/dist/index.js",
    "leviathan-crypto/serpent":  "https://unpkg.com/leviathan-crypto@1.3.0/dist/serpent/index.js",
    "leviathan-crypto/chacha20": "https://unpkg.com/leviathan-crypto@1.3.0/dist/chacha20/index.js",
    "leviathan-crypto/sha2":     "https://unpkg.com/leviathan-crypto@1.3.0/dist/sha2/index.js",
    "leviathan-crypto/sha3":     "https://unpkg.com/leviathan-crypto@1.3.0/dist/sha3/index.js"
  }
}
</script>

<script type="module">
  import { init, SerpentSeal, randomBytes } from 'leviathan-crypto'
  // identical to the npm usage docs from here
</script>
```

> [!NOTE]
> The import map must appear before any `<script type="module">` that uses bare
> specifiers. Import maps are [supported in all modern browsers](https://caniuse.com/import-maps)
> (Chrome 89+, Firefox 108+, Safari 16.4+).
