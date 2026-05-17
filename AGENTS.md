# Agent Instructions: Leviathan Crypto Library

Development contract for AI-assisted work on this repo. Read in full
before starting any task.

---

## What This Project Is

`leviathan-crypto` is a strictly-typed, zero-dependency WebAssembly
crypto library for the web. All cryptographic computation runs in WASM
(AssemblyScript), outside the JS JIT. The TypeScript layer provides
the public API, input validation, type safety, and ergonomics; it
never implements cryptographic algorithms.

`docs/architecture.md` is required reading before implementation work
(module structure, `init()` contract, class naming, build pipeline,
repo layout). On any conflict with `docs/architecture.md`, the
architecture doc wins; flag the conflict instead of resolving it
silently.

---

## Build & Test

`bun i` first, every session. Missing devDependencies cause debug-time
waste.

| Command | Action |
|---|---|
| `bun i` | install (first, every session) |
| `bun bake` | full build (asm → embed → ts → wasm copy → docs) |
| `bun check` | full test suite (unit + browser, correct timeouts) |
| `bun fix` | eslint autofix (before marking any task done) |
| `bun pin` | re-pin action SHAs (after any workflow file change) |

**Never run `bun build` directly.** That invokes the Bun bundler, not
the project build. Shorthands and `bun run {build,test,lint,pin-actions}`
dispatch through the same scripts (`scripts/{build,check,lint,pin-actions}.ts`);
prefer the shorthand.

`bun check` does a full build then runs lint + unit + e2e in parallel.
Capture output to avoid re-running:

```sh
bun check 2>&1 | tee /tmp/check.log
grep -E "passed|failed|error" /tmp/check.log
grep -A 10 "FAIL" /tmp/check.log    # on failure
```

**Workflow file changes require `bun pin` before committing.**

**`bun scripts/test.ts unit:group <name>` in CI workflows is correct
and intentional.** Each `.github/workflows/unit-*.yml` invokes this
for its group; per-group file lists, build prerequisites, and timeouts
live in `scripts/lib/test-groups.ts` as the single source of truth.
Don't replace these with `bun check`; don't edit workflow YAML to add
or remove individual test paths. Group composition belongs in
`test-groups.ts` (see Test File Maintenance below).

### Running tests during iteration

`bun check` is the umbrella. For one test or one family:

```sh
bun unit test/unit/aes/aes_kat.test.ts       # one unit test file
bun e2e test/e2e/seal.spec.ts                # one e2e spec
bun run test unit:group aes                  # one CI test group locally
```

`bun unit` / `bun e2e` forward extra args to vitest / playwright after
running build prerequisites. `bun run test unit:group <name>` reads
file list and build deps from `scripts/lib/test-groups.ts` and runs
the same composition as `.github/workflows/unit-<name>.yml`. See
[docs/development.md](./docs/development.md) for full developer
workflow.

Always `bun check` before marking a task done; targeted commands are
for iteration speed, not final verification.

---

## Ground Rules

Every session, every file, every decision. Not suggestions. If a task
conflicts, the rules win.

### 1. The spec is the authority

The published standard is authoritative when implementing a primitive:

- Serpent: AES submission (Anderson, Biham, Knudsen)
- ChaCha20, Poly1305, ChaCha20-Poly1305: RFC 8439
- XChaCha20-Poly1305: draft-irtf-cfrg-xchacha
- SHA-256, SHA-384, SHA-512: FIPS 180-4
- SHA-3, SHAKE: FIPS 202
- HMAC: RFC 2104
- HMAC test vectors: RFC 4231

If any repo file states a cryptographic value (hash output, round
constant, test vector expected) that differs from the spec, **the spec
wins**. Flag the discrepancy. Don't silently use the wrong value.

> **Why:** a planning doc once held a wrong expected for SHA-256("abc");
> an agent treated the doc as authoritative and corrupted the test
> vectors to make the (correct) implementation pass.

### 2. Test vectors are immutable

Once written from an authoritative reference, vectors do not change to
make a failing test pass. If a test fails:

- Debug the implementation
- Verify the vector against the authoritative source independently
- If sourced incorrectly, fix the vector and document why
- Never change a vector to match implementation output without
  independent verification. If this happens, produce a findings doc
  and present post-session for review.

A passing suite from adjusted vectors gives zero correctness assurance;
worse than no tests.

### 3. Gate discipline

Every primitive family has a gate test (simplest authoritative KAT,
marked `// GATE` in the test file).

**Gate must pass before any other tests in that family are written.**

If the gate fails, stop and debug the implementation. Don't write
round-trip, streaming, or cross-check tests on a failing gate; they
pass or fail for the wrong reasons.

If the gate passes on the first build, verify the expected was sourced
from the spec, not copied from implementation output. Output-derived
expected is not a gate.

### 4. Independent derivation

Each AssemblyScript primitive is implemented from the spec directly.
Don't port from an existing reference. If a reference exists for
cross-checking, use it **after** the independent implementation passes
its gate, never before. (A ported cross-check only verifies the port;
an independent one is a genuine correctness signal.)

### 5. Never embed cryptographic values in planning documents

Architecture docs, task files, and prompts describe structure and
contracts, not cryptographic values. Hash outputs, round constants,
S-box entries, rotation amounts, and test vector expecteds belong only
in:

- Test files (sourced from the authoritative spec)
- Source code (constants implemented from the spec, with spec section
  cited)

If a test needs an expected, fetch from the spec. Don't use a value
from a prompt or planning doc without independent verification.

### 6. The implementation, not the plan, is the product

Prompts and task files describe intent. Implementation must be correct
per the spec regardless of what the prompt says. If a prompt describes
an algorithm step incorrectly, implement the correct algorithm and
flag the discrepancy.

---

## Code Style

- **Tabs, not spaces** (AssemblyScript and TypeScript)
- **Unix line endings** (see `.gitattributes`)
- **Terse over verbose**: inline conditionals, short variable names,
  no unnecessary intermediates
- **No comments that restate code**: comments explain *why*, not *what*
- **NEVER use emdashes or endashes**: rewrite the sentence or use
  different punctuation. Ranges use a regular hyphen.
- **Spec citations in source**: cite the section. Example:
  `// FIPS 180-4 §4.1.2, Ch function`; use `§` as the section symbol.
- **Exports are the public contract**: keep internal functions
  unexported; only export what the TypeScript layer needs to call.
- **ASCII art header** on every source file (see any existing file)
- **Run `bun fix` before committing**; lint errors aren't the
  reviewer's problem.

---

## Architecture Constraints

Decisions already made. Don't relitigate without raising it first.

- **Independent WASM binaries** with separate linear memory, buffer
  layout, AS entry point. `ct.wasm` is internal SIMD constant-time
  compare.
- **Static buffers only**: no dynamic allocation (`memory.grow()`
  unused). All buffers are fixed offsets in linear memory defined in
  `buffers.ts`.
- **Buffer layout starts at 0**: each module's layout is independent
  and starts at offset 0. No shared memory between modules.
- **TS layer never implements crypto**: `src/ts/` classes write inputs
  to WASM memory, call exported functions, read outputs. That is all.
- **`init()` is required**: no class silently auto-initializes. Used
  before its module is loaded, it throws a clear error.
- **`src/ts/embedded/` is gitignored**: build artifacts generated by
  `scripts/embed-wasm.ts` (WASM thunks) and `scripts/embed-workers.ts`
  (pool-worker IIFE bundles). Don't create or edit manually.
- **`sideEffects: false`** in `package.json`. Every module must be
  genuinely side-effect-free for tree-shaking.
- **`stream/` is cipher-agnostic**: `SealStream`, `OpenStream`, and
  `SealStreamPool` take a `CipherSuite` at construction. Shipped:
  `XChaCha20Cipher` and `SerpentCipher`. Don't add cipher-specific
  stream classes; the generic pattern replaces them.
- **Pool workers bypass the module cache**: each worker instantiates
  its own WASM from pre-compiled `WebAssembly.Module` objects. They
  don't call `initModule()` or share the main-thread cache. Workers
  spawn from blob URLs over an IIFE source bundled at lib build time
  (`src/ts/embedded/<cipher>-pool-worker.ts`); the
  `<cipher>/pool-worker.ts` files are the build inputs, not the
  runtime spawn entries.
- **`/embedded` subpath exports**: each module has a `*/embedded.ts`
  that re-exports the gzip+base64 blob as a named export
  (`serpentWasm`, `chacha20Wasm`, etc.). `src/ts/embedded/` is the
  generated source; per-module files re-export from it.
- **SignatureSuite lifecycle**: suite consts under
  `src/ts/sign/suites/` are stateless and reentrant. Per-call WASM
  lifecycle: instantiate the primitive, use in `try`, `dispose()` in
  `finally`; no long-lived instance. Internal PascalCase factories;
  external named const per format byte; format-byte allocations
  locked. Factories wrapping a primitive whose sign path needs pk for
  the hash chain (Ed25519, ECDSA-P256, anything running
  `R || pk || M` through a digest) route through unexported
  `_signInternalPk` / `_signPrehashedInternalPk` helpers and skip the
  degenerate fault-injection cross-check at the suite call site
  (caller pk and WASM-derived pk come from the same potentially-faulted
  call). Direct-class callers keep `sign(sk, pk, ...)` with the
  cross-check intact for callers holding a stored, known-good pk.
- **SignatureSuite ctx**: every suite carries a built-in `ctxDomain`
  (`{scheme}-envelope-v3`, or `{scheme}-prehash-envelope-v3` for
  prehash, `{scheme1}-{scheme2}-envelope-v3` for hybrids). Suites
  wrap user_ctx via `buildEffectiveCtx(ctxDomain, user_ctx)` before
  calling the primitive. Wire carries raw user_ctx, never
  effective_ctx. Caps: ctxDomain ≤ 32 bytes (factory-validated, plain
  `Error`); user_ctx ≤ 255 bytes (throws
  `SigningError('sig-ctx-too-long')`, matches FIPS 204 §3.6.1);
  combined `effective_ctx` shares the 255-byte cap, lowering the
  user_ctx ceiling to `253 - len(ctxDomain)` (221-234 bytes across
  the catalog).
- **SignatureSuite type wall + composites**: pure-mode suites
  implement `SignatureSuite` only; `SignStream` / `VerifyStream`
  require `StreamableSignatureSuite` (compile-time wall). Prehash and
  hybrid suites implement the latter with `signPrehashed` /
  `verifyPrehashed`. `verifyPrehashed` throws
  `SigningError('sig-malformed-input')` on wrong-length digest
  (caller-side contract via the suite's locked `prehashAlgorithm`,
  not a signature-validity outcome). PQ-only hybrid composites:
  `pk_combined = pk_a || pk_b`, `sig_combined = sig_a || sig_b`, no
  length prefixes, ML-DSA half first by convention; `verifyPrehashed`
  always runs both sub-verifies (no early-return); signature
  subarrays from the wire-split must NOT be wiped on verify failure
  (caller-owned).

---

## Test File Maintenance

Any time a unit or e2e test file is added or removed, two things must
happen. Both required.

### 1. Update `docs/test-suite.md`

- **Test Counts table** (top of file): update unit or e2e count and
  total. Get the new file's count from the `bun check` log:
  `grep -E "test/unit/path/to/file" /tmp/check.log`, or count `it(` /
  `test(` calls in the file directly.
- **Unit Tests / E2E Tests table**: add or remove the matching row.
  Match existing row format (file path, description, vector/test
  count, gate column).

### 2. Update CI (unit tests only)

Playwright discovers e2e specs automatically; no CI change needed for
e2e. For unit tests:

- Find the `UNIT_GROUPS` entry in `scripts/lib/test-groups.ts` whose
  `name` matches the test family (`aes`, `mldsa`, `kyber`, etc.). When
  unsure: `grep -l "test/unit/family" scripts/lib/test-groups.ts`.
- Add or remove the test file path from that group's `files` array.
- No workflow file edit is needed when adding a test to an existing
  group; `.github/workflows/unit-<family>.yml` already calls
  `bun scripts/test.ts unit:group <name>`, which reads the file list
  from `test-groups.ts` at run time.

**Adding a new unit group.** If the new tests belong to a primitive
family with no existing group, do both: (1) add a new `UNIT_GROUPS`
entry to `scripts/lib/test-groups.ts` with `name`, `files`,
`buildTargets`, `timeoutMin`; (2) create a new `unit-<family>.yml`
workflow. Read an existing workflow first and match its structure
exactly (job name format, timeout settings, step order, `bun i`
precondition, the `bun scripts/test.ts unit:group <name>` invocation).
Wire it into `test-suite.yml` following the same pattern as other
unit jobs. Run `bun pin` when done.

---

## Memory and Security

- **`wipeBuffers()` on dispose**: every WASM module exports
  `wipeBuffers()`. The TS wrapper must call it in `dispose()`. Key
  material and intermediate state must not persist in WASM memory
  after an operation completes.
- **Constant-time operations**: MAC verification, padding validation,
  and any comparison of secret-derived values must use XOR-accumulate
  patterns. No early return on mismatch. No branch on secret bytes.
- **AEAD `decrypt()` throws on authentication failure**; never returns
  null. Null returns are a footgun for callers who might forget to
  check.
- **No polyfill for `crypto.getRandomValues`**: fail loudly in
  environments that don't have it.
- **Authentication warnings**: unauthenticated modes (`SerpentCbc`,
  `SerpentCtr`) must carry JSDoc warnings. The README must document
  that these modes require pairing with HMAC (Encrypt-then-MAC) or
  replacement with `XChaCha20Poly1305`.

---

## Docs as Contract (not Authority)

`docs/*.md` describe what the library does; they are not authoritative
on cryptographic values or algorithm behavior. The spec is. If a doc
contradicts the spec, the spec wins and the doc is wrong.

However, docs ARE authoritative on API shape. If `docs/serpent.md`
says `SerpentCipher` has `formatEnum: 0x02` and the source disagrees,
flag the discrepancy; don't silently resolve in either direction.

### Two doc audiences

`docs/` serves two distinct readers with different obligations:

1. **Per-feature API reference** (`docs/serpent.md`, `docs/aead.md`,
   `docs/mldsa.md`, etc). Canonical API references; ship inside the
   npm package via the INCLUDE list in `scripts/copy-docs.ts`.
   Load-bearing for consumer AI agents: `docs/CLAUDE_consumer.md`
   routes agents here for any non-trivial API work.

2. **Consumer AI quickstart** (`docs/CLAUDE_consumer.md`). The build
   pipeline copies this to repo-root `CLAUDE.md` at `npm pack` time
   via `scripts/pack.ts --pre`, removes post-pack. Consumers find it
   at `node_modules/leviathan-crypto/CLAUDE.md`. Source of truth
   always lives at `docs/CLAUDE_consumer.md`; never edit the root copy.

### `docs/CLAUDE_consumer.md` generation rules

`CLAUDE_consumer.md` is the consumer-facing AI quickstart. NOT a
duplicate of any `docs/<feature>.md`. It exists to front-load the
foot-guns an agent will hit immediately on first use, route the agent
to the right feature doc, and show one canonical example. Everything
else lives in the per-feature doc.

Structure (target ≤ 8000 chars, hard cap 10000):

1. **Repo-out redirect**: `> [!NOTE]` block at the top telling agents
   working *inside* the repo to stop and read `AGENTS.md` instead.
   Cheap insurance against the pack artifact slipping into a dev
   session.
2. **Identity**: what the library is. ~5 lines of content; paragraph
   or compact family table.
3. **API shape**: tier × axis table (one-shot / streaming / parallel
   × AEAD / signatures) plus the high-level-surface preference
   statement. Routes agents to the right entry point.
4. **Critical foot-guns**: repo-wide ones that apply to every consumer
   regardless of which primitive they touch: `init()` required,
   `dispose()` in finally, stateful exclusivity, `decrypt()` throws,
   raw `verify()` returns bool with `Sign.verify` envelope
   discriminator, pure vs prehash sig wall, sign-envelope `ctx`
   requirement, ratchet-is-KDF-not-session. ≤ 4000 chars.
5. **Subpath surface**: standard-pattern statement (`<mod>Init` and
   `<mod>Wasm`) plus aliases/exceptions table (`keccak`, `ed25519`,
   `x25519`, `ecdsa`, no-`/embedded` subpaths).
6. **Class → required modules → doc-file routing table**. One row per
   primitive family; doc column points at `docs/<feature>.md`. Hybrid
   suite rows MAY carry a `fmt 0xNN` annotation as a disambiguator;
   wire format internals stay in the feature doc.
7. **Single canonical example**: `Seal` + `SerpentCipher` round-trip
   showing `init` / `keygen` / `encrypt` / throw-on-failure `decrypt`.
   `Seal.encrypt` self-wipes (rule #2 in the file); no explicit
   dispose. No second example.
8. **Reference docs footer**: small table or list pointing to
   non-feature docs (`exports.md`, `init.md`, `examples.md`,
   `types.md`, `loader.md`, `cdn.md`).

Forbidden in `CLAUDE_consumer.md`:

- Per-primitive worked examples (lives in `docs/<primitive>.md`)
- Duplicate API reference tables (lives in `docs/<primitive>.md`)
- Cipher-specific deep dives, wire format internals beyond the
  format-byte disambiguator allowed in §6, error discriminator tables
  (lives in `docs/<primitive>.md`)
- Anything that pushes the file past 10000 chars

The size cap is load-bearing, not aesthetic. If tempted to add a
section, you are almost certainly adding content that belongs in a
feature doc.

Update triggers (modify `CLAUDE_consumer.md`):

- New primitive family → add row to routing table
- New module-init combination → update affected row
- New subpath import → add row to aliases/exceptions table
- New repo-wide foot-gun → add to critical section
- New feature doc shipping via `copy-docs.ts` INCLUDE → routing-table
  row is part of the same change
- Feature doc removed from `copy-docs.ts` INCLUDE → drop its routing
  row in the same change

Non-triggers (update `docs/<feature>.md` only, leave
`CLAUDE_consumer.md` alone):

- New method on an existing class
- New optional parameter on an existing method
- Error message text change
- Internal refactor with no public surface change
- Anything affecting only one primitive family without changing its
  module requirements or subpath surface

### `docs/<feature>.md` agent-readability bar

Because the routing table in `CLAUDE_consumer.md` makes per-feature
docs load-bearing for consumer agents, every `docs/<feature>.md` that
ships (see the INCLUDE list in `scripts/copy-docs.ts`) must contain at
minimum:

- Front-matter table of contents linking every H2 heading
- "Module Init" section near the top showing the exact `init()` call
- "Security Notes" with `> [!CAUTION]` / `> [!IMPORTANT]` callouts for
  every primitive-specific foot-gun
- "API Reference" tables for class members
- "Usage Examples" with at least one canonical happy-path per public
  class
- "Error Conditions" table listing every documented throw
- "Cross-References" footer table pointing to related docs

A new public class or const requires its `docs/<feature>.md` to meet
this bar in the same change that introduces the export. Any new doc
file added to `copy-docs.ts` INCLUDE must meet this bar before merging.

When adding a new primitive doc to `docs/`: add it to the INCLUDE list
in `scripts/copy-docs.ts` in alphabetical order, and add its routing
row to `CLAUDE_consumer.md`. Both edits are part of the same change.
The INCLUDE list edit is what makes the doc actually ship.

---

## Key Files

- Architecture: `docs/architecture.md`
- Test suite reference: `docs/test-suite.md`
- Test vectors: `test/vectors/` (tracked by `test/vectors/SHA256SUMS`)
- Per-module docs: `docs/*.md`
- Consumer AI guide: `docs/CLAUDE_consumer.md`

---

## Definition of Done

A task is complete when **all** are true:

1. `bun check` passes (all unit + e2e green)
2. `bun fix` run, no lint errors remain
3. Gate test for any new primitive sourced from the authoritative spec
4. `wipeBuffers()` covers all new buffers
5. No existing tests modified to make new tests pass
6. Implementation matches the spec, not just the tests
7. Test files added or removed have matching updates in
   `docs/test-suite.md` (Test Counts table + the per-file row in the
   Unit or E2E table)
8. Unit test files added or removed have matching updates in the
   appropriate `unit-*.yml` workflow, followed by `bun pin`
9. Any public API addition, removal, or signature change has matching
   doc updates:
   - `docs/<feature>.md` for affected primitives (canonical API
     reference; always required when that primitive's surface changes)
   - `docs/exports.md` for any export added, removed, or renamed
   - `docs/CLAUDE_consumer.md` only when the change matches an update
     trigger above. Most changes update only the relevant feature doc.
   - `docs/architecture.md` if module structure changed
   - `docs/aead.md` if streaming API or wire format changed

**Release tasks additionally require:**

10. `SECURITY.md` supported versions table updated
11. `CHANGELOG` entry: breaking changes, migration table if applicable,
    added / fixed / removed summary
12. `npm pack --dry-run` run; output reviewed; deleted files absent;
    no unexpected files included
13. `package.json` version bump is NOT part of any task. The release
    workflow handles it at tag time. Never touch `package.json`
    version.

---

## Raising an Issue

**Never guess. Never hallucinate a value, a spec behavior, or an API
decision.**

If any of these are true:

- Can't find an authoritative source for a value you need
- Test failing and you can't tell whether the bug is in the
  implementation, the test vector, or your understanding of the spec
- Two authoritative sources contradict each other
- Task as written is ambiguous and proceeding requires an assumption
  you aren't confident in
- More than two failed attempts at the same problem
- Anything else where the honest answer is "I am not sure"

**Stop. Don't guess. Don't proceed. Raise an issue.**

Two failed attempts is the limit. The third is guessing. Create
`ISSUE.md` at the repository root:

```markdown
# Issue, [short title]

## Status
Blocked. Implementation work stopped at [file / function / test].

## What I was trying to do
[The specific task or step that hit the blocker]

## What I tried
[Each attempt, in order, with the result. Be specific: error messages,
wrong output values, what you expected instead.]

## Where I am stuck
[The specific question, ambiguity, or failure I cannot resolve.
If a spec section is involved, name it.]

## What I need from you
[The specific information, clarification, or decision that would
unblock me.]

## Relevant files
[Source files, test files, docs to look at]

## Relevant spec sections
[Spec sections that are ambiguous, contradictory, or inaccessible]
```

Stop all work and present the issue. A detailed issue that stops work
cleanly is far more valuable than a completed task built on a guess.

---

## When Stuck (Before Raising an Issue)

- **Failing gate**: re-read the spec section. Most common causes:
  wrong rotation amounts, wrong endianness, wrong padding, wrong state
  indexing. Check each independently.
- **Passing tests, wrong output**: verify expecteds came from the spec,
  not the implementation. Run the input through an independent tool
  (OpenSSL, Python hashlib, Node.js crypto).
- **Conflict between files**: this file > `docs/architecture.md` >
  task instructions > any other file. Raise conflicts rather than
  resolving silently.
- **Uncertainty about a decision**: check `docs/architecture.md`. If
  not covered, raise an issue rather than deciding unilaterally.
