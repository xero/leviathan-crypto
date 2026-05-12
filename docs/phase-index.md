# Phase Index, v3 signature work

Status (as of 2026-05-14): Phase 1 and Phase 2 complete. DOGFOOD milestone reached.

## Phase 1, Abstraction
  Status: ✅ complete
  Delivers: sig-iface, sig-env, sig-stream, 6 mldsa suites (0x03-0x05, 0x13-0x15)
  Owned files: src/ts/sign/, src/ts/sign/suites/mldsa.ts
  Depends on: existing mldsa primitive (extended with signHashPrehashed/verifyHashPrehashed)
  Scope guard: no new WASM; no other suites; no log work

## Phase 2, SLH-DSA + PQ-only hybrids        [DOGFOOD MILESTONE]
  Status: ✅ complete
  Delivers: slhdsa primitive (3 levels) + 6 slhdsa suites (0x06-0x08, 0x16-0x18) + 3 PQ-only hybrid suites (0x30-0x32)
  Owned files: src/asm/slhdsa/, src/ts/slhdsa/, src/ts/sign/suites/slhdsa.ts, src/ts/sign/suites/hybrid-pq.ts
  Depends on: Phase 1 (sig-iface)
  Scope guard: SLH-DSA + PQ-only hybrids only; no classical work; no BLAKE3

## Phase 3, BLAKE3
  Status: ⏳ queued
  Delivers: BLAKE3 flat hash, tree mode, keyed hash, derive-key
  Owned files: src/asm/blake3/, src/ts/blake3/
  Depends on: nothing
  Scope guard: BLAKE3 primitives only; no log work

## Phase 4, Curve25519 family
  Status: ⏳ queued
  Delivers: Curve25519 substrate + Ed25519 + X25519 + 2 Ed25519 suites (0x01, 0x11)
  Owned files: src/asm/curve25519/, src/ts/ed25519/, src/ts/x25519/, src/ts/sign/suites/ed25519.ts
  Depends on: Phase 1 (sig-iface)
  Scope guard: Ed25519 + X25519 only; no Ristretto, no FROST, no Curve448

## Phase 5, P-256 / ECDSA
  Status: ⏳ queued
  Delivers: P-256 substrate + ECDSA-P256 + 1 ECDSA suite (0x02)
  Owned files: src/asm/p256/, src/ts/ecdsa/, src/ts/sign/suites/ecdsa-p256.ts
  Depends on: Phase 1 (sig-iface)
  Scope guard: P-256 + ECDSA only; no P-384; no DER on hot path

## Phase 6, Classical+PQ hybrids
  Status: ⏳ queued
  Delivers: 4 classical+PQ hybrid suites (0x20-0x23)
  Owned files: src/ts/sign/suites/hybrid-classical.ts
  Depends on: Phase 1 (mldsa-suites), Phase 4 (ed25519-suite), Phase 5 (ecdsa-suite)
  Scope guard: 4 hybrid suite consts only; no other suite work

## Phase 7, Merkle log + STH                  [RELEASE MILESTONE]
  Status: ⏳ queued
  Delivers: Rfc9162Log + Blake3Log + MerkleLog interface + SignedTreeHead + proof verification utilities
  Owned files: src/ts/merkle/
  Depends on: Phase 1 (sig-env), Phase 3 (blake3-tree)
  Scope guard: log + STH only; no new primitive work; no witness cosigning protocol
