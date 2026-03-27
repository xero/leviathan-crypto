#!/usr/bin/env bun
// scripts/generate_simd.ts
//
// Generates SIMD-accelerated encryptBlock_simd_4x and decryptBlock_simd_4x
// for src/asm/serpent/serpent_simd.ts.
//
// Usage:
//   bun scripts/generate_simd.ts > src/asm/serpent/serpent_simd.ts
//
// Each v128 register holds 4 × i32 lanes — one lane per independent block.
// S-box gate logic is extracted from src/asm/serpent/serpent.ts and translated
// mechanically: rget→rget_v, rset→rset_v, bitwise ops→v128 namespace.
//
// Commit the generator AND the generated output. To modify the SIMD
// functions, edit this generator and re-run — never edit the output by hand.

import { readFileSync } from 'fs'

// ── Round constant functions — copied verbatim from src/asm/serpent/serpent.ts ──
// MUST be identical to ec(), dc() in serpent.ts. Do not approximate or rederive.

const ec = (n: number): number => {
  const vals = [
    44255, 61867, 45034, 52496, 73087, 56255, 43827, 41448,
    18242,  1939, 18581, 56255, 64584, 31097, 26469, 77728,
    77639,  4216, 64585, 31097, 66861, 78949, 58006, 59943,
    49676, 78950,  5512, 78949, 27525, 52496, 18670, 76143,
  ]
  return vals[n] ?? 0
}

const dc = (n: number): number => {
  const vals = [
    44255, 60896, 28835,  1837,  1057,  4216, 18242, 77301,
    47399, 53992,  1939,  1940, 66420, 39172, 78950, 45917,
    82383,  7450, 67288, 26469, 83149, 57565, 66419, 47400,
    58006, 44254, 18581, 18228, 33048, 45034, 66508,  7449,
  ]
  return vals[n] ?? 0
}

// Extract 5 slot indices from CRT-encoded constant
const slots = (m: number): [number, number, number, number, number] =>
  [m % 5, m % 7, m % 11, m % 13, m % 17]

const SB = ['sb0_v', 'sb1_v', 'sb2_v', 'sb3_v', 'sb4_v', 'sb5_v', 'sb6_v', 'sb7_v']
const SI = ['si0_v', 'si1_v', 'si2_v', 'si3_v', 'si4_v', 'si5_v', 'si6_v', 'si7_v']

// ── Read scalar S-box gate logic from serpent.ts ────────────────────────────

const serpentSrc = readFileSync('src/asm/serpent/serpent.ts', 'utf8')

function extractBody(name: string): string {
  const m = serpentSrc.match(new RegExp(`function ${name}\\([^)]+\\):\\s*void\\s*\\{([^}]+)\\}`))
  if (!m) throw new Error(`Cannot find function ${name} in serpent.ts`)
  return m[1]
}

// Translate scalar S-box operations to v128 equivalents.
// Order matters: NOT before binary ops, binary ops before ASSIGN.
function toSimd(body: string): string {
  return body
    // ~rget(x) → v128.not(rget_v(x))
    .replace(/rset\((\w+), ~rget\((\w+)\)\)/g,
      'rset_v($1, v128.not(rget_v($2)))')
    // rget(x) | rget(y) → v128.or(rget_v(x), rget_v(y))
    .replace(/rset\((\w+), rget\((\w+)\) \| rget\((\w+)\)\)/g,
      'rset_v($1, v128.or(rget_v($2), rget_v($3)))')
    // rget(x) ^ rget(y) → v128.xor(rget_v(x), rget_v(y))
    .replace(/rset\((\w+), rget\((\w+)\) \^ rget\((\w+)\)\)/g,
      'rset_v($1, v128.xor(rget_v($2), rget_v($3)))')
    // rget(x) & rget(y) → v128.and(rget_v(x), rget_v(y))
    .replace(/rset\((\w+), rget\((\w+)\) & rget\((\w+)\)\)/g,
      'rset_v($1, v128.and(rget_v($2), rget_v($3)))')
    // rget(x) → rget_v(x) (simple assign — must be last)
    .replace(/rset\((\w+), rget\((\w+)\)\)/g,
      'rset_v($1, rget_v($2))')
}

function emitSbox(scalarName: string, simdName: string): string {
  const body = toSimd(extractBody(scalarName))
  return `@inline function ${simdName}(x0: i32, x1: i32, x2: i32, x3: i32, x4: i32): void {${body}}`
}

// ── Round generators ──────────────────────────────────────────────────────────

const genEncRound = (n: number): string => {
  const [a, b, c, d, e] = slots(ec(n))
  const [a2, b2, c2, d2, e2] = slots(ec(n + 1))
  return [
    `\t${SB[n % 8]}(${a}, ${b}, ${c}, ${d}, ${e})`,
    `\tlk_v(${a2}, ${b2}, ${c2}, ${d2}, ${e2}, ${n + 1})`,
  ].join('\n')
}

const genFinalEncRound = (): string => {
  const [a, b, c, d, e] = slots(ec(31))
  return `\t${SB[31 % 8]}(${a}, ${b}, ${c}, ${d}, ${e})`
}

const genDecRound = (n: number): string => {
  const sboxIdx = 7 - (n % 8)
  const [a, b, c, d, e] = slots(dc(n))
  const [a2, b2, c2, d2, e2] = slots(dc(n + 1))
  return [
    `\t${SI[sboxIdx]}(${a}, ${b}, ${c}, ${d}, ${e})`,
    `\tkl_v(${a2}, ${b2}, ${c2}, ${d2}, ${e2}, ${31 - n})`,
  ].join('\n')
}

const genFinalDecRound = (): string => {
  const sboxIdx = 7 - (31 % 8)
  const [a, b, c, d, e] = slots(dc(31))
  return `\t${SI[sboxIdx]}(${a}, ${b}, ${c}, ${d}, ${e})`
}

// ── ASCII art header ────────────────────────────────────────────────────────

const HEADER = `//                  ▄▄▄▄▄▄▄▄▄▄
//           ▄████████████████████▄▄          ▒  ▄▀▀ ▒ ▒ █ ▄▀▄ ▀█▀ █ ▒ ▄▀▄ █▀▄
//        ▄██████████████████████ ▀████▄      ▓  ▓▀  ▓ ▓ ▓ ▓▄▓  ▓  ▓▀▓ ▓▄▓ ▓ ▓
//      ▄█████████▀▀▀     ▀███████▄▄███████▌  ▀▄ ▀▄▄ ▀▄▀ ▒ ▒ ▒  ▒  ▒ █ ▒ ▒ ▒ █
//     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌
//     ████████      ███▀▀     ████▀  █▀ █▀       Leviathan Crypto Library
//     ███████▌    ▀██▀         ███
//      ███████   ▀███           ▀██ ▀█▄      Repository & Mirror:
//       ▀██████   ▄▄██            ▀▀  ██▄    github.com/xero/leviathan-crypto
//         ▀█████▄   ▄██▄             ▄▀▄▀    unpkg.com/leviathan-crypto
//            ▀████▄   ▄██▄
//              ▐████   ▐███                  Author: xero (https://x-e.ro)
//       ▄▄██████████    ▐███         ▄▄      License: MIT
//    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
//  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
//   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
//  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
//  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
//   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
//                           ▀█████▀▀`

// ── Emit file ───────────────────────────────────────────────────────────────

const lines: string[] = []

// Header
lines.push(HEADER)
lines.push('//')
lines.push('// src/asm/serpent/serpent_simd.ts')
lines.push('//')
lines.push('// AUTO-GENERATED — do not edit by hand.')
lines.push('// To regenerate: bun scripts/generate_simd.ts > src/asm/serpent/serpent_simd.ts')
lines.push('//')
lines.push('// SIMD-accelerated Serpent-256 encrypt and decrypt (4 blocks per call).')
lines.push('// Each v128 register holds 4 × i32 lanes; lane[k] = word from block k.')
lines.push('// S-box gate logic derived from serpent.ts; rotation amounts from the spec.')
lines.push('//')
lines.push(`// Generated: ${new Date().toISOString()}`)
lines.push('')
lines.push("import { SUBKEY_OFFSET, SIMD_WORK_OFFSET } from './buffers'")
lines.push('')

// v128 register helpers
lines.push('// v128 working register helpers — 5 × v128 at SIMD_WORK_OFFSET, 16-byte stride')
lines.push('@inline function rget_v(i: i32): v128 { return v128.load(SIMD_WORK_OFFSET + (i << 4)) }')
lines.push('@inline function rset_v(i: i32, v: v128): void { v128.store(SIMD_WORK_OFFSET + (i << 4), v) }')
lines.push('')

// Forward S-boxes (sb0_v – sb7_v)
lines.push('// ── Forward S-boxes (v128) ──────────────────────────────────────────────────')
lines.push('')
for (let i = 0; i < 8; i++) {
  lines.push(emitSbox(`sb${i}`, `sb${i}_v`))
  lines.push('')
}

// Inverse S-boxes (si0_v – si7_v)
lines.push('// ── Inverse S-boxes (v128) ──────────────────────────────────────────────────')
lines.push('')
for (let i = 0; i < 8; i++) {
  lines.push(emitSbox(`si${i}`, `si${i}_v`))
  lines.push('')
}

// keyXor_v — subkey XOR with splat broadcast
lines.push('// ── Key XOR (v128) — splat scalar subkey to all 4 lanes ────────────────────')
lines.push('')
lines.push(`@inline function keyXor_v(a: i32, b: i32, c: i32, d: i32, i: i32): void {
\trset_v(a, v128.xor(rget_v(a), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 0) * 4))))
\trset_v(b, v128.xor(rget_v(b), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 1) * 4))))
\trset_v(c, v128.xor(rget_v(c), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 2) * 4))))
\trset_v(d, v128.xor(rget_v(d), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 3) * 4))))
}`)
lines.push('')

// lk_v — linear transform + key XOR (encrypt direction)
// Rotation amounts copied exactly from lk() in serpent.ts (Serpent spec).
lines.push('// ── Linear transform + key XOR (v128, encrypt) ─────────────────────────────')
lines.push('// Rotation amounts: 13, 3, 1, 7, 5, 22 — from Serpent spec via serpent.ts lk()')
lines.push('')
lines.push(`@inline function lk_v(a: i32, b: i32, c: i32, d: i32, e: i32, i: i32): void {
\trset_v(a, v128.or(i32x4.shl(rget_v(a), 13), i32x4.shr_u(rget_v(a), 19)))
\trset_v(c, v128.or(i32x4.shl(rget_v(c), 3), i32x4.shr_u(rget_v(c), 29)))
\trset_v(b, v128.xor(rget_v(b), rget_v(a)))
\trset_v(e, i32x4.shl(rget_v(a), 3))
\trset_v(d, v128.xor(rget_v(d), rget_v(c)))
\trset_v(b, v128.xor(rget_v(b), rget_v(c)))
\trset_v(b, v128.or(i32x4.shl(rget_v(b), 1), i32x4.shr_u(rget_v(b), 31)))
\trset_v(d, v128.xor(rget_v(d), rget_v(e)))
\trset_v(d, v128.or(i32x4.shl(rget_v(d), 7), i32x4.shr_u(rget_v(d), 25)))
\trset_v(e, rget_v(b))
\trset_v(a, v128.xor(rget_v(a), rget_v(b)))
\trset_v(e, i32x4.shl(rget_v(e), 7))
\trset_v(c, v128.xor(rget_v(c), rget_v(d)))
\trset_v(a, v128.xor(rget_v(a), rget_v(d)))
\trset_v(c, v128.xor(rget_v(c), rget_v(e)))
\trset_v(d, v128.xor(rget_v(d), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 3) * 4))))
\trset_v(b, v128.xor(rget_v(b), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 1) * 4))))
\trset_v(a, v128.or(i32x4.shl(rget_v(a), 5), i32x4.shr_u(rget_v(a), 27)))
\trset_v(c, v128.or(i32x4.shl(rget_v(c), 22), i32x4.shr_u(rget_v(c), 10)))
\trset_v(a, v128.xor(rget_v(a), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 0) * 4))))
\trset_v(c, v128.xor(rget_v(c), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 2) * 4))))
}`)
lines.push('')

// kl_v — inverse linear transform + key XOR (decrypt direction)
// Rotation amounts copied exactly from kl() in serpent.ts (Serpent spec).
lines.push('// ── Inverse linear transform + key XOR (v128, decrypt) ──────────────────────')
lines.push('// Rotation amounts: 27, 10, 31, 25, 19, 29 — from Serpent spec via serpent.ts kl()')
lines.push('')
lines.push(`@inline function kl_v(a: i32, b: i32, c: i32, d: i32, e: i32, i: i32): void {
\trset_v(a, v128.xor(rget_v(a), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 0) * 4))))
\trset_v(b, v128.xor(rget_v(b), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 1) * 4))))
\trset_v(c, v128.xor(rget_v(c), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 2) * 4))))
\trset_v(d, v128.xor(rget_v(d), i32x4.splat(load<i32>(SUBKEY_OFFSET + (4 * i + 3) * 4))))
\trset_v(a, v128.or(i32x4.shl(rget_v(a), 27), i32x4.shr_u(rget_v(a), 5)))
\trset_v(c, v128.or(i32x4.shl(rget_v(c), 10), i32x4.shr_u(rget_v(c), 22)))
\trset_v(e, rget_v(b))
\trset_v(c, v128.xor(rget_v(c), rget_v(d)))
\trset_v(a, v128.xor(rget_v(a), rget_v(d)))
\trset_v(e, i32x4.shl(rget_v(e), 7))
\trset_v(a, v128.xor(rget_v(a), rget_v(b)))
\trset_v(b, v128.or(i32x4.shl(rget_v(b), 31), i32x4.shr_u(rget_v(b), 1)))
\trset_v(c, v128.xor(rget_v(c), rget_v(e)))
\trset_v(d, v128.or(i32x4.shl(rget_v(d), 25), i32x4.shr_u(rget_v(d), 7)))
\trset_v(e, i32x4.shl(rget_v(a), 3))
\trset_v(b, v128.xor(rget_v(b), rget_v(a)))
\trset_v(d, v128.xor(rget_v(d), rget_v(e)))
\trset_v(a, v128.or(i32x4.shl(rget_v(a), 19), i32x4.shr_u(rget_v(a), 13)))
\trset_v(b, v128.xor(rget_v(b), rget_v(c)))
\trset_v(d, v128.xor(rget_v(d), rget_v(c)))
\trset_v(c, v128.or(i32x4.shl(rget_v(c), 29), i32x4.shr_u(rget_v(c), 3)))
}`)
lines.push('')

// ── encryptBlock_simd_4x ──────────────────────────────────────────────────

lines.push('// ── Encrypt 4 blocks (v128) ─────────────────────────────────────────────────')
lines.push('// Caller loads 4 interleaved plaintext blocks into v128 registers [0..3].')
lines.push('// lane[k] of register r[w] = word w of block k  (k = 0..3).')
lines.push('// Result is left in v128 registers [0..3] for caller to deinterleave.')
lines.push('export function encryptBlock_simd_4x(): void {')
lines.push('\tkeyXor_v(0, 1, 2, 3, 0) // K(0)')
lines.push('')

for (let n = 0; n < 31; n++) {
  lines.push(`\t// Round ${n}: ${SB[n % 8]}`)
  lines.push(genEncRound(n))
  lines.push('')
}

lines.push('\t// Round 31 (final — no linear transform)')
lines.push(genFinalEncRound())
lines.push('')
lines.push('\tkeyXor_v(0, 1, 2, 3, 32) // K(32)')
lines.push('}')
lines.push('')

// ── decryptBlock_simd_4x ──────────────────────────────────────────────────

lines.push('// ── Decrypt 4 blocks (v128) ─────────────────────────────────────────────────')
lines.push('// Same interleaved layout as encrypt. Result in v128 registers.')
lines.push('// Note: output registers are [4,1,3,2] not [0,1,2,3] — matches scalar decrypt.')
lines.push('export function decryptBlock_simd_4x(): void {')
lines.push('\tkeyXor_v(0, 1, 2, 3, 32) // K(32)')
lines.push('')

for (let n = 0; n < 31; n++) {
  const sboxIdx = 7 - (n % 8)
  lines.push(`\t// Round ${n}: ${SI[sboxIdx]}`)
  lines.push(genDecRound(n))
  lines.push('')
}

lines.push('\t// Round 31 (final — no inverse linear transform)')
lines.push(genFinalDecRound())
lines.push('')
lines.push('\t// K(0): final key XOR — slots (2,3,1,4), NOT (0,1,2,3)')
lines.push('\tkeyXor_v(2, 3, 1, 4, 0)')
lines.push('}')

process.stdout.write(lines.join('\n') + '\n')
