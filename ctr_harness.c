/* ----------------------------------------------------------------------------
 *                  ▄▄▄▄▄▄▄▄▄▄
 *           ▄████████████████████▄▄          This file is part of the
 *        ▄██████████████████████ ▀████▄      leviathan crypto library
 *      ▄█████████▀▀▀     ▀███████▄▄███████▌
 *     ▐████████▀   ▄▄▄▄     ▀████████▀██▀█▌  Repository
 *     ████████      ███▀▀     ████▀  █▀ █▀   https://github.com/xero/leviathan
 *     ███████▌    ▀██▀         ███
 *      ███████   ▀███           ▀██ ▀█▄      Author: xero (https://x-e.ro)
 *       ▀██████   ▄▄██            ▀▀  ██▄    License: MIT
 *         ▀█████▄   ▄██▄             ▄▀▄▀
 *            ▀████▄   ▄██▄                   +-------------------------------+
 *              ▐████   ▐███                  | CTR Vector Generation Harness |
 *       ▄▄██████████    ▐███         ▄▄      +-------------------------------+
 *    ▄██▀▀▀▀▀▀▀▀▀▀     ▄████      ▄██▀
 *  ▄▀  ▄▄█████████▄▄  ▀▀▀▀▀     ▄███         This file is provided completely
 *   ▄██████▀▀▀▀▀▀██████▄ ▀▄▄▄▄████▀          free, "as is", and without
 *  ████▀    ▄▄▄▄▄▄▄ ▀████▄ ▀█████▀  ▄▄▄▄     warranty of any kind. The author
 *  █████▄▄█████▀▀▀▀▀▀▄ ▀███▄      ▄████      assumes absolutely no liability
 *   ▀██████▀             ▀████▄▄▄████▀       for its {ab,mis,}use.
 *                           ▀█████▀▀
 *
 * CTR mode vector generation harness for Serpent.
 *
 * Uses the Ross Anderson reference implementation (floppy1, AES submission
 * format) as the underlying ECB primitive.  This is the same reference that
 * produced the authoritative AES-submission test vectors (floppy4) and is
 * the same format used by leviathan's Serpent implementation.
 *
 * Verification: blockEncrypt(all-zero 256-bit key, all-zero block)
 *               == leviathan.encrypt(all-zero key, all-zero block)
 *               == 8910494504181950f98dd998a82b6749  (confirmed empirically)
 *
 * CTR mode is implemented IDENTICALLY to leviathan's CTR class
 * (sources/leviathan/src/blockmode.ts):
 *
 *   - Counter initialised as a direct copy of the IV bytes.
 *   - Keystream for block b = ECB_encrypt(key, ctr_b).
 *   - Ciphertext byte i = keystream[i] XOR plaintext[i].
 *   - Counter increment: ctr[0]++; carry propagates ctr[0]→ctr[1]→...→ctr[15].
 *     (little-endian integer — byte index 0 is the least-significant byte.)
 *
 * Portability note:
 *   The floppy1 reference uses  typedef unsigned long WORD  which is 64 bits
 *   on arm64/x86-64 macOS and Linux.  The BLOCK type (WORD[4]) therefore
 *   occupies 32 bytes, not 16.  To interoperate correctly we maintain the
 *   counter and keystream as  uint8_t[16]  and convert to/from BLOCK using
 *   the byte ordering implied by render(): w[3] = bytes 0-3 (MSB), w[0] =
 *   bytes 12-15 (LSB), each word big-endian within its 4 bytes.
 *
 * Build:  make ctr_harness   (in this directory, or pass CC=clang)
 * Run:    ./ctr_harness
 *
 * Output format:
 *   CASE=<letter>
 *   KEY=<uppercase hex>
 *   IV=<uppercase hex, 32 chars>
 *   PT=<uppercase hex>
 *   CT=<uppercase hex>
 *   ---
 */

/* ---- includes ---------------------------------------------------------- */
#include "serpent-api.h"
#include "serpent-aux.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* ---- byte / BLOCK conversion ------------------------------------------ */

/*
 * bytes_to_block: pack 16 raw bytes into a BLOCK (WORD[4]).
 *
 * The floppy1 reference stores a 128-bit block as four WORDs in
 * multi-word little-endian order (w[0] = LS-word, w[3] = MS-word), with
 * each 32-bit word stored big-endian in its byte lanes:
 *
 *   w[3] = (b[0]<<24)|(b[1]<<16)|(b[2]<<8)|b[3]   (bytes  0-3)
 *   w[2] = (b[4]<<24)|(b[5]<<16)|(b[6]<<8)|b[7]   (bytes  4-7)
 *   w[1] = (b[8]<<24)|(b[9]<<16)|(b[10]<<8)|b[11] (bytes  8-11)
 *   w[0] = (b[12]<<24)|(b[13]<<16)|(b[14]<<8)|b[15] (bytes 12-15)
 *
 * This is consistent with render() which prints w[3] first (MSB).
 */
static void bytes_to_block(const uint8_t *b, BLOCK blk)
{
    blk[3] = ((WORD)b[0]<<24)|((WORD)b[1]<<16)|((WORD)b[2]<<8)|(WORD)b[3];
    blk[2] = ((WORD)b[4]<<24)|((WORD)b[5]<<16)|((WORD)b[6]<<8)|(WORD)b[7];
    blk[1] = ((WORD)b[8]<<24)|((WORD)b[9]<<16)|((WORD)b[10]<<8)|(WORD)b[11];
    blk[0] = ((WORD)b[12]<<24)|((WORD)b[13]<<16)|((WORD)b[14]<<8)|(WORD)b[15];
}

/* block_to_bytes: unpack a BLOCK back to 16 raw bytes (inverse of above). */
static void block_to_bytes(const BLOCK blk, uint8_t *b)
{
    b[0]  = (uint8_t)((blk[3] >> 24) & 0xFF);
    b[1]  = (uint8_t)((blk[3] >> 16) & 0xFF);
    b[2]  = (uint8_t)((blk[3] >>  8) & 0xFF);
    b[3]  = (uint8_t)( blk[3]        & 0xFF);
    b[4]  = (uint8_t)((blk[2] >> 24) & 0xFF);
    b[5]  = (uint8_t)((blk[2] >> 16) & 0xFF);
    b[6]  = (uint8_t)((blk[2] >>  8) & 0xFF);
    b[7]  = (uint8_t)( blk[2]        & 0xFF);
    b[8]  = (uint8_t)((blk[1] >> 24) & 0xFF);
    b[9]  = (uint8_t)((blk[1] >> 16) & 0xFF);
    b[10] = (uint8_t)((blk[1] >>  8) & 0xFF);
    b[11] = (uint8_t)( blk[1]        & 0xFF);
    b[12] = (uint8_t)((blk[0] >> 24) & 0xFF);
    b[13] = (uint8_t)((blk[0] >> 16) & 0xFF);
    b[14] = (uint8_t)((blk[0] >>  8) & 0xFF);
    b[15] = (uint8_t)( blk[0]        & 0xFF);
}

/* ---- helpers ----------------------------------------------------------- */

/* Print a raw byte array as uppercase hex, no newline. */
static void print_hex(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02X", (unsigned int)buf[i]);
    }
}

/* ---- CTR encrypt ------------------------------------------------------- */

/*
 * serpent_ctr_encrypt
 *
 * Encrypt (or decrypt — CTR is symmetric) using Serpent-CTR, matching
 * leviathan's CTR class byte-for-byte.
 *
 * key_hex : uppercase hex ASCII key; keyLen = strlen(key_hex)*4 bits
 * pt      : plaintext bytes
 * pt_len  : number of plaintext bytes (must be a multiple of 16)
 * iv      : 16-byte IV, loaded as-is into the counter register
 * ct      : output ciphertext (must be >= pt_len bytes)
 */
static void serpent_ctr_encrypt(const char    *key_hex,
                                const uint8_t *pt,
                                size_t         pt_len,
                                const uint8_t *iv,
                                uint8_t       *ct)
{
    keyInstance    key;
    cipherInstance cipher;
    uint8_t        ctr[16];       /* counter bytes — matches leviathan's this.ctr */
    BLOCK          ctr_blk;       /* counter as BLOCK for blockEncrypt input      */
    BLOCK          ks_blk;        /* keystream as BLOCK from blockEncrypt         */
    uint8_t        keystream[16]; /* keystream as bytes after block_to_bytes      */
    size_t         b, i;
    int            key_bits;

    key_bits = (int)(strlen(key_hex) * 4); /* 128, 192, or 256 */

    if (makeKey(&key, DIR_ENCRYPT, key_bits, (char *)key_hex) != TRUE) {
        fprintf(stderr, "makeKey failed for key_bits=%d\n", key_bits);
        exit(1);
    }
    if (cipherInit(&cipher, MODE_ECB, 0) != TRUE) {
        fprintf(stderr, "cipherInit failed\n");
        exit(1);
    }

    /* Counter starts as an exact copy of the IV bytes
       (leviathan: this.ctr.set(iv))  */
    memcpy(ctr, iv, 16);

    for (b = 0; b * 16 < pt_len; b++) {

        /* Convert counter bytes → BLOCK for blockEncrypt
           (leviathan passes this.ctr — same bytes — to Serpent.encrypt())  */
        bytes_to_block(ctr, ctr_blk);

        /* Keystream_b = ECB_encrypt(key, ctr_b)
           (leviathan: blockcipher.encrypt(key, this.ctr))  */
        if (blockEncrypt(&cipher, &key,
                         (BYTE *)ctr_blk, 128,
                         (BYTE *)ks_blk) != 128) {
            fprintf(stderr, "blockEncrypt failed at block %zu\n", b);
            exit(1);
        }

        /* Convert BLOCK output → keystream bytes  */
        block_to_bytes(ks_blk, keystream);

        /* ct_b = keystream_b XOR pt_b
           (leviathan: ct[i + b*bs] ^= pt[i + b*bs])  */
        for (i = 0; i < 16; i++) {
            ct[b * 16 + i] = keystream[i] ^ pt[b * 16 + i];
        }

        /* Increment counter: little-endian, byte[0] first.
           Identical to leviathan:
             this.ctr[0]++;
             for (let i = 0; i < bs-1; i++) {
               if (this.ctr[i] === 0) { this.ctr[i+1]++; } else break;
             }                                                            */
        ctr[0]++;
        for (i = 0; i < 15; i++) {
            if (ctr[i] == 0) {
                ctr[i + 1]++;
            } else {
                break;
            }
        }
    }
}

/* ---- run one test case ------------------------------------------------- */

static void run_case(const char    *label,
                     const char    *key_hex,
                     const uint8_t *iv,
                     const uint8_t *pt,
                     size_t         pt_len)
{
    uint8_t ct[48]; /* 3 blocks max */

    if (pt_len > sizeof(ct)) {
        fprintf(stderr, "pt_len %zu exceeds buffer\n", pt_len);
        exit(1);
    }

    serpent_ctr_encrypt(key_hex, pt, pt_len, iv, ct);

    printf("CASE=%s\n",  label);
    printf("KEY=%s\n",   key_hex);
    printf("IV=");   print_hex(iv, 16);      printf("\n");
    printf("PT=");   print_hex(pt, pt_len);  printf("\n");
    printf("CT=");   print_hex(ct, pt_len);  printf("\n");
    printf("---\n");
}

/* ---- main -------------------------------------------------------------- */

int main(void)
{
    uint8_t zero16[16], zero48[48];
    uint8_t ff16[16],   ff32[32];
    uint8_t iv_d[16],   pt_d[32];
    int i;

    memset(zero16, 0x00, sizeof(zero16));
    memset(zero48, 0x00, sizeof(zero48));
    memset(ff16,   0xFF, sizeof(ff16));
    memset(ff32,   0xFF, sizeof(ff32));

    /* IV for Case D: 000102030405060708090A0B0C0D0E0F */
    for (i = 0; i < 16; i++) { iv_d[i] = (uint8_t)i; }

    /* PT for Case D: 2 blocks — 000102...0F then 101112...1F */
    for (i = 0; i < 32; i++) { pt_d[i] = (uint8_t)i; }

    /*
     * Case A — 128-bit all-zero key, all-zero IV, 3 blocks of all-zero PT.
     *
     * For all-zero PT, CT == raw keystream.  Block 0 of CT must match
     * ECB_encrypt(all-zero-128-key, all-zero-counter), which equals the
     * leviathan ECB output for the same inputs — use this as the Step 4
     * cross-check (see CLAUDE.md §Step 4 and TEST_REPORT.md).
     */
    run_case("A",
             "00000000000000000000000000000000",
             zero16, zero48, 48);

    /*
     * Case B — 256-bit all-zero key, all-zero IV, 3 blocks of all-zero PT.
     */
    run_case("B",
             "0000000000000000000000000000000000000000000000000000000000000000",
             zero16, zero48, 48);

    /*
     * Case C — 128-bit all-zero key, all-FF IV, 2 blocks of all-FF PT.
     *
     * Tests counter wrap-around: counter starts 0xFF×16, increments to
     * 0x00×16 after block 0 (all 16 bytes overflow to 0).
     */
    run_case("C",
             "00000000000000000000000000000000",
             ff16, ff32, 32);

    /*
     * Case D — 256-bit non-trivial key, non-trivial IV, 2 non-trivial PT blocks.
     *
     * Key = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
     * IV  = 000102030405060708090A0B0C0D0E0F
     * PT  = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
     */
    run_case("D",
             "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
             iv_d, pt_d, 32);

    /*
     * Case E — 192-bit all-zero key, all-zero IV, 3 blocks of all-zero PT.
     */
    run_case("E",
             "000000000000000000000000000000000000000000000000",
             zero16, zero48, 48);

    return 0;
}
