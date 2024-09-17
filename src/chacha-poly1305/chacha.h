/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHACHA_BLOCKLEN         64

/* use memcpy() to copy blocks of memory (typically faster) */
#define USE_MEMCPY          1
/* use unaligned little-endian load/store (can be faster) */
#define USE_UNALIGNED       0

struct chacha_ctx {
	uint32_t input[16];
};

void chacha_keysetup(struct chacha_ctx *x, const unsigned char *k,
                     uint32_t kbits);
void chacha_ivsetup(struct chacha_ctx *x, const unsigned char *iv,
                    const unsigned char *ctr);
void chacha_encrypt_bytes(struct chacha_ctx *x, const unsigned char *m,
                          unsigned char *c, uint32_t bytes);

#endif  /* CHACHA_H */
