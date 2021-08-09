#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define POLY1305_KEYLEN     32
#define POLY1305_TAGLEN     16
#define POLY1305_BLOCK_SIZE 16

/* use memcpy() to copy blocks of memory (typically faster) */
#define USE_MEMCPY          1
/* use unaligned little-endian load/store (can be faster) */
#define USE_UNALIGNED       0

struct poly1305_context {
	uint32_t r[5];
	uint32_t h[5];
	uint32_t pad[4];
	size_t leftover;
	unsigned char buffer[POLY1305_BLOCK_SIZE];
	unsigned char final;
};

void poly1305_init(struct poly1305_context *ctx, const unsigned char key[32]);
void poly1305_update(struct poly1305_context *ctx, const unsigned char *m, size_t bytes);
void poly1305_finish(struct poly1305_context *ctx, unsigned char mac[16]);
void poly1305_auth(unsigned char mac[16], const unsigned char *m, size_t bytes, const unsigned char key[32]);

#endif /* POLY1305_H */

