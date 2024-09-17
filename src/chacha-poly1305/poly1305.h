#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define POLY1305_KEYLEN     32
#define POLY1305_TAGLEN     16
#define POLY1305_BLOCK_SIZE 16

void poly1305_get_tag(const unsigned char key[32], const void *ct, int ct_len, unsigned char tag[16]);

#endif /* POLY1305_H */
