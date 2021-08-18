#ifndef TINC_GCRYPT_PEM_H
#define TINC_GCRYPT_PEM_H

#include "../system.h"

bool pem_decode(FILE *fp, const char *header, uint8_t *buf, size_t size, size_t *outsize);
bool pem_encode(FILE *fp, const char *header, uint8_t *buf, size_t size);

#endif // TINC_GCRYPT_PEM_H
