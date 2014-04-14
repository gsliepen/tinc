#ifndef CHACHA_POLY1305_H
#define CHACHA_POLY1305_H

#define CHACHA_POLY1305_KEYLEN 64

typedef struct chacha_poly1305_ctx chacha_poly1305_ctx_t;

extern chacha_poly1305_ctx_t *chacha_poly1305_init(void);
extern void chacha_poly1305_exit(chacha_poly1305_ctx_t *);
extern bool chacha_poly1305_set_key(chacha_poly1305_ctx_t *ctx, const void *key);

extern bool chacha_poly1305_encrypt(chacha_poly1305_ctx_t *ctx, uint64_t seqnr, const void *indata, size_t inlen, void *outdata, size_t *outlen);
extern bool chacha_poly1305_decrypt(chacha_poly1305_ctx_t *ctx, uint64_t seqnr, const void *indata, size_t inlen, void *outdata, size_t *outlen);

#endif //CHACHA_POLY1305_H
