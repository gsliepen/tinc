/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

struct chacha_ctx {
	uint32_t input[16];
};

#define CHACHA_MINKEYLEN 	16
#define CHACHA_NONCELEN		8
#define CHACHA_CTRLEN		8
#define CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

void chacha_keysetup(struct chacha_ctx *x, const uint8_t *k, uint32_t kbits);
void chacha_ivsetup(struct chacha_ctx *x, const uint8_t *iv, const uint8_t *ctr);
void chacha_encrypt_bytes(struct chacha_ctx *x, const uint8_t *m, uint8_t * c, uint32_t bytes);

#endif /* CHACHA_H */
