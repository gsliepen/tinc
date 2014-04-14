#include "../system.h"

#include "../cipher.h"
#include "../xalloc.h"

#include "chacha.h"
#include "chacha-poly1305.h"
#include "poly1305.h"

struct chacha_poly1305_ctx {
	struct chacha_ctx main_ctx, header_ctx;
};

chacha_poly1305_ctx_t *chacha_poly1305_init(void)
{
	chacha_poly1305_ctx_t *ctx = xzalloc(sizeof *ctx);
	return ctx;
}

void chacha_poly1305_exit(chacha_poly1305_ctx_t *ctx)
{
	free(ctx);
}

bool chacha_poly1305_set_key(chacha_poly1305_ctx_t *ctx, const void *key)
{
	chacha_keysetup(&ctx->main_ctx, key, 256);
	chacha_keysetup(&ctx->header_ctx, key + 32, 256);
	return true;
}

static void put_u64(void *vp, uint64_t v)
{
	uint8_t *p = (uint8_t *) vp;

	p[0] = (uint8_t) (v >> 56) & 0xff;
	p[1] = (uint8_t) (v >> 48) & 0xff;
	p[2] = (uint8_t) (v >> 40) & 0xff;
	p[3] = (uint8_t) (v >> 32) & 0xff;
	p[4] = (uint8_t) (v >> 24) & 0xff;
	p[5] = (uint8_t) (v >> 16) & 0xff;
	p[6] = (uint8_t) (v >> 8) & 0xff;
	p[7] = (uint8_t) v & 0xff;
}

bool chacha_poly1305_encrypt(chacha_poly1305_ctx_t *ctx, uint64_t seqnr, const void *indata, size_t inlen, void *outdata, size_t *outlen) {
	uint8_t seqbuf[8];
	const uint8_t one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };	/* NB little-endian */
	uint8_t poly_key[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_key, 0, sizeof(poly_key));
	put_u64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
	chacha_encrypt_bytes(&ctx->main_ctx, poly_key, poly_key, sizeof(poly_key));

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);

	chacha_encrypt_bytes(&ctx->main_ctx, indata, outdata, inlen);
	poly1305_auth(outdata + inlen, outdata, inlen, poly_key);

	if (outlen)
		*outlen = inlen + POLY1305_TAGLEN;

	return true;
}

bool chacha_poly1305_decrypt(chacha_poly1305_ctx_t *ctx, uint64_t seqnr, const void *indata, size_t inlen, void *outdata, size_t *outlen) {
	uint8_t seqbuf[8];
	const uint8_t one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };	/* NB little-endian */
	uint8_t expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_key, 0, sizeof(poly_key));
	put_u64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
	chacha_encrypt_bytes(&ctx->main_ctx, poly_key, poly_key, sizeof(poly_key));

	/* Set Chacha's block counter to 1 */
	chacha_ivsetup(&ctx->main_ctx, seqbuf, one);

	/* Check tag before anything else */
	inlen -= POLY1305_TAGLEN;
	const uint8_t *tag = indata + inlen;

	poly1305_auth(expected_tag, indata, inlen, poly_key);
	if (memcmp(expected_tag, tag, POLY1305_TAGLEN))
		return false;

	chacha_encrypt_bytes(&ctx->main_ctx, indata, outdata, inlen);

	if (outlen)
		*outlen = inlen;

	return true;
}
