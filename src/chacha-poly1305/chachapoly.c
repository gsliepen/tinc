/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Grigori Goronzy <goronzy@kinoho.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "chachapoly.h"

/**
 * Constant-time memory compare. This should help to protect against
 * side-channel attacks.
 *
 * \param av input 1
 * \param bv input 2
 * \param n bytes to compare
 * \return 0 if inputs are equal
 */
static int memcmp_eq(const void *av, const void *bv, int n) {
	const unsigned char *a = (const unsigned char *) av;
	const unsigned char *b = (const unsigned char *) bv;
	unsigned char res = 0;
	int i;

	for(i = 0; i < n; i++) {
		res |= *a ^ *b;
		a++;
		b++;
	}

	return res;
}

/**
 * Poly1305 tag generation. This concatenates a string according to the rules
 * outlined in RFC 7539 and calculates the tag.
 *
 * \param poly_key 32 byte secret one-time key for poly1305
 * \param ad associated data
 * \param ad_len associated data length in bytes
 * \param ct ciphertext
 * \param ct_len ciphertext length in bytes
 * \param tag pointer to 16 bytes for tag storage
 */
static void poly1305_get_tag(unsigned char *poly_key, const void *ad,
                             int ad_len, const void *ct, int ct_len, unsigned char *tag) {
	struct poly1305_context poly;
	unsigned left_over;
	uint64_t len;
	unsigned char pad[16];

	poly1305_init(&poly, poly_key);
	memset(&pad, 0, sizeof(pad));

	/* associated data and padding */
	poly1305_update(&poly, ad, ad_len);
	left_over = ad_len % 16;

	if(left_over) {
		poly1305_update(&poly, pad, 16 - left_over);
	}

	/* payload and padding */
	poly1305_update(&poly, ct, ct_len);
	left_over = ct_len % 16;

	if(left_over) {
		poly1305_update(&poly, pad, 16 - left_over);
	}

	/* lengths */
	len = ad_len;
	poly1305_update(&poly, (unsigned char *)&len, 8);
	len = ct_len;
	poly1305_update(&poly, (unsigned char *)&len, 8);

	poly1305_finish(&poly, tag);
}

int chachapoly_init(struct chachapoly_ctx *ctx, const void *key, int key_len) {
	assert(key_len == 128 || key_len == 256);

	memset(ctx, 0, sizeof(*ctx));
	chacha_keysetup(&ctx->cha_ctx, key, key_len);
	return CHACHAPOLY_OK;
}

int chachapoly_crypt(struct chachapoly_ctx *ctx, const void *nonce,
                     const void *ad, int ad_len, void *input, int input_len,
                     void *output, void *tag, int tag_len, int encrypt) {
	unsigned char poly_key[CHACHA_BLOCKLEN];
	unsigned char calc_tag[POLY1305_TAGLEN];
	const unsigned char one[4] = { 1, 0, 0, 0 };

	/* initialize keystream and generate poly1305 key */
	memset(poly_key, 0, sizeof(poly_key));
	chacha_ivsetup(&ctx->cha_ctx, nonce, NULL);
	chacha_encrypt_bytes(&ctx->cha_ctx, poly_key, poly_key, sizeof(poly_key));

	/* check tag if decrypting */
	if(encrypt == 0 && tag_len) {
		poly1305_get_tag(poly_key, ad, ad_len, input, input_len, calc_tag);

		if(memcmp_eq(calc_tag, tag, tag_len) != 0) {
			return CHACHAPOLY_INVALID_MAC;
		}
	}

	/* crypt data */
	chacha_ivsetup(&ctx->cha_ctx, nonce, one);
	chacha_encrypt_bytes(&ctx->cha_ctx, (unsigned char *)input,
	                     (unsigned char *)output, input_len);

	/* add tag if encrypting */
	if(encrypt && tag_len) {
		poly1305_get_tag(poly_key, ad, ad_len, output, input_len, calc_tag);
		memcpy(tag, calc_tag, tag_len);
	}

	return CHACHAPOLY_OK;
}

int chachapoly_crypt_short(struct chachapoly_ctx *ctx, const void *nonce,
                           const void *ad, int ad_len, void *input, int input_len,
                           void *output, void *tag, int tag_len, int encrypt) {
	unsigned char keystream[CHACHA_BLOCKLEN];
	unsigned char calc_tag[POLY1305_TAGLEN];
	int i;

	assert(input_len <= 32);

	/* initialize keystream and generate poly1305 key */
	memset(keystream, 0, sizeof(keystream));
	chacha_ivsetup(&ctx->cha_ctx, nonce, NULL);
	chacha_encrypt_bytes(&ctx->cha_ctx, keystream, keystream,
	                     sizeof(keystream));

	/* check tag if decrypting */
	if(encrypt == 0 && tag_len) {
		poly1305_get_tag(keystream, ad, ad_len, input, input_len, calc_tag);

		if(memcmp_eq(calc_tag, tag, tag_len) != 0) {
			return CHACHAPOLY_INVALID_MAC;
		}
	}

	/* crypt data */
	for(i = 0; i < input_len; i++) {
		((unsigned char *)output)[i] =
		        ((unsigned char *)input)[i] ^ keystream[32 + i];
	}

	/* add tag if encrypting */
	if(encrypt && tag_len) {
		poly1305_get_tag(keystream, ad, ad_len, output, input_len, calc_tag);
		memcpy(tag, calc_tag, tag_len);
	}

	return CHACHAPOLY_OK;
}
