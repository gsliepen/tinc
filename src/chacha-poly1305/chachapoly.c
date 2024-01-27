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

int chachapoly_init(struct chachapoly_ctx *ctx, const void *key, int key_len) {
	assert(key_len == 128 || key_len == 256);

	memset(ctx, 0, sizeof(*ctx));
	chacha_keysetup(&ctx->cha_ctx, key, key_len);
	return CHACHAPOLY_OK;
}

int chachapoly_crypt(struct chachapoly_ctx *ctx, const void *nonce,
                     void *input, int input_len,
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
		poly1305_get_tag(poly_key, input, input_len, calc_tag);

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
		poly1305_get_tag(poly_key, output, input_len, calc_tag);
		memcpy(tag, calc_tag, tag_len);
	}

	return CHACHAPOLY_OK;
}

int chachapoly_crypt_short(struct chachapoly_ctx *ctx, const void *nonce,
                           void *input, int input_len,
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
		poly1305_get_tag(keystream, input, input_len, calc_tag);

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
		poly1305_get_tag(keystream, output, input_len, calc_tag);
		memcpy(tag, calc_tag, tag_len);
	}

	return CHACHAPOLY_OK;
}
