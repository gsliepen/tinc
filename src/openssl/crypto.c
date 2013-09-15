/*
    crypto.c -- Cryptographic miscellaneous functions and initialisation
    Copyright (C) 2007-2013 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "../system.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#include "../crypto.h"

#include "brainpool.h"

EC_GROUP *brainpoolp512r1;

static void generate_brainpool_curve() {
	static const char *p = "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3";
	static const char *A = "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA";
	static const char *B = "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723";
	static const char *x = "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822";
	static const char *y = "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892";
	static const char *q = "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069";

	BIGNUM *bn_p = NULL;
	BIGNUM *bn_A = NULL;
	BIGNUM *bn_B = NULL;
	BIGNUM *bn_x = NULL;
	BIGNUM *bn_y = NULL;
	BIGNUM *bn_q = NULL;

	BN_hex2bn(&bn_p, p);
	BN_hex2bn(&bn_A, A);
	BN_hex2bn(&bn_B, B);
	BN_hex2bn(&bn_x, x);
	BN_hex2bn(&bn_y, y);
	BN_hex2bn(&bn_q, q);

	BN_CTX *ctx = BN_CTX_new();

	if(!bn_p || !bn_A || !bn_B || !bn_x || !bn_y || !bn_q || !ctx)
		abort();

	brainpoolp512r1 = EC_GROUP_new_curve_GFp(bn_p, bn_A, bn_B, ctx);

	if(!brainpoolp512r1)
		abort();

	EC_POINT *generator = EC_POINT_new(brainpoolp512r1);

	if(!generator)
		abort();

	if(EC_POINT_set_affine_coordinates_GFp(brainpoolp512r1, generator, bn_x, bn_y, ctx) != 1)
		abort();

	if(EC_GROUP_set_generator(brainpoolp512r1, generator, bn_q, NULL) != 1)
		abort();

	EC_POINT_free(generator);
	BN_CTX_free(ctx);
	BN_free(bn_p);
	BN_free(bn_A);
	BN_free(bn_B);
	BN_free(bn_x);
	BN_free(bn_y);
	BN_free(bn_q);
}

void crypto_init(void) {
	RAND_load_file("/dev/urandom", 1024);

	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	if(!RAND_status()) {
		fprintf(stderr, "Not enough entropy for the PRNG!\n");
		abort();
	}

	generate_brainpool_curve();
}

void crypto_exit(void) {
	EVP_cleanup();
}

void randomize(void *out, size_t outlen) {
	RAND_pseudo_bytes(out, outlen);
}
