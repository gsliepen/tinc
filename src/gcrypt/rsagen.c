/*
    rsagen.c -- RSA key generation and export
    Copyright (C) 2008-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#include <gcrypt.h>
#include <assert.h>

#include "asn1.h"
#include "rsa.h"
#include "pem.h"
#include "../rsagen.h"
#include "../xalloc.h"
#include "../utils.h"

static size_t der_tag_len(size_t n) {
	if(n < 128) {
		return 2;
	}

	if(n < 256) {
		return 3;
	}

	if(n < 65536) {
		return 4;
	}

	abort();
}

static uint8_t *der_store_tag(uint8_t *p, asn1_tag_t tag, size_t n) {
	if(tag == TAG_SEQUENCE) {
		tag |= 0x20;
	}

	*p++ = tag;

	if(n < 128) {
		*p++ = n;
	} else if(n < 256) {
		*p++ = 0x81;
		*p++ = n;
	} else if(n < 65536) {
		*p++ = 0x82;
		*p++ = n >> 8;
		*p++ = n & 0xff;
	} else {
		abort();
	}

	return p;
}

static size_t der_fill(uint8_t *derbuf, bool is_private, const gcry_mpi_t mpi[], size_t num_mpi) {
	size_t needed = 0;
	size_t lengths[16] = {0};

	assert(num_mpi > 0 && num_mpi < sizeof(lengths) / sizeof(*lengths));

	if(is_private) {
		// Add space for the version number.
		needed += der_tag_len(1) + 1;
	}

	for(size_t i = 0; i < num_mpi; ++i) {
		gcry_mpi_print(GCRYMPI_FMT_STD, NULL, 0, &lengths[i], mpi[i]);
		needed += der_tag_len(lengths[i]) + lengths[i];
	}

	const size_t derlen = der_tag_len(needed) + needed;

	uint8_t *der = derbuf;
	der = der_store_tag(der, TAG_SEQUENCE, needed);

	if(is_private) {
		// Private key requires storing version number.
		der = der_store_tag(der, TAG_INTEGER, 1);
		*der++ = 0;
	}

	for(size_t i = 0; i < num_mpi; ++i) {
		const size_t len = lengths[i];
		der = der_store_tag(der, TAG_INTEGER, len);
		gcry_mpi_print(GCRYMPI_FMT_STD, der, len, NULL, mpi[i]);
		der += len;
	}

	assert((size_t)(der - derbuf) == derlen);
	return derlen;
}

bool rsa_write_pem_public_key(rsa_t *rsa, FILE *fp) {
	uint8_t derbuf[8096];

	gcry_mpi_t params[] = {
		rsa->n,
		rsa->e,
	};

	size_t derlen = der_fill(derbuf, false, params, sizeof(params) / sizeof(*params));

	return pem_encode(fp, "RSA PUBLIC KEY", derbuf, derlen);
}

// Calculate p/q primes from n/e/d.
static void get_p_q(gcry_mpi_t *p,
                    gcry_mpi_t *q,
                    const gcry_mpi_t n,
                    const gcry_mpi_t e,
                    const gcry_mpi_t d) {
	const size_t nbits = gcry_mpi_get_nbits(n);

	gcry_mpi_t k = gcry_mpi_new(nbits);
	gcry_mpi_mul(k, e, d);
	gcry_mpi_sub_ui(k, k, 1);

	size_t t = 0;

	while(!gcry_mpi_test_bit(k, t)) {
		++t;
	}

	gcry_mpi_t g = gcry_mpi_new(nbits);
	gcry_mpi_t gk = gcry_mpi_new(0);
	gcry_mpi_t sq = gcry_mpi_new(0);
	gcry_mpi_t rem = gcry_mpi_new(0);
	gcry_mpi_t gcd = gcry_mpi_new(0);

	while(true) {
		gcry_mpi_t kt = gcry_mpi_copy(k);
		gcry_mpi_randomize(g, nbits, GCRY_STRONG_RANDOM);

		size_t i;

		for(i = 0; i < t; ++i) {
			gcry_mpi_rshift(kt, kt, 1);
			gcry_mpi_powm(gk, g, kt, n);

			if(gcry_mpi_cmp_ui(gk, 1) != 0) {
				gcry_mpi_mul(sq, gk, gk);
				gcry_mpi_mod(rem, sq, n);

				if(gcry_mpi_cmp_ui(rem, 1) == 0) {
					break;
				}
			}
		}

		gcry_mpi_release(kt);

		if(i < t) {
			gcry_mpi_sub_ui(gk, gk, 1);
			gcry_mpi_gcd(gcd, gk, n);

			if(gcry_mpi_cmp_ui(gcd, 1) != 0) {
				break;
			}
		}
	}

	gcry_mpi_release(k);
	gcry_mpi_release(g);
	gcry_mpi_release(gk);
	gcry_mpi_release(sq);
	gcry_mpi_release(rem);

	*p = gcd;
	*q = gcry_mpi_new(0);

	gcry_mpi_div(*q, NULL, n, *p, 0);
}

bool rsa_write_pem_private_key(rsa_t *rsa, FILE *fp) {
	gcry_mpi_t params[] = {
		rsa->n,
		rsa->e,
		rsa->d,
		NULL, // p
		NULL, // q
		gcry_mpi_new(0), // d mod (p-1)
		gcry_mpi_new(0), // d mod (q-1)
		gcry_mpi_new(0), // u = p^-1 mod q
	};

	// Indexes into params.
	const size_t d = 2;
	const size_t p = 3;
	const size_t q = 4;
	const size_t dp = 5;
	const size_t dq = 6;
	const size_t u = 7;

	// Calculate p and q.
	get_p_q(&params[p], &params[q], rsa->n, rsa->e, rsa->d);

	// Swap p and q if q > p.
	if(gcry_mpi_cmp(params[q], params[p]) > 0) {
		gcry_mpi_swap(params[p], params[q]);
	}

	// Calculate u.
	gcry_mpi_invm(params[u], params[p], params[q]);

	// Calculate d mod (p - 1).
	gcry_mpi_sub_ui(params[dp], params[p], 1);
	gcry_mpi_mod(params[dp], params[d], params[dp]);

	// Calculate d mod (q - 1).
	gcry_mpi_sub_ui(params[dq], params[q], 1);
	gcry_mpi_mod(params[dq], params[d], params[dq]);

	uint8_t derbuf[8096];
	const size_t nparams = sizeof(params) / sizeof(*params);
	size_t derlen = der_fill(derbuf, true, params, nparams);

	gcry_mpi_release(params[p]);
	gcry_mpi_release(params[q]);
	gcry_mpi_release(params[dp]);
	gcry_mpi_release(params[dq]);
	gcry_mpi_release(params[u]);

	bool success = pem_encode(fp, "RSA PRIVATE KEY", derbuf, derlen);
	memzero(derbuf, sizeof(derbuf));
	return success;
}

static gcry_mpi_t find_mpi(const gcry_sexp_t rsa, const char *token) {
	gcry_sexp_t sexp = gcry_sexp_find_token(rsa, token, 1);

	if(!sexp) {
		fprintf(stderr, "Token %s not found in RSA S-expression.\n", token);
		return NULL;
	}

	gcry_mpi_t mpi = gcry_sexp_nth_mpi(sexp, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(sexp);
	return mpi;
}

rsa_t *rsa_generate(size_t bits, unsigned long exponent) {
	gcry_sexp_t s_params;
	gcry_error_t err = gcry_sexp_build(&s_params, NULL,
	                                   "(genkey"
	                                   "  (rsa"
	                                   "    (nbits %u)"
	                                   "    (rsa-use-e %u)))",
	                                   bits,
	                                   exponent);

	if(err) {
		fprintf(stderr, "Error building keygen S-expression: %s.\n", gcry_strerror(err));
		return NULL;
	}

	gcry_sexp_t s_key;
	err = gcry_pk_genkey(&s_key, s_params);
	gcry_sexp_release(s_params);

	if(err) {
		fprintf(stderr, "Error generating RSA key pair: %s.\n", gcry_strerror(err));
		return NULL;
	}

	// `gcry_sexp_extract_param` can replace everything below
	// with a single line, but it's not available on CentOS 7.
	gcry_sexp_t s_priv = gcry_sexp_find_token(s_key, "private-key", 0);

	if(!s_priv) {
		fprintf(stderr, "Private key not found in gcrypt result.\n");
		gcry_sexp_release(s_key);
		return NULL;
	}

	gcry_sexp_t s_rsa = gcry_sexp_find_token(s_priv, "rsa", 0);

	if(!s_rsa) {
		fprintf(stderr, "RSA not found in gcrypt result.\n");
		gcry_sexp_release(s_priv);
		gcry_sexp_release(s_key);
		return NULL;
	}

	rsa_t *rsa = rsa_new();

	rsa->n = find_mpi(s_rsa, "n");
	rsa->e = find_mpi(s_rsa, "e");
	rsa->d = find_mpi(s_rsa, "d");

	gcry_sexp_release(s_rsa);
	gcry_sexp_release(s_priv);
	gcry_sexp_release(s_key);

	if(rsa->n && rsa->e && rsa->d) {
		return rsa;
	}

	rsa_free(rsa);
	return NULL;
}
