/*
    rsa.c -- RSA key handling
    Copyright (C) 2007-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#include "pem.h"

#include "asn1.h"
#include "rsa.h"
#include "../logger.h"
#include "../rsa.h"
#include "../xalloc.h"

// BER decoding functions

static int ber_read_id(unsigned char **p, size_t *buflen) {
	if(*buflen <= 0) {
		return -1;
	}

	if((**p & 0x1f) == 0x1f) {
		int id = 0;
		bool more;

		while(*buflen > 0) {
			id <<= 7;
			id |= **p & 0x7f;
			more = *(*p)++ & 0x80;
			(*buflen)--;

			if(!more) {
				break;
			}
		}

		return id;
	} else {
		(*buflen)--;
		return *(*p)++ & 0x1f;
	}
}

static size_t ber_read_len(unsigned char **p, size_t *buflen) {
	if(*buflen <= 0) {
		return -1;
	}

	if(**p & 0x80) {
		size_t result = 0;
		size_t len = *(*p)++ & 0x7f;
		(*buflen)--;

		if(len > *buflen) {
			return 0;
		}

		for(; len; --len) {
			result = (size_t)(result << 8);
			result |= *(*p)++;
			(*buflen)--;
		}

		return result;
	} else {
		(*buflen)--;
		return *(*p)++;
	}
}

static bool ber_skip_sequence(unsigned char **p, size_t *buflen) {
	int tag = ber_read_id(p, buflen);

	return tag == TAG_SEQUENCE &&
	       ber_read_len(p, buflen) > 0;
}

static bool ber_read_mpi(unsigned char **p, size_t *buflen, gcry_mpi_t *mpi) {
	int tag = ber_read_id(p, buflen);
	size_t len = ber_read_len(p, buflen);
	gcry_error_t err = 0;

	if(tag != 0x02 || len > *buflen) {
		return false;
	}

	if(mpi) {
		err = gcry_mpi_scan(mpi, GCRYMPI_FMT_USG, *p, len, NULL);
	}

	*p += len;
	*buflen -= len;

	return mpi ? !err : true;
}

rsa_t *rsa_new(void) {
	return xzalloc(sizeof(rsa_t));
}

rsa_t *rsa_set_hex_public_key(const char *n, const char *e) {
	rsa_t *rsa = rsa_new();

	gcry_error_t err = gcry_mpi_scan(&rsa->n, GCRYMPI_FMT_HEX, n, 0, NULL);

	if(!err) {
		err = gcry_mpi_scan(&rsa->e, GCRYMPI_FMT_HEX, e, 0, NULL);
	}

	if(err) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading RSA public key: %s", gcry_strerror(errno));
		rsa_free(rsa);
		return false;
	}

	return rsa;
}

rsa_t *rsa_set_hex_private_key(const char *n, const char *e, const char *d) {
	rsa_t *rsa = rsa_new();

	gcry_error_t err = gcry_mpi_scan(&rsa->n, GCRYMPI_FMT_HEX, n, 0, NULL);

	if(!err) {
		err = gcry_mpi_scan(&rsa->e, GCRYMPI_FMT_HEX, e, 0, NULL);
	}

	if(!err) {
		err = gcry_mpi_scan(&rsa->d, GCRYMPI_FMT_HEX, d, 0, NULL);
	}

	if(err) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading RSA public key: %s", gcry_strerror(errno));
		rsa_free(rsa);
		return NULL;
	}

	return rsa;
}

// Read PEM RSA keys

rsa_t *rsa_read_pem_public_key(FILE *fp) {
	uint8_t derbuf[8096], *derp = derbuf;
	size_t derlen;

	if(!pem_decode(fp, "RSA PUBLIC KEY", derbuf, sizeof(derbuf), &derlen)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read RSA public key: %s", strerror(errno));
		return NULL;
	}

	rsa_t *rsa = rsa_new();

	if(!ber_skip_sequence(&derp, &derlen)
	                || !ber_read_mpi(&derp, &derlen, &rsa->n)
	                || !ber_read_mpi(&derp, &derlen, &rsa->e)
	                || derlen) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while decoding RSA public key");
		rsa_free(rsa);
		return NULL;
	}

	return rsa;
}

rsa_t *rsa_read_pem_private_key(FILE *fp) {
	uint8_t derbuf[8096], *derp = derbuf;
	size_t derlen;

	if(!pem_decode(fp, "RSA PRIVATE KEY", derbuf, sizeof(derbuf), &derlen)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to read RSA private key: %s", strerror(errno));
		return NULL;
	}

	rsa_t *rsa = rsa_new();

	if(!ber_skip_sequence(&derp, &derlen)
	                || !ber_read_mpi(&derp, &derlen, NULL)
	                || !ber_read_mpi(&derp, &derlen, &rsa->n)
	                || !ber_read_mpi(&derp, &derlen, &rsa->e)
	                || !ber_read_mpi(&derp, &derlen, &rsa->d)
	                || !ber_read_mpi(&derp, &derlen, NULL) // p
	                || !ber_read_mpi(&derp, &derlen, NULL) // q
	                || !ber_read_mpi(&derp, &derlen, NULL)
	                || !ber_read_mpi(&derp, &derlen, NULL)
	                || !ber_read_mpi(&derp, &derlen, NULL) // u
	                || derlen) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error while decoding RSA private key");
		rsa_free(rsa);
		rsa = NULL;
	}

	memzero(derbuf, sizeof(derbuf));
	return rsa;
}

size_t rsa_size(const rsa_t *rsa) {
	return (gcry_mpi_get_nbits(rsa->n) + 7) / 8;
}

static bool check(gcry_error_t err) {
	if(err) {
		logger(DEBUG_ALWAYS, LOG_ERR, "gcrypt error %s/%s", gcry_strsource(err), gcry_strerror(err));
	}

	return !err;
}

/* Well, libgcrypt has functions to handle RSA keys, but they suck.
 * So we just use libgcrypt's mpi functions, and do the math ourselves.
 */

static bool rsa_powm(const gcry_mpi_t ed, const gcry_mpi_t n, const void *in, size_t len, void *out) {
	gcry_mpi_t inmpi = NULL;

	if(!check(gcry_mpi_scan(&inmpi, GCRYMPI_FMT_USG, in, len, NULL))) {
		return false;
	}

	gcry_mpi_t outmpi = gcry_mpi_snew(len * 8);
	gcry_mpi_powm(outmpi, inmpi, ed, n);

	size_t out_bytes = (gcry_mpi_get_nbits(outmpi) + 7) / 8;
	size_t pad = len - MIN(out_bytes, len);
	unsigned char *pout = out;

	for(; pad; --pad) {
		*pout++ = 0;
	}

	bool ok = check(gcry_mpi_print(GCRYMPI_FMT_USG, pout, len, NULL, outmpi));

	gcry_mpi_release(outmpi);
	gcry_mpi_release(inmpi);

	return ok;
}

bool rsa_public_encrypt(rsa_t *rsa, const void *in, size_t len, void *out) {
	return rsa_powm(rsa->e, rsa->n, in, len, out);
}

bool rsa_private_decrypt(rsa_t *rsa, const void *in, size_t len, void *out) {
	return rsa_powm(rsa->d, rsa->n, in, len, out);
}

void rsa_free(rsa_t *rsa) {
	if(rsa) {
		if(rsa->n) {
			gcry_mpi_release(rsa->n);
		}

		if(rsa->e) {
			gcry_mpi_release(rsa->e);
		}

		if(rsa->d) {
			gcry_mpi_release(rsa->d);
		}

		free(rsa);
	}
}
