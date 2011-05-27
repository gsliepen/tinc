/*
    rsa.c -- RSA key handling
    Copyright (C) 2007 Guus Sliepen <guus@tinc-vpn.org>

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

#include "system.h"

#include <gcrypt.h>

#include "logger.h"
#include "rsa.h"

// Base64 decoding table

static const uint8_t b64d[128] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
  0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
  0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
  0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
  0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
  0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
  0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
  0x31, 0x32, 0x33, 0xff, 0xff, 0xff,
  0xff, 0xff
};

// PEM encoding/decoding functions

static bool pem_decode(FILE *fp, const char *header, uint8_t *buf, size_t size, size_t *outsize) {
	bool decode = false;
	char line[1024];
	uint16_t word = 0;
	int shift = 10;
	size_t i, j = 0;

	while(!feof(fp)) {
		if(!fgets(line, sizeof line, fp))
			return false;

		if(!decode && !strncmp(line, "-----BEGIN ", 11)) {
			if(!strncmp(line + 11, header, strlen(header)))
				decode = true;
			continue;
		}

		if(decode && !strncmp(line, "-----END", 8)) {
			break;
		}

		if(!decode)
			continue;

		for(i = 0; line[i] >= ' '; i++) {
			if((signed char)line[i] < 0 || b64d[(int)line[i]] == 0xff)
				break;
			word |= b64d[(int)line[i]] << shift;
			shift -= 6;
			if(shift <= 2) {
				if(j > size) {
					errno = ENOMEM;
					return false;
				}

				buf[j++] = word >> 8;
				word <<= 8;
				shift += 8;
			}
		}
	}

	if(outsize)
		*outsize = j;
	return true;
}


// BER decoding functions

static int ber_read_id(unsigned char **p, size_t *buflen) {
	if(*buflen <= 0)
		return -1;

	if((**p & 0x1f) == 0x1f) {
		int id = 0;
		bool more;
		while(*buflen > 0) {
			id <<= 7;
			id |= **p & 0x7f;
			more = *(*p)++ & 0x80;
			(*buflen)--;
			if(!more)
				break;
		}
		return id;
	} else {
		(*buflen)--;
		return *(*p)++ & 0x1f;
	}
}

static size_t ber_read_len(unsigned char **p, size_t *buflen) {
	if(*buflen <= 0)
		return -1;

	if(**p & 0x80) {
		size_t result = 0;
		int len = *(*p)++ & 0x7f;
		(*buflen)--;
		if(len > *buflen)
			return 0;

		while(len--) {
			result <<= 8;
			result |= *(*p)++;
			(*buflen)--;
		}

		return result;
	} else {
		(*buflen)--;
		return *(*p)++;
	}
}
	

static bool ber_read_sequence(unsigned char **p, size_t *buflen, size_t *result) {
	int tag = ber_read_id(p, buflen);
	size_t len = ber_read_len(p, buflen);

	if(tag == 0x10) {
		if(result)
			*result = len;
		return true;
	} else {
		return false;
	}
}

static bool ber_read_mpi(unsigned char **p, size_t *buflen, gcry_mpi_t *mpi) {
	int tag = ber_read_id(p, buflen);
	size_t len = ber_read_len(p, buflen);
	gcry_error_t err = 0;

	if(tag != 0x02 || len > *buflen)
		return false;

	if(mpi)
		err = gcry_mpi_scan(mpi, GCRYMPI_FMT_USG, *p, len, NULL);
	
	*p += len;
	*buflen -= len;

	return mpi ? !err : true;
}

bool rsa_set_hex_public_key(rsa_t *rsa, char *n, char *e) {
	gcry_error_t err = 0;

	err = gcry_mpi_scan(&rsa->n, GCRYMPI_FMT_HEX, n, 0, NULL)
		?: gcry_mpi_scan(&rsa->e, GCRYMPI_FMT_HEX, e, 0, NULL);

	if(err) {
		logger(LOG_ERR, "Error while reading RSA public key: %s", gcry_strerror(errno));
		return false;
	}

	return true;
}

bool rsa_set_hex_private_key(rsa_t *rsa, char *n, char *e, char *d) {
	gcry_error_t err = 0;

	err = gcry_mpi_scan(&rsa->n, GCRYMPI_FMT_HEX, n, 0, NULL)
		?: gcry_mpi_scan(&rsa->e, GCRYMPI_FMT_HEX, e, 0, NULL)
		?: gcry_mpi_scan(&rsa->d, GCRYMPI_FMT_HEX, d, 0, NULL);

	if(err) {
		logger(LOG_ERR, "Error while reading RSA public key: %s", gcry_strerror(errno));
		return false;
	}

	return true;
}

// Read PEM RSA keys

bool rsa_read_pem_public_key(rsa_t *rsa, FILE *fp) {
	uint8_t derbuf[8096], *derp = derbuf;
	size_t derlen;

	if(!pem_decode(fp, "RSA PUBLIC KEY", derbuf, sizeof derbuf, &derlen)) {
		logger(LOG_ERR, "Unable to read RSA public key: %s", strerror(errno));
		return NULL;
	}

	if(!ber_read_sequence(&derp, &derlen, NULL)
			|| !ber_read_mpi(&derp, &derlen, &rsa->n)
			|| !ber_read_mpi(&derp, &derlen, &rsa->e)
			|| derlen) {
		logger(LOG_ERR, "Error while decoding RSA public key");
		return NULL;
	}

	return true;
}

bool rsa_read_pem_private_key(rsa_t *rsa, FILE *fp) {
	uint8_t derbuf[8096], *derp = derbuf;
	size_t derlen;

	if(!pem_decode(fp, "RSA PRIVATE KEY", derbuf, sizeof derbuf, &derlen)) {
		logger(LOG_ERR, "Unable to read RSA private key: %s", strerror(errno));
		return NULL;
	}

	if(!ber_read_sequence(&derp, &derlen, NULL)
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
		logger(LOG_ERR, "Error while decoding RSA private key");
		return NULL;
	}

	return true;
}

size_t rsa_size(rsa_t *rsa) {
	return (gcry_mpi_get_nbits(rsa->n) + 7) / 8;
}

/* Well, libgcrypt has functions to handle RSA keys, but they suck.
 * So we just use libgcrypt's mpi functions, and do the math ourselves.
 */

// TODO: get rid of this macro, properly clean up gcry_ structures after use
#define check(foo) { gcry_error_t err = (foo); if(err) {logger(LOG_ERR, "gcrypt error %s/%s at %s:%d", gcry_strsource(err), gcry_strerror(err), __FILE__, __LINE__); return false; }}

bool rsa_public_encrypt(rsa_t *rsa, void *in, size_t len, void *out) {
	gcry_mpi_t inmpi;
	check(gcry_mpi_scan(&inmpi, GCRYMPI_FMT_USG, in, len, NULL));

	gcry_mpi_t outmpi = gcry_mpi_new(len * 8);
	gcry_mpi_powm(outmpi, inmpi, rsa->e, rsa->n);

	int pad = len - (gcry_mpi_get_nbits(outmpi) + 7) / 8;
	while(pad--)
		*(char *)out++ = 0;

	check(gcry_mpi_print(GCRYMPI_FMT_USG, out,len, NULL, outmpi));

	return true;
}

bool rsa_private_decrypt(rsa_t *rsa, void *in, size_t len, void *out) {
	gcry_mpi_t inmpi;
	check(gcry_mpi_scan(&inmpi, GCRYMPI_FMT_USG, in, len, NULL));

	gcry_mpi_t outmpi = gcry_mpi_new(len * 8);
	gcry_mpi_powm(outmpi, inmpi, rsa->d, rsa->n);

	int pad = len - (gcry_mpi_get_nbits(outmpi) + 7) / 8;
	while(pad--)
		*(char *)out++ = 0;

	check(gcry_mpi_print(GCRYMPI_FMT_USG, out,len, NULL, outmpi));

	return true;
}
