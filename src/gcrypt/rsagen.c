/*
    rsagen.c -- RSA key generation and export
    Copyright (C) 2008 Guus Sliepen <guus@tinc-vpn.org>

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

#include "rsagen.h"

#if 0
// Base64 encoding table

static const char b64e[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// PEM encoding

static bool pem_encode(FILE *fp, const char *header, uint8_t *buf, size_t size) {
	bool decode = false;
	char line[1024];
	uint32_t word = 0;
	int shift = 0;
	size_t i, j = 0;

	fprintf(fp, "-----BEGIN %s-----\n", header);

	for(i = 0; i < size; i += 3) {
		if(i <= size - 3) {
			word = buf[i] << 16 | buf[i + 1] << 8 | buf[i + 2];
		} else {
			word = buf[i] << 16;
			if(i == size - 2)
				word |= buf[i + 1] << 8;
		}

		line[j++] = b64e[(word >> 18)       ];
		line[j++] = b64e[(word >> 12) & 0x3f];
		line[j++] = b64e[(word >>  6) & 0x3f];
		line[j++] = b64e[(word      ) & 0x3f];

		if(j >= 64) {
			line[j++] = '\n';
			line[j] = 0;
			fputs(line, fp);
			j = 0;
		}
	}

	if(size % 3 > 0) {
		if(size % 3 > 1)
			line[j++] = '=';
		line[j++] = '=';
	}

	if(j) {
		line[j++] = '\n';
		line[j] = 0;
		fputs(line, fp);
	}

	fprintf(fp, "-----END %s-----\n", header);

	return true;
}


// BER encoding functions

static bool ber_write_id(uint8_t **p, size_t *buflen, int id) {
	if(*buflen <= 0)
		return false;

	if(id >= 0x1f) {
		while(id) {
			if(*buflen <= 0)
				return false;

			(*buflen)--;
			**p = id & 0x7f;
			id >>= 7;
			if(id)
				**p |= 0x80;
			(*p)++;
		}
	} else {
		(*buflen)--;
		*(*p)++ = id;
	}

	return true;
}

static bool ber_write_len(uint8_t **p, size_t *buflen, size_t len) {
	do {
		if(*buflen <= 0)
			return false;

		(*buflen)--;
		**p = len & 0x7f;
		len >>= 7;
		if(len)
			**p |= 0x80;
		(*p)++;
	} while(len);

	return true;
}

static bool ber_write_sequence(uint8_t **p, size_t *buflen, uint8_t *seqbuf, size_t seqlen) {
	if(!ber_write_id(p, buflen, 0x10) || !ber_write_len(p, buflen, seqlen) || *buflen < seqlen)
		return false;

	memcpy(*p, seqbuf, seqlen);
	*p += seqlen;
	*buflen -= seqlen;

	return true;
}

static bool ber_write_mpi(uint8_t **p, size_t *buflen, gcry_mpi_t mpi) {
	uint8_t tmpbuf[1024];
	size_t tmplen = sizeof tmpbuf;
	gcry_error_t err;

	err = gcry_mpi_aprint(GCRYMPI_FMT_USG, &tmpbuf, &tmplen, mpi);
	if(err)
		return false;

	if(!ber_write_id(p, buflen, 0x02) || !ber_write_len(p, buflen, tmplen) || *buflen < tmplen)
		return false;

	memcpy(*p, tmpbuf, tmplen);
	*p += tmplen;
	*buflen -= tmplen;

	return true;
}

// Write PEM RSA keys

bool rsa_write_pem_public_key(rsa_t *rsa, FILE *fp) {
	uint8_t derbuf1[8096];
	uint8_t derbuf2[8096];
	uint8_t *derp1 = derbuf1;
	uint8_t *derp2 = derbuf2;
	size_t derlen1 = sizeof derbuf1;
	size_t derlen2 = sizeof derbuf2;

	if(!ber_write_mpi(&derp1, &derlen1, &rsa->n)
			|| !ber_write_mpi(&derp1, &derlen1, &rsa->e)
			|| !ber_write_sequence(&derp2, &derlen2, derbuf1, derlen1)) {
		logger(LOG_ERR, "Error while encoding RSA public key");
		return false;
	}

	if(!pem_encode(fp, "RSA PUBLIC KEY", derbuf2, derlen2)) {
		logger(LOG_ERR, "Unable to write RSA public key: %s", strerror(errno));
		return false;
	}

	return true;
}

bool rsa_write_pem_private_key(rsa_t *rsa, FILE *fp) {
	uint8_t derbuf1[8096];
	uint8_t derbuf2[8096];
	uint8_t *derp1 = derbuf1;
	uint8_t *derp2 = derbuf2;
	size_t derlen1 = sizeof derbuf1;
	size_t derlen2 = sizeof derbuf2;

	if(!ber_write_mpi(&derp1, &derlen1, &bits)
			|| ber_write_mpi(&derp1, &derlen1, &rsa->n) // modulus
			|| ber_write_mpi(&derp1, &derlen1, &rsa->e) // public exponent
			|| ber_write_mpi(&derp1, &derlen1, &rsa->d) // private exponent
			|| ber_write_mpi(&derp1, &derlen1, &p)
			|| ber_write_mpi(&derp1, &derlen1, &q)
			|| ber_write_mpi(&derp1, &derlen1, &exp1)
			|| ber_write_mpi(&derp1, &derlen1, &exp2)
			|| ber_write_mpi(&derp1, &derlen1, &coeff))
		logger(LOG_ERR, "Error while encoding RSA private key");
		return false;
	}

	if(!pem_encode(fp, "RSA PRIVATE KEY", derbuf2, derlen2)) {
		logger(LOG_ERR, "Unable to write RSA private key: %s", strerror(errno));
		return false;
	}

	return true;
}
#endif

bool rsa_write_pem_public_key(rsa_t *rsa, FILE *fp) {
	return false;
}

bool rsa_write_pem_private_key(rsa_t *rsa, FILE *fp) {
	return false;
}

bool rsa_generate(rsa_t *rsa, size_t bits, unsigned long exponent) {
	fprintf(stderr, "Generating RSA keys with libgcrypt not implemented yet\n");
	return false;
}
