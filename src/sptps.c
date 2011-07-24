/*
    sptps.c -- Simple Peer-to-Peer Security
    Copyright (C) 2011 Guus Sliepen <guus@tinc-vpn.org>,

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

#include "cipher.h"
#include "crypto.h"
#include "digest.h"
#include "ecdh.h"
#include "ecdsa.h"
#include "prf.h"
#include "sptps.h"

char *logfilename;
#include "utils.c"

static bool error(sptps_t *s, int s_errno, const char *msg) {
	fprintf(stderr, "SPTPS error: %s\n", msg);
	errno = s_errno;
	return false;
}

static bool send_record_priv(sptps_t *s, uint8_t type, const char *data, uint16_t len) {
	char plaintext[len + 23];
	char ciphertext[len + 19];

	// Create header with sequence number, length and record type
	uint32_t seqno = htonl(s->outseqno++);
	uint16_t netlen = htons(len);

	memcpy(plaintext, &seqno, 4);
	memcpy(plaintext + 4, &netlen, 2);
	plaintext[6] = type;

	// Add plaintext (TODO: avoid unnecessary copy)
	memcpy(plaintext + 7, data, len);

	if(s->state) {
		// If first handshake has finished, encrypt and HMAC
		if(!digest_create(&s->outdigest, plaintext, len + 7, plaintext + 7 + len))
			return false;

		if(!cipher_encrypt(&s->outcipher, plaintext + 4, sizeof ciphertext, ciphertext, NULL, false))
			return false;

		return s->send_data(s->handle, ciphertext, len + 19);
	} else {
		// Otherwise send as plaintext
		return s->send_data(s->handle, plaintext + 4, len + 3);
	}
}

bool send_record(sptps_t *s, uint8_t type, const char *data, uint16_t len) {
	// Sanity checks: application cannot send data before handshake is finished,
	// and only record types 0..127 are allowed.
	if(!s->state)
		return error(s, EINVAL, "Handshake phase not finished yet");

	if(type & 128)
		return error(s, EINVAL, "Invalid application record type");

	return send_record_priv(s, type, data, len);
}

static bool send_kex(sptps_t *s) {
	size_t keylen = ECDH_SIZE;
	size_t siglen = ecdsa_size(&s->mykey);
	char data[32 + keylen + siglen];

	// Create a random nonce.
	s->myrandom = realloc(s->myrandom, 32);
	if(!s->myrandom)
		return error(s, errno, strerror(errno));

	randomize(s->myrandom, 32);
	memcpy(data, s->myrandom, 32);

	// Create a new ECDH public key.
	if(!ecdh_generate_public(&s->ecdh, data + 32))
		return false;

	// Sign the former.
	if(!ecdsa_sign(&s->mykey, data, 32 + keylen, data + 32 + keylen))
		return false;

	// Send the handshake record.
	return send_record_priv(s, 128, data, sizeof data);
}

static bool generate_key_material(sptps_t *s, const char *shared, size_t len, const char *hisrandom) {
	// Initialise cipher and digest structures if necessary
	if(!s->state) {
		bool result
			=  cipher_open_by_name(&s->incipher, "aes-256-ofb")
			&& cipher_open_by_name(&s->outcipher, "aes-256-ofb")
			&& digest_open_by_name(&s->indigest, "sha256", 16)
			&& digest_open_by_name(&s->outdigest, "sha256", 16);
		if(!result)
			return false;
	}

	// Allocate memory for key material
	size_t keylen = digest_keylength(&s->indigest) + digest_keylength(&s->outdigest) + cipher_keylength(&s->incipher) + cipher_keylength(&s->outcipher);

	s->key = realloc(s->key, keylen);
	if(!s->key)
		return error(s, errno, strerror(errno));

	// Create the HMAC seed, which is "key expansion" + session label + server nonce + client nonce
	char seed[s->labellen + 64 + 13];
	strcpy(seed, "key expansion");
	if(s->initiator) {
		memcpy(seed + 13, hisrandom, 32);
		memcpy(seed + 45, s->myrandom, 32);
	} else {
		memcpy(seed + 13, s->myrandom, 32);
		memcpy(seed + 45, hisrandom, 32);
	}
	memcpy(seed + 78, s->label, s->labellen);

	// Use PRF to generate the key material
	if(!prf(shared, len, seed, s->labellen + 64 + 13, s->key, keylen))
		return false;

	return true;
}

static bool send_ack(sptps_t *s) {
	return send_record_priv(s, 128, "", 0);
}

static bool receive_ack(sptps_t *s, const char *data, uint16_t len) {
	if(len)
		return false;

	// TODO: set cipher/digest keys
	return error(s, ENOSYS, "receive_ack() not completely implemented yet");
}

static bool receive_kex(sptps_t *s, const char *data, uint16_t len) {
	size_t keylen = ECDH_SIZE;
	size_t siglen = ecdsa_size(&s->hiskey);

	// Verify length of KEX record.
	if(len != 32 + keylen + siglen)
		return error(s, EIO, "Invalid KEX record length");

	// Verify signature.
	if(!ecdsa_verify(&s->hiskey, data, 32 + keylen, data + 32 + keylen))
		return false;

	// Compute shared secret.
	char shared[ECDH_SHARED_SIZE];
	if(!ecdh_compute_shared(&s->ecdh, data + 32, shared))
		return false;

	// Generate key material from shared secret.
	if(!generate_key_material(s, shared, sizeof shared, data))
		return false;

	// Send cipher change record if necessary
	if(s->state)
		if(!send_ack(s))
			return false;

	// TODO: set cipher/digest keys
	if(s->initiator) {
		bool result
			=  cipher_set_key(&s->incipher, s->key, false)
			&& digest_set_key(&s->indigest, s->key + cipher_keylength(&s->incipher), digest_keylength(&s->indigest))
			&& cipher_set_key(&s->outcipher, s->key + cipher_keylength(&s->incipher) + digest_keylength(&s->indigest), true)
			&& digest_set_key(&s->outdigest, s->key + cipher_keylength(&s->incipher) + digest_keylength(&s->indigest) + cipher_keylength(&s->outcipher), digest_keylength(&s->outdigest));
		if(!result)
			return false;
	} else {
		bool result
			=  cipher_set_key(&s->outcipher, s->key, true)
			&& digest_set_key(&s->outdigest, s->key + cipher_keylength(&s->outcipher), digest_keylength(&s->outdigest))
			&& cipher_set_key(&s->incipher, s->key + cipher_keylength(&s->outcipher) + digest_keylength(&s->outdigest), false)
			&& digest_set_key(&s->indigest, s->key + cipher_keylength(&s->outcipher) + digest_keylength(&s->outdigest) + cipher_keylength(&s->incipher), digest_keylength(&s->indigest));
		if(!result)
			return false;
	}

	return true;
}

static bool receive_handshake(sptps_t *s, const char *data, uint16_t len) {
	// Only a few states to deal with handshaking.
	switch(s->state) {
		case 0:
			// We have sent our public ECDH key, we expect our peer to sent one as well.
			if(!receive_kex(s, data, len))
				return false;
			s->state = 1;
			return true;
		case 1:
			// We receive a secondary key exchange request, first respond by sending our own public ECDH key.
			if(!send_kex(s))
				return false;
		case 2:
			// If we already sent our secondary public ECDH key, we expect the peer to send his.
			if(!receive_kex(s, data, len))
				return false;
			s->state = 3;
			return true;
		case 3:
			// We expect an empty handshake message to indicate transition to the new keys.
			if(!receive_ack(s, data, len))
				return false;
			s->state = 1;
			return true;
		default:
			return error(s, EIO, "Invalid session state");
	}
}

bool receive_data(sptps_t *s, const char *data, size_t len) {
	while(len) {
		// First read the 2 length bytes.
		if(s->buflen < 6) {
			size_t toread = 6 - s->buflen;
			if(toread > len)
				toread = len;

			if(s->state) {
				if(!cipher_decrypt(&s->incipher, data, toread, s->inbuf + s->buflen, NULL, false))
					return false;
			} else {
				memcpy(s->inbuf + s->buflen, data, toread);
			}

			s->buflen += toread;
			len -= toread;
			data += toread;

			// Exit early if we don't have the full length.
			if(s->buflen < 6)
				return true;

			// If we have the length bytes, ensure our buffer can hold the whole request.
			uint16_t reclen;
			memcpy(&reclen, s->inbuf + 4, 2);
			reclen = htons(reclen);
			s->inbuf = realloc(s->inbuf, reclen + 23UL);
			if(!s->inbuf)
				return error(s, errno, strerror(errno));

			// Add sequence number.
			uint32_t seqno = htonl(s->inseqno++);
			memcpy(s->inbuf, &seqno, 4);

			// Exit early if we have no more data to process.
			if(!len)
				return true;
		}

		// Read up to the end of the record.
		uint16_t reclen;
		memcpy(&reclen, s->inbuf + 4, 2);
		reclen = htons(reclen);
		size_t toread = reclen + (s->state ? 23UL : 7UL) - s->buflen;
		if(toread > len)
			toread = len;

		if(s->state) {
			if(!cipher_decrypt(&s->incipher, data, toread, s->inbuf + s->buflen, NULL, false))
				return false;
		} else {
			memcpy(s->inbuf + s->buflen, data, toread);
		}

		s->buflen += toread;
		len -= toread;
		data += toread;

		// If we don't have a whole record, exit.
		if(s->buflen < reclen + (s->state ? 23UL : 7UL))
			return true;

		// Check HMAC.
		if(s->state)
			if(!digest_verify(&s->indigest, s->inbuf, reclen + 7UL, s->inbuf + reclen + 7UL))
				error(s, EIO, "Invalid HMAC");

		uint8_t type = s->inbuf[6];

		// Handle record.
		if(type < 128) {
			if(!s->receive_record(s->handle, type, s->inbuf + 7, reclen))
				return false;
		} else if(type == 128) {
			if(!receive_handshake(s, s->inbuf + 7, reclen))
				return false;
		} else {
			return error(s, EIO, "Invalid record type");
		}

		s->buflen = 4;
	}

	return true;
}

bool start_sptps(sptps_t *s, void *handle, bool initiator, ecdsa_t mykey, ecdsa_t hiskey, const char *label, size_t labellen, send_data_t send_data, receive_record_t receive_record) {
	// Initialise struct sptps
	memset(s, 0, sizeof *s);

	s->handle = handle;
	s->initiator = initiator;
	s->mykey = mykey;
	s->hiskey = hiskey;

	s->label = malloc(labellen);
	if(!s->label)
		return error(s, errno, strerror(errno));

	s->inbuf = malloc(7);
	if(!s->inbuf)
		return error(s, errno, strerror(errno));
	s->buflen = 4;
	memset(s->inbuf, 0, 4);

	memcpy(s->label, label, labellen);
	s->labellen = labellen;

	s->send_data = send_data;
	s->receive_record = receive_record;

	// Do first KEX immediately
	return send_kex(s);
}

bool stop_sptps(sptps_t *s) {
	// Clean up any resources.
	ecdh_free(&s->ecdh);
	free(s->inbuf);
	free(s->myrandom);
	free(s->key);
	free(s->label);
	return true;
}
