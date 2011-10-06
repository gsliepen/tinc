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

/*
   Nonce MUST be exchanged first (done)
   Signatures MUST be done over both nonces, to guarantee the signature is fresh
   Otherwise: if ECDHE key of one side is compromised, it can be reused!

   Add explicit tag to beginning of structure to distinguish the client and server when signing. (done)

   Sign all handshake messages up to ECDHE kex with long-term public keys. (done)

   HMACed KEX finished message to prevent downgrade attacks and prove you have the right key material (done by virtue of ECDSA over the whole ECDHE exchange?)

   Explicit close message needs to be added.

   Maybe do add some alert messages to give helpful error messages? Not more than TLS sends.

   Use counter mode instead of OFB. (done)

   Make sure ECC operations are fixed time (aka prevent side-channel attacks).
*/

// Log an error message.
static bool error(sptps_t *s, int s_errno, const char *msg) {
	fprintf(stderr, "SPTPS error: %s\n", msg);
	errno = s_errno;
	return false;
}

// Send a record (private version, accepts all record types, handles encryption and authentication).
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

	if(s->outstate) {
		// If first handshake has finished, encrypt and HMAC
		if(!digest_create(&s->outdigest, plaintext, len + 7, plaintext + 7 + len))
			return false;

		if(!cipher_counter_xor(&s->outcipher, plaintext + 4, sizeof ciphertext, ciphertext))
			return false;

		return s->send_data(s->handle, ciphertext, len + 19);
	} else {
		// Otherwise send as plaintext
		return s->send_data(s->handle, plaintext + 4, len + 3);
	}
}

// Send an application record.
bool send_record(sptps_t *s, uint8_t type, const char *data, uint16_t len) {
	// Sanity checks: application cannot send data before handshake is finished,
	// and only record types 0..127 are allowed.
	if(!s->outstate)
		return error(s, EINVAL, "Handshake phase not finished yet");

	if(type >= SPTPS_HANDSHAKE)
		return error(s, EINVAL, "Invalid application record type");

	return send_record_priv(s, type, data, len);
}

// Send a Key EXchange record, containing a random nonce and an ECDHE public key.
static bool send_kex(sptps_t *s) {
	size_t keylen = ECDH_SIZE;

	// Make room for our KEX message, which we will keep around since send_sig() needs it.
	s->mykex = realloc(s->mykex, 1 + 32 + keylen);
	if(!s->mykex)
		return error(s, errno, strerror(errno));

	// Set version byte to zero.
	s->mykex[0] = SPTPS_VERSION;

	// Create a random nonce.
	randomize(s->mykex + 1, 32);

	// Create a new ECDH public key.
	if(!ecdh_generate_public(&s->ecdh, s->mykex + 1 + 32))
		return false;

	return send_record_priv(s, SPTPS_HANDSHAKE, s->mykex, 1 + 32 + keylen);
}

// Send a SIGnature record, containing an ECDSA signature over both KEX records.
static bool send_sig(sptps_t *s) {
	size_t keylen = ECDH_SIZE;
	size_t siglen = ecdsa_size(&s->mykey);

	// Concatenate both KEX messages, plus tag indicating if it is from the connection originator
	char msg[(1 + 32 + keylen) * 2 + 1];
	char sig[siglen];

	msg[0] = s->initiator;
	memcpy(msg + 1, s->mykex, 1 + 32 + keylen);
	memcpy(msg + 2 + 32 + keylen, s->hiskex, 1 + 32 + keylen);

	// Sign the result.
	if(!ecdsa_sign(&s->mykey, msg, sizeof msg, sig))
		return false;

	// Send the SIG exchange record.
	return send_record_priv(s, SPTPS_HANDSHAKE, sig, sizeof sig);
}

// Generate key material from the shared secret created from the ECDHE key exchange.
static bool generate_key_material(sptps_t *s, const char *shared, size_t len) {
	// Initialise cipher and digest structures if necessary
	if(!s->outstate) {
		bool result
			=  cipher_open_by_name(&s->incipher, "aes-256-ecb")
			&& cipher_open_by_name(&s->outcipher, "aes-256-ecb")
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
		memcpy(seed + 13, s->mykex + 1, 32);
		memcpy(seed + 45, s->hiskex + 1, 32);
	} else {
		memcpy(seed + 13, s->hiskex + 1, 32);
		memcpy(seed + 45, s->mykex + 1, 32);
	}
	memcpy(seed + 78, s->label, s->labellen);

	// Use PRF to generate the key material
	if(!prf(shared, len, seed, s->labellen + 64 + 13, s->key, keylen))
		return false;

	return true;
}

// Send an ACKnowledgement record.
static bool send_ack(sptps_t *s) {
	return send_record_priv(s, SPTPS_HANDSHAKE, "", 0);
}

// Receive an ACKnowledgement record.
static bool receive_ack(sptps_t *s, const char *data, uint16_t len) {
	if(len)
		return false;

	// TODO: set cipher/digest keys
	return error(s, ENOSYS, "receive_ack() not completely implemented yet");
}

// Receive a Key EXchange record, respond by sending a SIG record.
static bool receive_kex(sptps_t *s, const char *data, uint16_t len) {
	// Verify length of the HELLO record
	if(len != 1 + 32 + ECDH_SIZE)
		return error(s, EIO, "Invalid KEX record length");

	// Ignore version number for now.

	// Make a copy of the KEX message, send_sig() and receive_sig() need it
	s->hiskex = realloc(s->hiskex, len);
	if(!s->hiskex)
		return error(s, errno, strerror(errno));

	memcpy(s->hiskex, data, len);

	return send_sig(s);
}

// Receive a SIGnature record, verify it, if it passed, compute the shared secret and calculate the session keys.
static bool receive_sig(sptps_t *s, const char *data, uint16_t len) {
	size_t keylen = ECDH_SIZE;
	size_t siglen = ecdsa_size(&s->hiskey);

	// Verify length of KEX record.
	if(len != siglen)
		return error(s, EIO, "Invalid KEX record length");

	// Concatenate both KEX messages, plus tag indicating if it is from the connection originator
	char msg[(1 + 32 + keylen) * 2 + 1];

	msg[0] = !s->initiator;
	memcpy(msg + 1, s->hiskex, 1 + 32 + keylen);
	memcpy(msg + 2 + 32 + keylen, s->mykex, 1 + 32 + keylen);

	// Verify signature.
	if(!ecdsa_verify(&s->hiskey, msg, sizeof msg, data))
		return false;

	// Compute shared secret.
	char shared[ECDH_SHARED_SIZE];
	if(!ecdh_compute_shared(&s->ecdh, s->hiskex + 1 + 32, shared))
		return false;

	// Generate key material from shared secret.
	if(!generate_key_material(s, shared, sizeof shared))
		return false;

	// Send cipher change record if necessary
	//if(s->outstate && !send_ack(s))
	//	return false;

	// TODO: only set new keys after ACK has been set/received
	if(s->initiator) {
		bool result
			=  cipher_set_counter_key(&s->incipher, s->key)
			&& digest_set_key(&s->indigest, s->key + cipher_keylength(&s->incipher), digest_keylength(&s->indigest))
			&& cipher_set_counter_key(&s->outcipher, s->key + cipher_keylength(&s->incipher) + digest_keylength(&s->indigest))
			&& digest_set_key(&s->outdigest, s->key + cipher_keylength(&s->incipher) + digest_keylength(&s->indigest) + cipher_keylength(&s->outcipher), digest_keylength(&s->outdigest));
		if(!result)
			return false;
	} else {
		bool result
			=  cipher_set_counter_key(&s->outcipher, s->key)
			&& digest_set_key(&s->outdigest, s->key + cipher_keylength(&s->outcipher), digest_keylength(&s->outdigest))
			&& cipher_set_counter_key(&s->incipher, s->key + cipher_keylength(&s->outcipher) + digest_keylength(&s->outdigest))
			&& digest_set_key(&s->indigest, s->key + cipher_keylength(&s->outcipher) + digest_keylength(&s->outdigest) + cipher_keylength(&s->incipher), digest_keylength(&s->indigest));
		if(!result)
			return false;
	}

	s->outstate = true;
	s->instate = true;

	return true;
}

// Force another Key EXchange (for testing purposes).
bool force_kex(sptps_t *s) {
	if(!s->outstate || s->state != SPTPS_SECONDARY_KEX)
		return error(s, EINVAL, "Cannot force KEX in current state");

	s->state = SPTPS_KEX;
	return send_kex(s);
}

// Receive a handshake record.
static bool receive_handshake(sptps_t *s, const char *data, uint16_t len) {
	// Only a few states to deal with handshaking.
	fprintf(stderr, "Received handshake message, current state %d\n", s->state);
	switch(s->state) {
		case SPTPS_SECONDARY_KEX:
			// We receive a secondary KEX request, first respond by sending our own.
			if(!send_kex(s))
				return false;
		case SPTPS_KEX:
			// We have sent our KEX request, we expect our peer to sent one as well.
			if(!receive_kex(s, data, len))
				return false;
			s->state = SPTPS_SIG;
			return true;
		case SPTPS_SIG:
			// If we already sent our secondary public ECDH key, we expect the peer to send his.
			if(!receive_sig(s, data, len))
				return false;
			// s->state = SPTPS_ACK;
			s->state = SPTPS_SECONDARY_KEX;
			return true;
		case SPTPS_ACK:
			// We expect a handshake message to indicate transition to the new keys.
			if(!receive_ack(s, data, len))
				return false;
			s->state = SPTPS_SECONDARY_KEX;
			return true;
		// TODO: split ACK into a VERify and ACK?
		default:
			return error(s, EIO, "Invalid session state");
	}
}

// Receive incoming data. Check if it contains a complete record, if so, handle it.
bool receive_data(sptps_t *s, const char *data, size_t len) {
	while(len) {
		// First read the 2 length bytes.
		if(s->buflen < 6) {
			size_t toread = 6 - s->buflen;
			if(toread > len)
				toread = len;

			if(s->instate) {
				if(!cipher_counter_xor(&s->incipher, data, toread, s->inbuf + s->buflen))
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
		size_t toread = reclen + (s->instate ? 23UL : 7UL) - s->buflen;
		if(toread > len)
			toread = len;

		if(s->instate) {
			if(!cipher_counter_xor(&s->incipher, data, toread, s->inbuf + s->buflen))
				return false;
		} else {
			memcpy(s->inbuf + s->buflen, data, toread);
		}

		s->buflen += toread;
		len -= toread;
		data += toread;

		// If we don't have a whole record, exit.
		if(s->buflen < reclen + (s->instate ? 23UL : 7UL))
			return true;

		// Check HMAC.
		if(s->instate)
			if(!digest_verify(&s->indigest, s->inbuf, reclen + 7UL, s->inbuf + reclen + 7UL))
				error(s, EIO, "Invalid HMAC");

		uint8_t type = s->inbuf[6];

		// Handle record.
		if(type < SPTPS_HANDSHAKE) {
			if(!s->receive_record(s->handle, type, s->inbuf + 7, reclen))
				return false;
		} else if(type == SPTPS_HANDSHAKE) {
			if(!receive_handshake(s, s->inbuf + 7, reclen))
				return false;
		} else {
			return error(s, EIO, "Invalid record type");
		}

		s->buflen = 4;
	}

	return true;
}

// Start a SPTPS session.
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
	s->state = SPTPS_KEX;
	return send_kex(s);
}

// Stop a SPTPS session.
bool stop_sptps(sptps_t *s) {
	// Clean up any resources.
	ecdh_free(&s->ecdh);
	free(s->inbuf);
	free(s->mykex);
	free(s->hiskex);
	free(s->key);
	free(s->label);
	return true;
}
