/*
    sptps.c -- Simple Peer-to-Peer Security
    Copyright (C) 2011-2021 Guus Sliepen <guus@tinc-vpn.org>,
                  2010      Brandon L. Black <blblack@gmail.com>

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

#include "chacha-poly1305/chachapoly.h"
#include "ecdh.h"
#include "ecdsa.h"
#include "prf.h"
#include "sptps.h"
#include "random.h"
#include "xalloc.h"

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

#define CIPHER_KEYLEN 64

unsigned int sptps_replaywin = 16;

/*
   Nonce MUST be exchanged first (done)
   Signatures MUST be done over both nonces, to guarantee the signature is fresh
   Otherwise: if ECDHE key of one side is compromised, it can be reused!

   Add explicit tag to beginning of structure to distinguish the client and server when signing. (done)

   Sign all handshake messages up to ECDHE kex with long-term public keys. (done)

   HMACed KEX finished message to prevent downgrade attacks and prove you have the right key material (done by virtue of Ed25519 over the whole ECDHE exchange?)

   Explicit close message needs to be added.

   Maybe do add some alert messages to give helpful error messages? Not more than TLS sends.

   Use counter mode instead of OFB. (done)

   Make sure ECC operations are fixed time (aka prevent side-channel attacks).
*/

void sptps_log_quiet(sptps_t *s, int s_errno, const char *format, va_list ap) {
	(void)s;
	(void)s_errno;
	(void)format;
	(void)ap;
}

void sptps_log_stderr(sptps_t *s, int s_errno, const char *format, va_list ap) {
	(void)s;
	(void)s_errno;

	vfprintf(stderr, format, ap);
	fputc('\n', stderr);
}

void (*sptps_log)(sptps_t *s, int s_errno, const char *format, va_list ap) = sptps_log_stderr;

// Log an error message.
static bool error(sptps_t *s, int s_errno, const char *format, ...) ATTR_FORMAT(printf, 3, 4);
static bool error(sptps_t *s, int s_errno, const char *format, ...) {
	(void)s;
	(void)s_errno;

	if(format) {
		va_list ap;
		va_start(ap, format);
		sptps_log(s, s_errno, format, ap);
		va_end(ap);
	}

	errno = s_errno;
	return false;
}

static void warning(sptps_t *s, const char *format, ...) ATTR_FORMAT(printf, 2, 3);
static void warning(sptps_t *s, const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	sptps_log(s, 0, format, ap);
	va_end(ap);
}

static sptps_kex_t *new_sptps_kex(void) {
	return xzalloc(sizeof(sptps_kex_t));
}

static void free_sptps_kex(sptps_kex_t *kex) {
	xzfree(kex, sizeof(sptps_kex_t));
}

static sptps_key_t *new_sptps_key(void) {
	return xzalloc(sizeof(sptps_key_t));
}

static void free_sptps_key(sptps_key_t *key) {
	xzfree(key, sizeof(sptps_key_t));
}

static bool cipher_init(uint8_t suite, void **ctx, const sptps_key_t *keys, bool key_half) {
	const uint8_t *key = key_half ? keys->key1 : keys->key0;

	switch(suite) {
#ifndef HAVE_OPENSSL

	case SPTPS_CHACHA_POLY1305:
		*ctx = malloc(sizeof(struct chachapoly_ctx));
		return *ctx && chachapoly_init(*ctx, key, 256) == CHACHAPOLY_OK;

#else

	case SPTPS_CHACHA_POLY1305:
#ifdef EVP_F_EVP_AEAD_CTX_INIT
		*ctx = malloc(sizeof(EVP_AEAD_CTX));

		return *ctx && EVP_AEAD_CTX_init(*ctx, EVP_aead_chacha20_poly1305(), key + (key_half ? CIPHER_KEYLEN : 0), 32, 16, NULL);
#else
		*ctx = EVP_CIPHER_CTX_new();

		return *ctx
		       && EVP_EncryptInit_ex(*ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)
		       && EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)
		       && EVP_EncryptInit_ex(*ctx, NULL, NULL, key, key + 32);
#endif

	case SPTPS_AES256_GCM:
		*ctx = EVP_CIPHER_CTX_new();

		return *ctx
		       && EVP_EncryptInit_ex(*ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)
		       && EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)
		       && EVP_EncryptInit_ex(*ctx, NULL, NULL, key, key + 32);
#endif

	default:
		return false;
	}
}

static void cipher_exit(uint8_t suite, void *ctx) {
	switch(suite) {
#ifndef HAVE_OPENSSL

	case SPTPS_CHACHA_POLY1305:
		free(ctx);
		break;

#else

	case SPTPS_CHACHA_POLY1305:
#ifdef EVP_F_EVP_AEAD_CTX_INIT
		EVP_AEAD_CTX_cleanup(ctx);
		free(ctx);
		break;
#endif

	case SPTPS_AES256_GCM:
		EVP_CIPHER_CTX_free(ctx);
		break;
#endif

	default:
		break;
	}
}

static bool cipher_encrypt(uint8_t suite, void *ctx, uint32_t seqno, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen) {
	switch(suite) {
#ifndef HAVE_OPENSSL

	case SPTPS_CHACHA_POLY1305: {
		if(chachapoly_crypt(ctx, nonce, (void *)in, inlen, out, out + inlen, 16, 1) != CHACHAPOLY_OK) {
			return false;
		}

		if(outlen) {
			*outlen = inlen + 16;
		}

		return true;
	}

#else

	case SPTPS_CHACHA_POLY1305:
#ifdef EVP_F_EVP_AEAD_CTX_INIT
		{
			size_t outlen1;

			if(!EVP_AEAD_CTX_seal(ctx, out, &outlen1, inlen + 16, nonce, sizeof(nonce), in, inlen, NULL, 0)) {
				return false;
			}

			if(outlen) {
				*outlen = outlen1;
			}

			return true;
		}

#endif

	case SPTPS_AES256_GCM: {
		uint8_t nonce[12] = {seqno, seqno >> 8, seqno >> 16, seqno >> 24};

		if(!EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, nonce)) {
			return false;
		}

		int outlen1 = 0, outlen2 = 0;

		if(!EVP_EncryptUpdate(ctx, out, &outlen1, in, (int)inlen)) {
			return false;
		}

		if(!EVP_EncryptFinal_ex(ctx, out + outlen1, &outlen2)) {
			return false;
		}

		outlen1 += outlen2;

		if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + outlen1)) {
			return false;
		}

		outlen1 += 16;

		if(outlen) {
			*outlen = outlen1;
		}

		return true;
	}

#endif

	default:
		return false;
	}
}

static bool cipher_decrypt(uint8_t suite, void *ctx, uint32_t seqno, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen) {
	if(inlen < 16) {
		return false;
	}

	inlen -= 16;

	switch(suite) {
#ifndef HAVE_OPENSSL

	case SPTPS_CHACHA_POLY1305:
		if(chachapoly_crypt(ctx, nonce, (void *)in, inlen, out, (void *)(in + inlen), 16, 0) != CHACHAPOLY_OK) {
			return false;
		}

		if(outlen) {
			*outlen = inlen;
		}

		return true;

#else

	case SPTPS_CHACHA_POLY1305:
#ifdef EVP_F_EVP_AEAD_CTX_INIT
		{
			size_t outlen1;

			if(!EVP_AEAD_CTX_open(ctx, out, &outlen1, inlen, nonce, sizeof(nonce), in, inlen + 16, NULL, 0)) {
				return false;
			}

			if(outlen) {
				*outlen = outlen1;
			}

			return true;
		}

#endif

	case SPTPS_AES256_GCM: {
		uint8_t nonce[12] = {seqno, seqno >> 8, seqno >> 16, seqno >> 24};

		if(!EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, nonce)) {
			return false;
		}

		int outlen1 = 0, outlen2 = 0;

		if(!EVP_DecryptUpdate(ctx, out, &outlen1, in, (int)inlen)) {
			return false;
		}

		if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(in + inlen))) {
			return false;
		}

		if(!EVP_DecryptFinal_ex(ctx, out + outlen1, &outlen2)) {
			return false;
		}

		if(outlen) {
			*outlen = outlen1 + outlen2;
		}

		return true;
	}

#endif

	default:
		return false;
	}
}

// Send a record (datagram version, accepts all record types, handles encryption and authentication).
static bool send_record_priv_datagram(sptps_t *s, uint8_t type, const void *data, uint16_t len) {
	uint8_t *buffer = alloca(len + SPTPS_DATAGRAM_OVERHEAD);
	// Create header with sequence number, length and record type
	uint32_t seqno = s->outseqno++;

	memcpy(buffer, &seqno, 4);
	buffer[4] = type;
	memcpy(buffer + 5, data, len);

	if(s->outstate) {
		// If first handshake has finished, encrypt and HMAC
		if(!cipher_encrypt(s->cipher_suite, s->outcipher, seqno, buffer + 4, len + 1, buffer + 4, NULL)) {
			return error(s, EINVAL, "Failed to encrypt message");
		}

		return s->send_data(s->handle, type, buffer, len + SPTPS_DATAGRAM_OVERHEAD);
	} else {
		// Otherwise send as plaintext
		return s->send_data(s->handle, type, buffer, len + SPTPS_DATAGRAM_HEADER);
	}
}
// Send a record (private version, accepts all record types, handles encryption and authentication).
static bool send_record_priv(sptps_t *s, uint8_t type, const void *data, uint16_t len) {
	if(s->datagram) {
		return send_record_priv_datagram(s, type, data, len);
	}

	uint8_t *buffer = alloca(len + SPTPS_OVERHEAD);

	// Create header with sequence number, length and record type
	uint32_t seqno = s->outseqno++;
	uint16_t netlen = len;

	memcpy(buffer, &netlen, 2);
	buffer[2] = type;
	memcpy(buffer + 3, data, len);

	if(s->outstate) {
		// If first handshake has finished, encrypt and HMAC
		if(!cipher_encrypt(s->cipher_suite, s->outcipher, seqno, buffer + 2, len + 1, buffer + 2, NULL)) {
			return error(s, EINVAL, "Failed to encrypt message");
		}

		return s->send_data(s->handle, type, buffer, len + SPTPS_OVERHEAD);
	} else {
		// Otherwise send as plaintext
		return s->send_data(s->handle, type, buffer, len + SPTPS_HEADER);
	}
}

// Send an application record.
bool sptps_send_record(sptps_t *s, uint8_t type, const void *data, uint16_t len) {
	// Sanity checks: application cannot send data before handshake is finished,
	// and only record types 0..127 are allowed.
	if(!s->outstate) {
		return error(s, EINVAL, "Handshake phase not finished yet");
	}

	if(type >= SPTPS_HANDSHAKE) {
		return error(s, EINVAL, "Invalid application record type");
	}

	return send_record_priv(s, type, data, len);
}

// Send a Key EXchange record, containing a random nonce and an ECDHE public key.
static bool send_kex(sptps_t *s) {
	// Make room for our KEX message, which we will keep around since send_sig() needs it.
	if(s->mykex) {
		return false;
	}

	s->mykex = new_sptps_kex();

	// Set version byte to zero.
	s->mykex->version = SPTPS_VERSION;
	s->mykex->preferred_suite = s->preferred_suite;
	s->mykex->cipher_suites = s->cipher_suites;

	// Create a random nonce.
	randomize(s->mykex->nonce, ECDH_SIZE);

	// Create a new ECDH public key.
	if(!(s->ecdh = ecdh_generate_public(s->mykex->pubkey))) {
		return error(s, EINVAL, "Failed to generate ECDH public key");
	}

	return send_record_priv(s, SPTPS_HANDSHAKE, s->mykex, sizeof(sptps_kex_t));
}

static size_t sigmsg_len(size_t labellen) {
	return 1 + 2 * sizeof(sptps_kex_t) + labellen;
}

static void fill_msg(uint8_t *msg, bool initiator, const sptps_kex_t *kex0, const sptps_kex_t *kex1, const sptps_t *s) {
	*msg = initiator, msg++;
	memcpy(msg, kex0, sizeof(*kex0)), msg += sizeof(*kex0);
	memcpy(msg, kex1, sizeof(*kex1)), msg += sizeof(*kex1);
	memcpy(msg, s->label, s->labellen);
}

// Send a SIGnature record, containing an Ed25519 signature over both KEX records.
static bool send_sig(sptps_t *s) {
	// Concatenate both KEX messages, plus tag indicating if it is from the connection originator, plus label
	size_t msglen = sigmsg_len(s->labellen);
	uint8_t *msg = alloca(msglen);
	fill_msg(msg, s->initiator, s->mykex, s->hiskex, s);

	// Sign the result.
	size_t siglen = ecdsa_size(s->mykey);
	uint8_t *sig = alloca(siglen);

	if(!ecdsa_sign(s->mykey, msg, msglen, sig)) {
		return error(s, EINVAL, "Failed to sign SIG record");
	}

	// Send the SIG exchange record.
	return send_record_priv(s, SPTPS_HANDSHAKE, sig, siglen);
}

// Generate key material from the shared secret created from the ECDHE key exchange.
static bool generate_key_material(sptps_t *s, const uint8_t *shared, size_t len) {
	// Allocate memory for key material
	s->key = new_sptps_key();

	// Create the HMAC seed, which is "key expansion" + session label + server nonce + client nonce
	const size_t msglen = sizeof("key expansion") - 1;
	const size_t seedlen = msglen + s->labellen + ECDH_SIZE * 2;
	uint8_t *seed = alloca(seedlen);

	uint8_t *ptr = seed;
	memcpy(ptr, "key expansion", msglen);
	ptr += msglen;

	memcpy(ptr, (s->initiator ? s->mykex : s->hiskex)->nonce, ECDH_SIZE);
	ptr += ECDH_SIZE;

	memcpy(ptr, (s->initiator ? s->hiskex : s->mykex)->nonce, ECDH_SIZE);
	ptr += ECDH_SIZE;

	memcpy(ptr, s->label, s->labellen);

	// Use PRF to generate the key material
	if(!prf(shared, len, seed, seedlen, s->key->both, sizeof(sptps_key_t))) {
		return error(s, EINVAL, "Failed to generate key material");
	}

	return true;
}

// Send an ACKnowledgement record.
static bool send_ack(sptps_t *s) {
	return send_record_priv(s, SPTPS_HANDSHAKE, "", 0);
}

// Receive an ACKnowledgement record.
static bool receive_ack(sptps_t *s, const uint8_t *data, uint16_t len) {
	(void)data;

	if(len) {
		return error(s, EIO, "Invalid ACK record length");
	}

	if(!cipher_init(s->cipher_suite, &s->incipher, s->key, s->initiator)) {
		return error(s, EINVAL, "Failed to initialize cipher");
	}

	free_sptps_key(s->key);
	s->key = NULL;
	s->instate = true;

	return true;
}

static uint8_t select_cipher_suite(uint16_t mask, uint8_t pref1, uint8_t pref2) {
	// Check if there is a viable preference, if so select the lowest one
	uint8_t selection = 255;

	if(mask & (1U << pref1)) {
		selection = pref1;
	}

	if(pref2 < selection && (mask & (1U << pref2))) {
		selection = pref2;
	}

	// Otherwise, select the lowest cipher suite both sides support
	if(selection == 255) {
		selection = 0;

		while(!(mask & 1U)) {
			selection++;
			mask >>= 1;
		}
	}

	return selection;
}

// Receive a Key EXchange record, respond by sending a SIG record.
static bool receive_kex(sptps_t *s, const uint8_t *data, uint16_t len) {
	// Verify length of the HELLO record

	if(len != sizeof(sptps_kex_t)) {
		return error(s, EIO, "Invalid KEX record length");
	}

	if(*data != SPTPS_VERSION) {
		return error(s, EINVAL, "Received incorrect version %d", *data);
	}

	uint16_t suites;
	memcpy(&suites, data + 2, 2);
	suites &= s->cipher_suites;

	if(!suites) {
		return error(s, EIO, "No matching cipher suites");
	}

	s->cipher_suite = select_cipher_suite(suites, s->preferred_suite, data[1] & 0xf);

	// Make a copy of the KEX message, send_sig() and receive_sig() need it
	if(s->hiskex) {
		return error(s, EINVAL, "Received a second KEX message before first has been processed");
	}

	s->hiskex = new_sptps_kex();
	memcpy(s->hiskex, data, sizeof(sptps_kex_t));

	if(s->initiator) {
		return send_sig(s);
	} else {
		return true;
	}
}

// Receive a SIGnature record, verify it, if it passed, compute the shared secret and calculate the session keys.
static bool receive_sig(sptps_t *s, const uint8_t *data, uint16_t len) {
	// Verify length of KEX record.
	if(len != ecdsa_size(s->hiskey)) {
		return error(s, EIO, "Invalid KEX record length");
	}

	// Concatenate both KEX messages, plus tag indicating if it is from the connection originator
	const size_t msglen = sigmsg_len(s->labellen);
	uint8_t *msg = alloca(msglen);
	fill_msg(msg, !s->initiator, s->hiskex, s->mykex, s);

	// Verify signature.
	if(!ecdsa_verify(s->hiskey, msg, msglen, data)) {
		return error(s, EIO, "Failed to verify SIG record");
	}

	// Compute shared secret.
	uint8_t shared[ECDH_SHARED_SIZE];

	if(!ecdh_compute_shared(s->ecdh, s->hiskex->pubkey, shared)) {
		memzero(shared, sizeof(shared));
		return error(s, EINVAL, "Failed to compute ECDH shared secret");
	}

	s->ecdh = NULL;

	// Generate key material from shared secret.
	bool generated = generate_key_material(s, shared, sizeof(shared));
	memzero(shared, sizeof(shared));

	if(!generated) {
		return false;
	}

	if(!s->initiator && !send_sig(s)) {
		return false;
	}

	free_sptps_kex(s->mykex);
	s->mykex = NULL;

	free_sptps_kex(s->hiskex);
	s->hiskex = NULL;

	// Send cipher change record
	if(s->outstate && !send_ack(s)) {
		return false;
	}

	if(!cipher_init(s->cipher_suite, &s->outcipher, s->key, !s->initiator)) {
		return error(s, EINVAL, "Failed to initialize cipher");
	}

	return true;
}

// Force another Key EXchange (for testing purposes).
bool sptps_force_kex(sptps_t *s) {
	if(!s->outstate || s->state != SPTPS_SECONDARY_KEX) {
		return error(s, EINVAL, "Cannot force KEX in current state");
	}

	s->state = SPTPS_KEX;
	return send_kex(s);
}

// Receive a handshake record.
static bool receive_handshake(sptps_t *s, const uint8_t *data, uint16_t len) {
	// Only a few states to deal with handshaking.
	switch(s->state) {
	case SPTPS_SECONDARY_KEX:

		// We receive a secondary KEX request, first respond by sending our own.
		if(!send_kex(s)) {
			return false;
		}

	// Fall through
	case SPTPS_KEX:

		// We have sent our KEX request, we expect our peer to sent one as well.
		if(!receive_kex(s, data, len)) {
			return false;
		}

		s->state = SPTPS_SIG;
		return true;

	case SPTPS_SIG:

		// If we already sent our secondary public ECDH key, we expect the peer to send his.
		if(!receive_sig(s, data, len)) {
			return false;
		}

		if(s->outstate) {
			s->state = SPTPS_ACK;
		} else {
			s->outstate = true;

			if(!receive_ack(s, NULL, 0)) {
				return false;
			}

			s->receive_record(s->handle, SPTPS_HANDSHAKE, NULL, 0);
			s->state = SPTPS_SECONDARY_KEX;
		}

		return true;

	case SPTPS_ACK:

		// We expect a handshake message to indicate transition to the new keys.
		if(!receive_ack(s, data, len)) {
			return false;
		}

		s->receive_record(s->handle, SPTPS_HANDSHAKE, NULL, 0);
		s->state = SPTPS_SECONDARY_KEX;
		return true;

	// TODO: split ACK into a VERify and ACK?
	default:
		return error(s, EIO, "Invalid session state %d", s->state);
	}
}

static bool sptps_check_seqno(sptps_t *s, uint32_t seqno, bool update_state) {
	// Replay protection using a sliding window of configurable size.
	// s->inseqno is expected sequence number
	// seqno is received sequence number
	// s->late[] is a circular buffer, a 1 bit means a packet has not been received yet
	// The circular buffer contains bits for sequence numbers from s->inseqno - s->replaywin * 8 to (but excluding) s->inseqno.
	if(s->replaywin) {
		if(seqno != s->inseqno) {
			if(seqno >= s->inseqno + s->replaywin * 8) {
				// Prevent packets that jump far ahead of the queue from causing many others to be dropped.
				bool farfuture = s->farfuture < s->replaywin >> 2;

				if(update_state) {
					s->farfuture++;
				}

				if(farfuture) {
					return update_state ? error(s, EIO, "Packet is %d seqs in the future, dropped (%u)\n", seqno - s->inseqno, s->farfuture) : false;
				}

				// Unless we have seen lots of them, in which case we consider the others lost.
				if(update_state) {
					warning(s, "Lost %d packets\n", seqno - s->inseqno);
				}

				if(update_state) {
					// Mark all packets in the replay window as being late.
					memset(s->late, 255, s->replaywin);
				}
			} else if(seqno < s->inseqno) {
				// If the sequence number is farther in the past than the bitmap goes, or if the packet was already received, drop it.
				if((s->inseqno >= s->replaywin * 8 && seqno < s->inseqno - s->replaywin * 8) || !(s->late[(seqno / 8) % s->replaywin] & (1 << seqno % 8))) {
					return update_state ? error(s, EIO, "Received late or replayed packet, seqno %d, last received %d\n", seqno, s->inseqno) : false;
				}
			} else if(update_state) {
				// We missed some packets. Mark them in the bitmap as being late.
				for(uint32_t i = s->inseqno; i < seqno; i++) {
					s->late[(i / 8) % s->replaywin] |= 1 << i % 8;
				}
			}
		}

		if(update_state) {
			// Mark the current packet as not being late.
			s->late[(seqno / 8) % s->replaywin] &= ~(1 << seqno % 8);
			s->farfuture = 0;
		}
	}

	if(update_state) {
		if(seqno >= s->inseqno) {
			s->inseqno = seqno + 1;
		}

		if(!s->inseqno) {
			s->received = 0;
		} else {
			s->received++;
		}
	}

	return true;
}

// Check datagram for valid HMAC
bool sptps_verify_datagram(sptps_t *s, const void *vdata, size_t len) {
	if(!s->instate || len < 21) {
		return error(s, EIO, "Received short packet");
	}

	const uint8_t *data = vdata;
	uint32_t seqno;
	memcpy(&seqno, data, 4);

	if(!sptps_check_seqno(s, seqno, false)) {
		return false;
	}

	uint8_t *buffer = alloca(len);
	return cipher_decrypt(s->cipher_suite, s->incipher, seqno, data + 4, len - 4, buffer, NULL);
}

// Receive incoming data, datagram version.
static bool sptps_receive_data_datagram(sptps_t *s, const uint8_t *data, size_t len) {
	if(len < (s->instate ? 21 : 5)) {
		return error(s, EIO, "Received short packet");
	}

	uint32_t seqno;
	memcpy(&seqno, data, 4);
	data += 4;
	len -= 4;

	if(!s->instate) {
		if(seqno != s->inseqno) {
			return error(s, EIO, "Invalid packet seqno: %d != %d", seqno, s->inseqno);
		}

		s->inseqno = seqno + 1;

		uint8_t type = *(data++);
		len--;

		if(type != SPTPS_HANDSHAKE) {
			return error(s, EIO, "Application record received before handshake finished");
		}

		return receive_handshake(s, data, len);
	}

	// Decrypt

	uint8_t *buffer = alloca(len);
	size_t outlen;

	if(!cipher_decrypt(s->cipher_suite, s->incipher, seqno, data, len, buffer, &outlen)) {
		return error(s, EIO, "Failed to decrypt and verify packet");
	}

	if(!sptps_check_seqno(s, seqno, true)) {
		return false;
	}

	// Append a NULL byte for safety.
	buffer[outlen] = 0;

	data = buffer;
	len = outlen;

	uint8_t type = *(data++);
	len--;

	if(type < SPTPS_HANDSHAKE) {
		if(!s->instate) {
			return error(s, EIO, "Application record received before handshake finished");
		}

		if(!s->receive_record(s->handle, type, data, len)) {
			return false;
		}
	} else if(type == SPTPS_HANDSHAKE) {
		if(!receive_handshake(s, data, len)) {
			return false;
		}
	} else {
		return error(s, EIO, "Invalid record type %d", type);
	}

	return true;
}

// Receive incoming data. Check if it contains a complete record, if so, handle it.
size_t sptps_receive_data(sptps_t *s, const void *vdata, size_t len) {
	const uint8_t *data = vdata;
	size_t total_read = 0;

	if(!s->state) {
		return error(s, EIO, "Invalid session state zero");
	}

	if(s->datagram) {
		return sptps_receive_data_datagram(s, data, len) ? len : false;
	}

	// First read the 2 length bytes.
	if(s->buflen < 2) {
		size_t toread = 2 - s->buflen;

		if(toread > len) {
			toread = len;
		}

		memcpy(s->inbuf + s->buflen, data, toread);

		total_read += toread;
		s->buflen += toread;
		len -= toread;
		data += toread;

		// Exit early if we don't have the full length.
		if(s->buflen < 2) {
			return total_read;
		}

		// Get the length bytes

		memcpy(&s->reclen, s->inbuf, 2);

		// If we have the length bytes, ensure our buffer can hold the whole request.
		s->inbuf = realloc(s->inbuf, s->reclen + SPTPS_OVERHEAD);

		if(!s->inbuf) {
			return error(s, errno, "%s", strerror(errno));
		}

		// Exit early if we have no more data to process.
		if(!len) {
			return total_read;
		}
	}

	// Read up to the end of the record.
	size_t toread = s->reclen + (s->instate ? SPTPS_OVERHEAD : SPTPS_HEADER) - s->buflen;

	if(toread > len) {
		toread = len;
	}

	memcpy(s->inbuf + s->buflen, data, toread);
	total_read += toread;
	s->buflen += toread;

	// If we don't have a whole record, exit.
	if(s->buflen < s->reclen + (s->instate ? SPTPS_OVERHEAD : SPTPS_HEADER)) {
		return total_read;
	}

	// Update sequence number.

	uint32_t seqno = s->inseqno++;

	// Check HMAC and decrypt.
	if(s->instate) {
		if(!cipher_decrypt(s->cipher_suite, s->incipher, seqno, s->inbuf + 2UL, s->reclen + 17UL, s->inbuf + 2UL, NULL)) {
			return error(s, EINVAL, "Failed to decrypt and verify record");
		}
	}

	// Append a NULL byte for safety.
	s->inbuf[s->reclen + SPTPS_HEADER] = 0;

	uint8_t type = s->inbuf[2];

	if(type < SPTPS_HANDSHAKE) {
		if(!s->instate) {
			return error(s, EIO, "Application record received before handshake finished");
		}

		if(!s->receive_record(s->handle, type, s->inbuf + 3, s->reclen)) {
			return false;
		}
	} else if(type == SPTPS_HANDSHAKE) {
		if(!receive_handshake(s, s->inbuf + 3, s->reclen)) {
			return false;
		}
	} else {
		return error(s, EIO, "Invalid record type %d", type);
	}

	s->buflen = 0;

	return total_read;
}

// Start a SPTPS session.
bool sptps_start(sptps_t *s, const sptps_params_t *params) {
	// Initialise struct sptps
	memset(s, 0, sizeof(*s));

	s->handle = params->handle;
	s->initiator = params->initiator;
	s->datagram = params->datagram;
	s->mykey = params->mykey;
	s->hiskey = params->hiskey;
	s->replaywin = sptps_replaywin;
	s->cipher_suites = params->cipher_suites ? params->cipher_suites & SPTPS_ALL_CIPHER_SUITES : SPTPS_ALL_CIPHER_SUITES;
	s->preferred_suite = params->preferred_suite;

	if(s->replaywin) {
		s->late = malloc(s->replaywin);

		if(!s->late) {
			return error(s, errno, "%s", strerror(errno));
		}

		memset(s->late, 0, s->replaywin);
	}

	s->labellen = params->labellen ? params->labellen : strlen(params->label);
	s->label = malloc(s->labellen);

	if(!s->label) {
		return error(s, errno, "%s", strerror(errno));
	}

	memcpy(s->label, params->label, s->labellen);

	if(!s->datagram) {
		s->inbuf = malloc(7);

		if(!s->inbuf) {
			return error(s, errno, "%s", strerror(errno));
		}

		s->buflen = 0;
	}


	s->send_data = params->send_data;
	s->receive_record = params->receive_record;

	// Do first KEX immediately
	s->state = SPTPS_KEX;
	return send_kex(s);
}

// Stop a SPTPS session.
bool sptps_stop(sptps_t *s) {
	// Clean up any resources.
	cipher_exit(s->cipher_suite, s->incipher);
	cipher_exit(s->cipher_suite, s->outcipher);
	ecdh_free(s->ecdh);
	free(s->inbuf);
	free_sptps_kex(s->mykex);
	free_sptps_kex(s->hiskex);
	free_sptps_key(s->key);
	free(s->label);
	free(s->late);
	memset(s, 0, sizeof(*s));
	return true;
}
