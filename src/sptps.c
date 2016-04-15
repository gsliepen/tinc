/*
    sptps.c -- Simple Peer-to-Peer Security
    Copyright (C) 2011-2015 Guus Sliepen <guus@tinc-vpn.org>,
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

#include "chacha-poly1305/chacha-poly1305.h"
#include "crypto.h"
#include "ecdh.h"
#include "ecdsa.h"
#include "logger.h"
#include "prf.h"
#include "sptps.h"

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
}

void sptps_log_stderr(sptps_t *s, int s_errno, const char *format, va_list ap) {
	vfprintf(stderr, format, ap);
	fputc('\n', stderr);
}

void (*sptps_log)(sptps_t *s, int s_errno, const char *format, va_list ap) = sptps_log_stderr;

// Log an error message.
static bool error(sptps_t *s, int s_errno, const char *format, ...) {
	if(format) {
		va_list ap;
		va_start(ap, format);
		sptps_log(s, s_errno, format, ap);
		va_end(ap);
	}

	errno = s_errno;
	return false;
}

static void warning(sptps_t *s, const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	sptps_log(s, 0, format, ap);
	va_end(ap);
}

// Send a record (datagram version, accepts all record types, handles encryption and authentication).
static bool send_record_priv_datagram(sptps_t *s, uint8_t type, const void *data, uint16_t len) {
	char buffer[len + 21UL];

	// Create header with sequence number, length and record type
	uint32_t seqno = s->outseqno++;
	uint32_t netseqno = ntohl(seqno);

	memcpy(buffer, &netseqno, 4);
	buffer[4] = type;
	memcpy(buffer + 5, data, len);

	if(s->outstate) {
		// If first handshake has finished, encrypt and HMAC
		chacha_poly1305_encrypt(s->outcipher, seqno, buffer + 4, len + 1, buffer + 4, NULL);
		return s->send_data(s->handle, type, buffer, len + 21UL);
	} else {
		// Otherwise send as plaintext
		return s->send_data(s->handle, type, buffer, len + 5UL);
	}
}
// Send a record (private version, accepts all record types, handles encryption and authentication).
static bool send_record_priv(sptps_t *s, uint8_t type, const void *data, uint16_t len) {
	if(s->datagram)
		return send_record_priv_datagram(s, type, data, len);

	char buffer[len + 19UL];

	// Create header with sequence number, length and record type
	uint32_t seqno = s->outseqno++;
	uint16_t netlen = htons(len);

	memcpy(buffer, &netlen, 2);
	buffer[2] = type;
	memcpy(buffer + 3, data, len);

	if(s->outstate) {
		// If first handshake has finished, encrypt and HMAC
		chacha_poly1305_encrypt(s->outcipher, seqno, buffer + 2, len + 1, buffer + 2, NULL);
		return s->send_data(s->handle, type, buffer, len + 19UL);
	} else {
		// Otherwise send as plaintext
		return s->send_data(s->handle, type, buffer, len + 3UL);
	}
}

// Send an application record.
bool sptps_send_record(sptps_t *s, uint8_t type, const void *data, uint16_t len) {
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
	if(s->mykex)
		return false;
	s->mykex = realloc(s->mykex, 1 + 32 + keylen);
	if(!s->mykex)
		return error(s, errno, strerror(errno));

	// Set version byte to zero.
	s->mykex[0] = SPTPS_VERSION;

	// Create a random nonce.
	randomize(s->mykex + 1, 32);

	// Create a new ECDH public key.
	if(!(s->ecdh = ecdh_generate_public(s->mykex + 1 + 32)))
		return error(s, EINVAL, "Failed to generate ECDH public key");

	return send_record_priv(s, SPTPS_HANDSHAKE, s->mykex, 1 + 32 + keylen);
}

// Send a SIGnature record, containing an Ed25519 signature over both KEX records.
static bool send_sig(sptps_t *s) {
	size_t keylen = ECDH_SIZE;
	size_t siglen = ecdsa_size(s->mykey);

	// Concatenate both KEX messages, plus tag indicating if it is from the connection originator, plus label
	char msg[(1 + 32 + keylen) * 2 + 1 + s->labellen];
	char sig[siglen];

	msg[0] = s->initiator;
	memcpy(msg + 1, s->mykex, 1 + 32 + keylen);
	memcpy(msg + 1 + 33 + keylen, s->hiskex, 1 + 32 + keylen);
	memcpy(msg + 1 + 2 * (33 + keylen), s->label, s->labellen);

	// Sign the result.
	if(!ecdsa_sign(s->mykey, msg, sizeof msg, sig))
		return error(s, EINVAL, "Failed to sign SIG record");

	// Send the SIG exchange record.
	return send_record_priv(s, SPTPS_HANDSHAKE, sig, sizeof sig);
}

// Generate key material from the shared secret created from the ECDHE key exchange.
static bool generate_key_material(sptps_t *s, const char *shared, size_t len) {
	// Initialise cipher and digest structures if necessary
	if(!s->outstate) {
		s->incipher = chacha_poly1305_init();
		s->outcipher = chacha_poly1305_init();
		if(!s->incipher || !s->outcipher)
			return error(s, EINVAL, "Failed to open cipher");
	}

	// Allocate memory for key material
	size_t keylen = 2 * CHACHA_POLY1305_KEYLEN;

	s->key = realloc(s->key, keylen);
	if(!s->key)
		return error(s, errno, strerror(errno));

	// Create the HMAC seed, which is "key expansion" + session label + server nonce + client nonce
	char seed[s->labellen + 64 + 13];
	memcpy(seed, "key expansion", 13);
	if(s->initiator) {
		memcpy(seed + 13, s->mykex + 1, 32);
		memcpy(seed + 45, s->hiskex + 1, 32);
	} else {
		memcpy(seed + 13, s->hiskex + 1, 32);
		memcpy(seed + 45, s->mykex + 1, 32);
	}
	memcpy(seed + 77, s->label, s->labellen);

	// Use PRF to generate the key material
	if(!prf(shared, len, seed, s->labellen + 64 + 13, s->key, keylen))
		return error(s, EINVAL, "Failed to generate key material");

	return true;
}

// Send an ACKnowledgement record.
static bool send_ack(sptps_t *s) {
	return send_record_priv(s, SPTPS_HANDSHAKE, "", 0);
}

// Receive an ACKnowledgement record.
static bool receive_ack(sptps_t *s, const char *data, uint16_t len) {
	if(len)
		return error(s, EIO, "Invalid ACK record length");

	if(s->initiator) {
		if(!chacha_poly1305_set_key(s->incipher, s->key))
			return error(s, EINVAL, "Failed to set counter");
	} else {
		if(!chacha_poly1305_set_key(s->incipher, s->key + CHACHA_POLY1305_KEYLEN))
			return error(s, EINVAL, "Failed to set counter");
	}

	free(s->key);
	s->key = NULL;
	s->instate = true;

	return true;
}

// Receive a Key EXchange record, respond by sending a SIG record.
static bool receive_kex(sptps_t *s, const char *data, uint16_t len) {
	// Verify length of the HELLO record
	if(len != 1 + 32 + ECDH_SIZE)
		return error(s, EIO, "Invalid KEX record length");

	// Ignore version number for now.

	// Make a copy of the KEX message, send_sig() and receive_sig() need it
	if(s->hiskex)
		return error(s, EINVAL, "Received a second KEX message before first has been processed");
	s->hiskex = realloc(s->hiskex, len);
	if(!s->hiskex)
		return error(s, errno, strerror(errno));

	memcpy(s->hiskex, data, len);

	return send_sig(s);
}

// Receive a SIGnature record, verify it, if it passed, compute the shared secret and calculate the session keys.
static bool receive_sig(sptps_t *s, const char *data, uint16_t len) {
	size_t keylen = ECDH_SIZE;
	size_t siglen = ecdsa_size(s->hiskey);

	// Verify length of KEX record.
	if(len != siglen)
		return error(s, EIO, "Invalid KEX record length");

	// Concatenate both KEX messages, plus tag indicating if it is from the connection originator
	char msg[(1 + 32 + keylen) * 2 + 1 + s->labellen];

	msg[0] = !s->initiator;
	memcpy(msg + 1, s->hiskex, 1 + 32 + keylen);
	memcpy(msg + 1 + 33 + keylen, s->mykex, 1 + 32 + keylen);
	memcpy(msg + 1 + 2 * (33 + keylen), s->label, s->labellen);

	// Verify signature.
	if(!ecdsa_verify(s->hiskey, msg, sizeof msg, data))
		return error(s, EIO, "Failed to verify SIG record");

	// Compute shared secret.
	char shared[ECDH_SHARED_SIZE];
	if(!ecdh_compute_shared(s->ecdh, s->hiskex + 1 + 32, shared))
		return error(s, EINVAL, "Failed to compute ECDH shared secret");
	s->ecdh = NULL;

	// Generate key material from shared secret.
	if(!generate_key_material(s, shared, sizeof shared))
		return false;

	free(s->mykex);
	free(s->hiskex);

	s->mykex = NULL;
	s->hiskex = NULL;

	// Send cipher change record
	if(s->outstate && !send_ack(s))
		return false;

	// TODO: only set new keys after ACK has been set/received
	if(s->initiator) {
		if(!chacha_poly1305_set_key(s->outcipher, s->key + CHACHA_POLY1305_KEYLEN))
			return error(s, EINVAL, "Failed to set key");
	} else {
		if(!chacha_poly1305_set_key(s->outcipher, s->key))
			return error(s, EINVAL, "Failed to set key");
	}

	return true;
}

// Force another Key EXchange (for testing purposes).
bool sptps_force_kex(sptps_t *s) {
	if(!s->outstate || s->state != SPTPS_SECONDARY_KEX)
		return error(s, EINVAL, "Cannot force KEX in current state");

	s->state = SPTPS_KEX;
	return send_kex(s);
}

// Receive a handshake record.
static bool receive_handshake(sptps_t *s, const char *data, uint16_t len) {
	// Only a few states to deal with handshaking.
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
			if(s->outstate)
				s->state = SPTPS_ACK;
			else {
				s->outstate = true;
				if(!receive_ack(s, NULL, 0))
					return false;
				s->receive_record(s->handle, SPTPS_HANDSHAKE, NULL, 0);
				s->state = SPTPS_SECONDARY_KEX;
			}

			return true;
		case SPTPS_ACK:
			// We expect a handshake message to indicate transition to the new keys.
			if(!receive_ack(s, data, len))
				return false;
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
				if (update_state)
					s->farfuture++;
				if(farfuture)
					return update_state ? error(s, EIO, "Packet is %d seqs in the future, dropped (%u)\n", seqno - s->inseqno, s->farfuture) : false;

				// Unless we have seen lots of them, in which case we consider the others lost.
				if(update_state)
					warning(s, "Lost %d packets\n", seqno - s->inseqno);
				if (update_state) {
					// Mark all packets in the replay window as being late.
					memset(s->late, 255, s->replaywin);
				}
			} else if (seqno < s->inseqno) {
				// If the sequence number is farther in the past than the bitmap goes, or if the packet was already received, drop it.
				if((s->inseqno >= s->replaywin * 8 && seqno < s->inseqno - s->replaywin * 8) || !(s->late[(seqno / 8) % s->replaywin] & (1 << seqno % 8)))
					return update_state ? error(s, EIO, "Received late or replayed packet, seqno %d, last received %d\n", seqno, s->inseqno) : false;
			} else if (update_state) {
				// We missed some packets. Mark them in the bitmap as being late.
				for(int i = s->inseqno; i < seqno; i++)
					s->late[(i / 8) % s->replaywin] |= 1 << i % 8;
			}
		}

		if (update_state) {
			// Mark the current packet as not being late.
			s->late[(seqno / 8) % s->replaywin] &= ~(1 << seqno % 8);
			s->farfuture = 0;
		}
	}

	if (update_state) {
		if(seqno >= s->inseqno)
			s->inseqno = seqno + 1;

		if(!s->inseqno)
			s->received = 0;
		else
			s->received++;
	}

	return true;
}

// Check datagram for valid HMAC
bool sptps_verify_datagram(sptps_t *s, const void *data, size_t len) {
	if(!s->instate || len < 21)
		return error(s, EIO, "Received short packet");

	uint32_t seqno;
	memcpy(&seqno, data, 4);
	seqno = ntohl(seqno);
	if (!sptps_check_seqno(s, seqno, false))
		return false;

	char buffer[len];
	size_t outlen;
	return chacha_poly1305_decrypt(s->incipher, seqno, data + 4, len - 4, buffer, &outlen);
}

// Receive incoming data, datagram version.
static bool sptps_receive_data_datagram(sptps_t *s, const char *data, size_t len) {
	if(len < (s->instate ? 21 : 5))
		return error(s, EIO, "Received short packet");

	uint32_t seqno;
	memcpy(&seqno, data, 4);
	seqno = ntohl(seqno);
	data += 4; len -= 4;

	if(!s->instate) {
		if(seqno != s->inseqno)
			return error(s, EIO, "Invalid packet seqno: %d != %d", seqno, s->inseqno);

		s->inseqno = seqno + 1;

		uint8_t type = *(data++); len--;

		if(type != SPTPS_HANDSHAKE)
			return error(s, EIO, "Application record received before handshake finished");

		return receive_handshake(s, data, len);
	}

	// Decrypt

	char buffer[len];
	size_t outlen;
	if(!chacha_poly1305_decrypt(s->incipher, seqno, data, len, buffer, &outlen))
		return error(s, EIO, "Failed to decrypt and verify packet");

	if(!sptps_check_seqno(s, seqno, true))
		return false;

	// Append a NULL byte for safety.
	buffer[outlen] = 0;

	data = buffer;
	len = outlen;

	uint8_t type = *(data++); len--;

	if(type < SPTPS_HANDSHAKE) {
		if(!s->instate)
			return error(s, EIO, "Application record received before handshake finished");
		if(!s->receive_record(s->handle, type, data, len))
			return false;
	} else if(type == SPTPS_HANDSHAKE) {
		if(!receive_handshake(s, data, len))
			return false;
	} else {
		return error(s, EIO, "Invalid record type %d", type);
	}

	return true;
}

// Receive incoming data. Check if it contains a complete record, if so, handle it.
size_t sptps_receive_data(sptps_t *s, const void *data, size_t len) {
	size_t total_read = 0;

	if(!s->state)
		return error(s, EIO, "Invalid session state zero");

	if(s->datagram)
		return sptps_receive_data_datagram(s, data, len) ? len : false;

	// First read the 2 length bytes.
	if(s->buflen < 2) {
		size_t toread = 2 - s->buflen;
		if(toread > len)
			toread = len;

		memcpy(s->inbuf + s->buflen, data, toread);

		total_read += toread;
		s->buflen += toread;
		len -= toread;
		data += toread;

		// Exit early if we don't have the full length.
		if(s->buflen < 2)
			return total_read;

		// Get the length bytes

		memcpy(&s->reclen, s->inbuf, 2);
		s->reclen = ntohs(s->reclen);

		// If we have the length bytes, ensure our buffer can hold the whole request.
		s->inbuf = realloc(s->inbuf, s->reclen + 19UL);
		if(!s->inbuf)
			return error(s, errno, strerror(errno));

		// Exit early if we have no more data to process.
		if(!len)
			return total_read;
	}

	// Read up to the end of the record.
	size_t toread = s->reclen + (s->instate ? 19UL : 3UL) - s->buflen;
	if(toread > len)
		toread = len;

	memcpy(s->inbuf + s->buflen, data, toread);
	total_read += toread;
	s->buflen += toread;
	len -= toread;
	data += toread;

	// If we don't have a whole record, exit.
	if(s->buflen < s->reclen + (s->instate ? 19UL : 3UL))
		return total_read;

	// Update sequence number.

	uint32_t seqno = s->inseqno++;

	// Check HMAC and decrypt.
	if(s->instate) {
		if(!chacha_poly1305_decrypt(s->incipher, seqno, s->inbuf + 2UL, s->reclen + 17UL, s->inbuf + 2UL, NULL))
			return error(s, EINVAL, "Failed to decrypt and verify record");
	}

	// Append a NULL byte for safety.
	s->inbuf[s->reclen + 3UL] = 0;

	uint8_t type = s->inbuf[2];

	if(type < SPTPS_HANDSHAKE) {
		if(!s->instate)
			return error(s, EIO, "Application record received before handshake finished");
		if(!s->receive_record(s->handle, type, s->inbuf + 3, s->reclen))
			return false;
	} else if(type == SPTPS_HANDSHAKE) {
		if(!receive_handshake(s, s->inbuf + 3, s->reclen))
			return false;
	} else {
		return error(s, EIO, "Invalid record type %d", type);
	}

	s->buflen = 0;

	return total_read;
}

// Start a SPTPS session.
bool sptps_start(sptps_t *s, void *handle, bool initiator, bool datagram, ecdsa_t *mykey, ecdsa_t *hiskey, const void *label, size_t labellen, send_data_t send_data, receive_record_t receive_record) {
	// Initialise struct sptps
	memset(s, 0, sizeof *s);

	s->handle = handle;
	s->initiator = initiator;
	s->datagram = datagram;
	s->mykey = mykey;
	s->hiskey = hiskey;
	s->replaywin = sptps_replaywin;
	if(s->replaywin) {
		s->late = malloc(s->replaywin);
		if(!s->late)
			return error(s, errno, strerror(errno));
		memset(s->late, 0, s->replaywin);
	}

	s->label = malloc(labellen);
	if(!s->label)
		return error(s, errno, strerror(errno));

	if(!datagram) {
		s->inbuf = malloc(7);
		if(!s->inbuf)
			return error(s, errno, strerror(errno));
		s->buflen = 0;
	}

	memcpy(s->label, label, labellen);
	s->labellen = labellen;

	s->send_data = send_data;
	s->receive_record = receive_record;

	// Do first KEX immediately
	s->state = SPTPS_KEX;
	return send_kex(s);
}

// Stop a SPTPS session.
bool sptps_stop(sptps_t *s) {
	// Clean up any resources.
	chacha_poly1305_exit(s->incipher);
	chacha_poly1305_exit(s->outcipher);
	ecdh_free(s->ecdh);
	free(s->inbuf);
	free(s->mykex);
	free(s->hiskex);
	free(s->key);
	free(s->label);
	free(s->late);
	memset(s, 0, sizeof *s);
	return true;
}
