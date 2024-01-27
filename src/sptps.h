#ifndef TINC_SPTPS_H
#define TINC_SPTPS_H

/*
    sptps.h -- Simple Peer-to-Peer Security
    Copyright (C) 2011-2021 Guus Sliepen <guus@tinc-vpn.org>

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

#define SPTPS_VERSION 1

// Record types
#define SPTPS_HANDSHAKE 128   // Key exchange and authentication
#define SPTPS_ALERT 129       // Warning or error messages
#define SPTPS_CLOSE 130       // Application closed the connection

// Overhead for datagrams
static const size_t SPTPS_OVERHEAD = 19;
static const size_t SPTPS_HEADER = 3;
static const size_t SPTPS_DATAGRAM_OVERHEAD = 21;
static const size_t SPTPS_DATAGRAM_HEADER = 5;

typedef bool (*send_data_t)(void *handle, uint8_t type, const void *data, size_t len);
typedef bool (*receive_record_t)(void *handle, uint8_t type, const void *data, uint16_t len);

// Key exchange states
typedef enum sptps_state_t {
	SPTPS_KEX = 1,           // Waiting for the first Key EXchange record
	SPTPS_SECONDARY_KEX = 2, // Ready to receive a secondary Key EXchange record
	SPTPS_SIG = 3,           // Waiting for a SIGnature record
	SPTPS_ACK = 4,           // Waiting for an ACKnowledgement record
} sptps_state_t;

PACKED(struct sptps_kex_t {
	uint8_t version;
	uint8_t preferred_suite;
	uint16_t cipher_suites;
	uint8_t nonce[ECDH_SIZE];
	uint8_t pubkey[ECDH_SIZE];
});

typedef struct sptps_kex_t sptps_kex_t;

STATIC_ASSERT(sizeof(sptps_kex_t) == 68, "sptps_kex_t has invalid size");

// Big enough to handle a 256 bit key + IV
#define SPTPS_KEYLEN 64

typedef union sptps_key_t {
	struct {
		uint8_t key0[SPTPS_KEYLEN];
		uint8_t key1[SPTPS_KEYLEN];
	};
	uint8_t both[SPTPS_KEYLEN * 2];
} sptps_key_t;

STATIC_ASSERT(sizeof(sptps_key_t) == 128, "sptps_key_t has invalid size");

// Public key suites
enum {
	SPTPS_ED25519 = 0,
};

// Cipher suites
enum {
	SPTPS_CHACHA_POLY1305 = 0,
	SPTPS_AES256_GCM = 1,
	SPTPS_ALL_CIPHER_SUITES = 0x3,
};

typedef struct sptps_params {
	void *handle;
	bool initiator;
	bool datagram;
	uint8_t preferred_suite;
	uint16_t cipher_suites;
	ecdsa_t *mykey;
	ecdsa_t *hiskey;
	const void *label;
	size_t labellen;
	send_data_t send_data;
	receive_record_t receive_record;
} sptps_params_t;

typedef struct sptps {
	bool initiator;
	bool datagram;
	uint8_t preferred_suite;
	uint16_t cipher_suites;

	uint8_t pk_suite;
	uint8_t cipher_suite;
	sptps_state_t state;

	uint8_t *inbuf;
	size_t buflen;
	uint16_t reclen;

	bool instate;
	void *incipher;
	uint32_t inseqno;
	uint32_t received;
	unsigned int replaywin;
	unsigned int farfuture;
	uint8_t *late;

	bool outstate;
	void *outcipher;
	uint32_t outseqno;

	ecdsa_t *mykey;
	ecdsa_t *hiskey;
	ecdh_t *ecdh;

	sptps_kex_t *mykex;
	sptps_kex_t *hiskex;
	sptps_key_t *key;
	uint8_t *label;
	size_t labellen;

	void *handle;
	send_data_t send_data;
	receive_record_t receive_record;
} sptps_t;

extern unsigned int sptps_replaywin;
extern void sptps_log_quiet(sptps_t *s, int s_errno, const char *format, va_list ap) ATTR_FORMAT(printf, 3, 0);
extern void sptps_log_stderr(sptps_t *s, int s_errno, const char *format, va_list ap) ATTR_FORMAT(printf, 3, 0);
extern void (*sptps_log)(sptps_t *s, int s_errno, const char *format, va_list ap) ATTR_FORMAT(printf, 3, 0);
extern bool sptps_start(sptps_t *s, const struct sptps_params *params);
extern bool sptps_stop(sptps_t *s);
extern bool sptps_send_record(sptps_t *s, uint8_t type, const void *data, uint16_t len);
extern size_t sptps_receive_data(sptps_t *s, const void *data, size_t len);
extern bool sptps_force_kex(sptps_t *s);
extern bool sptps_verify_datagram(sptps_t *s, const void *data, size_t len);

#endif
