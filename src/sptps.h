/*
    sptps.h -- Simple Peer-to-Peer Security
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
#include "digest.h"
#include "ecdh.h"
#include "ecdsa.h"

#define STATE_FIRST_KEX 0 // Waiting for peer's ECDHE pubkey
#define STATE_NORMAL 1
#define STATE_WAIT_KEX 2 // Waiting for peer's ECDHE pubkey
#define STATE_WAIT_ACK 3 // Waiting for peer's acknowledgement of pubkey reception

typedef bool (*send_data_t)(void *handle, const char *data, size_t len);
typedef bool (*receive_record_t)(void *handle, uint8_t type, const char *data, uint16_t len);

typedef struct sptps {
	bool initiator;
	int state;

	char *inbuf;
	size_t buflen;

	cipher_t incipher;
	digest_t indigest;
	uint32_t inseqno;

	cipher_t outcipher;
	digest_t outdigest;
	uint32_t outseqno;

	ecdsa_t mykey;
	ecdsa_t hiskey;
	ecdh_t ecdh;

	char *myrandom;
	char *key;
	char *label;
	size_t labellen;

	void *handle;
	send_data_t send_data;
	receive_record_t receive_record;
} sptps_t;

extern bool start_sptps(sptps_t *s, void *handle, bool initiator, ecdsa_t mykey, ecdsa_t hiskey, const char *label, size_t labellen, send_data_t send_data, receive_record_t receive_record);
extern bool stop_sptps(sptps_t *s);
extern bool send_record(sptps_t *s, uint8_t type, const char *data, uint16_t len);
extern bool receive_data(sptps_t *s, const char *data, size_t len);
