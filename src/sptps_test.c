/*
    sptps_test.c -- Simple Peer-to-Peer Security test program
    Copyright (C) 2011-2012 Guus Sliepen <guus@tinc-vpn.org>,

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

#include "crypto.h"
#include "ecdsa.h"
#include "sptps.h"
#include "utils.h"

// Symbols necessary to link with logger.o
bool send_request(void *c, const char *msg, ...) { return false; }
struct list_t *connection_list = NULL;
bool send_meta(void *c, const char *msg , int len) { return false; }
char *logfilename = NULL;
struct timeval now;

ecdsa_t mykey, hiskey;

static bool send_data(void *handle, uint8_t type, const char *data, size_t len) {
	char hex[len * 2 + 1];
	bin2hex(data, hex, len);
	fprintf(stderr, "Sending %d bytes of data:\n%s\n", (int)len, hex);
	const int *sock = handle;
	if(send(*sock, data, len, 0) != len)
		return false;
	return true;
}

static bool receive_record(void *handle, uint8_t type, const char *data, uint16_t len) {
	fprintf(stderr, "Received type %d record of %hu bytes:\n", type, len);
	fwrite(data, len, 1, stdout);
	return true;
}

int main(int argc, char *argv[]) {
	bool initiator = false;
	bool datagram = false;

	if(argc > 1 && !strcmp(argv[1], "-d")) {
		datagram = true;
		argc--;
		argv++;
	}

	if(argc < 4) {
		fprintf(stderr, "Usage: %s [-d] my_ecdsa_key_file his_ecdsa_key_file [host] port\n", argv[0]);
		return 1;
	}

	if(argc > 4)
		initiator = true;

#ifdef HAVE_MINGW
	static struct WSAData wsa_state;
	if(WSAStartup(MAKEWORD(2, 2), &wsa_state))
		return 1;
#endif

	struct addrinfo *ai, hint;
	memset(&hint, 0, sizeof hint);

	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = datagram ? SOCK_DGRAM : SOCK_STREAM;
	hint.ai_protocol = datagram ? IPPROTO_UDP : IPPROTO_TCP;
	hint.ai_flags = initiator ? 0 : AI_PASSIVE;

	if(getaddrinfo(initiator ? argv[3] : NULL, initiator ? argv[4] : argv[3], &hint, &ai) || !ai) {
		fprintf(stderr, "getaddrinfo() failed: %s\n", strerror(errno));
		return 1;
	}

	int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if(sock < 0) {
		fprintf(stderr, "Could not create socket: %s\n", strerror(errno));
		return 1;
	}

	int one = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof one);

	if(initiator) {
		if(connect(sock, ai->ai_addr, ai->ai_addrlen)) {
			fprintf(stderr, "Could not connect to peer: %s\n", strerror(errno));
			return 1;
		}
		fprintf(stderr, "Connected\n");
	} else {
		if(bind(sock, ai->ai_addr, ai->ai_addrlen)) {
			fprintf(stderr, "Could not bind socket: %s\n", strerror(errno));
			return 1;
		}

		if(!datagram) {
			if(listen(sock, 1)) {
				fprintf(stderr, "Could not listen on socket: %s\n", strerror(errno));
				return 1;
			}
			fprintf(stderr, "Listening...\n");

			sock = accept(sock, NULL, NULL);
			if(sock < 0) {
				fprintf(stderr, "Could not accept connection: %s\n", strerror(errno));
				return 1;
			}
		} else {
			fprintf(stderr, "Listening...\n");

			char buf[65536];
			struct sockaddr addr;
			socklen_t addrlen = sizeof addr;

			if(recvfrom(sock, buf, sizeof buf, MSG_PEEK, &addr, &addrlen) <= 0) {
				fprintf(stderr, "Could not read from socket: %s\n", strerror(errno));
				return 1;
			}

			if(connect(sock, &addr, addrlen)) {
				fprintf(stderr, "Could not accept connection: %s\n", strerror(errno));
				return 1;
			}
		}

		fprintf(stderr, "Connected\n");
	}

	crypto_init();

	FILE *fp = fopen(argv[1], "r");
	if(!ecdsa_read_pem_private_key(&mykey, fp))
		return 1;
	fclose(fp);

	fp = fopen(argv[2], "r");
	if(!ecdsa_read_pem_public_key(&hiskey, fp))
		return 1;
	fclose(fp);

	fprintf(stderr, "Keys loaded\n");

	sptps_t s;
	if(!sptps_start(&s, &sock, initiator, datagram, mykey, hiskey, "sptps_test", 10, send_data, receive_record))
		return 1;

	while(true) {
		char buf[65535] = "";

		fd_set fds;
		FD_ZERO(&fds);
#ifndef HAVE_MINGW
		FD_SET(0, &fds);
#endif
		FD_SET(sock, &fds);
		if(select(sock + 1, &fds, NULL, NULL, NULL) <= 0)
			return 1;

		if(FD_ISSET(0, &fds)) {
			ssize_t len = read(0, buf, sizeof buf);
			if(len < 0) {
				fprintf(stderr, "Could not read from stdin: %s\n", strerror(errno));
				return 1;
			}
			if(len == 0)
				break;
			if(buf[0] == '^')
				sptps_send_record(&s, SPTPS_HANDSHAKE, NULL, 0);
			else if(buf[0] == '$') {
				sptps_force_kex(&s);
				if(len > 1)
					sptps_send_record(&s, 0, buf, len);
			} else
			if(!sptps_send_record(&s, buf[0] == '!' ? 1 : 0, buf, buf[0] == '\n' ? 0 : buf[0] == '*' ? sizeof buf : len))
				return 1;
		}

		if(FD_ISSET(sock, &fds)) {
			ssize_t len = recv(sock, buf, sizeof buf, 0);
			if(len < 0) {
				fprintf(stderr, "Could not read from socket: %s\n", strerror(errno));
				return 1;
			}
			if(len == 0) {
				fprintf(stderr, "Connection terminated by peer.\n");
				break;
			}
			char hex[len * 2 + 1];
			bin2hex(buf, hex, len);
			fprintf(stderr, "Received %d bytes of data:\n%s\n", (int)len, hex);
			if(!sptps_receive_data(&s, buf, len))
				return 1;
		}
	}

	if(!sptps_stop(&s))
		return 1;

	return 0;
}
