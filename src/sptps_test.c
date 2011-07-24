/*
    sptps_test.c -- Simple Peer-to-Peer Security test program
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
#include "poll.h"

#include "crypto.h"
#include "ecdsa.h"
#include "sptps.h"
#include "utils.h"

ecdsa_t mykey, hiskey;

static bool send_data(void *handle, const char *data, size_t len) {
	char hex[len * 2 + 1];
	bin2hex(data, hex, len);
	fprintf(stderr, "Sending %zu bytes of data:\n%s\n", len, hex);
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

	if(argc < 3) {
		fprintf(stderr, "Usage: %s my_ecdsa_key_file his_ecdsa_key_file [host] port\n", argv[0]);
		return 1;
	}

	if(argc > 4)
		initiator = true;

	struct addrinfo *ai, hint;
	memset(&hint, 0, sizeof hint);

	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	hint.ai_flags = initiator ? 0 : AI_PASSIVE;
	
	if(getaddrinfo(initiator ? argv[3] : NULL, initiator ? argv[4] : argv[3], &hint, &ai) || !ai) {
		fprintf(stderr, "getaddrinfo() failed: %s\n", strerror(errno));
		return 1;
	}

	int sock = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);
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
	if(!start_sptps(&s, &sock, initiator, mykey, hiskey, "sptps_test", 10, send_data, receive_record))
		return 1;

	while(true) {
		char buf[4095];

		struct pollfd fds[2];
		fds[0].fd = 0;
		fds[0].events = POLLIN;
		fds[1].fd = sock;
		fds[1].events = POLLIN;
		if(poll(fds, 2, -1) < 0)
			return 1;

		if(fds[0].revents) {
			ssize_t len = read(0, buf, sizeof buf);
			if(len < 0) {
				fprintf(stderr, "Could not read from stdin: %s\n", strerror(errno));
				return 1;
			}
			if(len == 0)
				break;
			if(!send_record(&s, 0, buf, len))
				return 1;
		}

		if(fds[1].revents) {
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
			fprintf(stderr, "Received %zd bytes of data:\n%s\n", len, hex);
			if(!receive_data(&s, buf, len))
				return 1;
		}
	}

	return 0;
}
