/*
    splice.c -- Splice two outgoing tinc connections together
    Copyright (C) 2018 Guus Sliepen <guus@tinc-vpn.org>

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

#include "../src/system.h"

#ifdef HAVE_MINGW
static const char *winerror(int err) {
        static char buf[1024], *ptr;

        ptr = buf + snprintf(buf, sizeof(buf), "(%d) ", err);

        if(!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), ptr, sizeof(buf) - (ptr - buf), NULL)) {
                strncpy(buf, "(unable to format errormessage)", sizeof(buf));
        };

        if((ptr = strchr(buf, '\r'))) {
                *ptr = '\0';
        }

        return buf;
}

#define strerror(x) ((x)>0?strerror(x):winerror(GetLastError()))
#define sockerrno WSAGetLastError()
#define sockstrerror(x) winerror(x)
#else
#define sockerrno errno
#define sockstrerror(x) strerror(x)
#endif

int main(int argc, char *argv[]) {
	if(argc < 7) {
		fprintf(stderr, "Usage: %s name1 host1 port1 name2 host2 port2 [protocol]\n", argv[0]);
		return 1;
	}

	const char *protocol;

	if(argc >= 8) {
		protocol = argv[7];
	} else {
		protocol = "17.7";
	}

#ifdef HAVE_MINGW
	static struct WSAData wsa_state;

	if(WSAStartup(MAKEWORD(2, 2), &wsa_state)) {
		return 1;
	}

#endif
	int sock[2];
	char buf[1024];

	struct addrinfo *ai, hint;
	memset(&hint, 0, sizeof(hint));

	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	hint.ai_flags = 0;

	for (int i = 0; i < 2; i++) {
		if(getaddrinfo(argv[2 + 3 * i], argv[3 + 3 * i], &hint, &ai) || !ai) {
			fprintf(stderr, "getaddrinfo() failed: %s\n", sockstrerror(sockerrno));
			return 1;
		}

		sock[i] = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

		if(sock[i] == -1) {
			fprintf(stderr, "Could not create socket: %s\n", sockstrerror(sockerrno));
			return 1;
		}

		if(connect(sock[i], ai->ai_addr, ai->ai_addrlen)) {
			fprintf(stderr, "Could not connect to %s: %s\n", argv[i + 3 * i], sockstrerror(sockerrno));
			return 1;
		}

		fprintf(stderr, "Connected to %s\n", argv[1 + 3 * i]);

		/* Pretend to be the other one */
		int len = snprintf(buf, sizeof buf, "0 %s %s\n", argv[4 - 3 * i], protocol);
		if (send(sock[i], buf, len, 0) != len) {
			fprintf(stderr, "Error sending data to %s: %s\n", argv[1 + 3 * i], sockstrerror(sockerrno));
			return 1;
		}

		/* Ignore the response */
		do {
			if (recv(sock[i], buf, 1, 0) != 1) {
				fprintf(stderr, "Error reading data from %s: %s\n", argv[1 + 3 * i], sockstrerror(sockerrno));
				return 1;
			}
		} while(*buf != '\n');
	}

	fprintf(stderr, "Splicing...\n");

	int nfds = (sock[0] > sock[1] ? sock[0] : sock[1]) + 1;

	while(true) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(sock[0], &fds);
		FD_SET(sock[1], &fds);

		if(select(nfds, &fds, NULL, NULL, NULL) <= 0) {
			return 1;
		}

		for(int i = 0; i < 2; i++ ) {
			if(FD_ISSET(sock[i], &fds)) {
				ssize_t len = recv(sock[i], buf, sizeof buf, 0);

				if(len < 0) {
					fprintf(stderr, "Error while reading from %s: %s\n", argv[1 + i * 3], sockstrerror(sockerrno));
					return 1;
				}

				if(len == 0) {
					fprintf(stderr, "Connection closed by %s\n", argv[1 + i * 3]);
					return 0;
				}

				if(send(sock[i ^ 1], buf, len, 0) != len) {
					fprintf(stderr, "Error while writing to %s: %s\n", argv[4 - i * 3], sockstrerror(sockerrno));
					return 1;
				}
			}
		}
	}

	return 0;
}
