/*
    sptps_test.c -- Simple Peer-to-Peer Security test program
    Copyright (C) 2011-2014 Guus Sliepen <guus@tinc-vpn.org>

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

#ifdef HAVE_LINUX
#include <linux/if_tun.h>
#endif

#include <getopt.h>

#include "crypto.h"
#include "ecdsa.h"
#include "sptps.h"
#include "utils.h"

// Symbols necessary to link with logger.o
bool send_request(void *c, const char *msg, ...) {
	(void)c;
	(void)msg;
	return false;
}

struct list_t *connection_list = NULL;

bool send_meta(void *c, const char *msg, int len) {
	(void)c;
	(void)msg;
	(void)len;
	return false;
}

char *logfilename = NULL;
bool do_detach = false;
struct timeval now;

static bool special;
static bool verbose;
static bool readonly;
static bool writeonly;
static int in = 0;
static int out = 1;
static int addressfamily = AF_UNSPEC;

static bool send_data(void *handle, uint8_t type, const void *data, size_t len) {
	(void)type;
	char hex[len * 2 + 1];
	bin2hex(data, hex, len);

	if(verbose) {
		fprintf(stderr, "Sending %d bytes of data:\n%s\n", (int)len, hex);
	}

	const int *sock = handle;

	if((size_t)send(*sock, data, len, 0) != len) {
		return false;
	}

	return true;
}

static bool receive_record(void *handle, uint8_t type, const void *data, uint16_t len) {
	(void)handle;
	if(verbose) {
		fprintf(stderr, "Received type %d record of %u bytes:\n", type, len);
	}

	if(!writeonly) {
		write(out, data, len);
	}

	return true;
}

static struct option const long_options[] = {
	{"datagram", no_argument, NULL, 'd'},
	{"quit", no_argument, NULL, 'q'},
	{"readonly", no_argument, NULL, 'r'},
	{"writeonly", no_argument, NULL, 'w'},
	{"packet-loss", required_argument, NULL, 'L'},
	{"replay-window", required_argument, NULL, 'W'},
	{"special", no_argument, NULL, 's'},
	{"verbose", required_argument, NULL, 'v'},
	{"help", no_argument, NULL, 1},
	{NULL, 0, NULL, 0}
};

const char *program_name;

static void usage() {
	fprintf(stderr, "Usage: %s [options] my_ed25519_key_file his_ed25519_key_file [host] port\n\n", program_name);
	fprintf(stderr, "Valid options are:\n"
	        "  -d, --datagram          Enable datagram mode.\n"
	        "  -q, --quit              Quit when EOF occurs on stdin.\n"
	        "  -r, --readonly          Only send data from the socket to stdout.\n"
#ifdef HAVE_LINUX
	        "  -t, --tun               Use a tun device instead of stdio.\n"
#endif
	        "  -w, --writeonly         Only send data from stdin to the socket.\n"
	        "  -L, --packet-loss RATE  Fake packet loss of RATE percent.\n"
	        "  -R, --replay-window N   Set replay window to N bytes.\n"
	        "  -s, --special           Enable special handling of lines starting with #, ^ and $.\n"
	        "  -v, --verbose           Display debug messages.\n"
	        "  -4                      Use IPv4.\n"
	        "  -6                      Use IPv6.\n"
	        "\n");
	fprintf(stderr, "Report bugs to tinc@tinc-vpn.org.\n");
}

int main(int argc, char *argv[]) {
	program_name = argv[0];
	bool initiator = false;
	bool datagram = false;
#ifdef HAVE_LINUX
	bool tun = false;
#endif
	int packetloss = 0;
	int r;
	int option_index = 0;
	ecdsa_t *mykey = NULL, *hiskey = NULL;
	bool quit = false;

	while((r = getopt_long(argc, argv, "dqrstwL:W:v46", long_options, &option_index)) != EOF) {
		switch(r) {
		case 0:   /* long option */
			break;

		case 'd': /* datagram mode */
			datagram = true;
			break;

		case 'q': /* close connection on EOF from stdin */
			quit = true;
			break;

		case 'r': /* read only */
			readonly = true;
			break;

		case 't': /* read only */
#ifdef HAVE_LINUX
			tun = true;
#else
			fprintf(stderr, "--tun is only supported on Linux.\n");
			usage();
			return 1;
#endif
			break;

		case 'w': /* write only */
			writeonly = true;
			break;

		case 'L': /* packet loss rate */
			packetloss = atoi(optarg);
			break;

		case 'W': /* replay window size */
			sptps_replaywin = atoi(optarg);
			break;

		case 'v': /* be verbose */
			verbose = true;
			break;

		case 's': /* special character handling */
			special = true;
			break;

		case '?': /* wrong options */
			usage();
			return 1;

		case '4': /* IPv4 */
			addressfamily = AF_INET;
			break;

		case '6': /* IPv6 */
			addressfamily = AF_INET6;
			break;

		case 1: /* help */
			usage();
			return 0;

		default:
			break;
		}
	}

	argc -= optind - 1;
	argv += optind - 1;

	if(argc < 4 || argc > 5) {
		fprintf(stderr, "Wrong number of arguments.\n");
		usage();
		return 1;
	}

	if(argc > 4) {
		initiator = true;
	}

	srand(time(NULL));

#ifdef HAVE_LINUX

	if(tun) {
		in = out = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

		if(in < 0) {
			fprintf(stderr, "Could not open tun device: %s\n", strerror(errno));
			return 1;
		}

		struct ifreq ifr = {
			.ifr_flags = IFF_TUN
		};

		if(ioctl(in, TUNSETIFF, &ifr)) {
			fprintf(stderr, "Could not configure tun interface: %s\n", strerror(errno));
			return 1;
		}

		ifr.ifr_name[IFNAMSIZ - 1] = 0;
		fprintf(stderr, "Using tun interface %s\n", ifr.ifr_name);
	}

#endif

#ifdef HAVE_MINGW
	static struct WSAData wsa_state;

	if(WSAStartup(MAKEWORD(2, 2), &wsa_state)) {
		return 1;
	}

#endif

	struct addrinfo *ai, hint;
	memset(&hint, 0, sizeof(hint));

	hint.ai_family = addressfamily;
	hint.ai_socktype = datagram ? SOCK_DGRAM : SOCK_STREAM;
	hint.ai_protocol = datagram ? IPPROTO_UDP : IPPROTO_TCP;
	hint.ai_flags = initiator ? 0 : AI_PASSIVE;

	if(getaddrinfo(initiator ? argv[3] : NULL, initiator ? argv[4] : argv[3], &hint, &ai) || !ai) {
		fprintf(stderr, "getaddrinfo() failed: %s\n", sockstrerror(sockerrno));
		return 1;
	}

	int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

	if(sock < 0) {
		fprintf(stderr, "Could not create socket: %s\n", sockstrerror(sockerrno));
		return 1;
	}

	int one = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one));

	if(initiator) {
		if(connect(sock, ai->ai_addr, ai->ai_addrlen)) {
			fprintf(stderr, "Could not connect to peer: %s\n", sockstrerror(sockerrno));
			return 1;
		}

		fprintf(stderr, "Connected\n");
	} else {
		if(bind(sock, ai->ai_addr, ai->ai_addrlen)) {
			fprintf(stderr, "Could not bind socket: %s\n", sockstrerror(sockerrno));
			return 1;
		}

		if(!datagram) {
			if(listen(sock, 1)) {
				fprintf(stderr, "Could not listen on socket: %s\n", sockstrerror(sockerrno));
				return 1;
			}

			fprintf(stderr, "Listening...\n");

			sock = accept(sock, NULL, NULL);

			if(sock < 0) {
				fprintf(stderr, "Could not accept connection: %s\n", sockstrerror(sockerrno));
				return 1;
			}
		} else {
			fprintf(stderr, "Listening...\n");

			char buf[65536];
			struct sockaddr addr;
			socklen_t addrlen = sizeof(addr);

			if(recvfrom(sock, buf, sizeof(buf), MSG_PEEK, &addr, &addrlen) <= 0) {
				fprintf(stderr, "Could not read from socket: %s\n", sockstrerror(sockerrno));
				return 1;
			}

			if(connect(sock, &addr, addrlen)) {
				fprintf(stderr, "Could not accept connection: %s\n", sockstrerror(sockerrno));
				return 1;
			}
		}

		fprintf(stderr, "Connected\n");
	}

	crypto_init();

	FILE *fp = fopen(argv[1], "r");

	if(!fp) {
		fprintf(stderr, "Could not open %s: %s\n", argv[1], strerror(errno));
		return 1;
	}

	if(!(mykey = ecdsa_read_pem_private_key(fp))) {
		return 1;
	}

	fclose(fp);

	fp = fopen(argv[2], "r");

	if(!fp) {
		fprintf(stderr, "Could not open %s: %s\n", argv[2], strerror(errno));
		return 1;
	}

	if(!(hiskey = ecdsa_read_pem_public_key(fp))) {
		return 1;
	}

	fclose(fp);

	if(verbose) {
		fprintf(stderr, "Keys loaded\n");
	}

	sptps_t s;

	if(!sptps_start(&s, &sock, initiator, datagram, mykey, hiskey, "sptps_test", 10, send_data, receive_record)) {
		return 1;
	}

	while(true) {
		if(writeonly && readonly) {
			break;
		}

		char buf[65535] = "";

		fd_set fds;
		FD_ZERO(&fds);
#ifndef HAVE_MINGW

		if(!readonly && s.instate) {
			FD_SET(in, &fds);
		}

#endif
		FD_SET(sock, &fds);

		if(select(sock + 1, &fds, NULL, NULL, NULL) <= 0) {
			return 1;
		}

		if(FD_ISSET(in, &fds)) {
			ssize_t len = read(in, buf, sizeof(buf));

			if(len < 0) {
				fprintf(stderr, "Could not read from stdin: %s\n", strerror(errno));
				return 1;
			}

			if(len == 0) {
				if(quit) {
					break;
				}

				readonly = true;
				continue;
			}

			if(special && buf[0] == '#') {
				s.outseqno = atoi(buf + 1);
			}

			if(special && buf[0] == '^') {
				sptps_send_record(&s, SPTPS_HANDSHAKE, NULL, 0);
			} else if(special && buf[0] == '$') {
				sptps_force_kex(&s);

				if(len > 1) {
					sptps_send_record(&s, 0, buf, len);
				}
			} else if(!sptps_send_record(&s, buf[0] == '!' ? 1 : 0, buf, (len == 1 && buf[0] == '\n') ? 0 : buf[0] == '*' ? sizeof(buf) : (size_t)len)) {
				return 1;
			}
		}

		if(FD_ISSET(sock, &fds)) {
			ssize_t len = recv(sock, buf, sizeof(buf), 0);

			if(len < 0) {
				fprintf(stderr, "Could not read from socket: %s\n", sockstrerror(sockerrno));
				return 1;
			}

			if(len == 0) {
				fprintf(stderr, "Connection terminated by peer.\n");
				break;
			}

			if(verbose) {
				char hex[len * 2 + 1];
				bin2hex(buf, hex, len);
				fprintf(stderr, "Received %d bytes of data:\n%s\n", (int)len, hex);
			}

			if(packetloss && (rand() % 100) < packetloss) {
				if(verbose) {
					fprintf(stderr, "Dropped.\n");
				}

				continue;
			}

			char *bufp = buf;

			while(len) {
				size_t done = sptps_receive_data(&s, bufp, len);

				if(!done) {
					if(!datagram) {
						return 1;
					}
				}

				bufp += done;
				len -= done;
			}
		}
	}

	if(!sptps_stop(&s)) {
		return 1;
	}

	return 0;
}
