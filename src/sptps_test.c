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

#ifdef HAVE_MINGW
#include <pthread.h>
#endif

#include "crypto.h"
#include "ecdsa.h"
#include "sptps.h"
#include "utils.h"
#include "locale.h"

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef HAVE_MINGW
#define closesocket(s) close(s)
#endif

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
		fprintf(stderr, _("Sending %zu bytes of data:\n%s\n"), len, hex);
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
		fprintf(stderr, _("Received type %d record of %u bytes:\n"), type, len);
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
	fprintf(stderr, _("Usage: %s [options] my_ed25519_key_file his_ed25519_key_file [host] port\n\n"),
	        program_name);

	fprintf(stderr, "%s\n%s%s\n%s%s\n%s%s\n\n%s%s\n%s%s\n%s%s\n%s%s\n%s%s\n%s%s\n%s%s\n%s%s\n",
	        _("Valid options are:"),
	        "  -d, --datagram          ", _("Enable datagram mode."),
	        "  -q, --quit              ", _("Quit when EOF occurs on stdin."),
	        "  -r, --readonly          ", _("Only send data from the socket to stdout."),
	        "  -w, --writeonly         ", _("Only send data from stdin to the socket."),
	        "  -L, --packet-loss RATE  ", _("Fake packet loss of RATE percent."),
	        "  -R, --replay-window N   ", _("Set replay window to N bytes."),
	        "  -s, --special           ", _("Enable special handling of lines starting with #, ^ and $."),
	        "  -v, --verbose           ", _("Display debug messages."),
	        "  -4                      ", _("Use IPv4."),
	        "  -6                      ", _("Use IPv6."),
#ifdef HAVE_LINUX
	        "  -t, --tun               ", _("Use a tun device instead of stdio.")
#else
	        "", ""
#endif
	       );

	fprintf(stderr, _("Report bugs to %s.\n"), MAINTAINER_EMAIL);
}

#ifdef HAVE_MINGW

int stdin_sock_fd = -1;

// Windows does not allow calling select() on anything but sockets. Therefore,
// to keep the same code as on other operating systems, we have to put a
// separate thread between the stdin and the sptps loop way below. This thread
// reads stdin and sends its content to the main thread through a TCP socket,
// which can be properly select()'ed.
void *stdin_reader_thread(void *arg) {
	struct sockaddr_in sa;
	socklen_t sa_size = sizeof(sa);

	while(true) {
		int peer_fd = accept(stdin_sock_fd, (struct sockaddr *) &sa, &sa_size);

		if(peer_fd < 0) {
			fprintf(stderr, _("%s failed: %s\n"), "accept()", strerror(errno));
			continue;
		}

		if(verbose) {
			fprintf(stderr, _("New connection received from :%d\n"), ntohs(sa.sin_port));
		}

		uint8_t buf[1024];
		ssize_t nread;

		while((nread = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
			if(verbose) {
				fprintf(stderr, _("Read %lld bytes from input\n"), nread);
			}

			uint8_t *start = buf;
			ssize_t nleft = nread;

			while(nleft) {
				ssize_t nsend = send(peer_fd, start, nleft, 0);

				if(nsend < 0) {
					if(sockwouldblock(sockerrno)) {
						continue;
					}

					break;
				}

				start += nsend;
				nleft -= nsend;
			}

			if(nleft) {
				fprintf(stderr, _("Could not send data: %s\n"), strerror(errno));
				break;
			}

			if(verbose) {
				fprintf(stderr, _("Sent %lld bytes to peer\n"), nread);
			}
		}

		closesocket(peer_fd);
	}

	closesocket(stdin_sock_fd);
	stdin_sock_fd = -1;
}

int start_input_reader() {
	if(stdin_sock_fd != -1) {
		fprintf(stderr, _("stdin thread can only be started once.\n"));
		return -1;
	}

	stdin_sock_fd = socket(AF_INET, SOCK_STREAM, 0);

	if(stdin_sock_fd < 0) {
		fprintf(stderr, _("Could not create server socket: %s\n"), strerror(errno));
		return -1;
	}

	struct sockaddr_in serv_sa;

	memset(&serv_sa, 0, sizeof(serv_sa));

	serv_sa.sin_family = AF_INET;

	serv_sa.sin_addr.s_addr = htonl(0x7f000001); // 127.0.0.1

	int res = bind(stdin_sock_fd, (struct sockaddr *)&serv_sa, sizeof(serv_sa));

	if(res < 0) {
		fprintf(stderr, _("Could not bind socket: %s\n"), strerror(errno));
		goto server_err;
	}

	if(listen(stdin_sock_fd, 1) < 0) {
		fprintf(stderr, _("Could not listen: %s\n"), strerror(errno));
		goto server_err;
	}

	struct sockaddr_in connect_sa;

	socklen_t addr_len = sizeof(connect_sa);

	if(getsockname(stdin_sock_fd, (struct sockaddr *)&connect_sa, &addr_len) < 0) {
		fprintf(stderr, _("Could not determine the address of the stdin thread socket\n"));
		goto server_err;
	}

	if(verbose) {
		fprintf(stderr, _("stdin thread is listening on :%d\n"), ntohs(connect_sa.sin_port));
	}

	pthread_t th;
	int err = pthread_create(&th, NULL, stdin_reader_thread, NULL);

	if(err) {
		fprintf(stderr, _("Could not start reader thread: %s\n"), strerror(err));
		goto server_err;
	}

	int client_fd = socket(AF_INET, SOCK_STREAM, 0);

	if(client_fd < 0) {
		fprintf(stderr, _("Could not create client socket: %s\n"), strerror(errno));
		return -1;
	}

	if(connect(client_fd, (struct sockaddr *)&connect_sa, sizeof(connect_sa)) < 0) {
		fprintf(stderr, _("Could not connect: %s\n"), strerror(errno));
		closesocket(client_fd);
		return -1;
	}

	return client_fd;

server_err:

	if(stdin_sock_fd != -1) {
		closesocket(stdin_sock_fd);
		stdin_sock_fd = -1;
	}

	return -1;
}

#endif // HAVE_MINGW

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
	bool quit = false;

	init_locale();

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
			fprintf(stderr, _("--tun is only supported on Linux.\n"));
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
		fprintf(stderr, _("Wrong number of arguments.\n"));
		usage();
		return 1;
	}

	if(argc > 4) {
		initiator = true;
	}

	srand(getpid());

#ifdef HAVE_LINUX

	if(tun) {
		in = out = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

		if(in < 0) {
			fprintf(stderr, _("Could not open tun device: %s\n"), strerror(errno));
			return 1;
		}

		struct ifreq ifr = {
			.ifr_flags = IFF_TUN
		};

		if(ioctl(in, TUNSETIFF, &ifr)) {
			fprintf(stderr, _("Could not configure tun interface: %s\n"), strerror(errno));
			return 1;
		}

		ifr.ifr_name[IFNAMSIZ - 1] = 0;
		fprintf(stderr, _("Using tun interface %s\n"), ifr.ifr_name);
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
		fprintf(stderr, _("%s failed: %s\n"), "getaddrinfo()", sockstrerror(sockerrno));
		return 1;
	}

	int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

	if(sock < 0) {
		fprintf(stderr, _("Could not create socket: %s\n"), sockstrerror(sockerrno));
		freeaddrinfo(ai);
		return 1;
	}

	int one = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one));

	if(initiator) {
		int res = connect(sock, ai->ai_addr, ai->ai_addrlen);

		freeaddrinfo(ai);
		ai = NULL;

		if(res) {
			fprintf(stderr, _("Could not connect to peer: %s\n"), sockstrerror(sockerrno));
			return 1;
		}

		fprintf(stderr, _("Connected\n"));
	} else {
		int res = bind(sock, ai->ai_addr, ai->ai_addrlen);

		freeaddrinfo(ai);
		ai = NULL;

		if(res) {
			fprintf(stderr, _("Could not bind socket: %s\n"), sockstrerror(sockerrno));
			return 1;
		}

		if(!datagram) {
			if(listen(sock, 1)) {
				fprintf(stderr, _("Could not listen on socket: %s\n"), sockstrerror(sockerrno));
				return 1;
			}

			fprintf(stderr, _("Listening...\n"));

			sock = accept(sock, NULL, NULL);

			if(sock < 0) {
				fprintf(stderr, _("Could not accept connection: %s\n"), sockstrerror(sockerrno));
				return 1;
			}
		} else {
			fprintf(stderr, _("Listening...\n"));

			uint8_t buf[65536];
			struct sockaddr addr;
			socklen_t addrlen = sizeof(addr);

			if(recvfrom(sock, buf, sizeof(buf), MSG_PEEK, &addr, &addrlen) <= 0) {
				fprintf(stderr, _("Could not read from socket: %s\n"), sockstrerror(sockerrno));
				return 1;
			}

			if(connect(sock, &addr, addrlen)) {
				fprintf(stderr, _("Could not accept connection: %s\n"), sockstrerror(sockerrno));
				return 1;
			}
		}

		fprintf(stderr, _("Connected\n"));
	}

	crypto_init();

	FILE *fp = fopen(argv[1], "r");

	if(!fp) {
		fprintf(stderr, _("Could not open %s: %s\n"), argv[1], strerror(errno));
		return 1;
	}

	ecdsa_t *mykey = NULL;

	if(!(mykey = ecdsa_read_pem_private_key(fp))) {
		return 1;
	}

	fclose(fp);

	fp = fopen(argv[2], "r");

	if(!fp) {
		fprintf(stderr, _("Could not open %s: %s\n"), argv[2], strerror(errno));
		free(mykey);
		return 1;
	}

	ecdsa_t *hiskey = NULL;

	if(!(hiskey = ecdsa_read_pem_public_key(fp))) {
		free(mykey);
		return 1;
	}

	fclose(fp);

	if(verbose) {
		fprintf(stderr, _("Keys loaded\n"));
	}

	sptps_t s;

	if(!sptps_start(&s, &sock, initiator, datagram, mykey, hiskey, "sptps_test", 10, send_data, receive_record)) {
		free(mykey);
		free(hiskey);
		return 1;
	}

#ifdef HAVE_MINGW

	if(!readonly) {
		in = start_input_reader();

		if(in < 0) {
			fprintf(stderr, _("Could not init stdin reader thread\n"));
			free(mykey);
			free(hiskey);
			return 1;
		}
	}

#endif

	int max_fd = MAX(sock, in);

	while(true) {
		if(writeonly && readonly) {
			break;
		}

		char buf[65535] = "";
		size_t readsize = datagram ? 1460u : sizeof(buf);

		fd_set fds;
		FD_ZERO(&fds);

		if(!readonly && s.instate) {
			FD_SET(in, &fds);
		}

		FD_SET(sock, &fds);

		if(select(max_fd + 1, &fds, NULL, NULL, NULL) <= 0) {
			free(mykey);
			free(hiskey);
			return 1;
		}

		if(FD_ISSET(in, &fds)) {
#ifdef HAVE_MINGW
			ssize_t len = recv(in, buf, readsize, 0);
#else
			ssize_t len = read(in, buf, readsize);
#endif

			if(len < 0) {
				fprintf(stderr, _("Could not read from stdin: %s\n"), strerror(errno));
				free(mykey);
				free(hiskey);
				return 1;
			}

			if(len == 0) {
#ifdef HAVE_MINGW
				shutdown(in, SD_SEND);
				closesocket(in);
#endif

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
				free(mykey);
				free(hiskey);
				return 1;
			}
		}

		if(FD_ISSET(sock, &fds)) {
			ssize_t len = recv(sock, buf, sizeof(buf), 0);

			if(len < 0) {
				fprintf(stderr, _("Could not read from socket: %s\n"), sockstrerror(sockerrno));
				free(mykey);
				free(hiskey);
				return 1;
			}

			if(len == 0) {
				fprintf(stderr, _("Connection terminated by peer.\n"));
				break;
			}

			if(verbose) {
				char hex[len * 2 + 1];
				bin2hex(buf, hex, len);
				fprintf(stderr, _("Received %zd bytes of data:\n%s\n"), len, hex);
			}

			if(packetloss && (rand() % 100) < packetloss) {
				if(verbose) {
					fprintf(stderr, _("Dropped.\n"));
				}

				continue;
			}

			char *bufp = buf;

			while(len) {
				size_t done = sptps_receive_data(&s, bufp, len);

				if(!done) {
					if(!datagram) {
						free(mykey);
						free(hiskey);
						return 1;
					}
				}

				bufp += done;
				len -= (ssize_t) done;
			}
		}
	}

	bool stopped = sptps_stop(&s);

	free(mykey);
	free(hiskey);

	if(!stopped) {
		return 1;
	}

	closesocket(sock);

	return 0;
}
