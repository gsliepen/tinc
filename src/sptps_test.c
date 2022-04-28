/*
    sptps_test.c -- Simple Peer-to-Peer Security test program
    Copyright (C) 2011-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#include "crypto.h"
#include "ecdsa.h"
#include "meta.h"
#include "protocol.h"
#include "sptps.h"
#include "utils.h"
#include "names.h"
#include "random.h"

#ifndef HAVE_WINDOWS
#define closesocket(s) close(s)
#endif

// Symbols necessary to link with logger.o
bool send_request(struct connection_t *c, const char *msg, ...) {
	(void)c;
	(void)msg;
	return false;
}

list_t connection_list;

bool send_meta(struct connection_t *c, const void *msg, size_t len) {
	(void)c;
	(void)msg;
	(void)len;
	return false;
}

bool do_detach = false;
struct timeval now;

static bool special;
static bool verbose;
static bool readonly;
static bool writeonly;
static int in = 0;
static int out = 1;
int addressfamily = AF_UNSPEC;

static bool send_data(void *handle, uint8_t type, const void *data, size_t len) {
	(void)type;
	char *hex = alloca(len * 2 + 1);
	bin2hex(data, hex, len);

	if(verbose) {
		fprintf(stderr, "Sending %lu bytes of data:\n%s\n", (unsigned long)len, hex);
	}

	const int *sock = handle;
	const char *p = data;

	while(len) {
		ssize_t sent = send(*sock, p, len, 0);

		if(sent <= 0) {
			fprintf(stderr, "Error sending data: %s\n", strerror(errno));
			return false;
		}

		p += sent;
		len -= sent;
	}

	return true;
}

static bool receive_record(void *handle, uint8_t type, const void *data, uint16_t len) {
	(void)handle;

	if(verbose) {
		fprintf(stderr, "Received type %d record of %u bytes:\n", type, len);
	}

	if(writeonly) {
		return true;
	}

	const char *p = data;

	while(len) {
		ssize_t written = write(out, p, len);

		if(written <= 0) {
			fprintf(stderr, "Error writing received data: %s\n", strerror(errno));
			return false;
		}

		p += written;
		len -= written;
	}

	return true;
}

typedef enum option_t {
	OPT_BAD_OPTION    = '?',
	OPT_LONG_OPTION   =  0,

	// Short options
	OPT_DATAGRAM      = 'd',
	OPT_QUIT_ON_EOF   = 'q',
	OPT_READONLY      = 'r',
	OPT_WRITEONLY     = 'w',
	OPT_PACKET_LOSS   = 'L',
	OPT_REPLAY_WINDOW = 'W',
	OPT_SPECIAL_CHAR  = 's',
	OPT_TUN           = 't',
	OPT_VERBOSE       = 'v',
	OPT_IPV4          = '4',
	OPT_IPV6          = '6',

	// Long options
	OPT_HELP          = 255,
} option_t;

static struct option const long_options[] = {
	{"datagram",      no_argument,       NULL, OPT_DATAGRAM},
	{"quit",          no_argument,       NULL, OPT_QUIT_ON_EOF},
	{"readonly",      no_argument,       NULL, OPT_READONLY},
	{"writeonly",     no_argument,       NULL, OPT_WRITEONLY},
	{"packet-loss",   required_argument, NULL, OPT_PACKET_LOSS},
	{"replay-window", required_argument, NULL, OPT_REPLAY_WINDOW},
	{"special",       no_argument,       NULL, OPT_SPECIAL_CHAR},
	{"tun",           no_argument,       NULL, OPT_TUN},
	{"verbose",       required_argument, NULL, OPT_VERBOSE},
	{"help",          no_argument,       NULL, OPT_HELP},
	{NULL,            0,                 NULL, 0}
};

static void usage(void) {
	fprintf(stderr,
	        "Usage: %s [options] my_ed25519_key_file his_ed25519_key_file [host] port\n"
	        "\n"
	        "Valid options are:\n"
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
	        "\n"
	        "Report bugs to tinc@tinc-vpn.org.\n",
	        program_name);
}

#ifdef HAVE_WINDOWS

int stdin_sock_fd = -1;

// Windows does not allow calling select() on anything but sockets. Therefore,
// to keep the same code as on other operating systems, we have to put a
// separate thread between the stdin and the sptps loop way below. This thread
// reads stdin and sends its content to the main thread through a TCP socket,
// which can be properly select()'ed.
static DWORD WINAPI stdin_reader_thread(LPVOID arg) {
	struct sockaddr_in sa;
	socklen_t sa_size = sizeof(sa);

	while(true) {
		int peer_fd = accept(stdin_sock_fd, (struct sockaddr *) &sa, &sa_size);

		if(peer_fd < 0) {
			fprintf(stderr, "accept() failed: %s\n", strerror(errno));
			continue;
		}

		if(verbose) {
			fprintf(stderr, "New connection received from :%d\n", ntohs(sa.sin_port));
		}

		char buf[1024];
		ssize_t nread;

		while((nread = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
			if(verbose) {
				fprintf(stderr, "Read %lld bytes from input\n", nread);
			}

			char *start = buf;
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
				fprintf(stderr, "Could not send data: %s\n", strerror(errno));
				break;
			}

			if(verbose) {
				fprintf(stderr, "Sent %lld bytes to peer\n", nread);
			}
		}

		closesocket(peer_fd);
	}

	closesocket(stdin_sock_fd);
	stdin_sock_fd = -1;
	return 0;
}

static int start_input_reader(void) {
	if(stdin_sock_fd != -1) {
		fprintf(stderr, "stdin thread can only be started once.\n");
		return -1;
	}

	stdin_sock_fd = socket(AF_INET, SOCK_STREAM, 0);

	if(stdin_sock_fd < 0) {
		fprintf(stderr, "Could not create server socket: %s\n", strerror(errno));
		return -1;
	}

	struct sockaddr_in serv_sa;

	memset(&serv_sa, 0, sizeof(serv_sa));

	serv_sa.sin_family = AF_INET;

	serv_sa.sin_addr.s_addr = htonl(0x7f000001); // 127.0.0.1

	int res = bind(stdin_sock_fd, (struct sockaddr *)&serv_sa, sizeof(serv_sa));

	if(res < 0) {
		fprintf(stderr, "Could not bind socket: %s\n", strerror(errno));
		goto server_err;
	}

	if(listen(stdin_sock_fd, 1) < 0) {
		fprintf(stderr, "Could not listen: %s\n", strerror(errno));
		goto server_err;
	}

	struct sockaddr_in connect_sa;

	socklen_t addr_len = sizeof(connect_sa);

	if(getsockname(stdin_sock_fd, (struct sockaddr *)&connect_sa, &addr_len) < 0) {
		fprintf(stderr, "Could not determine the address of the stdin thread socket\n");
		goto server_err;
	}

	if(verbose) {
		fprintf(stderr, "stdin thread is listening on :%d\n", ntohs(connect_sa.sin_port));
	}

	if(!CreateThread(NULL, 0, stdin_reader_thread, NULL, 0, NULL)) {
		fprintf(stderr, "Could not start reader thread: %d\n", GetLastError());
		goto server_err;
	}

	int client_fd = socket(AF_INET, SOCK_STREAM, 0);

	if(client_fd < 0) {
		fprintf(stderr, "Could not create client socket: %s\n", strerror(errno));
		return -1;
	}

	if(connect(client_fd, (struct sockaddr *)&connect_sa, sizeof(connect_sa)) < 0) {
		fprintf(stderr, "Could not connect: %s\n", strerror(errno));
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

#endif // HAVE_WINDOWS

static void print_listening_msg(int sock) {
	sockaddr_t sa = {0};
	socklen_t salen = sizeof(sa);
	int port = 0;

	if(!getsockname(sock, &sa.sa, &salen)) {
		port = ntohs(sa.in.sin_port);
	}

	fprintf(stderr, "Listening on %d...\n", port);
	fflush(stderr);
}

static int run_test(int argc, char *argv[]) {
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

	while((r = getopt_long(argc, argv, "dqrstwL:W:v46", long_options, &option_index)) != EOF) {
		switch((option_t) r) {
		case OPT_LONG_OPTION:
			break;

		case OPT_BAD_OPTION:
			usage();
			return 1;

		case OPT_DATAGRAM:
			datagram = true;
			break;

		case OPT_QUIT_ON_EOF:
			quit = true;
			break;

		case OPT_READONLY:
			readonly = true;
			break;

		case OPT_TUN:
#ifdef HAVE_LINUX
			tun = true;
#else
			fprintf(stderr, "--tun is only supported on Linux.\n");
			usage();
			return 1;
#endif
			break;

		case OPT_WRITEONLY:
			writeonly = true;
			break;

		case OPT_PACKET_LOSS:
			packetloss = atoi(optarg);
			break;

		case OPT_REPLAY_WINDOW:
			sptps_replaywin = atoi(optarg);
			break;

		case OPT_VERBOSE:
			verbose = true;
			break;

		case OPT_SPECIAL_CHAR:
			special = true;
			break;

		case OPT_IPV4:
			addressfamily = AF_INET;
			break;

		case OPT_IPV6:
			addressfamily = AF_INET6;
			break;

		case OPT_HELP:
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

#ifdef HAVE_WINDOWS
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
			fprintf(stderr, "Could not connect to peer: %s\n", sockstrerror(sockerrno));
			return 1;
		}

		fprintf(stderr, "Connected\n");
	} else {
		int res = bind(sock, ai->ai_addr, ai->ai_addrlen);

		freeaddrinfo(ai);
		ai = NULL;

		if(res) {
			fprintf(stderr, "Could not bind socket: %s\n", sockstrerror(sockerrno));
			return 1;
		}

		if(!datagram) {
			if(listen(sock, 1)) {
				fprintf(stderr, "Could not listen on socket: %s\n", sockstrerror(sockerrno));
				return 1;
			}

			print_listening_msg(sock);

			sock = accept(sock, NULL, NULL);

			if(sock < 0) {
				fprintf(stderr, "Could not accept connection: %s\n", sockstrerror(sockerrno));
				return 1;
			}
		} else {
			print_listening_msg(sock);

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

	FILE *fp = fopen(argv[1], "r");

	if(!fp) {
		fprintf(stderr, "Could not open %s: %s\n", argv[1], strerror(errno));
		return 1;
	}

	ecdsa_t *mykey = NULL;

	if(!(mykey = ecdsa_read_pem_private_key(fp))) {
		return 1;
	}

	fclose(fp);

	fp = fopen(argv[2], "r");

	if(!fp) {
		fprintf(stderr, "Could not open %s: %s\n", argv[2], strerror(errno));
		ecdsa_free(mykey);
		return 1;
	}

	ecdsa_t *hiskey = NULL;

	if(!(hiskey = ecdsa_read_pem_public_key(fp))) {
		ecdsa_free(mykey);
		return 1;
	}

	fclose(fp);

	if(verbose) {
		fprintf(stderr, "Keys loaded\n");
	}

	sptps_t s;

	if(!sptps_start(&s, &sock, initiator, datagram, mykey, hiskey, "sptps_test", 10, send_data, receive_record)) {
		ecdsa_free(mykey);
		ecdsa_free(hiskey);
		return 1;
	}

#ifdef HAVE_WINDOWS

	if(!readonly) {
		in = start_input_reader();

		if(in < 0) {
			fprintf(stderr, "Could not init stdin reader thread\n");
			ecdsa_free(mykey);
			ecdsa_free(hiskey);
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
			ecdsa_free(mykey);
			ecdsa_free(hiskey);
			return 1;
		}

		if(FD_ISSET(in, &fds)) {
#ifdef HAVE_WINDOWS
			ssize_t len = recv(in, buf, readsize, 0);
#else
			ssize_t len = read(in, buf, readsize);
#endif

			if(len < 0) {
				fprintf(stderr, "Could not read from stdin: %s\n", strerror(errno));
				ecdsa_free(mykey);
				ecdsa_free(hiskey);
				return 1;
			}

			if(len == 0) {
#ifdef HAVE_WINDOWS
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
				ecdsa_free(mykey);
				ecdsa_free(hiskey);
				return 1;
			}
		}

		if(FD_ISSET(sock, &fds)) {
			ssize_t len = recv(sock, buf, sizeof(buf), 0);

			if(len < 0) {
				fprintf(stderr, "Could not read from socket: %s\n", sockstrerror(sockerrno));
				ecdsa_free(mykey);
				ecdsa_free(hiskey);
				return 1;
			}

			if(len == 0) {
				fprintf(stderr, "Connection terminated by peer.\n");
				break;
			}

			if(verbose) {
				char *hex = alloca(len * 2 + 1);
				bin2hex(buf, hex, len);
				fprintf(stderr, "Received %ld bytes of data:\n%s\n", (long)len, hex);
			}

			if(packetloss && (int)prng(100) < packetloss) {
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
						ecdsa_free(mykey);
						ecdsa_free(hiskey);
						return 1;
					}
				}

				bufp += done;
				len -= (ssize_t) done;
			}
		}
	}

	bool stopped = sptps_stop(&s);

	ecdsa_free(mykey);
	ecdsa_free(hiskey);
	closesocket(sock);

	return !stopped;
}

int main(int argc, char *argv[]) {
	random_init();
	crypto_init();
	prng_init();

	int result = run_test(argc, argv);

	random_exit();

	return result;
}
