/*
    tincctl.c -- Controlling a running tincd
    Copyright (C) 2007-2011 Guus Sliepen <guus@tinc-vpn.org>

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

#include <getopt.h>

#include "xalloc.h"
#include "protocol.h"
#include "control_common.h"
#include "ecdsagen.h"
#include "rsagen.h"
#include "utils.h"
#include "tincctl.h"
#include "top.h"

/* The name this program was run with. */
static char *program_name = NULL;

/* If nonzero, display usage information and exit. */
static bool show_help = false;

/* If nonzero, print the version on standard output and exit.  */
static bool show_version = false;

static char *name = NULL;
static char *identname = NULL;				/* program name for syslog */
static char *pidfilename = NULL;			/* pid file location */
static char controlcookie[1024];
char *netname = NULL;
char *confbase = NULL;

#ifdef HAVE_MINGW
static struct WSAData wsa_state;
#endif

static struct option const long_options[] = {
	{"config", required_argument, NULL, 'c'},
	{"net", required_argument, NULL, 'n'},
	{"help", no_argument, NULL, 1},
	{"version", no_argument, NULL, 2},
	{"pidfile", required_argument, NULL, 5},
	{NULL, 0, NULL, 0}
};

static void usage(bool status) {
	if(status)
		fprintf(stderr, "Try `%s --help\' for more information.\n",
				program_name);
	else {
		printf("Usage: %s [options] command\n\n", program_name);
		printf("Valid options are:\n"
				"  -c, --config=DIR        Read configuration options from DIR.\n"
				"  -n, --net=NETNAME       Connect to net NETNAME.\n"
				"      --pidfile=FILENAME  Read control cookie from FILENAME.\n"
				"      --help              Display this help and exit.\n"
				"      --version           Output version information and exit.\n"
				"\n"
				"Valid commands are:\n"
				"  start                      Start tincd.\n"
				"  stop                       Stop tincd.\n"
				"  restart                    Restart tincd.\n"
				"  reload                     Reload configuration of running tincd.\n"
				"  pid                        Show PID of currently running tincd.\n"
				"  generate-keys [bits]       Generate new RSA and ECDSA public/private keypairs.\n"
				"  generate-rsa-keys [bits]   Generate a new RSA public/private keypair.\n"
				"  generate-ecdsa-keys        Generate a new ECDSA public/private keypair.\n"
				"  dump                       Dump a list of one of the following things:\n"
				"    nodes                    - all known nodes in the VPN\n"
				"    edges                    - all known connections in the VPN\n"
				"    subnets                  - all known subnets in the VPN\n"
				"    connections              - all meta connections with ourself\n"
				"    graph                    - graph of the VPN in dotty format\n"
				"  purge                      Purge unreachable nodes\n"
				"  debug N                    Set debug level\n"
				"  retry                      Retry all outgoing connections\n"
				"  reload                     Partial reload of configuration\n"
				"  disconnect NODE            Close meta connection with NODE\n"
#ifdef HAVE_CURSES
				"  top                        Show real-time statistics\n"
#endif
				"  pcap                       Dump traffic in pcap format\n"
				"\n");
		printf("Report bugs to tinc@tinc-vpn.org.\n");
	}
}

static bool parse_options(int argc, char **argv) {
	int r;
	int option_index = 0;

	while((r = getopt_long(argc, argv, "c:n:", long_options, &option_index)) != EOF) {
		switch (r) {
			case 0:				/* long option */
				break;

			case 'c':				/* config file */
				confbase = xstrdup(optarg);
				break;

			case 'n':				/* net name given */
				netname = xstrdup(optarg);
				break;

			case 1:					/* show help */
				show_help = true;
				break;

			case 2:					/* show version */
				show_version = true;
				break;

			case 5:					/* open control socket here */
				pidfilename = xstrdup(optarg);
				break;

			case '?':
				usage(true);
				return false;

			default:
				break;
		}
	}

	return true;
}

FILE *ask_and_open(const char *filename, const char *what, const char *mode) {
	FILE *r;
	char *directory;
	char buf[PATH_MAX];
	char buf2[PATH_MAX];

	/* Check stdin and stdout */
	if(isatty(0) && isatty(1)) {
		/* Ask for a file and/or directory name. */
		fprintf(stdout, "Please enter a file to save %s to [%s]: ",
				what, filename);
		fflush(stdout);

		if(fgets(buf, sizeof buf, stdin) == NULL) {
			fprintf(stderr, "Error while reading stdin: %s\n",
					strerror(errno));
			return NULL;
		}

		size_t len = strlen(buf);
		if(len)
			buf[--len] = 0;

		if(len)
			filename = buf;
	}

#ifdef HAVE_MINGW
	if(filename[0] != '\\' && filename[0] != '/' && !strchr(filename, ':')) {
#else
	if(filename[0] != '/') {
#endif
		/* The directory is a relative path or a filename. */
		directory = get_current_dir_name();
		snprintf(buf2, sizeof buf2, "%s/%s", directory, filename);
		filename = buf2;
	}

	umask(0077);				/* Disallow everything for group and other */

	/* Open it first to keep the inode busy */

	r = fopen(filename, mode);

	if(!r) {
		fprintf(stderr, "Error opening file `%s': %s\n", filename, strerror(errno));
		return NULL;
	}

	return r;
}

/*
  Generate a public/private ECDSA keypair, and ask for a file to store
  them in.
*/
static bool ecdsa_keygen() {
	ecdsa_t key;
	FILE *f;
	char *filename;

	fprintf(stderr, "Generating ECDSA keypair:\n");

	if(!ecdsa_generate(&key)) {
		fprintf(stderr, "Error during key generation!\n");
		return false;
	} else
		fprintf(stderr, "Done.\n");

	xasprintf(&filename, "%s/ecdsa_key.priv", confbase);
	f = ask_and_open(filename, "private ECDSA key", "a");

	if(!f)
		return false;
  
#ifdef HAVE_FCHMOD
	/* Make it unreadable for others. */
	fchmod(fileno(f), 0600);
#endif
		
	if(ftell(f))
		fprintf(stderr, "Appending key to existing contents.\nMake sure only one key is stored in the file.\n");

	ecdsa_write_pem_private_key(&key, f);

	fclose(f);
	free(filename);

	if(name)
		xasprintf(&filename, "%s/hosts/%s", confbase, name);
	else
		xasprintf(&filename, "%s/ecdsa_key.pub", confbase);

	f = ask_and_open(filename, "public ECDSA key", "a");

	if(!f)
		return false;

	if(ftell(f))
		fprintf(stderr, "Appending key to existing contents.\nMake sure only one key is stored in the file.\n");

	char *pubkey = ecdsa_get_base64_public_key(&key);
	fprintf(f, "ECDSAPublicKey = %s\n", pubkey);
	free(pubkey);

	fclose(f);
	free(filename);

	return true;
}

/*
  Generate a public/private RSA keypair, and ask for a file to store
  them in.
*/
static bool rsa_keygen(int bits) {
	rsa_t key;
	FILE *f;
	char *filename;

	fprintf(stderr, "Generating %d bits keys:\n", bits);

	if(!rsa_generate(&key, bits, 0x10001)) {
		fprintf(stderr, "Error during key generation!\n");
		return false;
	} else
		fprintf(stderr, "Done.\n");

	xasprintf(&filename, "%s/rsa_key.priv", confbase);
	f = ask_and_open(filename, "private RSA key", "a");

	if(!f)
		return false;
  
#ifdef HAVE_FCHMOD
	/* Make it unreadable for others. */
	fchmod(fileno(f), 0600);
#endif
		
	if(ftell(f))
		fprintf(stderr, "Appending key to existing contents.\nMake sure only one key is stored in the file.\n");

	rsa_write_pem_private_key(&key, f);

	fclose(f);
	free(filename);

	if(name)
		xasprintf(&filename, "%s/hosts/%s", confbase, name);
	else
		xasprintf(&filename, "%s/rsa_key.pub", confbase);

	f = ask_and_open(filename, "public RSA key", "a");

	if(!f)
		return false;

	if(ftell(f))
		fprintf(stderr, "Appending key to existing contents.\nMake sure only one key is stored in the file.\n");

	rsa_write_pem_public_key(&key, f);

	fclose(f);
	free(filename);

	return true;
}

/*
  Set all files and paths according to netname
*/
static void make_names(void) {
#ifdef HAVE_MINGW
	HKEY key;
	char installdir[1024] = "";
	long len = sizeof installdir;
#endif

	if(netname)
		xasprintf(&identname, "tinc.%s", netname);
	else
		identname = xstrdup("tinc");

#ifdef HAVE_MINGW
	if(!RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\tinc", 0, KEY_READ, &key)) {
		if(!RegQueryValueEx(key, NULL, 0, 0, installdir, &len)) {
			if(!confbase) {
				if(netname)
					xasprintf(&confbase, "%s/%s", installdir, netname);
				else
					xasprintf(&confbase, "%s", installdir);
			}
		}
		if(!pidfilename)
			xasprintf(&pidfilename, "%s/pid", confbase);
		RegCloseKey(key);
		if(*installdir)
			return;
	}
#endif

	if(!pidfilename)
		xasprintf(&pidfilename, "%s/run/%s.pid", LOCALSTATEDIR, identname);

	if(netname) {
		if(!confbase)
			xasprintf(&confbase, CONFDIR "/tinc/%s", netname);
		else
			fprintf(stderr, "Both netname and configuration directory given, using the latter...\n");
	} else {
		if(!confbase)
			xasprintf(&confbase, CONFDIR "/tinc");
	}
}

static char buffer[4096];
static size_t blen = 0;

bool recvline(int fd, char *line, size_t len) {
	char *newline = NULL;

	while(!(newline = memchr(buffer, '\n', blen))) {
		int result = recv(fd, buffer + blen, sizeof buffer - blen, 0);
		if(result == -1 && errno == EINTR)
			continue;
		else if(result <= 0)
			return false;
		blen += result;
	}

	if(newline - buffer >= len)
		return false;

	len = newline - buffer;

	memcpy(line, buffer, len);
	line[len] = 0;
	memmove(buffer, newline + 1, blen - len - 1);
	blen -= len + 1;

	return true;
}

bool recvdata(int fd, char *data, size_t len) {
	while(blen < len) {
		int result = recv(fd, buffer + blen, sizeof buffer - blen, 0);
		if(result == -1 && errno == EINTR)
			continue;
		else if(result <= 0)
			return false;
		blen += result;
	}

	memcpy(data, buffer, len);
	memmove(buffer, buffer + len, blen - len);
	blen -= len;

	return true;
}

bool sendline(int fd, char *format, ...) {
	static char buffer[4096];
	char *p = buffer;
	int blen = 0;
	va_list ap;

	va_start(ap, format);
	blen = vsnprintf(buffer, sizeof buffer, format, ap);
	va_end(ap);

	if(blen < 1 || blen >= sizeof buffer)
		return false;

	buffer[blen] = '\n';
	blen++;

	while(blen) {
		int result = send(fd, p, blen, 0);
		if(result == -1 && errno == EINTR)
			continue;
		else if(result <= 0)
			return false;
		p += result;
		blen -= result;
	}

	return true;	
}

void pcap(int fd, FILE *out) {
	sendline(fd, "%d %d", CONTROL, REQ_PCAP);
	char data[9018];

	struct {
		uint32_t magic;
		uint16_t major;
		uint16_t minor;
		uint32_t tz_offset;
		uint32_t tz_accuracy;
		uint32_t snaplen;
		uint32_t ll_type;
	} header = {
		0xa1b2c3d4,
		2, 4,
		0, 0,
		sizeof data,
		1,
	};

	struct {
		uint32_t tv_sec;
		uint32_t tv_usec;
		uint32_t len;
		uint32_t origlen;
	} packet;

	struct timeval tv;

	fwrite(&header, sizeof header, 1, out);
	fflush(out);

	char line[32];
	while(recvline(fd, line, sizeof line)) {
		int code, req, len;
		int n = sscanf(line, "%d %d %d", &code, &req, &len);
		gettimeofday(&tv, NULL);
		if(n != 3 || code != CONTROL || req != REQ_PCAP || len < 0 || len > sizeof data)
			break;
		if(!recvdata(fd, data, len))
			break;
		packet.tv_sec = tv.tv_sec;
		packet.tv_usec = tv.tv_usec;
		packet.len = len;
		packet.origlen = len;
		fwrite(&packet, sizeof packet, 1, out);
		fwrite(data, len, 1, out);
		fflush(out);
	}
}

#ifdef HAVE_MINGW
static bool remove_service(void) {
	SC_HANDLE manager = NULL;
	SC_HANDLE service = NULL;
	SERVICE_STATUS status = {0};

	manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager) {
		fprintf(stderr, "Could not open service manager: %s\n", winerror(GetLastError()));
		return false;
	}

	service = OpenService(manager, identname, SERVICE_ALL_ACCESS);

	if(!service) {
		fprintf(stderr, "Could not open %s service: %s\n", identname, winerror(GetLastError()));
		return false;
	}

	if(!ControlService(service, SERVICE_CONTROL_STOP, &status))
		fprintf(stderr, "Could not stop %s service: %s\n", identname, winerror(GetLastError()));
	else
		fprintf(stderr, "%s service stopped\n", identname);

	if(!DeleteService(service)) {
		fprintf(stderr, "Could not remove %s service: %s\n", identname, winerror(GetLastError()));
		return false;
	}

	fprintf(stderr, "%s service removed\n", identname);

	return true;
}
#endif

int main(int argc, char *argv[], char *envp[]) {
	int fd;
	int result;
	char host[128];
	char port[128];
	int pid;

	program_name = argv[0];

	if(!parse_options(argc, argv))
		return 1;
	
	make_names();

	if(show_version) {
		printf("%s version %s (built %s %s, protocol %d.%d)\n", PACKAGE,
			   VERSION, __DATE__, __TIME__, PROT_MAJOR, PROT_MINOR);
		printf("Copyright (C) 1998-2009 Ivo Timmermans, Guus Sliepen and others.\n"
				"See the AUTHORS file for a complete list.\n\n"
				"tinc comes with ABSOLUTELY NO WARRANTY.  This is free software,\n"
				"and you are welcome to redistribute it under certain conditions;\n"
				"see the file COPYING for details.\n");

		return 0;
	}

	if(show_help) {
		usage(false);
		return 0;
	}

	if(optind >= argc) {
		fprintf(stderr, "Not enough arguments.\n");
		usage(true);
		return 1;
	}

	// First handle commands that don't involve connecting to a running tinc daemon.

	if(!strcasecmp(argv[optind], "generate-rsa-keys")) {
		return !rsa_keygen(optind > argc ? atoi(argv[optind + 1]) : 2048);
	}

	if(!strcasecmp(argv[optind], "generate-ecdsa-keys")) {
		return !ecdsa_keygen();
	}

	if(!strcasecmp(argv[optind], "generate-keys")) {
		return !(rsa_keygen(optind > argc ? atoi(argv[optind + 1]) : 2048) && ecdsa_keygen());
	}

	if(!strcasecmp(argv[optind], "start")) {
		argv[optind] = NULL;
		execve(SBINDIR "/tincd", argv, envp);
		fprintf(stderr, "Could not start tincd: %s", strerror(errno));
		return 1;
	}

	/*
	 * Now handle commands that do involve connecting to a running tinc daemon.
	 * Authenticate the server by ensuring the parent directory can be
	 * traversed only by root. Note this is not totally race-free unless all
	 * ancestors are writable only by trusted users, which we don't verify.
	 */

	FILE *f = fopen(pidfilename, "r");
	if(!f) {
		fprintf(stderr, "Could not open pid file %s: %s\n", pidfilename, strerror(errno));
		return 1;
	}
	if(fscanf(f, "%20d %1024s %128s port %128s", &pid, controlcookie, host, port) != 4) {
		fprintf(stderr, "Could not parse pid file %s\n", pidfilename);
		return 1;
	}

#ifdef HAVE_MINGW
	if(WSAStartup(MAKEWORD(2, 2), &wsa_state)) {
		fprintf(stderr, "System call `%s' failed: %s", "WSAStartup", winerror(GetLastError()));
		return 1;
	}
#endif

	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = 0,
	};

	struct addrinfo *res = NULL;

	if(getaddrinfo(host, port, &hints, &res) || !res) {
		fprintf(stderr, "Cannot resolve %s port %s: %s", host, port, strerror(errno));
		return 1;
	}

	fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
	if(fd < 0) {
		fprintf(stderr, "Cannot create TCP socket: %s\n", sockstrerror(sockerrno));
		return 1;
	}

#ifdef HAVE_MINGW
	unsigned long arg = 0;

	if(ioctlsocket(fd, FIONBIO, &arg) != 0) {
		fprintf(stderr, "ioctlsocket failed: %s", sockstrerror(sockerrno));
	}
#endif

	if(connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
		fprintf(stderr, "Cannot connect to %s port %s: %s\n", host, port, sockstrerror(sockerrno));
		return 1;
	}

	freeaddrinfo(res);

	char line[4096];
	char data[4096];
	int code, version, req;

	if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %s %d", &code, data, &version) != 3 || code != 0) {
		fprintf(stderr, "Cannot read greeting from control socket: %s\n",
				sockstrerror(sockerrno));
		return 1;
	}

	sendline(fd, "%d ^%s %d", ID, controlcookie, TINC_CTL_VERSION_CURRENT);
	
	if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &version, &pid) != 3 || code != 4 || version != TINC_CTL_VERSION_CURRENT) {
		fprintf(stderr, "Could not fully establish control socket connection\n");
		return 1;
	}

	if(!strcasecmp(argv[optind], "pid")) {
		printf("%d\n", pid);
		return 0;
	}

	if(!strcasecmp(argv[optind], "stop")) {
#ifndef HAVE_MINGW
		sendline(fd, "%d %d", CONTROL, REQ_STOP);
		if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_STOP || result) {
			fprintf(stderr, "Could not stop tinc daemon\n");
			return 1;
		}
#else
		if(!remove_service())
			return 1;
#endif
		return 0;
	}

	if(!strcasecmp(argv[optind], "reload")) {
		sendline(fd, "%d %d", CONTROL, REQ_RELOAD);
		if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_RELOAD || result) {
			fprintf(stderr, "Could not reload tinc daemon\n");
			return 1;
		}
		return 0;
	}

	if(!strcasecmp(argv[optind], "restart")) {
		sendline(fd, "%d %d", CONTROL, REQ_RESTART);
		if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_RESTART || result) {
			fprintf(stderr, "Could not restart tinc daemon\n");
			return 1;
		}
		return 0;
	}

	if(!strcasecmp(argv[optind], "retry")) {
		sendline(fd, "%d %d", CONTROL, REQ_RETRY);
		if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_RETRY || result) {
			fprintf(stderr, "Could not retry outgoing connections\n");
			return 1;
		}
		return 0;
	}

	if(!strcasecmp(argv[optind], "dump")) {
		if(argc < optind + 2) {
			fprintf(stderr, "Not enough arguments.\n");
			usage(true);
			return 1;
		}

		bool do_graph = false;

		if(!strcasecmp(argv[optind+1], "nodes"))
			sendline(fd, "%d %d", CONTROL, REQ_DUMP_NODES);
		else if(!strcasecmp(argv[optind+1], "edges"))
			sendline(fd, "%d %d", CONTROL, REQ_DUMP_EDGES);
		else if(!strcasecmp(argv[optind+1], "subnets"))
			sendline(fd, "%d %d", CONTROL, REQ_DUMP_SUBNETS);
		else if(!strcasecmp(argv[optind+1], "connections"))
			sendline(fd, "%d %d", CONTROL, REQ_DUMP_CONNECTIONS);
		else if(!strcasecmp(argv[optind+1], "graph")) {
			sendline(fd, "%d %d", CONTROL, REQ_DUMP_NODES);
			sendline(fd, "%d %d", CONTROL, REQ_DUMP_EDGES);
			do_graph = true;
			printf("digraph {\n");
		} else {
			fprintf(stderr, "Unknown dump type '%s'.\n", argv[optind+1]);
			usage(true);
			return 1;
		}

		while(recvline(fd, line, sizeof line)) {
			char node1[4096], node2[4096];
			int n = sscanf(line, "%d %d %s to %s", &code, &req, node1, node2);
			if(n == 2) {
				if(do_graph && req == REQ_DUMP_NODES)
					continue;
				else {
					if(do_graph)
						printf("}\n");
					return 0;
				}
			}
			if(n < 2)
				break;

			if(!do_graph)
				printf("%s\n", line + 5);
			else {
				if(req == REQ_DUMP_NODES)
					printf(" %s [label = \"%s\"];\n", node1, node1);
				else
					printf(" %s -> %s;\n", node1, node2);
			}
		}

		fprintf(stderr, "Error receiving dump\n");
		return 1;
	}

	if(!strcasecmp(argv[optind], "purge")) {
		sendline(fd, "%d %d", CONTROL, REQ_PURGE);
		if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_PURGE || result) {
			fprintf(stderr, "Could not purge tinc daemon\n");
			return 1;
		}
		return 0;
	}

	if(!strcasecmp(argv[optind], "debug")) {
		int debuglevel, origlevel;

		if(argc != optind + 2) {
			fprintf(stderr, "Invalid arguments.\n");
			return 1;
		}
		debuglevel = atoi(argv[optind+1]);

		sendline(fd, "%d %d %d", CONTROL, REQ_SET_DEBUG, debuglevel);
		if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &origlevel) != 3 || code != CONTROL || req != REQ_SET_DEBUG) {
			fprintf(stderr, "Could not purge tinc daemon\n");
			return 1;
		}

		fprintf(stderr, "Old level %d, new level %d\n", origlevel, debuglevel);
		return 0;
	}

	if(!strcasecmp(argv[optind], "connect")) {
		if(argc != optind + 2) {
			fprintf(stderr, "Invalid arguments.\n");
			return 1;
		}
		char *name = argv[optind + 1];

		sendline(fd, "%d %d %s", CONTROL, REQ_CONNECT, name);
		if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_CONNECT || result) {
			fprintf(stderr, "Could not connect to %s\n", name);
			return 1;
		}
		return 0;
	}

	if(!strcasecmp(argv[optind], "disconnect")) {
		if(argc != optind + 2) {
			fprintf(stderr, "Invalid arguments.\n");
			return 1;
		}
		char *name = argv[optind + 1];

		sendline(fd, "%d %d %s", CONTROL, REQ_DISCONNECT, name);
		if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_DISCONNECT || result) {
			fprintf(stderr, "Could not disconnect %s\n", name);
			return 1;
		}
		return 0;
	}

#ifdef HAVE_CURSES
	if(!strcasecmp(argv[optind], "top")) {
		top(fd);
		return 0;
	}
#endif

	if(!strcasecmp(argv[optind], "pcap")) {
		pcap(fd, stdout);
		return 0;
	}

	fprintf(stderr, "Unknown command `%s'.\n", argv[optind]);
	usage(true);
	
	close(fd);

	return 0;
}
