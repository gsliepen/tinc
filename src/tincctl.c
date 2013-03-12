/*
    tincctl.c -- Controlling a running tincd
    Copyright (C) 2007-2013 Guus Sliepen <guus@tinc-vpn.org>

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

#ifdef HAVE_READLINE
#include "readline/readline.h"
#include "readline/history.h"
#endif

#include "xalloc.h"
#include "protocol.h"
#include "control_common.h"
#include "ecdsagen.h"
#include "info.h"
#include "names.h"
#include "rsagen.h"
#include "utils.h"
#include "tincctl.h"
#include "top.h"

#ifdef HAVE_MINGW
#define mkdir(a, b) mkdir(a)
#endif

static char **orig_argv;
static int orig_argc;

/* If nonzero, display usage information and exit. */
static bool show_help = false;

/* If nonzero, print the version on standard output and exit.  */
static bool show_version = false;

static char *name = NULL;
static char controlcookie[1025];
static char *tinc_conf = NULL;
static char *hosts_dir = NULL;
struct timeval now;

// Horrible global variables...
static int pid = 0;
static int fd = -1;
static char line[4096];
static int code;
static int req;
static int result;
static bool force = false;
static bool tty = true;

#ifdef HAVE_MINGW
static struct WSAData wsa_state;
#endif

static struct option const long_options[] = {
	{"config", required_argument, NULL, 'c'},
	{"debug", optional_argument, NULL, 0},
	{"no-detach", no_argument, NULL, 0},
	{"mlock", no_argument, NULL, 0},
	{"net", required_argument, NULL, 'n'},
	{"help", no_argument, NULL, 1},
	{"version", no_argument, NULL, 2},
	{"pidfile", required_argument, NULL, 5},
	{"logfile", required_argument, NULL, 0},
	{"bypass-security", no_argument, NULL, 0},
	{"chroot", no_argument, NULL, 0},
	{"user", required_argument, NULL, 0},
	{"option", required_argument, NULL, 0},
	{"force", no_argument, NULL, 6},
	{NULL, 0, NULL, 0}
};

static void version(void) {
	printf("%s version %s (built %s %s, protocol %d.%d)\n", PACKAGE,
		   VERSION, __DATE__, __TIME__, PROT_MAJOR, PROT_MINOR);
	printf("Copyright (C) 1998-2012 Ivo Timmermans, Guus Sliepen and others.\n"
			"See the AUTHORS file for a complete list.\n\n"
			"tinc comes with ABSOLUTELY NO WARRANTY.  This is free software,\n"
			"and you are welcome to redistribute it under certain conditions;\n"
			"see the file COPYING for details.\n");
}

static void usage(bool status) {
	if(status) {
		fprintf(stderr, "Try `%s --help\' for more information.\n", program_name);
	} else {
		printf("Usage: %s [options] command\n\n", program_name);
		printf("Valid options are:\n"
				"  -c, --config=DIR        Read configuration options from DIR.\n"
				"  -n, --net=NETNAME       Connect to net NETNAME.\n"
				"      --pidfile=FILENAME  Read control cookie from FILENAME.\n"
				"      --help              Display this help and exit.\n"
				"      --version           Output version information and exit.\n"
				"\n"
				"Valid commands are:\n"
				"  init [name]                Create initial configuration files.\n"
				"  get VARIABLE               Print current value of VARIABLE\n"
				"  set VARIABLE VALUE         Set VARIABLE to VALUE\n"
				"  add VARIABLE VALUE         Add VARIABLE with the given VALUE\n"
				"  del VARIABLE [VALUE]       Remove VARIABLE [only ones with watching VALUE]\n"
				"  start [tincd options]      Start tincd.\n"
				"  stop                       Stop tincd.\n"
				"  restart                    Restart tincd.\n"
				"  reload                     Partially reload configuration of running tincd.\n"
				"  pid                        Show PID of currently running tincd.\n"
				"  generate-keys [bits]       Generate new RSA and ECDSA public/private keypairs.\n"
				"  generate-rsa-keys [bits]   Generate a new RSA public/private keypair.\n"
				"  generate-ecdsa-keys        Generate a new ECDSA public/private keypair.\n"
				"  dump                       Dump a list of one of the following things:\n"
				"    [reachable] nodes        - all known nodes in the VPN\n"
				"    edges                    - all known connections in the VPN\n"
				"    subnets                  - all known subnets in the VPN\n"
				"    connections              - all meta connections with ourself\n"
				"    [di]graph                - graph of the VPN in dotty format\n"
				"  info NODE|SUBNET|ADDRESS   Give information about a particular NODE, SUBNET or ADDRESS.\n"
				"  purge                      Purge unreachable nodes\n"
				"  debug N                    Set debug level\n"
				"  retry                      Retry all outgoing connections\n"
				"  disconnect NODE            Close meta connection with NODE\n"
#ifdef HAVE_CURSES
				"  top                        Show real-time statistics\n"
#endif
				"  pcap [snaplen]             Dump traffic in pcap format [up to snaplen bytes per packet]\n"
				"  log [level]                Dump log output [up to the specified level]\n"
				"  export                     Export host configuration of local node to standard output\n"
				"  export-all                 Export all host configuration files to standard output\n"
				"  import [--force]           Import host configuration file(s) from standard input\n"
				"  exchange [--force]         Same as export followed by import\n"
				"  exchange-all [--force]     Same as export-all followed by import\n"
				"\n");
		printf("Report bugs to tinc@tinc-vpn.org.\n");
	}
}

static bool parse_options(int argc, char **argv) {
	int r;
	int option_index = 0;

	while((r = getopt_long(argc, argv, "c:n:Dd::Lo:RU:", long_options, &option_index)) != EOF) {
		switch (r) {
			case 0:   /* long option */
				break;

			case 'c': /* config file */
				confbase = xstrdup(optarg);
				break;

			case 'n': /* net name given */
				netname = xstrdup(optarg);
				break;

			case 1:   /* show help */
				show_help = true;
				break;

			case 2:   /* show version */
				show_version = true;
				break;

			case 5:   /* open control socket here */
				pidfilename = xstrdup(optarg);
				break;

			case 6:   /* force */
				force = true;
				break;

			case '?': /* wrong options */
				usage(true);
				return false;

			default:
				break;
		}
	}

	if(!netname && (netname = getenv("NETNAME")))
		netname = xstrdup(netname);

	/* netname "." is special: a "top-level name" */

	if(netname && (!*netname || !strcmp(netname, "."))) {
		free(netname);
		netname = NULL;
	}

	if(netname && (strpbrk(netname, "\\/") || *netname == '.')) {
		fprintf(stderr, "Invalid character in netname!\n");
		return false;
	}

	return true;
}

static void disable_old_keys(const char *filename, const char *what) {
	char tmpfile[PATH_MAX] = "";
	char buf[1024];
	bool disabled = false;
	bool block = false;
	bool error = false;
	FILE *r, *w;

	r = fopen(filename, "r");
	if(!r)
		return;

	snprintf(tmpfile, sizeof tmpfile, "%s.tmp", filename);

	w = fopen(tmpfile, "w");

	while(fgets(buf, sizeof buf, r)) {
		if(!block && !strncmp(buf, "-----BEGIN ", 11)) {
			if((strstr(buf, " EC ") && strstr(what, "ECDSA")) || (strstr(buf, " RSA ") && strstr(what, "RSA"))) {
				disabled = true;
				block = true;
			}
		}

		bool ecdsapubkey = !strncasecmp(buf, "ECDSAPublicKey", 14) && strchr(" \t=", buf[14]) && strstr(what, "ECDSA");

		if(ecdsapubkey)
			disabled = true;

		if(w) {
			if(block || ecdsapubkey)
				fputc('#', w);
			if(fputs(buf, w) < 0) {
				error = true;
				break;
			}
		}

		if(block && !strncmp(buf, "-----END ", 9))
			block = false;
	}

	if(w)
		if(fclose(w) < 0)
			error = true;
	if(ferror(r) || fclose(r) < 0)
		error = true;

	if(disabled) {
		if(!w || error) {
			fprintf(stderr, "Warning: old key(s) found, remove them by hand!\n");
			if(w)
				unlink(tmpfile);
			return;
		}

#ifdef HAVE_MINGW
		// We cannot atomically replace files on Windows.
		char bakfile[PATH_MAX] = "";
		snprintf(bakfile, sizeof bakfile, "%s.bak", filename);
		if(rename(filename, bakfile) || rename(tmpfile, filename)) {
			rename(bakfile, filename);
#else
		if(rename(tmpfile, filename)) {
#endif
			fprintf(stderr, "Warning: old key(s) found, remove them by hand!\n");
		} else  {
#ifdef HAVE_MINGW
			unlink(bakfile);
#endif
			fprintf(stderr, "Warning: old key(s) found and disabled.\n");
		}
	}

	unlink(tmpfile);
}

static FILE *ask_and_open(const char *filename, const char *what, const char *mode, bool ask) {
	FILE *r;
	char *directory;
	char buf[PATH_MAX];
	char buf2[PATH_MAX];

	/* Check stdin and stdout */
	if(ask && tty) {
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
		snprintf(buf2, sizeof buf2, "%s" SLASH "%s", directory, filename);
		filename = buf2;
	}

	umask(0077); /* Disallow everything for group and other */

	disable_old_keys(filename, what);

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
static bool ecdsa_keygen(bool ask) {
	ecdsa_t key;
	FILE *f;
	char *pubname, *privname;

	fprintf(stderr, "Generating ECDSA keypair:\n");

	if(!ecdsa_generate(&key)) {
		fprintf(stderr, "Error during key generation!\n");
		return false;
	} else
		fprintf(stderr, "Done.\n");

	xasprintf(&privname, "%s" SLASH "ecdsa_key.priv", confbase);
	f = ask_and_open(privname, "private ECDSA key", "a", ask);
	free(privname);

	if(!f)
		return false;

#ifdef HAVE_FCHMOD
	/* Make it unreadable for others. */
	fchmod(fileno(f), 0600);
#endif

	ecdsa_write_pem_private_key(&key, f);

	fclose(f);

	if(name)
		xasprintf(&pubname, "%s" SLASH "hosts" SLASH "%s", confbase, name);
	else
		xasprintf(&pubname, "%s" SLASH "ecdsa_key.pub", confbase);

	f = ask_and_open(pubname, "public ECDSA key", "a", ask);
	free(pubname);

	if(!f)
		return false;

	char *pubkey = ecdsa_get_base64_public_key(&key);
	fprintf(f, "ECDSAPublicKey = %s\n", pubkey);
	free(pubkey);

	fclose(f);

	return true;
}

/*
  Generate a public/private RSA keypair, and ask for a file to store
  them in.
*/
static bool rsa_keygen(int bits, bool ask) {
	rsa_t key;
	FILE *f;
	char *pubname, *privname;

	fprintf(stderr, "Generating %d bits keys:\n", bits);

	if(!rsa_generate(&key, bits, 0x10001)) {
		fprintf(stderr, "Error during key generation!\n");
		return false;
	} else
		fprintf(stderr, "Done.\n");

	xasprintf(&privname, "%s" SLASH "rsa_key.priv", confbase);
	f = ask_and_open(privname, "private RSA key", "a", ask);
	free(privname);

	if(!f)
		return false;

#ifdef HAVE_FCHMOD
	/* Make it unreadable for others. */
	fchmod(fileno(f), 0600);
#endif

	rsa_write_pem_private_key(&key, f);

	fclose(f);

	if(name)
		xasprintf(&pubname, "%s" SLASH "hosts" SLASH "%s", confbase, name);
	else
		xasprintf(&pubname, "%s" SLASH "rsa_key.pub", confbase);

	f = ask_and_open(pubname, "public RSA key", "a", ask);
	free(pubname);

	if(!f)
		return false;

	rsa_write_pem_public_key(&key, f);

	fclose(f);

	return true;
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

static bool recvdata(int fd, char *data, size_t len) {
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

static void pcap(int fd, FILE *out, int snaplen) {
	sendline(fd, "%d %d %d", CONTROL, REQ_PCAP, snaplen);
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
		snaplen ?: sizeof data,
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

static void logcontrol(int fd, FILE *out, int level) {
	sendline(fd, "%d %d %d", CONTROL, REQ_LOG, level);
	char data[1024];
	char line[32];

	while(recvline(fd, line, sizeof line)) {
		int code, req, len;
		int n = sscanf(line, "%d %d %d", &code, &req, &len);
		if(n != 3 || code != CONTROL || req != REQ_LOG || len < 0 || len > sizeof data)
			break;
		if(!recvdata(fd, data, len))
			break;
		fwrite(data, len, 1, out);
		fputc('\n', out);
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

static bool connect_tincd(bool verbose) {
	if(fd >= 0) {
		fd_set r;
		FD_ZERO(&r);
		FD_SET(fd, &r);
		struct timeval tv = {0, 0};
		if(select(fd + 1, &r, NULL, NULL, &tv)) {
			fprintf(stderr, "Previous connection to tincd lost, reconnecting.\n");
			close(fd);
			fd = -1;
		} else {
			return true;
		}
	}

	FILE *f = fopen(pidfilename, "r");
	if(!f) {
		if(verbose)
			fprintf(stderr, "Could not open pid file %s: %s\n", pidfilename, strerror(errno));
		return false;
	}

	char host[129];
	char port[129];

	if(fscanf(f, "%20d %1024s %128s port %128s", &pid, controlcookie, host, port) != 4) {
		if(verbose)
			fprintf(stderr, "Could not parse pid file %s\n", pidfilename);
		fclose(f);
		return false;
	}

	fclose(f);

#ifdef HAVE_MINGW
	if(WSAStartup(MAKEWORD(2, 2), &wsa_state)) {
		if(verbose)
			fprintf(stderr, "System call `%s' failed: %s", "WSAStartup", winerror(GetLastError()));
		return false;
	}
#endif

#ifndef HAVE_MINGW
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, unixsocketname, sizeof sa.sun_path);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(fd < 0) {
		if(verbose)
			fprintf(stderr, "Cannot create UNIX socket: %s\n", sockstrerror(sockerrno));
		return false;
	}

	if(connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		if(verbose)
			fprintf(stderr, "Cannot connect to UNIX socket %s: %s\n", unixsocketname, sockstrerror(sockerrno));
		close(fd);
		fd = -1;
		return false;
	}
#else
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = 0,
	};

	struct addrinfo *res = NULL;

	if(getaddrinfo(host, port, &hints, &res) || !res) {
		if(verbose)
			fprintf(stderr, "Cannot resolve %s port %s: %s", host, port, strerror(errno));
		return false;
	}

	fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
	if(fd < 0) {
		if(verbose)
			fprintf(stderr, "Cannot create TCP socket: %s\n", sockstrerror(sockerrno));
		return false;
	}

#ifdef HAVE_MINGW
	unsigned long arg = 0;

	if(ioctlsocket(fd, FIONBIO, &arg) != 0) {
		if(verbose)
			fprintf(stderr, "ioctlsocket failed: %s", sockstrerror(sockerrno));
	}
#endif

	if(connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
		if(verbose)
			fprintf(stderr, "Cannot connect to %s port %s: %s\n", host, port, sockstrerror(sockerrno));
		close(fd);
		fd = -1;
		return false;
	}

	freeaddrinfo(res);
#endif

	char data[4096];
	int version;

	if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %s %d", &code, data, &version) != 3 || code != 0) {
		if(verbose)
			fprintf(stderr, "Cannot read greeting from control socket: %s\n", sockstrerror(sockerrno));
		close(fd);
		fd = -1;
		return false;
	}

	sendline(fd, "%d ^%s %d", ID, controlcookie, TINC_CTL_VERSION_CURRENT);

	if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &version, &pid) != 3 || code != 4 || version != TINC_CTL_VERSION_CURRENT) {
		if(verbose)
			fprintf(stderr, "Could not fully establish control socket connection\n");
		close(fd);
		fd = -1;
		return false;
	}

	return true;
}


static int cmd_start(int argc, char *argv[]) {
	if(connect_tincd(false)) {
		if(netname)
			fprintf(stderr, "A tincd is already running for net `%s' with pid %d.\n", netname, pid);
		else
			fprintf(stderr, "A tincd is already running with pid %d.\n", pid);
		return 0;
	}

	char *c;
	char *slash = strrchr(program_name, '/');

#ifdef HAVE_MINGW
	if ((c = strrchr(program_name, '\\')) > slash)
		slash = c;
#endif

	if (slash++)
		xasprintf(&c, "%.*stincd", (int)(slash - program_name), program_name);
	else
		c = "tincd";

	int nargc = 0;
	char **nargv = xmalloc_and_zero((optind + argc) * sizeof *nargv);

	nargv[nargc++] = c;
	for(int i = 1; i < optind; i++)
		nargv[nargc++] = orig_argv[i];
	for(int i = 1; i < argc; i++)
		nargv[nargc++] = argv[i];

#ifdef HAVE_MINGW
	execvp(c, nargv);
	fprintf(stderr, "Error starting %s: %s\n", c, strerror(errno));
	return 1;
#else
	pid_t pid = fork();
	if(pid == -1) {
		fprintf(stderr, "Could not fork: %s\n", strerror(errno));
		free(nargv);
		return 1;
	}

	if(!pid)
		exit(execvp(c, nargv));

	free(nargv);

	int status = -1;
	if(waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
		fprintf(stderr, "Error starting %s\n", c);
		return 1;
	}

	return 0;
#endif
}

static int cmd_stop(int argc, char *argv[]) {
	if(argc > 1) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

#ifndef HAVE_MINGW
	if(!connect_tincd(true)) {
		if(pid) {
			if(kill(pid, SIGTERM)) {
				fprintf(stderr, "Could not send TERM signal to process with PID %u: %s\n", pid, strerror(errno));
				return 1;
			}

			fprintf(stderr, "Sent TERM signal to process with PID %u.\n", pid);
			waitpid(pid, NULL, 0);
			return 0;
		}

		return 1;
	}

	sendline(fd, "%d %d", CONTROL, REQ_STOP);

	while(recvline(fd, line, sizeof line)) {
		// Wait for tincd to close the connection...
	}
#else
	if(!remove_service())
		return 1;
#endif
	close(fd);
	pid = 0;
	fd = -1;

	return 0;
}

static int cmd_restart(int argc, char *argv[]) {
	cmd_stop(argc, argv);
	return cmd_start(argc, argv);
}

static int cmd_reload(int argc, char *argv[]) {
	if(argc > 1) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	if(!connect_tincd(true))
		return 1;

	sendline(fd, "%d %d", CONTROL, REQ_RELOAD);
	if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_RELOAD || result) {
		fprintf(stderr, "Could not reload configuration.\n");
		return 1;
	}

	return 0;

}

static int cmd_dump(int argc, char *argv[]) {
	bool only_reachable = false;

	if(argc > 2 && !strcasecmp(argv[1], "reachable")) {
		if(strcasecmp(argv[2], "nodes")) {
			fprintf(stderr, "`reachable' only supported for nodes.\n");
			usage(true);
			return 1;
		}
		only_reachable = true;
		argv++;
		argc--;
	}

	if(argc != 2) {
		fprintf(stderr, "Invalid number of arguments.\n");
		usage(true);
		return 1;
	}

	if(!connect_tincd(true))
		return 1;

	int do_graph = 0;

	if(!strcasecmp(argv[1], "nodes"))
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_NODES);
	else if(!strcasecmp(argv[1], "edges"))
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_EDGES);
	else if(!strcasecmp(argv[1], "subnets"))
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_SUBNETS);
	else if(!strcasecmp(argv[1], "connections"))
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_CONNECTIONS);
	else if(!strcasecmp(argv[1], "graph")) {
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_NODES);
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_EDGES);
		do_graph = 1;
	} else if(!strcasecmp(argv[1], "digraph")) {
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_NODES);
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_EDGES);
		do_graph = 2;
	} else {
		fprintf(stderr, "Unknown dump type '%s'.\n", argv[1]);
		usage(true);
		return 1;
	}

	if(do_graph == 1)
		printf("graph {\n");
	else if(do_graph == 2)
		printf("digraph {\n");

	while(recvline(fd, line, sizeof line)) {
		char node1[4096], node2[4096];
		int n = sscanf(line, "%d %d %s %s", &code, &req, node1, node2);
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

		char node[4096];
		char from[4096];
		char to[4096];
		char subnet[4096];
		char host[4096];
		char port[4096];
		char via[4096];
		char nexthop[4096];
		int cipher, digest, maclength, compression, distance, socket, weight;
		short int pmtu, minmtu, maxmtu;
		unsigned int options, status_int;
		node_status_t status;
		long int last_state_change;

		switch(req) {
			case REQ_DUMP_NODES: {
				int n = sscanf(line, "%*d %*d %s %s port %s %d %d %d %d %x %x %s %s %d %hd %hd %hd %ld", node, host, port, &cipher, &digest, &maclength, &compression, &options, &status_int, nexthop, via, &distance, &pmtu, &minmtu, &maxmtu, &last_state_change);
				if(n != 16) {
					fprintf(stderr, "Unable to parse node dump from tincd: %s\n", line);
					return 1;
				}

				memcpy(&status, &status_int, sizeof status);

				if(do_graph) {
					const char *color = "black";
					if(!strcmp(host, "MYSELF"))
						color = "green";
					else if(!status.reachable)
						color = "red";
					else if(strcmp(via, node))
						color = "orange";
					else if(!status.validkey)
						color = "black";
					else if(minmtu > 0)
						color = "green";
					printf(" %s [label = \"%s\", color = \"%s\"%s];\n", node, node, color, strcmp(host, "MYSELF") ? "" : ", style = \"filled\"");
				} else {
					if(only_reachable && !status.reachable)
						continue;
					printf("%s at %s port %s cipher %d digest %d maclength %d compression %d options %x status %04x nexthop %s via %s distance %d pmtu %hd (min %hd max %hd)\n",
							node, host, port, cipher, digest, maclength, compression, options, status_int, nexthop, via, distance, pmtu, minmtu, maxmtu);
				}
			} break;

			case REQ_DUMP_EDGES: {
				int n = sscanf(line, "%*d %*d %s %s %s port %s %x %d", from, to, host, port, &options, &weight);
				if(n != 6) {
					fprintf(stderr, "Unable to parse edge dump from tincd.\n");
					return 1;
				}

				if(do_graph) {
					float w = 1 + 65536.0 / weight;
					if(do_graph == 1 && strcmp(node1, node2) > 0)
						printf(" %s -- %s [w = %f, weight = %f];\n", node1, node2, w, w);
					else if(do_graph == 2)
						printf(" %s -> %s [w = %f, weight = %f];\n", node1, node2, w, w);
				} else {
					printf("%s to %s at %s port %s options %x weight %d\n", from, to, host, port, options, weight);
				}
			} break;

			case REQ_DUMP_SUBNETS: {
				int n = sscanf(line, "%*d %*d %s %s", subnet, node);
				if(n != 2) {
					fprintf(stderr, "Unable to parse subnet dump from tincd.\n");
					return 1;
				}
				printf("%s owner %s\n", strip_weight(subnet), node);
			} break;

			case REQ_DUMP_CONNECTIONS: {
				int n = sscanf(line, "%*d %*d %s %s port %s %x %d %x", node, host, port, &options, &socket, &status_int);
				if(n != 6) {
					fprintf(stderr, "Unable to parse connection dump from tincd.\n");
					return 1;
				}
				printf("%s at %s port %s options %x socket %d status %x\n", node, host, port, options, socket, status_int);
			} break;

			default:
				fprintf(stderr, "Unable to parse dump from tincd.\n");
				return 1;
		}
	}

	fprintf(stderr, "Error receiving dump.\n");
	return 1;
}

static int cmd_purge(int argc, char *argv[]) {
	if(argc > 1) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	if(!connect_tincd(true))
		return 1;

	sendline(fd, "%d %d", CONTROL, REQ_PURGE);
	if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_PURGE || result) {
		fprintf(stderr, "Could not purge old information.\n");
		return 1;
	}

	return 0;
}

static int cmd_debug(int argc, char *argv[]) {
	if(argc != 2) {
		fprintf(stderr, "Invalid number of arguments.\n");
		return 1;
	}

	if(!connect_tincd(true))
		return 1;

	int debuglevel = atoi(argv[1]);
	int origlevel;

	sendline(fd, "%d %d %d", CONTROL, REQ_SET_DEBUG, debuglevel);
	if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &origlevel) != 3 || code != CONTROL || req != REQ_SET_DEBUG) {
		fprintf(stderr, "Could not set debug level.\n");
		return 1;
	}

	fprintf(stderr, "Old level %d, new level %d.\n", origlevel, debuglevel);
	return 0;
}

static int cmd_retry(int argc, char *argv[]) {
	if(argc > 1) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	if(!connect_tincd(true))
		return 1;

	sendline(fd, "%d %d", CONTROL, REQ_RETRY);
	if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_RETRY || result) {
		fprintf(stderr, "Could not retry outgoing connections.\n");
		return 1;
	}

	return 0;
}

static int cmd_connect(int argc, char *argv[]) {
	if(argc != 2) {
		fprintf(stderr, "Invalid number of arguments.\n");
		return 1;
	}

	if(!check_id(argv[1])) {
		fprintf(stderr, "Invalid name for node.\n");
		return 1;
	}

	if(!connect_tincd(true))
		return 1;

	sendline(fd, "%d %d %s", CONTROL, REQ_CONNECT, argv[1]);
	if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_CONNECT || result) {
		fprintf(stderr, "Could not connect to %s.\n", argv[1]);
		return 1;
	}

	return 0;
}

static int cmd_disconnect(int argc, char *argv[]) {
	if(argc != 2) {
		fprintf(stderr, "Invalid number of arguments.\n");
		return 1;
	}

	if(!check_id(argv[1])) {
		fprintf(stderr, "Invalid name for node.\n");
		return 1;
	}

	if(!connect_tincd(true))
		return 1;

	sendline(fd, "%d %d %s", CONTROL, REQ_DISCONNECT, argv[1]);
	if(!recvline(fd, line, sizeof line) || sscanf(line, "%d %d %d", &code, &req, &result) != 3 || code != CONTROL || req != REQ_DISCONNECT || result) {
		fprintf(stderr, "Could not disconnect %s.\n", argv[1]);
		return 1;
	}

	return 0;
}

static int cmd_top(int argc, char *argv[]) {
	if(argc > 1) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

#ifdef HAVE_CURSES
	if(!connect_tincd(true))
		return 1;

	top(fd);
	return 0;
#else
	fprintf(stderr, "This version of tinc was compiled without support for the curses library.\n");
	return 1;
#endif
}

static int cmd_pcap(int argc, char *argv[]) {
	if(argc > 2) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	if(!connect_tincd(true))
		return 1;

	pcap(fd, stdout, argc > 1 ? atoi(argv[1]) : 0);
	return 0;
}

static int cmd_log(int argc, char *argv[]) {
	if(argc > 2) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	if(!connect_tincd(true))
		return 1;

	logcontrol(fd, stdout, argc > 1 ? atoi(argv[1]) : -1);
	return 0;
}

static int cmd_pid(int argc, char *argv[]) {
	if(argc > 1) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	if(!connect_tincd(true) && !pid)
		return 1;

	printf("%d\n", pid);
	return 0;
}

static int rstrip(char *value) {
	int len = strlen(value);
	while(len && strchr("\t\r\n ", value[len - 1]))
		value[--len] = 0;
	return len;
}

static char *get_my_name(bool verbose) {
	FILE *f = fopen(tinc_conf, "r");
	if(!f) {
		if(verbose)
			fprintf(stderr, "Could not open %s: %s\n", tinc_conf, strerror(errno));
		return NULL;
	}

	char buf[4096];
	char *value;
	while(fgets(buf, sizeof buf, f)) {
		int len = strcspn(buf, "\t =");
		value = buf + len;
		value += strspn(value, "\t ");
		if(*value == '=') {
			value++;
			value += strspn(value, "\t ");
		}
		if(!rstrip(value))
			continue;
		buf[len] = 0;
		if(strcasecmp(buf, "Name"))
			continue;
		if(*value) {
			fclose(f);
			return strdup(value);
		}
	}

	fclose(f);
	if(verbose)
		fprintf(stderr, "Could not find Name in %s.\n", tinc_conf);
	return NULL;
}

#define VAR_SERVER 1    /* Should be in tinc.conf */
#define VAR_HOST 2      /* Can be in host config file */
#define VAR_MULTIPLE 4  /* Multiple statements allowed */
#define VAR_OBSOLETE 8  /* Should not be used anymore */

static struct {
	const char *name;
	int type;
} const variables[] = {
	/* Server configuration */
	{"AddressFamily", VAR_SERVER},
	{"AutoConnect", VAR_SERVER},
	{"BindToAddress", VAR_SERVER | VAR_MULTIPLE},
	{"BindToInterface", VAR_SERVER},
	{"Broadcast", VAR_SERVER},
	{"ConnectTo", VAR_SERVER | VAR_MULTIPLE},
	{"DecrementTTL", VAR_SERVER},
	{"Device", VAR_SERVER},
	{"DeviceType", VAR_SERVER},
	{"DirectOnly", VAR_SERVER},
	{"ECDSAPrivateKeyFile", VAR_SERVER},
	{"ExperimentalProtocol", VAR_SERVER},
	{"Forwarding", VAR_SERVER},
	{"GraphDumpFile", VAR_SERVER | VAR_OBSOLETE},
	{"Hostnames", VAR_SERVER},
	{"IffOneQueue", VAR_SERVER},
	{"Interface", VAR_SERVER},
	{"KeyExpire", VAR_SERVER},
	{"LocalDiscovery", VAR_SERVER},
	{"MACExpire", VAR_SERVER},
	{"MaxOutputBufferSize", VAR_SERVER},
	{"MaxTimeout", VAR_SERVER},
	{"Mode", VAR_SERVER},
	{"Name", VAR_SERVER},
	{"PingInterval", VAR_SERVER},
	{"PingTimeout", VAR_SERVER},
	{"PriorityInheritance", VAR_SERVER},
	{"PrivateKey", VAR_SERVER | VAR_OBSOLETE},
	{"PrivateKeyFile", VAR_SERVER},
	{"ProcessPriority", VAR_SERVER},
	{"Proxy", VAR_SERVER},
	{"ReplayWindow", VAR_SERVER},
	{"ScriptsExtension", VAR_SERVER},
	{"ScriptsInterpreter", VAR_SERVER},
	{"StrictSubnets", VAR_SERVER},
	{"TunnelServer", VAR_SERVER},
	{"UDPRcvBuf", VAR_SERVER},
	{"UDPSndBuf", VAR_SERVER},
	{"VDEGroup", VAR_SERVER},
	{"VDEPort", VAR_SERVER},
	/* Host configuration */
	{"Address", VAR_HOST | VAR_MULTIPLE},
	{"Cipher", VAR_SERVER | VAR_HOST},
	{"ClampMSS", VAR_SERVER | VAR_HOST},
	{"Compression", VAR_SERVER | VAR_HOST},
	{"Digest", VAR_SERVER | VAR_HOST},
	{"ECDSAPublicKey", VAR_HOST},
	{"ECDSAPublicKeyFile", VAR_SERVER | VAR_HOST},
	{"IndirectData", VAR_SERVER | VAR_HOST},
	{"MACLength", VAR_SERVER | VAR_HOST},
	{"PMTU", VAR_SERVER | VAR_HOST},
	{"PMTUDiscovery", VAR_SERVER | VAR_HOST},
	{"Port", VAR_HOST},
	{"PublicKey", VAR_HOST | VAR_OBSOLETE},
	{"PublicKeyFile", VAR_SERVER | VAR_HOST | VAR_OBSOLETE},
	{"Subnet", VAR_HOST | VAR_MULTIPLE},
	{"TCPOnly", VAR_SERVER | VAR_HOST},
	{"Weight", VAR_HOST},
	{NULL, 0}
};

static int cmd_config(int argc, char *argv[]) {
	if(argc < 2) {
		fprintf(stderr, "Invalid number of arguments.\n");
		return 1;
	}

	if(strcasecmp(argv[0], "config"))
		argv--, argc++;

	int action = -2;
	if(!strcasecmp(argv[1], "get")) {
		argv++, argc--;
	} else if(!strcasecmp(argv[1], "add")) {
		argv++, argc--, action = 1;
	} else if(!strcasecmp(argv[1], "del")) {
		argv++, argc--, action = -1;
	} else if(!strcasecmp(argv[1], "replace") || !strcasecmp(argv[1], "set") || !strcasecmp(argv[1], "change")) {
		argv++, argc--, action = 0;
	}

	if(argc < 2) {
		fprintf(stderr, "Invalid number of arguments.\n");
		return 1;
	}

	// Concatenate the rest of the command line
	strncpy(line, argv[1], sizeof line - 1);
	for(int i = 2; i < argc; i++) {
		strncat(line, " ", sizeof line - 1 - strlen(line));
		strncat(line, argv[i], sizeof line - 1 - strlen(line));
	}

	// Liberal parsing into node name, variable name and value.
	char *node = NULL;
	char *variable;
	char *value;
	int len;

	len = strcspn(line, "\t =");
	value = line + len;
	value += strspn(value, "\t ");
	if(*value == '=') {
		value++;
		value += strspn(value, "\t ");
	}
	line[len] = '\0';
	variable = strchr(line, '.');
	if(variable) {
		node = line;
		*variable++ = 0;
	} else {
		variable = line;
	}

	if(!*variable) {
		fprintf(stderr, "No variable given.\n");
		return 1;
	}

	if(action >= 0 && !*value) {
		fprintf(stderr, "No value for variable given.\n");
		return 1;
	}

	if(action < -1 && *value)
		action = 0;

	/* Some simple checks. */
	bool found = false;

	for(int i = 0; variables[i].name; i++) {
		if(strcasecmp(variables[i].name, variable))
			continue;

		found = true;
		variable = (char *)variables[i].name;

		/* Discourage use of obsolete variables. */

		if(variables[i].type & VAR_OBSOLETE && action >= 0) {
			if(force) {
				fprintf(stderr, "Warning: %s is an obsolete variable!\n", variable);
			} else {
				fprintf(stderr, "%s is an obsolete variable! Use --force to use it anyway.\n", variable);
				return 1;
			}
		}

		/* Don't put server variables in host config files */

		if(node && !(variables[i].type & VAR_HOST) && action >= 0) {
			if(force) {
				fprintf(stderr, "Warning: %s is not a host configuration variable!\n", variable);
			} else {
				fprintf(stderr, "%s is not a host configuration variable! Use --force to use it anyway.\n", variable);
				return 1;
			}
		}

		/* Should this go into our own host config file? */

		if(!node && !(variables[i].type & VAR_SERVER)) {
			node = get_my_name(true);
			if(!node)
				return 1;
		}

		break;
	}

	if(node && !check_id(node)) {
		fprintf(stderr, "Invalid name for node.\n");
		return 1;
	}

	if(!found) {
		if(force || action < 0) {
			fprintf(stderr, "Warning: %s is not a known configuration variable!\n", variable);
		} else {
			fprintf(stderr, "%s: is not a known configuration variable! Use --force to use it anyway.\n", variable);
			return 1;
		}
	}

	// Open the right configuration file.
	char *filename;
	if(node)
		xasprintf(&filename, "%s" SLASH "%s", hosts_dir, node);
	else
		filename = tinc_conf;

	FILE *f = fopen(filename, "r");
	if(!f) {
		if(action < 0 || errno != ENOENT) {
			fprintf(stderr, "Could not open configuration file %s: %s\n", filename, strerror(errno));
			return 1;
		}

		// If it doesn't exist, create it.
		f = fopen(filename, "a+");
		if(!f) {
			fprintf(stderr, "Could not create configuration file %s: %s\n", filename, strerror(errno));
			return 1;
		} else {
			fprintf(stderr, "Created configuration file %s.\n", filename);
		}
	}

	char *tmpfile = NULL;
	FILE *tf = NULL;

	if(action >= -1) {
		xasprintf(&tmpfile, "%s.config.tmp", filename);
		tf = fopen(tmpfile, "w");
		if(!tf) {
			fprintf(stderr, "Could not open temporary file %s: %s\n", tmpfile, strerror(errno));
			fclose(f);
			return 1;
		}
	}

	// Copy the file, making modifications on the fly, unless we are just getting a value.
	char buf1[4096];
	char buf2[4096];
	bool set = false;
	bool removed = false;
	found = false;

	while(fgets(buf1, sizeof buf1, f)) {
		buf1[sizeof buf1 - 1] = 0;
		strncpy(buf2, buf1, sizeof buf2);

		// Parse line in a simple way
		char *bvalue;
		int len;

		len = strcspn(buf2, "\t =");
		bvalue = buf2 + len;
		bvalue += strspn(bvalue, "\t ");
		if(*bvalue == '=') {
			bvalue++;
			bvalue += strspn(bvalue, "\t ");
		}
		rstrip(bvalue);
		buf2[len] = '\0';

		// Did it match?
		if(!strcasecmp(buf2, variable)) {
			// Get
			if(action < -1) {
				found = true;
				printf("%s\n", bvalue);
			// Del
			} else if(action == -1) {
				if(!*value || !strcasecmp(bvalue, value)) {
					removed = true;
					continue;
				}
			// Set
			} else if(action == 0) {
				// Already set? Delete the rest...
				if(set)
					continue;
				// Otherwise, replace.
				if(fprintf(tf, "%s = %s\n", variable, value) < 0) {
					fprintf(stderr, "Error writing to temporary file %s: %s\n", tmpfile, strerror(errno));
					return 1;
				}
				set = true;
				continue;
			}
		}

		if(action >= -1) {
			// Copy original line...
			if(fputs(buf1, tf) < 0) {
				fprintf(stderr, "Error writing to temporary file %s: %s\n", tmpfile, strerror(errno));
				return 1;
			}

			// Add newline if it is missing...
			if(*buf1 && buf1[strlen(buf1) - 1] != '\n') {
				if(fputc('\n', tf) < 0) {
					fprintf(stderr, "Error writing to temporary file %s: %s\n", tmpfile, strerror(errno));
					return 1;
				}
			}
		}
	}

	// Make sure we read everything...
	if(ferror(f) || !feof(f)) {
		fprintf(stderr, "Error while reading from configuration file %s: %s\n", filename, strerror(errno));
		return 1;
	}

	if(fclose(f)) {
		fprintf(stderr, "Error closing configuration file %s: %s\n", filename, strerror(errno));
		return 1;
	}

	// Add new variable if necessary.
	if(action > 0 || (action == 0 && !set)) {
		if(fprintf(tf, "%s = %s\n", variable, value) < 0) {
			fprintf(stderr, "Error writing to temporary file %s: %s\n", tmpfile, strerror(errno));
			return 1;
		}
	}

	if(action < -1) {
		if(!found)
			fprintf(stderr, "No matching configuration variables found.\n");
		return 0;
	}

	// Make sure we wrote everything...
	if(fclose(tf)) {
		fprintf(stderr, "Error closing temporary file %s: %s\n", tmpfile, strerror(errno));
		return 1;
	}

	// Could we find what we had to remove?
	if(action < 0 && !removed) {
		remove(tmpfile);
		fprintf(stderr, "No configuration variables deleted.\n");
		return *value;
	}

	// Replace the configuration file with the new one
#ifdef HAVE_MINGW
	if(remove(filename)) {
		fprintf(stderr, "Error replacing file %s: %s\n", filename, strerror(errno));
		return 1;
	}
#endif
	if(rename(tmpfile, filename)) {
		fprintf(stderr, "Error renaming temporary file %s to configuration file %s: %s\n", tmpfile, filename, strerror(errno));
		return 1;
	}

	// Silently try notifying a running tincd of changes.
	if(connect_tincd(false))
		sendline(fd, "%d %d", CONTROL, REQ_RELOAD);

	return 0;
}

bool check_id(const char *name) {
	if(!name || !*name)
		return false;

	for(int i = 0; i < strlen(name); i++) {
		if(!isalnum(name[i]) && name[i] != '_')
			return false;
	}

	return true;
}

static int cmd_init(int argc, char *argv[]) {
	if(!access(tinc_conf, F_OK)) {
		fprintf(stderr, "Configuration file %s already exists!\n", tinc_conf);
		return 1;
	}

	if(argc > 2) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	} else if(argc < 2) {
		if(tty) {
			char buf[1024];
			fprintf(stdout, "Enter the Name you want your tinc node to have: ");
			fflush(stdout);
			if(!fgets(buf, sizeof buf, stdin)) {
				fprintf(stderr, "Error while reading stdin: %s\n", strerror(errno));
				return 1;
			}
			int len = rstrip(buf);
			if(!len) {
				fprintf(stderr, "No name given!\n");
				return 1;
			}
			name = strdup(buf);
		} else {
			fprintf(stderr, "No Name given!\n");
			return 1;
		}
	} else {
		name = strdup(argv[1]);
		if(!*name) {
			fprintf(stderr, "No Name given!\n");
			return 1;
		}
	}

	if(!check_id(name)) {
		fprintf(stderr, "Invalid Name! Only a-z, A-Z, 0-9 and _ are allowed characters.\n");
		return 1;
	}

	if(mkdir(confdir, 0755) && errno != EEXIST) {
		fprintf(stderr, "Could not create directory %s: %s\n", CONFDIR, strerror(errno));
		return 1;
	}

	if(mkdir(confbase, 0755) && errno != EEXIST) {
		fprintf(stderr, "Could not create directory %s: %s\n", confbase, strerror(errno));
		return 1;
	}

	if(mkdir(hosts_dir, 0755) && errno != EEXIST) {
		fprintf(stderr, "Could not create directory %s: %s\n", hosts_dir, strerror(errno));
		return 1;
	}

	FILE *f = fopen(tinc_conf, "w");
	if(!f) {
		fprintf(stderr, "Could not create file %s: %s\n", tinc_conf, strerror(errno));
		return 1;
	}

	fprintf(f, "Name = %s\n", name);
	fclose(f);

	if(!rsa_keygen(2048, false) || !ecdsa_keygen(false))
		return 1;

#ifndef HAVE_MINGW
	char *filename;
	xasprintf(&filename, "%s" SLASH "tinc-up", confbase);
	if(access(filename, F_OK)) {
		FILE *f = fopen(filename, "w");
		if(!f) {
			fprintf(stderr, "Could not create file %s: %s\n", filename, strerror(errno));
			return 1;
		}
		fchmod(fileno(f), 0755);
		fprintf(f, "#!/bin/sh\n\necho 'Unconfigured tinc-up script, please edit!'\n\n#ifconfig $INTERFACE <your vpn IP address> netmask <netmask of whole VPN>\n");
		fclose(f);
	}
#endif

	return 0;

}

static int cmd_generate_keys(int argc, char *argv[]) {
	if(argc > 2) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	if(!name)
		name = get_my_name(false);

	return !(rsa_keygen(argc > 1 ? atoi(argv[1]) : 2048, true) && ecdsa_keygen(true));
}

static int cmd_generate_rsa_keys(int argc, char *argv[]) {
	if(argc > 2) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	if(!name)
		name = get_my_name(false);

	return !rsa_keygen(argc > 1 ? atoi(argv[1]) : 2048, true);
}

static int cmd_generate_ecdsa_keys(int argc, char *argv[]) {
	if(argc > 1) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	if(!name)
		name = get_my_name(false);

	return !ecdsa_keygen(true);
}

static int cmd_help(int argc, char *argv[]) {
	usage(false);
	return 0;
}

static int cmd_version(int argc, char *argv[]) {
	if(argc > 1) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	version();
	return 0;
}

static int cmd_info(int argc, char *argv[]) {
	if(argc != 2) {
		fprintf(stderr, "Invalid number of arguments.\n");
		return 1;
	}

	if(!connect_tincd(true))
		return 1;

	return info(fd, argv[1]);
}

static const char *conffiles[] = {
	"tinc.conf",
	"tinc-up",
	"tinc-down",
	"subnet-up",
	"subnet-down",
	"host-up",
	"host-down",
	NULL,
};

static int cmd_edit(int argc, char *argv[]) {
	if(argc != 2) {
		fprintf(stderr, "Invalid number of arguments.\n");
		return 1;
	}

	char *filename = NULL;

	if(strncmp(argv[1], "hosts" SLASH, 6)) {
		for(int i = 0; conffiles[i]; i++) {
			if(!strcmp(argv[1], conffiles[i])) {
				xasprintf(&filename, "%s" SLASH "%s", confbase, argv[1]);
				break;
			}
		}
	} else {
		argv[1] += 6;
	}

	if(!filename) {
		xasprintf(&filename, "%s" SLASH "%s", hosts_dir, argv[1]);
		char *dash = strchr(argv[1], '-');
		if(dash) {
			*dash++ = 0;
			if((strcmp(dash, "up") && strcmp(dash, "down")) || !check_id(argv[1])) {
				fprintf(stderr, "Invalid configuration filename.\n");
				return 1;
			}
		}
	}

	char *command;
#ifndef HAVE_MINGW
	xasprintf(&command, "\"%s\" \"%s\"", getenv("VISUAL") ?: getenv("EDITOR") ?: "vi", filename);
#else
	xasprintf(&command, "edit \"%s\"", filename);
#endif
	int result = system(command);
	if(result)
		return result;

	// Silently try notifying a running tincd of changes.
	if(connect_tincd(false))
		sendline(fd, "%d %d", CONTROL, REQ_RELOAD);

	return 0;
}

static int export(const char *name, FILE *out) {
	char *filename;
	xasprintf(&filename, "%s" SLASH "%s", hosts_dir, name);
	FILE *in = fopen(filename, "r");
	if(!in) {
		fprintf(stderr, "Could not open configuration file %s: %s\n", filename, strerror(errno));
		return 1;
	}

	fprintf(out, "Name = %s\n", name);
	char buf[4096];
	while(fgets(buf, sizeof buf, in)) {
		if(strcspn(buf, "\t =") != 4 || strncasecmp(buf, "Name", 4))
			fputs(buf, out);
	}

	if(ferror(in)) {
		fprintf(stderr, "Error while reading configuration file %s: %s\n", filename, strerror(errno));
		fclose(in);
		return 1;
	}

	fclose(in);
	return 0;
}

static int cmd_export(int argc, char *argv[]) {
	if(argc > 1) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	char *name = get_my_name(true);
	if(!name)
		return 1;

	int result = export(name, stdout);
	if(!tty)
		fclose(stdout);

	free(name);
	return result;
}

static int cmd_export_all(int argc, char *argv[]) {
	if(argc > 1) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	DIR *dir = opendir(hosts_dir);
	if(!dir) {
		fprintf(stderr, "Could not open host configuration directory %s: %s\n", hosts_dir, strerror(errno));
		return 1;
	}

	bool first = true;
	int result = 0;
	struct dirent *ent;

	while((ent = readdir(dir))) {
		if(!check_id(ent->d_name))
			continue;

		if(first)
			first = false;
		else
			printf("#---------------------------------------------------------------#\n");

		result |= export(ent->d_name, stdout);
	}

	closedir(dir);
	if(!tty)
		fclose(stdout);
	return result;
}

static int cmd_import(int argc, char *argv[]) {
	if(argc > 1) {
		fprintf(stderr, "Too many arguments!\n");
		return 1;
	}

	FILE *in = stdin;
	FILE *out = NULL;

	char buf[4096];
	char name[4096];
	char *filename = NULL;
	int count = 0;
	bool firstline = true;

	while(fgets(buf, sizeof buf, in)) {
		if(sscanf(buf, "Name = %s", name) == 1) {
			firstline = false;

			if(!check_id(name)) {
				fprintf(stderr, "Invalid Name in input!\n");
				return 1;
			}

			if(out)
				fclose(out);

			free(filename);
			xasprintf(&filename, "%s" SLASH "%s", hosts_dir, name);

			if(!force && !access(filename, F_OK)) {
				fprintf(stderr, "Host configuration file %s already exists, skipping.\n", filename);
				out = NULL;
				continue;
			}

			out = fopen(filename, "w");
			if(!out) {
				fprintf(stderr, "Error creating configuration file %s: %s\n", filename, strerror(errno));
				return 1;
			}

			count++;
			continue;
		} else if(firstline) {
			fprintf(stderr, "Junk at the beginning of the input, ignoring.\n");
			firstline = false;
		}


		if(!strcmp(buf, "#---------------------------------------------------------------#\n"))
			continue;

		if(out) {
			if(fputs(buf, out) < 0) {
				fprintf(stderr, "Error writing to host configuration file %s: %s\n", filename, strerror(errno));
				return 1;
			}
		}
	}

	if(out)
		fclose(out);

	if(count) {
		fprintf(stderr, "Imported %d host configuration files.\n", count);
		return 0;
	} else {
		fprintf(stderr, "No host configuration files imported.\n");
		return 1;
	}
}

static int cmd_exchange(int argc, char *argv[]) {
	return cmd_export(argc, argv) ?: cmd_import(argc, argv);
}

static int cmd_exchange_all(int argc, char *argv[]) {
	return cmd_export_all(argc, argv) ?: cmd_import(argc, argv);
}

static const struct {
	const char *command;
	int (*function)(int argc, char *argv[]);
	bool hidden;
} commands[] = {
	{"start", cmd_start},
	{"stop", cmd_stop},
	{"restart", cmd_restart},
	{"reload", cmd_reload},
	{"dump", cmd_dump},
	{"purge", cmd_purge},
	{"debug", cmd_debug},
	{"retry", cmd_retry},
	{"connect", cmd_connect},
	{"disconnect", cmd_disconnect},
	{"top", cmd_top},
	{"pcap", cmd_pcap},
	{"log", cmd_log},
	{"pid", cmd_pid},
	{"config", cmd_config, true},
	{"add", cmd_config},
	{"del", cmd_config},
	{"get", cmd_config},
	{"set", cmd_config},
	{"init", cmd_init},
	{"generate-keys", cmd_generate_keys},
	{"generate-rsa-keys", cmd_generate_rsa_keys},
	{"generate-ecdsa-keys", cmd_generate_ecdsa_keys},
	{"help", cmd_help},
	{"version", cmd_version},
	{"info", cmd_info},
	{"edit", cmd_edit},
	{"export", cmd_export},
	{"export-all", cmd_export_all},
	{"import", cmd_import},
	{"exchange", cmd_exchange},
	{"exchange-all", cmd_exchange_all},
	{NULL, NULL},
};

#ifdef HAVE_READLINE
static char *complete_command(const char *text, int state) {
	static int i;

	if(!state)
		i = 0;
	else
		i++;

	while(commands[i].command) {
		if(!commands[i].hidden && !strncasecmp(commands[i].command, text, strlen(text)))
			return xstrdup(commands[i].command);
		i++;
	}

	return NULL;
}

static char *complete_dump(const char *text, int state) {
	const char *matches[] = {"reachable", "nodes", "edges", "subnets", "connections", "graph", NULL};
	static int i;

	if(!state)
		i = 0;
	else
		i++;

	while(matches[i]) {
		if(!strncasecmp(matches[i], text, strlen(text)))
			return xstrdup(matches[i]);
		i++;
	}

	return NULL;
}

static char *complete_config(const char *text, int state) {
	static int i;

	if(!state)
		i = 0;
	else
		i++;

	while(variables[i].name) {
		char *dot = strchr(text, '.');
		if(dot) {
			if((variables[i].type & VAR_HOST) && !strncasecmp(variables[i].name, dot + 1, strlen(dot + 1))) {
				char *match;
				xasprintf(&match, "%.*s.%s", dot - text, text, variables[i].name);
				return match;
			}
		} else {
			if(!strncasecmp(variables[i].name, text, strlen(text)))
				return xstrdup(variables[i].name);
		}
		i++;
	}

	return NULL;
}

static char *complete_info(const char *text, int state) {
	static int i;
	if(!state) {
		i = 0;
		if(!connect_tincd(false))
			return NULL;
		// Check the list of nodes
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_NODES);
		sendline(fd, "%d %d", CONTROL, REQ_DUMP_SUBNETS);
	}

	while(recvline(fd, line, sizeof line)) {
		char item[4096];
		int n = sscanf(line, "%d %d %s", &code, &req, item);
		if(n == 2) {
			i++;
			if(i >= 2)
				break;
			else
				continue;
		}

		if(n != 3) {
			fprintf(stderr, "Unable to parse dump from tincd, n = %d, i = %d.\n", n, i);
			break;
		}

		if(!strncmp(item, text, strlen(text)))
			return xstrdup(strip_weight(item));
	}

	return NULL;
}

static char *complete_nothing(const char *text, int state) {
	return NULL;
}

static char **completion (const char *text, int start, int end) {
	char **matches = NULL;

	if(!start)
		matches = rl_completion_matches(text, complete_command);
	else if(!strncasecmp(rl_line_buffer, "dump ", 5))
		matches = rl_completion_matches(text, complete_dump);
	else if(!strncasecmp(rl_line_buffer, "add ", 4))
		matches = rl_completion_matches(text, complete_config);
	else if(!strncasecmp(rl_line_buffer, "del ", 4))
		matches = rl_completion_matches(text, complete_config);
	else if(!strncasecmp(rl_line_buffer, "get ", 4))
		matches = rl_completion_matches(text, complete_config);
	else if(!strncasecmp(rl_line_buffer, "set ", 4))
		matches = rl_completion_matches(text, complete_config);
	else if(!strncasecmp(rl_line_buffer, "info ", 5))
		matches = rl_completion_matches(text, complete_info);

	return matches;
}
#endif

static int cmd_shell(int argc, char *argv[]) {
	char *prompt;
	xasprintf(&prompt, "%s> ", identname);
	int result = 0;
	char buf[4096];
	char *line = NULL;
	int maxargs = argc + 16;
	char **nargv = xmalloc(maxargs * sizeof *nargv);

	for(int i = 0; i < argc; i++)
		nargv[i] = argv[i];

#ifdef HAVE_READLINE
	rl_readline_name = "tinc";
	rl_completion_entry_function = complete_nothing;
	rl_attempted_completion_function = completion;
	rl_filename_completion_desired = 0;
	char *copy = NULL;
#endif

	while(true) {
#ifdef HAVE_READLINE
		if(tty) {
			free(copy);
			free(line);
			rl_basic_word_break_characters = "\t\n ";
			line = readline(prompt);
			if(line)
				copy = xstrdup(line);
		} else {
			line = fgets(buf, sizeof buf, stdin);
		}
#else
		if(tty)
			fputs(prompt, stdout);

		line = fgets(buf, sizeof buf, stdin);
#endif

		if(!line)
			break;

		/* Ignore comments */

		if(*line == '#')
			continue;

		/* Split */

		int nargc = argc;
		char *p = line + strspn(line, " \t\n");
		char *next = strtok(p, " \t\n");

		while(p && *p) {
			if(nargc >= maxargs) {
				fprintf(stderr, "next %p '%s', p %p '%s'\n", next, next, p, p);
				abort();
				maxargs *= 2;
				nargv = xrealloc(nargv, maxargs * sizeof *nargv);
			}

			nargv[nargc++] = p;
			p = next;
			next = strtok(NULL, " \t\n");
		}

		if(nargc == argc)
			continue;

		if(!strcasecmp(nargv[argc], "exit") || !strcasecmp(nargv[argc], "quit"))
			return result;

		bool found = false;

		for(int i = 0; commands[i].command; i++) {
			if(!strcasecmp(nargv[argc], commands[i].command)) {
				result |= commands[i].function(nargc - argc - 1, nargv + argc + 1);
				found = true;
				break;
			}
		}

#ifdef HAVE_READLINE
		if(tty && found)
			add_history(copy);
#endif

		if(!found) {
			fprintf(stderr, "Unknown command `%s'.\n", nargv[argc]);
			result |= 1;
		}
	}

	free(nargv);

	if(tty)
		printf("\n");
	return result;
}


int main(int argc, char *argv[]) {
	program_name = argv[0];
	orig_argv = argv;
	orig_argc = argc;

	if(!parse_options(argc, argv))
		return 1;

	make_names();
	xasprintf(&tinc_conf, "%s" SLASH "tinc.conf", confbase);
	xasprintf(&hosts_dir, "%s" SLASH "hosts", confbase);

	if(show_version) {
		version();
		return 0;
	}

	if(show_help) {
		usage(false);
		return 0;
	}

	tty = isatty(0) && isatty(1);

	if(optind >= argc)
		return cmd_shell(argc, argv);

	for(int i = 0; commands[i].command; i++) {
		if(!strcasecmp(argv[optind], commands[i].command))
			return commands[i].function(argc - optind, argv + optind);
	}

	fprintf(stderr, "Unknown command `%s'.\n", argv[optind]);
	usage(true);
	return 1;
}
