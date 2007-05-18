/*
    tincctl.c -- Controlling a running tincd
    Copyright (C) 2007 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id$
*/

#include "system.h"

#include <sys/un.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#include <getopt.h>

#include "conf.h"
#include "protocol.h"
#include "xalloc.h"

/* The name this program was run with. */
char *program_name = NULL;

/* If nonzero, display usage information and exit. */
bool show_help = false;

/* If nonzero, print the version on standard output and exit.  */
bool show_version = false;

/* If nonzero, it will attempt to kill a running tincd and exit. */
int kill_tincd = 0;

/* If nonzero, generate public/private keypair for this host/net. */
int generate_keys = 0;

char *identname = NULL;				/* program name for syslog */
char *pidfilename = NULL;			/* pid file location */
char *controlfilename = NULL;			/* pid file location */
char *confbase = NULL;
char *netname = NULL;

static int status;

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
		fprintf(stderr, _("Try `%s --help\' for more information.\n"),
				program_name);
	else {
		printf(_("Usage: %s [options] command\n\n"), program_name);
		printf(_("Valid options are:\n"
				"  -c, --config=DIR           Read configuration options from DIR.\n"
				"  -n, --net=NETNAME          Connect to net NETNAME.\n"
				"      --pidfile=FILENAME     Write PID to FILENAME.\n"
				"      --help                 Display this help and exit.\n"
				"      --version              Output version information and exit.\n"
				"Valid commands are:\n"
				"  start                      Start tincd.\n"
				"  stop                       Stop tincd.\n"
				"  restart                    Restart tincd.\n"
				"  reload                     Reload configuration of running tincd.\n"
				"  genkey [bits]              Generate a new public/private keypair.\n"
				"  dump                       Dump a list of one of the following things:\n"
				"    nodes                    - all known nodes in the VPN\n"
				"    edges                    - all known connections in the VPN\n"
				"    subnets                  - all known subnets in the VPN\n"
				"    connections              - all meta connections with ourself\n"
				"    graph                    - graph of the VPN in dotty format\n"
				"\n"));
		printf(_("Report bugs to tinc@tinc-vpn.org.\n"));
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

			case 5:					/* write PID to a file */
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

/* This function prettyprints the key generation process */

static void indicator(int a, int b, void *p) {
	switch (a) {
		case 0:
			fprintf(stderr, ".");
			break;

		case 1:
			fprintf(stderr, "+");
			break;

		case 2:
			fprintf(stderr, "-");
			break;

		case 3:
			switch (b) {
				case 0:
					fprintf(stderr, " p\n");
					break;

				case 1:
					fprintf(stderr, " q\n");
					break;

				default:
					fprintf(stderr, "?");
			}
			break;

		default:
			fprintf(stderr, "?");
	}
}

/*
  Generate a public/private RSA keypair, and ask for a file to store
  them in.
*/
static bool keygen(int bits) {
	RSA *rsa_key;
	FILE *f;
	char *name = NULL;
	char *filename;

	fprintf(stderr, _("Generating %d bits keys:\n"), bits);
	rsa_key = RSA_generate_key(bits, 0x10001, indicator, NULL);

	if(!rsa_key) {
		fprintf(stderr, _("Error during key generation!\n"));
		return false;
	} else
		fprintf(stderr, _("Done.\n"));

	asprintf(&filename, "%s/rsa_key.priv", confbase);
	f = ask_and_open(filename, _("private RSA key"), "a");

	if(!f)
		return false;
  
#ifdef HAVE_FCHMOD
	/* Make it unreadable for others. */
	fchmod(fileno(f), 0600);
#endif
		
	if(ftell(f))
		fprintf(stderr, _("Appending key to existing contents.\nMake sure only one key is stored in the file.\n"));

	PEM_write_RSAPrivateKey(f, rsa_key, NULL, NULL, 0, NULL, NULL);
	fclose(f);
	free(filename);

	if(name)
		asprintf(&filename, "%s/hosts/%s", confbase, name);
	else
		asprintf(&filename, "%s/rsa_key.pub", confbase);

	f = ask_and_open(filename, _("public RSA key"), "a");

	if(!f)
		return false;

	if(ftell(f))
		fprintf(stderr, _("Appending key to existing contents.\nMake sure only one key is stored in the file.\n"));

	PEM_write_RSAPublicKey(f, rsa_key);
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
	long len = sizeof(installdir);
#endif

	if(netname)
		asprintf(&identname, "tinc.%s", netname);
	else
		identname = xstrdup("tinc");

#ifdef HAVE_MINGW
	if(!RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\tinc", 0, KEY_READ, &key)) {
		if(!RegQueryValueEx(key, NULL, 0, 0, installdir, &len)) {
			if(!logfilename)
				asprintf(&logfilename, "%s/log/%s.log", identname);
			if(!confbase) {
				if(netname)
					asprintf(&confbase, "%s/%s", installdir, netname);
				else
					asprintf(&confbase, "%s", installdir);
			}
		}
		RegCloseKey(key);
		if(*installdir)
			return;
	}
#endif

	if(!pidfilename)
		asprintf(&pidfilename, LOCALSTATEDIR "/run/%s.pid", identname);

	asprintf(&controlfilename, LOCALSTATEDIR "/run/%s.control", identname);

	if(netname) {
		if(!confbase)
			asprintf(&confbase, CONFDIR "/tinc/%s", netname);
		else
			fprintf(stderr, _("Both netname and configuration directory given, using the latter...\n"));
	} else {
		if(!confbase)
			asprintf(&confbase, CONFDIR "/tinc");
	}
}

int main(int argc, char **argv) {
	int fd;
	struct sockaddr_un addr;
	program_name = argv[0];

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	if(!parse_options(argc, argv))
		return 1;
	
	make_names();

	if(show_version) {
		printf(_("%s version %s (built %s %s, protocol %d)\n"), PACKAGE,
			   VERSION, __DATE__, __TIME__, PROT_CURRENT);
		printf(_("Copyright (C) 1998-2007 Ivo Timmermans, Guus Sliepen and others.\n"
				"See the AUTHORS file for a complete list.\n\n"
				"tinc comes with ABSOLUTELY NO WARRANTY.  This is free software,\n"
				"and you are welcome to redistribute it under certain conditions;\n"
				"see the file COPYING for details.\n"));

		return 0;
	}

	if(show_help) {
		usage(false);
		return 0;
	}

	if(strlen(controlfilename) >= sizeof addr.sun_path) {
		fprintf(stderr, _("Control socket filename too long!\n"));
		return 1;
	}

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(fd < 0) {
		fprintf(stderr, _("Cannot create UNIX socket: %s\n"), strerror(errno));
		return 1;
	}

	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, controlfilename, sizeof addr.sun_path - 1);

	if(connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		fprintf(stderr, _("Cannot connect to %s: %s\n"), controlfilename, strerror(errno));
		return 1;
	}

	printf("Connected to %s.\n", controlfilename);

	close(fd);

	return 0;
}
