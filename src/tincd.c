/*
    tincd.c -- the main file for tincd
    Copyright (C) 1998-2003 Ivo Timmermans <ivo@o2w.nl>
                  2000-2003 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: tincd.c,v 1.10.4.80 2003/08/02 20:50:38 guus Exp $
*/

#include "system.h"

/* Darwin (MacOS/X) needs the following definition... */
#ifndef _P1003_1B_VISIBLE
#define _P1003_1B_VISIBLE
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include <lzo1x.h>

#include <getopt.h>

#include "conf.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
#include "protocol.h"
#include "utils.h"
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

/* If nonzero, use null ciphers and skip all key exchanges. */
bool bypass_security = false;

/* If nonzero, disable swapping for this process. */
bool do_mlock = false;

/* If nonzero, write log entries to a separate file. */
bool use_logfile = false;

char *identname = NULL;				/* program name for syslog */
char *pidfilename = NULL;			/* pid file location */
char *logfilename = NULL;			/* log file location */
char **g_argv;					/* a copy of the cmdline arguments */

int exitstatus = 0;

static struct option const long_options[] = {
	{"config", required_argument, NULL, 'c'},
	{"kill", optional_argument, NULL, 'k'},
	{"net", required_argument, NULL, 'n'},
	{"help", no_argument, NULL, 1},
	{"version", no_argument, NULL, 2},
	{"no-detach", no_argument, NULL, 'D'},
	{"generate-keys", optional_argument, NULL, 'K'},
	{"debug", optional_argument, NULL, 'd'},
	{"bypass-security", no_argument, NULL, 3},
	{"mlock", no_argument, NULL, 'L'},
	{"logfile", optional_argument, NULL, 4},
	{"pidfile", required_argument, NULL, 5},
	{NULL, 0, NULL, 0}
};

#ifdef HAVE_MINGW
static struct WSAData wsa_state;
#endif

static void usage(bool status)
{
	if(status)
		fprintf(stderr, _("Try `%s --help\' for more information.\n"),
				program_name);
	else {
		printf(_("Usage: %s [option]...\n\n"), program_name);
		printf(_("  -c, --config=DIR           Read configuration options from DIR.\n"
				"  -D, --no-detach            Don't fork and detach.\n"
				"  -d, --debug[=LEVEL]        Increase debug level or set it to LEVEL.\n"
				"  -k, --kill[=SIGNAL]        Attempt to kill a running tincd and exit.\n"
				"  -n, --net=NETNAME          Connect to net NETNAME.\n"
				"  -K, --generate-keys[=BITS] Generate public/private RSA keypair.\n"
				"  -L, --mlock                Lock tinc into main memory.\n"
				"      --logfile[=FILENAME]   Write log entries to a logfile.\n"
				"      --pidfile=FILENAME     Write PID to FILENAME.\n"
				"      --help                 Display this help and exit.\n"
				"      --version              Output version information and exit.\n\n"));
		printf(_("Report bugs to tinc@nl.linux.org.\n"));
	}
}

static bool parse_options(int argc, char **argv)
{
	int r;
	int option_index = 0;

	while((r = getopt_long(argc, argv, "c:DLd::k::n:K::", long_options, &option_index)) != EOF) {
		switch (r) {
			case 0:				/* long option */
				break;

			case 'c':				/* config file */
				confbase = xstrdup(optarg);
				break;

			case 'D':				/* no detach */
				do_detach = false;
				break;

			case 'L':				/* no detach */
				do_mlock = true;
				break;

			case 'd':				/* inc debug level */
				if(optarg)
					debug_level = atoi(optarg);
				else
					debug_level++;
				break;

			case 'k':				/* kill old tincds */
#ifndef HAVE_MINGW
				if(optarg) {
					if(!strcasecmp(optarg, "HUP"))
						kill_tincd = SIGHUP;
					else if(!strcasecmp(optarg, "TERM"))
						kill_tincd = SIGTERM;
					else if(!strcasecmp(optarg, "KILL"))
						kill_tincd = SIGKILL;
					else if(!strcasecmp(optarg, "USR1"))
						kill_tincd = SIGUSR1;
					else if(!strcasecmp(optarg, "USR2"))
						kill_tincd = SIGUSR2;
					else if(!strcasecmp(optarg, "WINCH"))
						kill_tincd = SIGWINCH;
					else if(!strcasecmp(optarg, "INT"))
						kill_tincd = SIGINT;
					else if(!strcasecmp(optarg, "ALRM"))
						kill_tincd = SIGALRM;
					else {
						kill_tincd = atoi(optarg);

						if(!kill_tincd) {
							fprintf(stderr, _("Invalid argument `%s'; SIGNAL must be a number or one of HUP, TERM, KILL, USR1, USR2, WINCH, INT or ALRM.\n"),
									optarg);
							usage(true);
							return false;
						}
					}
				} else
					kill_tincd = SIGTERM;
#else
					kill_tincd = 1;
#endif
				break;

			case 'n':				/* net name given */
				netname = xstrdup(optarg);
				break;

			case 'K':				/* generate public/private keypair */
				if(optarg) {
					generate_keys = atoi(optarg);

					if(generate_keys < 512) {
						fprintf(stderr, _("Invalid argument `%s'; BITS must be a number equal to or greater than 512.\n"),
								optarg);
						usage(true);
						return false;
					}

					generate_keys &= ~7;	/* Round it to bytes */
				} else
					generate_keys = 1024;
				break;

			case 1:					/* show help */
				show_help = true;
				break;

			case 2:					/* show version */
				show_version = true;
				break;

			case 3:					/* bypass security */
				bypass_security = true;
				break;

			case 4:					/* write log entries to a file */
				use_logfile = true;
				if(optarg)
					logfilename = xstrdup(optarg);
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

static void indicator(int a, int b, void *p)
{
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
static bool keygen(int bits)
{
	RSA *rsa_key;
	FILE *f;
	char *name = NULL;
	char *filename;

	fprintf(stderr, _("Generating %d bits keys:\n"), bits);
	rsa_key = RSA_generate_key(bits, 0xFFFF, indicator, NULL);

	if(!rsa_key) {
		fprintf(stderr, _("Error during key generation!\n"));
		return false;
	} else
		fprintf(stderr, _("Done.\n"));

	asprintf(&filename, "%s/rsa_key.priv", confbase);
	f = ask_and_safe_open(filename, _("private RSA key"), true, "a");

	if(!f)
		return false;

	if(ftell(f))
		fprintf(stderr, _("Appending key to existing contents.\nMake sure only one key is stored in the file.\n"));

	PEM_write_RSAPrivateKey(f, rsa_key, NULL, NULL, 0, NULL, NULL);
	fclose(f);
	free(filename);

	get_config_string(lookup_config(config_tree, "Name"), &name);

	if(name)
		asprintf(&filename, "%s/hosts/%s", confbase, name);
	else
		asprintf(&filename, "%s/rsa_key.pub", confbase);

	f = ask_and_safe_open(filename, _("public RSA key"), false, "a");

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
static void make_names(void)
{
	if(netname)
		asprintf(&identname, "tinc.%s", netname);
	else
		identname = xstrdup("tinc");

	if(!pidfilename)
		asprintf(&pidfilename, LOCALSTATEDIR "/run/%s.pid", identname);

	if(!logfilename)
		asprintf(&logfilename, LOCALSTATEDIR "/log/%s.log", identname);

	if(netname) {
		if(!confbase)
			asprintf(&confbase, "%s/tinc/%s", CONFDIR, netname);
		else
			logger(LOG_INFO, _("Both netname and configuration directory given, using the latter..."));
	} else {
		if(!confbase)
			asprintf(&confbase, "%s/tinc", CONFDIR);
	}
}

int main(int argc, char **argv)
{
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
		printf(_("Copyright (C) 1998-2003 Ivo Timmermans, Guus Sliepen and others.\n"
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

	if(kill_tincd)
		return !kill_other(kill_tincd);

	openlogger("tinc", LOGMODE_STDERR);

	/* Lock all pages into memory if requested */

	if(do_mlock)
#ifdef HAVE_MLOCKALL
		if(mlockall(MCL_CURRENT | MCL_FUTURE)) {
			logger(LOG_ERR, _("System call `%s' failed: %s"), "mlockall",
				   strerror(errno));
#else
	{
		logger(LOG_ERR, _("mlockall() not supported on this platform!"));
#endif
		return -1;
	}

	g_argv = argv;

	init_configuration(&config_tree);

	/* Slllluuuuuuurrrrp! */

	RAND_load_file("/dev/urandom", 1024);

	OpenSSL_add_all_algorithms();

	if(generate_keys) {
		read_server_config();
		return !keygen(generate_keys);
	}

	if(!read_server_config())
		return 1;

	if(lzo_init() != LZO_E_OK) {
		logger(LOG_ERR, _("Error initializing LZO compressor!"));
		return 1;
	}

#ifdef HAVE_MINGW
	if(WSAStartup(MAKEWORD(2, 2), &wsa_state)) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "WSAStartup", winerror(GetLastError()));
		return 1;
	}

	if(!do_detach || !init_service())
		return main2(argc, argv);
	else
		return 1;
}

int main2(int argc, char **argv)
{
#endif

	if(!detach())
		return 1;
		
	for(;;) {
		if(setup_network_connections()) {
			int status;
			status = main_loop();

		        close_network_connections();

			ifdebug(CONNECTIONS)
				dump_device_stats();

			logger(LOG_NOTICE, _("Terminating"));
			return status;
		}

		logger(LOG_ERR, _("Unrecoverable error"));
		cp_trace();

		if(do_detach) {
			logger(LOG_NOTICE, _("Restarting in %d seconds!"), maxtimeout);
			sleep(maxtimeout);
		} else {
			logger(LOG_ERR, _("Not restarting."));
			return 1;
		}
	}
}
