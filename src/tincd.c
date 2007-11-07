/*
    tincd.c -- the main file for tincd
    Copyright (C) 1998-2005 Ivo Timmermans
                  2000-2007 Guus Sliepen <guus@tinc-vpn.org>

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
#include <openssl/engine.h>

#include LZO1X_H

#include <getopt.h>

#include "conf.h"
#include "control.h"
#include "device.h"
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

/* If nonzero, use null ciphers and skip all key exchanges. */
bool bypass_security = false;

/* If nonzero, disable swapping for this process. */
bool do_mlock = false;

/* If nonzero, write log entries to a separate file. */
bool use_logfile = false;

char *identname = NULL;				/* program name for syslog */
char *controlsocketname = NULL;			/* control socket location */
char *logfilename = NULL;			/* log file location */
char **g_argv;					/* a copy of the cmdline arguments */

static int status;

static struct option const long_options[] = {
	{"config", required_argument, NULL, 'c'},
	{"net", required_argument, NULL, 'n'},
	{"help", no_argument, NULL, 1},
	{"version", no_argument, NULL, 2},
	{"no-detach", no_argument, NULL, 'D'},
	{"debug", optional_argument, NULL, 'd'},
	{"bypass-security", no_argument, NULL, 3},
	{"mlock", no_argument, NULL, 'L'},
	{"logfile", optional_argument, NULL, 4},
	{"controlsocket", required_argument, NULL, 5},
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
		printf(_(	"  -c, --config=DIR              Read configuration options from DIR.\n"
				"  -D, --no-detach               Don't fork and detach.\n"
				"  -d, --debug[=LEVEL]           Increase debug level or set it to LEVEL.\n"
				"  -n, --net=NETNAME             Connect to net NETNAME.\n"
				"  -L, --mlock                   Lock tinc into main memory.\n"
				"      --logfile[=FILENAME]      Write log entries to a logfile.\n"
				"      --controlsocket=FILENAME  Open control socket at FILENAME.\n"
				"      --bypass-security         Disables meta protocol security, for debugging.\n"
				"      --help                    Display this help and exit.\n"
				"      --version                 Output version information and exit.\n\n"));
		printf(_("Report bugs to tinc@tinc-vpn.org.\n"));
	}
}

static bool parse_options(int argc, char **argv)
{
	int r;
	int option_index = 0;

	while((r = getopt_long(argc, argv, "c:DLd::n:", long_options, &option_index)) != EOF) {
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

			case 'n':				/* net name given */
				netname = xstrdup(optarg);
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

			case 5:					/* open control socket here */
				controlsocketname = xstrdup(optarg);
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

/*
  Set all files and paths according to netname
*/
static void make_names(void)
{
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

	if(!controlsocketname)
		asprintf(&controlsocketname, LOCALSTATEDIR "/run/%s.control", identname);

	if(!logfilename)
		asprintf(&logfilename, LOCALSTATEDIR "/log/%s.log", identname);

	if(netname) {
		if(!confbase)
			asprintf(&confbase, CONFDIR "/tinc/%s", netname);
		else
			logger(LOG_INFO, _("Both netname and configuration directory given, using the latter..."));
	} else {
		if(!confbase)
			asprintf(&confbase, CONFDIR "/tinc");
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

	openlogger("tinc", use_logfile?LOGMODE_FILE:LOGMODE_STDERR);

	if(!event_init()) {
		logger(LOG_ERR, _("Error initializing libevent!"));
		return 1;
	}

	if(!init_control())
		return 1;

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

	srand(time(NULL));
	RAND_load_file("/dev/urandom", 1024);

	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	OpenSSL_add_all_algorithms();

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
		

	/* Setup sockets and open device. */

	if(!setup_network_connections())
		goto end;

	/* Start main loop. It only exits when tinc is killed. */

	status = main_loop();

	/* Shutdown properly. */

	close_network_connections();

	ifdebug(CONNECTIONS)
		dump_device_stats();

end:
	logger(LOG_NOTICE, _("Terminating"));

#ifndef HAVE_MINGW
	exit_control();
#endif

	EVP_cleanup();
	
	return status;
}
