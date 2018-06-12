/*
    tincd.c -- the main file for tincd
    Copyright (C) 1998-2005 Ivo Timmermans
                  2000-2018 Guus Sliepen <guus@tinc-vpn.org>
                  2008      Max Rijevski <maksuf@gmail.com>
                  2009      Michael Tokarev <mjt@tls.msk.ru>
                  2010      Julien Muchembled <jm@jmuchemb.eu>
                  2010      Timothy Redaelli <timothy@redaelli.eu>

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

/* Darwin (MacOS/X) needs the following definition... */
#ifndef _P1003_1B_VISIBLE
#define _P1003_1B_VISIBLE
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_LZO
#include LZO1X_H
#endif

#ifndef HAVE_MINGW
#include <pwd.h>
#include <grp.h>
#include <time.h>
#endif

#include "conf.h"
#include "control.h"
#include "crypto.h"
#include "device.h"
#include "event.h"
#include "logger.h"
#include "names.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"
#include "version.h"

/* If nonzero, display usage information and exit. */
static bool show_help = false;

/* If nonzero, print the version on standard output and exit.  */
static bool show_version = false;

/* If nonzero, use null ciphers and skip all key exchanges. */
bool bypass_security = false;

#ifdef HAVE_MLOCKALL
/* If nonzero, disable swapping for this process. */
static bool do_mlock = false;
#endif

#ifndef HAVE_MINGW
/* If nonzero, chroot to netdir after startup. */
static bool do_chroot = false;

/* If !NULL, do setuid to given user after startup */
static const char *switchuser = NULL;
#endif

/* If nonzero, write log entries to a separate file. */
bool use_logfile = false;

/* If nonzero, use syslog instead of stderr in no-detach mode. */
bool use_syslog = false;

char **g_argv;                  /* a copy of the cmdline arguments */

static int status = 1;

static struct option const long_options[] = {
	{"config", required_argument, NULL, 'c'},
	{"net", required_argument, NULL, 'n'},
	{"help", no_argument, NULL, 1},
	{"version", no_argument, NULL, 2},
	{"no-detach", no_argument, NULL, 'D'},
	{"debug", optional_argument, NULL, 'd'},
	{"bypass-security", no_argument, NULL, 3},
	{"mlock", no_argument, NULL, 'L'},
	{"chroot", no_argument, NULL, 'R'},
	{"user", required_argument, NULL, 'U'},
	{"logfile", optional_argument, NULL, 4},
	{"syslog", no_argument, NULL, 's'},
	{"pidfile", required_argument, NULL, 5},
	{"option", required_argument, NULL, 'o'},
	{NULL, 0, NULL, 0}
};

#ifdef HAVE_MINGW
static struct WSAData wsa_state;
int main2(int argc, char **argv);
#endif

static void usage(bool status) {
	if(status)
		fprintf(stderr, "Try `%s --help\' for more information.\n",
		        program_name);
	else {
		printf("Usage: %s [option]...\n\n", program_name);
		printf("  -c, --config=DIR              Read configuration options from DIR.\n"
		       "  -D, --no-detach               Don't fork and detach.\n"
		       "  -d, --debug[=LEVEL]           Increase debug level or set it to LEVEL.\n"
		       "  -n, --net=NETNAME             Connect to net NETNAME.\n"
#ifdef HAVE_MLOCKALL
		       "  -L, --mlock                   Lock tinc into main memory.\n"
#endif
		       "      --logfile[=FILENAME]      Write log entries to a logfile.\n"
		       "  -s  --syslog                  Use syslog instead of stderr with --no-detach.\n"
		       "      --pidfile=FILENAME        Write PID and control socket cookie to FILENAME.\n"
		       "      --bypass-security         Disables meta protocol security, for debugging.\n"
		       "  -o, --option[HOST.]KEY=VALUE  Set global/host configuration value.\n"
#ifndef HAVE_MINGW
		       "  -R, --chroot                  chroot to NET dir at startup.\n"
		       "  -U, --user=USER               setuid to given USER at startup.\n"
#endif
		       "      --help                    Display this help and exit.\n"
		       "      --version                 Output version information and exit.\n\n");
		printf("Report bugs to tinc@tinc-vpn.org.\n");
	}
}

static bool parse_options(int argc, char **argv) {
	config_t *cfg;
	int r;
	int option_index = 0;
	int lineno = 0;

	cmdline_conf = list_alloc((list_action_t)free_config);

	while((r = getopt_long(argc, argv, "c:DLd::n:so:RU:", long_options, &option_index)) != EOF) {
		switch(r) {
		case 0:   /* long option */
			break;

		case 'c': /* config file */
			confbase = xstrdup(optarg);
			break;

		case 'D': /* no detach */
			do_detach = false;
			break;

		case 'L': /* no detach */
#ifndef HAVE_MLOCKALL
			logger(DEBUG_ALWAYS, LOG_ERR, "The %s option is not supported on this platform.", argv[optind - 1]);
			return false;
#else
			do_mlock = true;
			break;
#endif

		case 'd': /* increase debug level */
			if(!optarg && optind < argc && *argv[optind] != '-') {
				optarg = argv[optind++];
			}

			if(optarg) {
				debug_level = atoi(optarg);
			} else {
				debug_level++;
			}

			break;

		case 'n': /* net name given */
			netname = xstrdup(optarg);
			break;

		case 's': /* syslog */
			use_logfile = false;
			use_syslog = true;
			break;

		case 'o': /* option */
			cfg = parse_config_line(optarg, NULL, ++lineno);

			if(!cfg) {
				return false;
			}

			list_insert_tail(cmdline_conf, cfg);
			break;

#ifdef HAVE_MINGW

		case 'R':
		case 'U':
			logger(DEBUG_ALWAYS, LOG_ERR, "The %s option is not supported on this platform.", argv[optind - 1]);
			return false;
#else

		case 'R': /* chroot to NETNAME dir */
			do_chroot = true;
			break;

		case 'U': /* setuid to USER */
			switchuser = optarg;
			break;
#endif

		case 1:   /* show help */
			show_help = true;
			break;

		case 2:   /* show version */
			show_version = true;
			break;

		case 3:   /* bypass security */
			bypass_security = true;
			break;

		case 4:   /* write log entries to a file */
			use_syslog = false;
			use_logfile = true;

			if(!optarg && optind < argc && *argv[optind] != '-') {
				optarg = argv[optind++];
			}

			if(optarg) {
				logfilename = xstrdup(optarg);
			}

			break;

		case 5:   /* open control socket here */
			pidfilename = xstrdup(optarg);
			break;

		case '?': /* wrong options */
			usage(true);
			return false;

		default:
			break;
		}
	}

	if(optind < argc) {
		fprintf(stderr, "%s: unrecognized argument '%s'\n", argv[0], argv[optind]);
		usage(true);
		return false;
	}

	if(!netname && (netname = getenv("NETNAME"))) {
		netname = xstrdup(netname);
	}

	/* netname "." is special: a "top-level name" */

	if(netname && (!*netname || !strcmp(netname, "."))) {
		free(netname);
		netname = NULL;
	}

	if(netname && !check_netname(netname, false)) {
		fprintf(stderr, "Invalid character in netname!\n");
		return false;
	}

	if(netname && !check_netname(netname, true)) {
		fprintf(stderr, "Warning: unsafe character in netname!\n");
	}

	return true;
}

static bool drop_privs(void) {
#ifndef HAVE_MINGW
	uid_t uid = 0;

	if(switchuser) {
		struct passwd *pw = getpwnam(switchuser);

		if(!pw) {
			logger(DEBUG_ALWAYS, LOG_ERR, "unknown user `%s'", switchuser);
			return false;
		}

		uid = pw->pw_uid;

		if(initgroups(switchuser, pw->pw_gid) != 0 ||
		                setgid(pw->pw_gid) != 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s",
			       "initgroups", strerror(errno));
			return false;
		}

#ifndef __ANDROID__
// Not supported in android NDK
		endgrent();
		endpwent();
#endif
	}

	if(do_chroot) {
		tzset();        /* for proper timestamps in logs */

		if(chroot(confbase) != 0 || chdir("/") != 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s",
			       "chroot", strerror(errno));
			return false;
		}

		free(confbase);
		confbase = xstrdup("");
	}

	if(switchuser)
		if(setuid(uid) != 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s",
			       "setuid", strerror(errno));
			return false;
		}

#endif
	return true;
}

#ifdef HAVE_MINGW
# define setpriority(level) !SetPriorityClass(GetCurrentProcess(), (level))

static void stop_handler(void *data, int flags) {
	event_exit();
}

static BOOL WINAPI console_ctrl_handler(DWORD type) {
	logger(DEBUG_ALWAYS, LOG_NOTICE, "Got console shutdown request");

	if(WSASetEvent(stop_io.event) == FALSE) {
		abort();
	}

	return TRUE;
}
#else
# define NORMAL_PRIORITY_CLASS 0
# define BELOW_NORMAL_PRIORITY_CLASS 10
# define HIGH_PRIORITY_CLASS -10
# define setpriority(level) (setpriority(PRIO_PROCESS, 0, (level)))
#endif

int main(int argc, char **argv) {
	program_name = argv[0];

	if(!parse_options(argc, argv)) {
		return 1;
	}

	if(show_version) {
		printf("%s version %s (built %s %s, protocol %d.%d)\n", PACKAGE,
		       BUILD_VERSION, BUILD_DATE, BUILD_TIME, PROT_MAJOR, PROT_MINOR);
		printf("Copyright (C) 1998-2018 Ivo Timmermans, Guus Sliepen and others.\n"
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

	make_names(true);
	chdir(confbase);

#ifdef HAVE_MINGW

	if(WSAStartup(MAKEWORD(2, 2), &wsa_state)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "WSAStartup", winerror(GetLastError()));
		return 1;
	}

#else
	// Check if we got an umbilical fd from the process that started us
	char *umbstr = getenv("TINC_UMBILICAL");

	if(umbstr) {
		umbilical = atoi(umbstr);

		if(fcntl(umbilical, F_GETFL) < 0) {
			umbilical = 0;
		}

#ifdef FD_CLOEXEC

		if(umbilical) {
			fcntl(umbilical, F_SETFD, FD_CLOEXEC);
		}

#endif
	}

#endif

	openlogger("tinc", use_logfile ? LOGMODE_FILE : LOGMODE_STDERR);

	g_argv = argv;

	if(getenv("LISTEN_PID") && atoi(getenv("LISTEN_PID")) == getpid()) {
		do_detach = false;
	}

#ifdef HAVE_UNSETENV
	unsetenv("LISTEN_PID");
#endif

	init_configuration(&config_tree);

	/* Slllluuuuuuurrrrp! */

	gettimeofday(&now, NULL);
	srand(now.tv_sec + now.tv_usec);
	crypto_init();

	if(!read_server_config()) {
		return 1;
	}

	if(!debug_level) {
		get_config_int(lookup_config(config_tree, "LogLevel"), &debug_level);
	}

#ifdef HAVE_LZO

	if(lzo_init() != LZO_E_OK) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error initializing LZO compressor!");
		return 1;
	}

#endif

#ifdef HAVE_MINGW
	io_add_event(&stop_io, stop_handler, NULL, WSACreateEvent());

	if(stop_io.event == FALSE) {
		abort();
	}

	int result;

	if(!do_detach || !init_service()) {
		SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
		result = main2(argc, argv);
	} else {
		result = 1;
	}

	if(WSACloseEvent(stop_io.event) == FALSE) {
		abort();
	}

	io_del(&stop_io);
	return result;
}

int main2(int argc, char **argv) {
#endif
	char *priority = NULL;

	if(!detach()) {
		return 1;
	}

#ifdef HAVE_MLOCKALL

	/* Lock all pages into memory if requested.
	 * This has to be done after daemon()/fork() so it works for child.
	 * No need to do that in parent as it's very short-lived. */
	if(do_mlock && mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "mlockall",
		       strerror(errno));
		return 1;
	}

#endif

	/* Setup sockets and open device. */

	if(!setup_network()) {
		goto end;
	}

	/* Change process priority */

	if(get_config_string(lookup_config(config_tree, "ProcessPriority"), &priority)) {
		if(!strcasecmp(priority, "Normal")) {
			if(setpriority(NORMAL_PRIORITY_CLASS) != 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "setpriority", strerror(errno));
				goto end;
			}
		} else if(!strcasecmp(priority, "Low")) {
			if(setpriority(BELOW_NORMAL_PRIORITY_CLASS) != 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "setpriority", strerror(errno));
				goto end;
			}
		} else if(!strcasecmp(priority, "High")) {
			if(setpriority(HIGH_PRIORITY_CLASS) != 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "setpriority", strerror(errno));
				goto end;
			}
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid priority `%s`!", priority);
			goto end;
		}
	}

	/* drop privileges */
	if(!drop_privs()) {
		goto end;
	}

	/* Start main loop. It only exits when tinc is killed. */

	logger(DEBUG_ALWAYS, LOG_NOTICE, "Ready");

	if(umbilical) { // snip!
		write(umbilical, "", 1);
		close(umbilical);
		umbilical = 0;
	}

	try_outgoing_connections();

	status = main_loop();

	/* Shutdown properly. */

end:
	close_network_connections();

	logger(DEBUG_ALWAYS, LOG_NOTICE, "Terminating");

	free(priority);

	crypto_exit();

	exit_configuration(&config_tree);
	free(cmdline_conf);
	free_names();

	return status;
}
