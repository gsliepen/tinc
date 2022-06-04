/*
    tincd.c -- the main file for tincd
    Copyright (C) 1998-2005 Ivo Timmermans
                  2000-2022 Guus Sliepen <guus@tinc-vpn.org>
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

#ifdef HAVE_LZO
#include LZO1X_H
#endif

#ifdef HAVE_LZ4
#include <lz4.h>
#endif

#ifndef HAVE_WINDOWS
#include <pwd.h>
#include <grp.h>
#include <time.h>
#endif

#include "conf.h"
#include "crypto.h"
#include "event.h"
#include "logger.h"
#include "names.h"
#include "net.h"
#include "process.h"
#include "protocol.h"
#include "utils.h"
#include "xalloc.h"
#include "version.h"
#include "random.h"
#include "sandbox.h"
#include "watchdog.h"
#include "fs.h"

/* If nonzero, display usage information and exit. */
static bool show_help = false;

/* If nonzero, print the version on standard output and exit.  */
static bool show_version = false;

#ifdef HAVE_MLOCKALL
/* If nonzero, disable swapping for this process. */
static bool do_mlock = false;
#endif

#ifndef HAVE_WINDOWS
/* If nonzero, chroot to netdir after startup. */
static bool do_chroot = false;

/* If !NULL, do setuid to given user after startup */
static const char *switchuser = NULL;
#endif

char **g_argv;                  /* a copy of the cmdline arguments */

static int status = 1;

typedef enum option_t {
	OPT_BAD_OPTION  = '?',
	OPT_LONG_OPTION =  0,

	// Short options
	OPT_CONFIG_FILE = 'c',
	OPT_NETNAME     = 'n',
	OPT_NO_DETACH   = 'D',
	OPT_DEBUG       = 'd',
	OPT_MLOCK       = 'L',
	OPT_CHROOT      = 'R',
	OPT_CHANGE_USER = 'U',
	OPT_SYSLOG      = 's',
	OPT_OPTION      = 'o',

	// Long options
	OPT_HELP        = 255,
	OPT_VERSION,
	OPT_NO_SECURITY,
	OPT_LOGFILE,
	OPT_PIDFILE,
} option_t;

static struct option const long_options[] = {
	{"config",          required_argument, NULL, OPT_CONFIG_FILE},
	{"net",             required_argument, NULL, OPT_NETNAME},
	{"no-detach",       no_argument,       NULL, OPT_NO_DETACH},
	{"debug",           optional_argument, NULL, OPT_DEBUG},
	{"mlock",           no_argument,       NULL, OPT_MLOCK},
	{"chroot",          no_argument,       NULL, OPT_CHROOT},
	{"user",            required_argument, NULL, OPT_CHANGE_USER},
	{"syslog",          no_argument,       NULL, OPT_SYSLOG},
	{"option",          required_argument, NULL, OPT_OPTION},
	{"help",            no_argument,       NULL, OPT_HELP},
	{"version",         no_argument,       NULL, OPT_VERSION},
	{"bypass-security", no_argument,       NULL, OPT_NO_SECURITY},
	{"logfile",         optional_argument, NULL, OPT_LOGFILE},
	{"pidfile",         required_argument, NULL, OPT_PIDFILE},
	{NULL,              0,                 NULL, 0},
};

#ifdef HAVE_WINDOWS
static struct WSAData wsa_state;
int main2(int argc, char **argv);
#endif

static void usage(bool status) {
	if(status)
		fprintf(stderr, "Try `%s --help\' for more information.\n",
		        program_name);
	else {
		fprintf(stdout,
		        "Usage: %s [option]...\n"
		        "\n"
		        "  -c, --config=DIR              Read configuration options from DIR.\n"
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
#ifndef HAVE_WINDOWS
		        "  -R, --chroot                  chroot to NET dir at startup.\n"
		        "  -U, --user=USER               setuid to given USER at startup.\n"
#endif
		        "      --help                    Display this help and exit.\n"
		        "      --version                 Output version information and exit.\n"
		        "\n"
		        "Report bugs to tinc@tinc-vpn.org.\n",
		        program_name);
	}
}

// Try to resolve path to absolute, return a copy of the argument if this fails.
static char *get_path_arg(char *arg) {
	char *result = absolute_path(arg);

	if(!result) {
		result = xstrdup(arg);
	}

	return result;
}

static bool parse_options(int argc, char **argv) {
	config_t *cfg;
	int r;
	int option_index = 0;
	int lineno = 0;

	while((r = getopt_long(argc, argv, "c:DLd::n:so:RU:", long_options, &option_index)) != EOF) {
		switch((option_t) r) {
		case OPT_LONG_OPTION:
			break;

		case OPT_BAD_OPTION:
			usage(true);
			goto exit_fail;

		case OPT_CONFIG_FILE:
			assert(optarg);
			free(confbase);
			confbase = get_path_arg(optarg);
			break;

		case OPT_NO_DETACH:
			do_detach = false;
			break;

		case OPT_MLOCK: /* lock tincd into RAM */
#ifndef HAVE_MLOCKALL
			logger(DEBUG_ALWAYS, LOG_ERR, "The %s option is not supported on this platform.", argv[optind - 1]);
			goto exit_fail;
#else
			do_mlock = true;
			break;
#endif

		case OPT_DEBUG: /* increase debug level */
			if(!optarg && optind < argc && *argv[optind] != '-') {
				optarg = argv[optind++];
			}

			if(optarg) {
				debug_level = atoi(optarg);
			} else {
				debug_level++;
			}

			break;

		case OPT_NETNAME:
			assert(optarg);
			free(netname);
			netname = xstrdup(optarg);
			break;

		case OPT_SYSLOG:
			use_logfile = false;
			use_syslog = true;
			break;

		case OPT_OPTION:
			cfg = parse_config_line(optarg, NULL, ++lineno);

			if(!cfg) {
				goto exit_fail;
			}

			list_insert_tail(&cmdline_conf, cfg);
			break;

#ifdef HAVE_WINDOWS

		case OPT_CHANGE_USER:
		case OPT_CHROOT:
			logger(DEBUG_ALWAYS, LOG_ERR, "The %s option is not supported on this platform.", argv[optind - 1]);
			goto exit_fail;
#else

		case OPT_CHROOT:
			do_chroot = true;
			break;

		case OPT_CHANGE_USER:
			switchuser = optarg;
			break;
#endif

		case OPT_HELP:
			show_help = true;
			break;

		case OPT_VERSION:
			show_version = true;
			break;

		case OPT_NO_SECURITY:
			bypass_security = true;
			break;

		case OPT_LOGFILE:
			use_syslog = false;
			use_logfile = true;

			if(!optarg && optind < argc && *argv[optind] != '-') {
				optarg = argv[optind++];
			}

			if(optarg) {
				free(logfilename);
				logfilename = get_path_arg(optarg);
			}

			break;

		case OPT_PIDFILE:
			assert(optarg);
			free(pidfilename);
			pidfilename = get_path_arg(optarg);
			break;

		default:
			break;
		}
	}

	if(optind < argc) {
		fprintf(stderr, "%s: unrecognized argument '%s'\n", argv[0], argv[optind]);
		usage(true);
		goto exit_fail;
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
		goto exit_fail;
	}

	if(netname && !check_netname(netname, true)) {
		fprintf(stderr, "Warning: unsafe character in netname!\n");
	}

	return true;

exit_fail:
	free_names();
	list_empty_list(&cmdline_conf);
	return false;
}

static bool read_sandbox_level(void) {
	sandbox_level_t level;
	char *value = NULL;

	if(get_config_string(lookup_config(&config_tree, "Sandbox"), &value)) {
		if(!strcasecmp("off", value)) {
			level = SANDBOX_NONE;
		} else if(!strcasecmp("normal", value)) {
			level = SANDBOX_NORMAL;
		} else if(!strcasecmp("high", value)) {
			level = SANDBOX_HIGH;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Bad sandbox value %s!", value);
			free(value);
			return false;
		}

		free(value);
	} else {
#ifdef HAVE_SANDBOX
		level = SANDBOX_NORMAL;
#else
		level = SANDBOX_NONE;
#endif
	}

#ifndef HAVE_SANDBOX

	if(level > SANDBOX_NONE) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Sandbox is used but is not supported on this platform");
		return false;
	}

#endif
	sandbox_set_level(level);
	return true;
}

static bool drop_privs(void) {
#ifndef HAVE_WINDOWS
	uid_t uid = 0;

	if(switchuser) {
		struct passwd *pw = getpwnam(switchuser);

		if(!pw) {
			logger(DEBUG_ALWAYS, LOG_ERR, "unknown user `%s'", switchuser);
			return false;
		}

		uid = pw->pw_uid;

		// The second parameter to initgroups on macOS requires int,
		// but __gid_t is unsigned int. There's not much we can do here.
		if(initgroups(switchuser, pw->pw_gid) != 0 || // NOLINT(bugprone-narrowing-conversions)
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

#endif // HAVE_WINDOWS

	makedirs(DIR_CACHE | DIR_HOSTS | DIR_INVITATIONS);

	return sandbox_enter();
}

#ifdef HAVE_WINDOWS
# define setpriority(level) !SetPriorityClass(GetCurrentProcess(), (level))

static void stop_handler(void *data, int flags) {
	(void)data;
	(void)flags;

	event_exit();
}

static BOOL WINAPI console_ctrl_handler(DWORD type) {
	(void)type;

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

static void cleanup(void) {
	splay_empty_tree(&config_tree);
	list_empty_list(&cmdline_conf);
	free_names();
}

int main(int argc, char **argv) {
	program_name = argv[0];

	if(!parse_options(argc, argv)) {
		return 1;
	}

	if(show_version) {
		fprintf(stdout,
		        "%s version %s (built %s %s, protocol %d.%d)\n"
		        "Features:"
#ifdef HAVE_OPENSSL
		        " openssl"
#endif
#ifdef HAVE_LIBGCRYPT
		        " libgcrypt"
#endif
#ifdef HAVE_LZO
		        " comp_lzo"
#endif
#ifdef HAVE_ZLIB
		        " comp_zlib"
#endif
#ifdef HAVE_LZ4
		        " comp_lz4"
#endif
#ifndef DISABLE_LEGACY
		        " legacy_protocol"
#endif
#ifdef ENABLE_JUMBOGRAMS
		        " jumbograms"
#endif
#ifdef ENABLE_TUNEMU
		        " tunemu"
#endif
#ifdef HAVE_MINIUPNPC
		        " miniupnpc"
#endif
#ifdef HAVE_SANDBOX
		        " sandbox"
#endif
#ifdef ENABLE_UML
		        " uml"
#endif
#ifdef ENABLE_VDE
		        " vde"
#endif
#ifdef HAVE_WATCHDOG
		        " watchdog"
#endif
		        "\n\n"
		        "Copyright (C) 1998-2021 Ivo Timmermans, Guus Sliepen and others.\n"
		        "See the AUTHORS file for a complete list.\n"
		        "\n"
		        "tinc comes with ABSOLUTELY NO WARRANTY.  This is free software,\n"
		        "and you are welcome to redistribute it under certain conditions;\n"
		        "see the file COPYING for details.\n",
		        PACKAGE, BUILD_VERSION, BUILD_DATE, BUILD_TIME, PROT_MAJOR, PROT_MINOR);
		return 0;
	}

	if(show_help) {
		usage(false);
		return 0;
	}

	make_names(true);
	atexit(cleanup);

	if(chdir(confbase) == -1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not change to configuration directory: %s", strerror(errno));
		return 1;
	}

#ifdef HAVE_WINDOWS

	if(WSAStartup(MAKEWORD(2, 2), &wsa_state)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "WSAStartup", winerror(GetLastError()));
		return 1;
	}

#else
	// Check if we got an umbilical fd from the process that started us
	char *umbstr = getenv("TINC_UMBILICAL");

	if(umbstr) {
		int colorize = 0;
		sscanf(umbstr, "%d %d", &umbilical, &colorize);
		umbilical_colorize = colorize;

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

	const char *listen_pid = getenv("LISTEN_PID");

	if(listen_pid && atoi(listen_pid) == getpid()) {
		do_detach = false;
	}

#ifdef HAVE_UNSETENV
	unsetenv("LISTEN_PID");
#endif

	gettimeofday(&now, NULL);
	random_init();
	crypto_init();
	prng_init();

	if(!read_server_config(&config_tree)) {
		return 1;
	}

	if(!read_sandbox_level()) {
		return 1;
	}

	if(debug_level == DEBUG_NOTHING) {
		int level = 0;

		if(get_config_int(lookup_config(&config_tree, "LogLevel"), &level)) {
			debug_level = level;
		}
	}

#ifdef HAVE_LZO

	if(lzo_init() != LZO_E_OK) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error initializing LZO compressor!");
		return 1;
	}

#endif

#ifdef HAVE_WINDOWS
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
	(void)argc;
	(void)argv;
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

	if(get_config_string(lookup_config(&config_tree, "ProcessPriority"), &priority)) {
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
		if(write(umbilical, "", 1) != 1) {
			// Pipe full or broken, nothing we can do about it.
		}

		close(umbilical);
		umbilical = 0;
	}

	try_outgoing_connections();

#ifdef HAVE_WATCHDOG
	watchdog_start();
#endif

	status = main_loop();

#ifdef HAVE_WATCHDOG
	watchdog_stop();
#endif

	/* Shutdown properly. */

end:
	close_network_connections();

	logger(DEBUG_ALWAYS, LOG_NOTICE, "Terminating");

	free(priority);

	random_exit();

	return status;
}
