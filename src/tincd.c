/*
    tincd.c -- the main file for tincd
    Copyright (C) 1998-2005 Ivo Timmermans
                  2000-2015 Guus Sliepen <guus@tinc-vpn.org>
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

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#ifdef HAVE_LZO
#include LZO1X_H
#endif

#ifndef HAVE_MINGW
#include <pwd.h>
#include <grp.h>
#include <time.h>
#endif

#include <getopt.h>
#include "pidfile.h"

#include "conf.h"
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

/* If nonzero, it will attempt to kill a running tincd and exit. */
int kill_tincd = 0;

/* If nonzero, generate public/private keypair for this host/net. */
int generate_keys = 0;

/* If nonzero, use null ciphers and skip all key exchanges. */
bool bypass_security = false;

/* If nonzero, disable swapping for this process. */
bool do_mlock = false;

/* If nonzero, chroot to netdir after startup. */
static bool do_chroot = false;

/* If !NULL, do setuid to given user after startup */
static const char *switchuser = NULL;

/* If nonzero, write log entries to a separate file. */
bool use_logfile = false;

char *identname = NULL;				/* program name for syslog */
char *pidfilename = NULL;			/* pid file location */
char *logfilename = NULL;			/* log file location */
char **g_argv;					/* a copy of the cmdline arguments */

static int status = 1;

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
	{"chroot", no_argument, NULL, 'R'},
	{"user", required_argument, NULL, 'U'},
	{"logfile", optional_argument, NULL, 4},
	{"pidfile", required_argument, NULL, 5},
	{"option", required_argument, NULL, 'o'},
	{NULL, 0, NULL, 0}
};

#ifdef HAVE_MINGW
static struct WSAData wsa_state;
CRITICAL_SECTION mutex;
int main2(int argc, char **argv);
#endif

static void usage(bool status) {
	if(status)
		fprintf(stderr, "Try `%s --help\' for more information.\n",
				program_name);
	else {
		printf("Usage: %s [option]...\n\n", program_name);
		printf("  -c, --config=DIR               Read configuration options from DIR.\n"
				"  -D, --no-detach                Don't fork and detach.\n"
				"  -d, --debug[=LEVEL]            Increase debug level or set it to LEVEL.\n"
				"  -k, --kill[=SIGNAL]            Attempt to kill a running tincd and exit.\n"
				"  -n, --net=NETNAME              Connect to net NETNAME.\n"
				"  -K, --generate-keys[=BITS]     Generate public/private RSA keypair.\n"
				"  -L, --mlock                    Lock tinc into main memory.\n"
				"      --logfile[=FILENAME]       Write log entries to a logfile.\n"
				"      --pidfile=FILENAME         Write PID to FILENAME.\n"
				"  -o, --option=[HOST.]KEY=VALUE  Set global/host configuration value.\n"
				"  -R, --chroot                   chroot to NET dir at startup.\n"
				"  -U, --user=USER                setuid to given USER at startup.\n"
				"      --help                     Display this help and exit.\n"
				"      --version                  Output version information and exit.\n\n");
		printf("Report bugs to tinc@tinc-vpn.org.\n");
	}
}

static bool parse_options(int argc, char **argv) {
	config_t *cfg;
	int r;
	int option_index = 0;
	int lineno = 0;

	cmdline_conf = list_alloc((list_action_t)free_config);

	while((r = getopt_long(argc, argv, "c:DLd::k::n:o:K::RU:", long_options, &option_index)) != EOF) {
		switch (r) {
			case 0:				/* long option */
				break;

			case 'c':				/* config file */
				if(confbase) {
					fprintf(stderr, "Only one configuration directory can be given.\n");
					usage(true);
					return false;
				}
				confbase = xstrdup(optarg);
				break;

			case 'D':				/* no detach */
				do_detach = false;
				break;

			case 'L':				/* no detach */
#ifndef HAVE_MLOCKALL
				logger(LOG_ERR, "%s not supported on this platform", "mlockall()");
				return false;
#else
				do_mlock = true;
				break;
#endif

			case 'd':				/* increase debug level */
				if(!optarg && optind < argc && *argv[optind] != '-')
					optarg = argv[optind++];
				if(optarg)
					debug_level = atoi(optarg);
				else
					debug_level++;
				break;

			case 'k':				/* kill old tincds */
#ifndef HAVE_MINGW
				if(!optarg && optind < argc && *argv[optind] != '-')
					optarg = argv[optind++];
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
					else if(!strcasecmp(optarg, "ABRT"))
						kill_tincd = SIGABRT;
					else {
						kill_tincd = atoi(optarg);

						if(!kill_tincd) {
							fprintf(stderr, "Invalid argument `%s'; SIGNAL must be a number or one of HUP, TERM, KILL, USR1, USR2, WINCH, INT or ALRM.\n",
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
				/* netname "." is special: a "top-level name" */
				if(netname) {
					fprintf(stderr, "Only one netname can be given.\n");
					usage(true);
					return false;
				}
				netname = strcmp(optarg, ".") != 0 ? xstrdup(optarg) : NULL;
				break;

			case 'o':				/* option */
				cfg = parse_config_line(optarg, NULL, ++lineno);
				if (!cfg)
					return false;
				list_insert_tail(cmdline_conf, cfg);
				break;

			case 'K':				/* generate public/private keypair */
				if(!optarg && optind < argc && *argv[optind] != '-')
					optarg = argv[optind++];
				if(optarg) {
					generate_keys = atoi(optarg);

					if(generate_keys < 512) {
						fprintf(stderr, "Invalid argument `%s'; BITS must be a number equal to or greater than 512.\n",
								optarg);
						usage(true);
						return false;
					}

					generate_keys &= ~7;	/* Round it to bytes */
				} else
					generate_keys = 2048;
				break;

			case 'R':				/* chroot to NETNAME dir */
				do_chroot = true;
				break;

			case 'U':				/* setuid to USER */
				switchuser = optarg;
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
				if(!optarg && optind < argc && *argv[optind] != '-')
					optarg = argv[optind++];
				if(optarg) {
					if(logfilename) {
						fprintf(stderr, "Only one logfile can be given.\n");
						usage(true);
						return false;
					}
					logfilename = xstrdup(optarg);
				}
				break;

			case 5:					/* write PID to a file */
				if(pidfilename) {
					fprintf(stderr, "Only one pidfile can be given.\n");
					usage(true);
					return false;
				}
				pidfilename = xstrdup(optarg);
				break;

			case '?':
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
	char *pubname, *privname;

	fprintf(stderr, "Generating %d bits keys:\n", bits);
	rsa_key = RSA_generate_key(bits, 0x10001, indicator, NULL);

	if(!rsa_key) {
		fprintf(stderr, "Error during key generation!\n");
		return false;
	} else
		fprintf(stderr, "Done.\n");

	xasprintf(&privname, "%s/rsa_key.priv", confbase);
	f = ask_and_open(privname, "private RSA key");
	free(privname);

	if(!f)
		return false;

#ifdef HAVE_FCHMOD
	/* Make it unreadable for others. */
	fchmod(fileno(f), 0600);
#endif
		
	fputc('\n', f);
	PEM_write_RSAPrivateKey(f, rsa_key, NULL, NULL, 0, NULL, NULL);
	fclose(f);

	char *name = get_name();

	if(name) {
		xasprintf(&pubname, "%s/hosts/%s", confbase, name);
		free(name);
	} else {
		xasprintf(&pubname, "%s/rsa_key.pub", confbase);
	}

	f = ask_and_open(pubname, "public RSA key");
	free(pubname);

	if(!f)
		return false;

	fputc('\n', f);
	PEM_write_RSAPublicKey(f, rsa_key);
	fclose(f);

	return true;
}

/*
  Set all files and paths according to netname
*/
static void make_names(void) {
#ifdef HAVE_MINGW
	HKEY key;
	char installdir[1024] = "";
	DWORD len = sizeof(installdir);
#endif

	if(netname)
		xasprintf(&identname, "tinc.%s", netname);
	else
		identname = xstrdup("tinc");

#ifdef HAVE_MINGW
	if(!RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\tinc", 0, KEY_READ, &key)) {
		if(!RegQueryValueEx(key, NULL, 0, 0, (LPBYTE)installdir, &len)) {
			if(!confbase) {
				if(netname)
					xasprintf(&confbase, "%s/%s", installdir, netname);
				else
					xasprintf(&confbase, "%s", installdir);
			}
			if(!logfilename)
				xasprintf(&logfilename, "%s/tinc.log", confbase);
		}
		RegCloseKey(key);
		if(*installdir)
			return;
	}
#endif

	if(!pidfilename)
		xasprintf(&pidfilename, LOCALSTATEDIR "/run/%s.pid", identname);

	if(!logfilename)
		xasprintf(&logfilename, LOCALSTATEDIR "/log/%s.log", identname);

	if(netname) {
		if(!confbase)
			xasprintf(&confbase, CONFDIR "/tinc/%s", netname);
		else
			logger(LOG_INFO, "Both netname and configuration directory given, using the latter...");
	} else {
		if(!confbase)
			xasprintf(&confbase, CONFDIR "/tinc");
	}
}

static void free_names() {
	if (identname) free(identname);
	if (netname) free(netname);
	if (pidfilename) free(pidfilename);
	if (logfilename) free(logfilename);
	if (confbase) free(confbase);
}

static bool drop_privs() {
#ifdef HAVE_MINGW
	if (switchuser) {
		logger(LOG_ERR, "%s not supported on this platform", "-U");
		return false;
	}
	if (do_chroot) {
		logger(LOG_ERR, "%s not supported on this platform", "-R");
		return false;
	}
#else
	uid_t uid = 0;
	if (switchuser) {
		struct passwd *pw = getpwnam(switchuser);
		if (!pw) {
			logger(LOG_ERR, "unknown user `%s'", switchuser);
			return false;
		}
		uid = pw->pw_uid;
		if (initgroups(switchuser, pw->pw_gid) != 0 ||
		    setgid(pw->pw_gid) != 0) {
			logger(LOG_ERR, "System call `%s' failed: %s",
			       "initgroups", strerror(errno));
			return false;
		}
#ifndef __ANDROID__
// Not supported in android NDK
		endgrent();
		endpwent();
#endif
	}
	if (do_chroot) {
		tzset();	/* for proper timestamps in logs */
		if (chroot(confbase) != 0 || chdir("/") != 0) {
			logger(LOG_ERR, "System call `%s' failed: %s",
			       "chroot", strerror(errno));
			return false;
		}
		free(confbase);
		confbase = xstrdup("");
	}
	if (switchuser)
		if (setuid(uid) != 0) {
			logger(LOG_ERR, "System call `%s' failed: %s",
			       "setuid", strerror(errno));
			return false;
		}
#endif
	return true;
}

#ifdef HAVE_MINGW
# define setpriority(level) !SetPriorityClass(GetCurrentProcess(), (level))
#else
# define NORMAL_PRIORITY_CLASS 0
# define BELOW_NORMAL_PRIORITY_CLASS 10
# define HIGH_PRIORITY_CLASS -10
# define setpriority(level) (setpriority(PRIO_PROCESS, 0, (level)))
#endif

int main(int argc, char **argv) {
	program_name = argv[0];

	if(!parse_options(argc, argv))
		return 1;
	
	make_names();

	if(show_version) {
		printf("%s version %s (built %s %s, protocol %d)\n", PACKAGE,
			   VERSION, __DATE__, __TIME__, PROT_CURRENT);
		printf("Copyright (C) 1998-2015 Ivo Timmermans, Guus Sliepen and others.\n"
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

	if(kill_tincd)
		return !kill_other(kill_tincd);

	openlogger("tinc", use_logfile?LOGMODE_FILE:LOGMODE_STDERR);

	g_argv = argv;

	if(getenv("LISTEN_PID") && atoi(getenv("LISTEN_PID")) == getpid())
		do_detach = false;
#ifdef HAVE_UNSETENV
	unsetenv("LISTEN_PID");
#endif

	init_configuration(&config_tree);

	/* Slllluuuuuuurrrrp! */

	RAND_load_file("/dev/urandom", 1024);

	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	OpenSSL_add_all_algorithms();

	if(generate_keys) {
		read_server_config();
		return !keygen(generate_keys);
	}

	if(!read_server_config())
		return 1;

#ifdef HAVE_LZO
	if(lzo_init() != LZO_E_OK) {
		logger(LOG_ERR, "Error initializing LZO compressor!");
		return 1;
	}
#endif

#ifdef HAVE_MINGW
	if(WSAStartup(MAKEWORD(2, 2), &wsa_state)) {
		logger(LOG_ERR, "System call `%s' failed: %s", "WSAStartup", winerror(GetLastError()));
		return 1;
	}

	if(!do_detach || !init_service())
		return main2(argc, argv);
	else
		return 1;
}

int main2(int argc, char **argv) {
	InitializeCriticalSection(&mutex);
	EnterCriticalSection(&mutex);
#endif
        char *priority = NULL;

	if(!detach())
		return 1;

#ifdef HAVE_MLOCKALL
	/* Lock all pages into memory if requested.
	 * This has to be done after daemon()/fork() so it works for child.
	 * No need to do that in parent as it's very short-lived. */
	if(do_mlock && mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
		logger(LOG_ERR, "System call `%s' failed: %s", "mlockall",
		   strerror(errno));
		return 1;
	}
#endif

	/* Setup sockets and open device. */

	if(!setup_network())
		goto end;

	/* Initiate all outgoing connections. */

	try_outgoing_connections();

	/* Change process priority */

        if(get_config_string(lookup_config(config_tree, "ProcessPriority"), &priority)) {
                if(!strcasecmp(priority, "Normal")) {
                        if (setpriority(NORMAL_PRIORITY_CLASS) != 0) {
                                logger(LOG_ERR, "System call `%s' failed: %s",
                                       "setpriority", strerror(errno));
                                goto end;
                        }
                } else if(!strcasecmp(priority, "Low")) {
                        if (setpriority(BELOW_NORMAL_PRIORITY_CLASS) != 0) {
                                       logger(LOG_ERR, "System call `%s' failed: %s",
                                       "setpriority", strerror(errno));
                                goto end;
                        }
                } else if(!strcasecmp(priority, "High")) {
                        if (setpriority(HIGH_PRIORITY_CLASS) != 0) {
                                logger(LOG_ERR, "System call `%s' failed: %s",
                                       "setpriority", strerror(errno));
                                goto end;
                        }
                } else {
                        logger(LOG_ERR, "Invalid priority `%s`!", priority);
                        goto end;
                }
        }

	/* drop privileges */
	if (!drop_privs())
		goto end;

	/* Start main loop. It only exits when tinc is killed. */

	status = main_loop();

	/* Shutdown properly. */

	ifdebug(CONNECTIONS)
		devops.dump_stats();

	close_network_connections();

end:
	logger(LOG_NOTICE, "Terminating");

#ifndef HAVE_MINGW
	remove_pid(pidfilename);
#endif

	free(priority);

	EVP_cleanup();
	ENGINE_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();

	exit_configuration(&config_tree);
	list_free(cmdline_conf);
	free_names();

	return status;
}
