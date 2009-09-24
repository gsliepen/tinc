/*
    process.c -- process management functions
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2009 Guus Sliepen <guus@tinc-vpn.org>

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

#include "conf.h"
#include "connection.h"
#include "device.h"
#include "edge.h"
#include "logger.h"
#include "node.h"
#include "pidfile.h"
#include "process.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

/* If zero, don't detach from the terminal. */
bool do_detach = true;
bool sighup = false;
bool sigalrm = false;

extern char *identname;
extern char *pidfilename;
extern char **g_argv;
extern bool use_logfile;
extern volatile bool running;

sigset_t emptysigset;

static int saved_debug_level = -1;

static void memory_full(int size) {
	logger(LOG_ERR, "Memory exhausted (couldn't allocate %d bytes), exitting.", size);
	exit(1);
}

/* Some functions the less gifted operating systems might lack... */

#ifdef HAVE_MINGW
extern char *identname;
extern char *program_name;
extern char **g_argv;

static SC_HANDLE manager = NULL;
static SC_HANDLE service = NULL;
static SERVICE_STATUS status = {0};
static SERVICE_STATUS_HANDLE statushandle = 0;

bool install_service(void) {
	char command[4096] = "\"";
	char **argp;
	bool space;
	SERVICE_DESCRIPTION description = {"Virtual Private Network daemon"};

	manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager) {
		logger(LOG_ERR, "Could not open service manager: %s", winerror(GetLastError()));
		return false;
	}

	if(!strchr(program_name, '\\')) {
		GetCurrentDirectory(sizeof command - 1, command + 1);
		strncat(command, "\\", sizeof command - strlen(command));
	}

	strncat(command, program_name, sizeof command - strlen(command));

	strncat(command, "\"", sizeof command - strlen(command));

	for(argp = g_argv + 1; *argp; argp++) {
		space = strchr(*argp, ' ');
		strncat(command, " ", sizeof command - strlen(command));
		
		if(space)
			strncat(command, "\"", sizeof command - strlen(command));
		
		strncat(command, *argp, sizeof command - strlen(command));

		if(space)
			strncat(command, "\"", sizeof command - strlen(command));
	}

	service = CreateService(manager, identname, identname,
			SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
			command, NULL, NULL, NULL, NULL, NULL);
	
	if(!service) {
		logger(LOG_ERR, "Could not create %s service: %s", identname, winerror(GetLastError()));
		return false;
	}

	ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &description);

	logger(LOG_INFO, "%s service installed", identname);

	if(!StartService(service, 0, NULL))
		logger(LOG_WARNING, "Could not start %s service: %s", identname, winerror(GetLastError()));
	else
		logger(LOG_INFO, "%s service started", identname);

	return true;
}

bool remove_service(void) {
	manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager) {
		logger(LOG_ERR, "Could not open service manager: %s", winerror(GetLastError()));
		return false;
	}

	service = OpenService(manager, identname, SERVICE_ALL_ACCESS);

	if(!service) {
		logger(LOG_ERR, "Could not open %s service: %s", identname, winerror(GetLastError()));
		return false;
	}

	if(!ControlService(service, SERVICE_CONTROL_STOP, &status))
		logger(LOG_ERR, "Could not stop %s service: %s", identname, winerror(GetLastError()));
	else
		logger(LOG_INFO, "%s service stopped", identname);

	if(!DeleteService(service)) {
		logger(LOG_ERR, "Could not remove %s service: %s", identname, winerror(GetLastError()));
		return false;
	}

	logger(LOG_INFO, "%s service removed", identname);

	return true;
}

DWORD WINAPI controlhandler(DWORD request, DWORD type, LPVOID boe, LPVOID bah) {
	switch(request) {
		case SERVICE_CONTROL_INTERROGATE:
			SetServiceStatus(statushandle, &status);
			return NO_ERROR;
		case SERVICE_CONTROL_STOP:
			logger(LOG_NOTICE, "Got %s request", "SERVICE_CONTROL_STOP");
			break;
		case SERVICE_CONTROL_SHUTDOWN:
			logger(LOG_NOTICE, "Got %s request", "SERVICE_CONTROL_SHUTDOWN");
			break;
		default:
			logger(LOG_WARNING, "Got unexpected request %d", request);
			return ERROR_CALL_NOT_IMPLEMENTED;
	}

	if(running) {
		running = false;
		status.dwWaitHint = 30000; 
		status.dwCurrentState = SERVICE_STOP_PENDING; 
		SetServiceStatus(statushandle, &status);
		return NO_ERROR;
	} else {
		status.dwWaitHint = 0; 
		status.dwCurrentState = SERVICE_STOPPED; 
		SetServiceStatus(statushandle, &status);
		exit(1);
	}

}

VOID WINAPI run_service(DWORD argc, LPTSTR* argv) {
	int err = 1;
	extern int main2(int argc, char **argv);


	status.dwServiceType = SERVICE_WIN32; 
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	status.dwWin32ExitCode = 0; 
	status.dwServiceSpecificExitCode = 0; 
	status.dwCheckPoint = 0; 

	statushandle = RegisterServiceCtrlHandlerEx(identname, controlhandler, NULL); 

	if (!statushandle) {
		logger(LOG_ERR, "System call `%s' failed: %s", "RegisterServiceCtrlHandlerEx", winerror(GetLastError()));
		err = 1;
	} else {
		status.dwWaitHint = 30000; 
		status.dwCurrentState = SERVICE_START_PENDING; 
		SetServiceStatus(statushandle, &status);

		status.dwWaitHint = 0; 
		status.dwCurrentState = SERVICE_RUNNING;
		SetServiceStatus(statushandle, &status);

		err = main2(argc, argv);

		status.dwWaitHint = 0;
		status.dwCurrentState = SERVICE_STOPPED; 
		//status.dwWin32ExitCode = err; 
		SetServiceStatus(statushandle, &status);
	}

	return;
}

bool init_service(void) {
	SERVICE_TABLE_ENTRY services[] = {
		{identname, run_service},
		{NULL, NULL}
	};

	if(!StartServiceCtrlDispatcher(services)) {
		if(GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
			return false;
		}
		else
			logger(LOG_ERR, "System call `%s' failed: %s", "StartServiceCtrlDispatcher", winerror(GetLastError()));
	}

	return true;
}
#endif

#ifndef HAVE_MINGW
/*
  check for an existing tinc for this net, and write pid to pidfile
*/
static bool write_pidfile(void) {
	pid_t pid;

	pid = check_pid(pidfilename);

	if(pid) {
		if(netname)
			fprintf(stderr, "A tincd is already running for net `%s' with pid %ld.\n",
					netname, (long)pid);
		else
			fprintf(stderr, "A tincd is already running with pid %ld.\n", (long)pid);
		return false;
	}

	/* if it's locked, write-protected, or whatever */
	if(!write_pid(pidfilename)) {
		fprintf(stderr, "Could write pid file %s: %s\n", pidfilename, strerror(errno));
		return false;
	}

	return true;
}
#endif

/*
  kill older tincd for this net
*/
bool kill_other(int signal) {
#ifndef HAVE_MINGW
	pid_t pid;

	pid = read_pid(pidfilename);

	if(!pid) {
		if(netname)
			fprintf(stderr, "No other tincd is running for net `%s'.\n",
					netname);
		else
			fprintf(stderr, "No other tincd is running.\n");
		return false;
	}

	errno = 0;					/* No error, sometimes errno is only changed on error */

	/* ESRCH is returned when no process with that pid is found */
	if(kill(pid, signal) && errno == ESRCH) {
		if(netname)
			fprintf(stderr, "The tincd for net `%s' is no longer running. ",
					netname);
		else
			fprintf(stderr, "The tincd is no longer running. ");

		fprintf(stderr, "Removing stale lock file.\n");
		remove_pid(pidfilename);
	}

	return true;
#else
	return remove_service();
#endif
}

/*
  Detach from current terminal, write pidfile, kill parent
*/
bool detach(void) {
	setup_signals();

	/* First check if we can open a fresh new pidfile */

#ifndef HAVE_MINGW
	if(!write_pidfile())
		return false;

	/* If we succeeded in doing that, detach */

	closelogger();
#endif

	if(do_detach) {
#ifndef HAVE_MINGW
		if(daemon(0, 0)) {
			fprintf(stderr, "Couldn't detach from terminal: %s",
					strerror(errno));
			return false;
		}

		/* Now UPDATE the pid in the pidfile, because we changed it... */

		if(!write_pid(pidfilename)) {
			fprintf(stderr, "Could not write pid file %s: %s\n", pidfilename, strerror(errno));
			return false;
		}
#else
		if(!statushandle)
			exit(install_service());
#endif
	}

	openlogger(identname, use_logfile?LOGMODE_FILE:(do_detach?LOGMODE_SYSLOG:LOGMODE_STDERR));

	logger(LOG_NOTICE, "tincd %s (%s %s) starting, debug level %d",
			   VERSION, __DATE__, __TIME__, debug_level);

	xalloc_fail_func = memory_full;

	return true;
}

bool execute_script(const char *name, char **envp) {
#ifdef HAVE_SYSTEM
	int status, len;
	char *scriptname, *p;
	int i;

#ifndef HAVE_MINGW
	len = xasprintf(&scriptname, "\"%s/%s\"", confbase, name);
#else
	len = xasprintf(&scriptname, "\"%s/%s.bat\"", confbase, name);
#endif
	if(len < 0)
		return false;

	scriptname[len - 1] = '\0';

#ifndef HAVE_TUNEMU
	/* First check if there is a script */

	if(access(scriptname + 1, F_OK)) {
		free(scriptname);
		return true;
	}
#endif

	ifdebug(STATUS) logger(LOG_INFO, "Executing script %s", name);

#ifdef HAVE_PUTENV
	/* Set environment */
	
	for(i = 0; envp[i]; i++)
		putenv(envp[i]);
#endif

	scriptname[len - 1] = '\"';
	status = system(scriptname);

	free(scriptname);

	/* Unset environment */

	for(i = 0; envp[i]; i++) {
		char *e = strchr(envp[i], '=');
		if(e) {
			p = alloca(e - envp[i] + 1);
			strncpy(p, envp[i], e - envp[i]);
			p[e - envp[i]] = '\0';
			putenv(p);
		}
	}

#ifdef WEXITSTATUS
	if(status != -1) {
		if(WIFEXITED(status)) {	/* Child exited by itself */
			if(WEXITSTATUS(status)) {
				logger(LOG_ERR, "Script %s exited with non-zero status %d",
					   name, WEXITSTATUS(status));
				return false;
			}
		} else if(WIFSIGNALED(status)) {	/* Child was killed by a signal */
			logger(LOG_ERR, "Script %s was killed by signal %d (%s)",
				   name, WTERMSIG(status), strsignal(WTERMSIG(status)));
			return false;
		} else {			/* Something strange happened */
			logger(LOG_ERR, "Script %s terminated abnormally", name);
			return false;
		}
	} else {
		logger(LOG_ERR, "System call `%s' failed: %s", "system", strerror(errno));
		return false;
	}
#endif
#endif
	return true;
}


/*
  Signal handlers.
*/

#ifndef HAVE_MINGW
static RETSIGTYPE sigterm_handler(int a) {
	logger(LOG_NOTICE, "Got %s signal", "TERM");
	if(running)
		running = false;
	else
		exit(1);
}

static RETSIGTYPE sigquit_handler(int a) {
	logger(LOG_NOTICE, "Got %s signal", "QUIT");
	if(running)
		running = false;
	else
		exit(1);
}

static RETSIGTYPE fatal_signal_square(int a) {
	logger(LOG_ERR, "Got another fatal signal %d (%s): not restarting.", a,
		   strsignal(a));
	exit(1);
}

static RETSIGTYPE fatal_signal_handler(int a) {
	struct sigaction act;
	logger(LOG_ERR, "Got fatal signal %d (%s)", a, strsignal(a));

	if(do_detach) {
		logger(LOG_NOTICE, "Trying to re-execute in 5 seconds...");

		act.sa_handler = fatal_signal_square;
		act.sa_mask = emptysigset;
		act.sa_flags = 0;
		sigaction(SIGSEGV, &act, NULL);

		close_network_connections();
		sleep(5);
		remove_pid(pidfilename);
		execvp(g_argv[0], g_argv);
	} else {
		logger(LOG_NOTICE, "Not restarting.");
		exit(1);
	}
}

static RETSIGTYPE sighup_handler(int a) {
	logger(LOG_NOTICE, "Got %s signal", "HUP");
	sighup = true;
}

static RETSIGTYPE sigint_handler(int a) {
	logger(LOG_NOTICE, "Got %s signal", "INT");

	if(saved_debug_level != -1) {
		logger(LOG_NOTICE, "Reverting to old debug level (%d)",
			saved_debug_level);
		debug_level = saved_debug_level;
		saved_debug_level = -1;
	} else {
		logger(LOG_NOTICE,
			"Temporarily setting debug level to 5.  Kill me with SIGINT again to go back to level %d.",
			debug_level);
		saved_debug_level = debug_level;
		debug_level = 5;
	}
}

static RETSIGTYPE sigalrm_handler(int a) {
	logger(LOG_NOTICE, "Got %s signal", "ALRM");
	sigalrm = true;
}

static RETSIGTYPE sigusr1_handler(int a) {
	dump_connections();
}

static RETSIGTYPE sigusr2_handler(int a) {
	dump_device_stats();
	dump_nodes();
	dump_edges();
	dump_subnets();
}

static RETSIGTYPE sigwinch_handler(int a) {
	do_purge = true;
}

static RETSIGTYPE unexpected_signal_handler(int a) {
	logger(LOG_WARNING, "Got unexpected signal %d (%s)", a, strsignal(a));
}

static RETSIGTYPE ignore_signal_handler(int a) {
	ifdebug(SCARY_THINGS) logger(LOG_DEBUG, "Ignored signal %d (%s)", a, strsignal(a));
}

static struct {
	int signal;
	void (*handler)(int);
} sighandlers[] = {
	{SIGHUP, sighup_handler},
	{SIGTERM, sigterm_handler},
	{SIGQUIT, sigquit_handler},
	{SIGSEGV, fatal_signal_handler},
	{SIGBUS, fatal_signal_handler},
	{SIGILL, fatal_signal_handler},
	{SIGPIPE, ignore_signal_handler},
	{SIGINT, sigint_handler},
	{SIGUSR1, sigusr1_handler},
	{SIGUSR2, sigusr2_handler},
	{SIGCHLD, ignore_signal_handler},
	{SIGALRM, sigalrm_handler},
	{SIGWINCH, sigwinch_handler},
	{0, NULL}
};
#endif

void setup_signals(void) {
#ifndef HAVE_MINGW
	int i;
	struct sigaction act;

	sigemptyset(&emptysigset);
	act.sa_handler = NULL;
	act.sa_mask = emptysigset;
	act.sa_flags = 0;

	/* Set a default signal handler for every signal, errors will be
	   ignored. */
	for(i = 1; i < NSIG; i++) {
		if(!do_detach)
			act.sa_handler = SIG_DFL;
		else
			act.sa_handler = unexpected_signal_handler;
		sigaction(i, &act, NULL);
	}

	/* If we didn't detach, allow coredumps */
	if(!do_detach)
		sighandlers[3].handler = SIG_DFL;

	/* Then, for each known signal that we want to catch, assign a
	   handler to the signal, with error checking this time. */
	for(i = 0; sighandlers[i].signal; i++) {
		act.sa_handler = sighandlers[i].handler;
		if(sigaction(sighandlers[i].signal, &act, NULL) < 0)
			fprintf(stderr, "Installing signal handler for signal %d (%s) failed: %s\n",
					sighandlers[i].signal, strsignal(sighandlers[i].signal),
					strerror(errno));
	}
#endif
}
