/*
    process.c -- process management functions
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2011 Guus Sliepen <guus@tinc-vpn.org>

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
#include "control.h"
#include "device.h"
#include "edge.h"
#include "logger.h"
#include "net.h"
#include "node.h"
#include "process.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

/* If zero, don't detach from the terminal. */
bool do_detach = true;
bool sigalrm = false;

extern char *identname;
extern char **g_argv;
extern bool use_logfile;

/* Some functions the less gifted operating systems might lack... */

#ifdef HAVE_MINGW
extern char *identname;
extern char *program_name;
extern char **g_argv;

static SC_HANDLE manager = NULL;
static SC_HANDLE service = NULL;
static SERVICE_STATUS status = {0};
static SERVICE_STATUS_HANDLE statushandle = 0;

static bool install_service(void) {
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
		DWORD lasterror = GetLastError();
		logger(LOG_ERR, "Could not create %s service: %s", identname, winerror(lasterror));
		if(lasterror != ERROR_SERVICE_EXISTS)
			return false;
	}

	if(service) {
		ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &description);
		logger(LOG_INFO, "%s service installed", identname);
	} else {
		service = OpenService(manager, identname, SERVICE_ALL_ACCESS);
	}

	if(!StartService(service, 0, NULL))
		logger(LOG_WARNING, "Could not start %s service: %s", identname, winerror(GetLastError()));
	else
		logger(LOG_INFO, "%s service started", identname);

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

	event_loopexit(NULL);
	status.dwWaitHint = 30000; 
	status.dwCurrentState = SERVICE_STOP_PENDING; 
	SetServiceStatus(statushandle, &status);
	return NO_ERROR;
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

/*
  Detach from current terminal
*/
bool detach(void) {
#ifndef HAVE_MINGW
	signal(SIGPIPE, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
	signal(SIGWINCH, SIG_IGN);

	closelogger();
#endif

	if(do_detach) {
#ifndef HAVE_MINGW
		if(daemon(0, 0)) {
			fprintf(stderr, "Couldn't detach from terminal: %s",
					strerror(errno));
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

	return true;
}

bool execute_script(const char *name, char **envp) {
#ifdef HAVE_SYSTEM
	int status, len;
	char *scriptname;
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
			char p[e - envp[i] + 1];
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
