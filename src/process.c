/*
    process.c -- process management functions
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2018 Guus Sliepen <guus@tinc-vpn.org>

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

#include "logger.h"
#include "names.h"
#include "process.h"
#include "version.h"

#ifdef HAVE_MINGW
#include "utils.h"
#endif

/* If zero, don't detach from the terminal. */
bool do_detach = true;

extern char **g_argv;
extern bool use_logfile;
extern bool use_syslog;

/* Some functions the less gifted operating systems might lack... */

#ifdef HAVE_MINGW
static SC_HANDLE manager = NULL;
static SC_HANDLE service = NULL;
static SERVICE_STATUS status = {0};
static SERVICE_STATUS_HANDLE statushandle = 0;

static bool install_service(void) {
	char command[4096] = "\"";

	SERVICE_DESCRIPTION description;
	description.lpDescription = _("Virtual Private Network daemon");

	manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if(!manager) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("Could not open service manager: %s"), winerror(GetLastError()));
		return false;
	}

	HMODULE module = GetModuleHandle(NULL);
	GetModuleFileName(module, command + 1, sizeof(command) - 1);
	command[sizeof(command) - 1] = 0;

	strncat(command, "\"", sizeof(command) - strlen(command));

	for(char **argp = g_argv + 1; *argp; argp++) {
		char *space = strchr(*argp, ' ');
		strncat(command, " ", sizeof(command) - strlen(command));

		if(space) {
			strncat(command, "\"", sizeof(command) - strlen(command));
		}

		strncat(command, *argp, sizeof(command) - strlen(command));

		if(space) {
			strncat(command, "\"", sizeof(command) - strlen(command));
		}
	}

	service = CreateService(manager, identname, identname,
	                        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
	                        command, NULL, NULL, NULL, NULL, NULL);

	if(!service) {
		DWORD lasterror = GetLastError();
		logger(DEBUG_ALWAYS, LOG_ERR, _("Could not create %s service: %s"), identname, winerror(lasterror));

		if(lasterror != ERROR_SERVICE_EXISTS) {
			return false;
		}
	}

	if(service) {
		ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &description);
		logger(DEBUG_ALWAYS, LOG_INFO, _("%s service installed"), identname);
	} else {
		service = OpenService(manager, identname, SERVICE_ALL_ACCESS);
	}

	if(!StartService(service, 0, NULL)) {
		logger(DEBUG_ALWAYS, LOG_WARNING, _("Could not start %s service: %s"), identname, winerror(GetLastError()));
	} else {
		logger(DEBUG_ALWAYS, LOG_INFO, _("%s service started"), identname);
	}

	return true;
}

io_t stop_io;

DWORD WINAPI controlhandler(DWORD request, DWORD type, LPVOID data, LPVOID context) {
	(void)type;
	(void)data;
	(void)context;

	switch(request) {
	case SERVICE_CONTROL_INTERROGATE:
		SetServiceStatus(statushandle, &status);
		return NO_ERROR;

	case SERVICE_CONTROL_STOP:
		logger(DEBUG_ALWAYS, LOG_NOTICE, _("Got %s request"), "SERVICE_CONTROL_STOP");
		break;

	case SERVICE_CONTROL_SHUTDOWN:
		logger(DEBUG_ALWAYS, LOG_NOTICE, _("Got %s request"), "SERVICE_CONTROL_SHUTDOWN");
		break;

	default:
		logger(DEBUG_ALWAYS, LOG_WARNING, _("Got unexpected request %d"), (int)request);
		return ERROR_CALL_NOT_IMPLEMENTED;
	}

	status.dwWaitHint = 1000;
	status.dwCurrentState = SERVICE_STOP_PENDING;
	SetServiceStatus(statushandle, &status);

	if(WSASetEvent(stop_io.event) == FALSE) {
		abort();
	}

	return NO_ERROR;
}

VOID WINAPI run_service(DWORD argc, LPTSTR *argv) {
	extern int main2(int argc, char **argv);

	status.dwServiceType = SERVICE_WIN32;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	status.dwWin32ExitCode = 0;
	status.dwServiceSpecificExitCode = 0;
	status.dwCheckPoint = 0;

	statushandle = RegisterServiceCtrlHandlerEx(identname, controlhandler, NULL);

	if(!statushandle) {
		logger(DEBUG_ALWAYS, LOG_ERR, _("System call `%s' failed: %s"), "RegisterServiceCtrlHandlerEx", winerror(GetLastError()));
	} else {
		status.dwWaitHint = 30000;
		status.dwCurrentState = SERVICE_START_PENDING;
		SetServiceStatus(statushandle, &status);

		status.dwWaitHint = 0;
		status.dwCurrentState = SERVICE_RUNNING;
		SetServiceStatus(statushandle, &status);

		main2(argc, argv);

		status.dwWaitHint = 0;
		status.dwCurrentState = SERVICE_STOPPED;
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
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, _("System call `%s' failed: %s"), "StartServiceCtrlDispatcher", winerror(GetLastError()));
		}
	}

	return true;
}
#endif

/*
  Detach from current terminal
*/
bool detach(void) {
	logmode_t logmode;

#ifndef HAVE_MINGW
	signal(SIGPIPE, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
	signal(SIGWINCH, SIG_IGN);

	closelogger();
#endif

	if(do_detach) {
#ifndef HAVE_MINGW

		if(daemon(1, 0)) {
			logger(DEBUG_ALWAYS, LOG_ERR, _("Couldn't detach from terminal: %s"), strerror(errno));
			return false;
		}

#else

		if(!statushandle) {
			exit(!install_service());
		}

#endif
	}

	if(use_logfile) {
		logmode = LOGMODE_FILE;
	} else if(use_syslog || do_detach) {
		logmode = LOGMODE_SYSLOG;
	} else {
		logmode = LOGMODE_STDERR;
	}

	openlogger(identname, logmode);

	logger(DEBUG_ALWAYS, LOG_NOTICE, _("tincd %s (%s %s) starting, debug level %d"),
	       BUILD_VERSION, BUILD_DATE, BUILD_TIME, debug_level);

	return true;
}
