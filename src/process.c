/*
    process.c -- process management functions
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2013 Guus Sliepen <guus@tinc-vpn.org>

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
#include "event.h"
#include "logger.h"
#include "names.h"
#include "net.h"
#include "node.h"
#include "process.h"
#include "subnet.h"
#include "utils.h"
#include "xalloc.h"

/* If zero, don't detach from the terminal. */
bool do_detach = true;
bool sigalrm = false;

extern char **g_argv;
extern bool use_logfile;

/* Some functions the less gifted operating systems might lack... */

#ifdef HAVE_MINGW
static SC_HANDLE manager = NULL;
static SC_HANDLE service = NULL;
static SERVICE_STATUS status = {0};
static SERVICE_STATUS_HANDLE statushandle = 0;

static bool install_service(void) {
	char command[4096] = "\"";
	SERVICE_DESCRIPTION description = {"Virtual Private Network daemon"};

	manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if(!manager) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open service manager: %s", winerror(GetLastError()));
		return false;
	}

	if(!strchr(program_name, '\\')) {
		GetCurrentDirectory(sizeof command - 1, command + 1);
		strncat(command, "\\", sizeof command - strlen(command));
	}

	strncat(command, program_name, sizeof command - strlen(command));

	strncat(command, "\"", sizeof command - strlen(command));

	for(char **argp = g_argv + 1; *argp; argp++) {
		char *space = strchr(*argp, ' ');
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
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not create %s service: %s", identname, winerror(lasterror));
		if(lasterror != ERROR_SERVICE_EXISTS)
			return false;
	}

	if(service) {
		ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &description);
		logger(DEBUG_ALWAYS, LOG_INFO, "%s service installed", identname);
	} else {
		service = OpenService(manager, identname, SERVICE_ALL_ACCESS);
	}

	if(!StartService(service, 0, NULL))
		logger(DEBUG_ALWAYS, LOG_WARNING, "Could not start %s service: %s", identname, winerror(GetLastError()));
	else
		logger(DEBUG_ALWAYS, LOG_INFO, "%s service started", identname);

	return true;
}

DWORD WINAPI controlhandler(DWORD request, DWORD type, LPVOID boe, LPVOID bah) {
	switch(request) {
		case SERVICE_CONTROL_INTERROGATE:
			SetServiceStatus(statushandle, &status);
			return NO_ERROR;
		case SERVICE_CONTROL_STOP:
			logger(DEBUG_ALWAYS, LOG_NOTICE, "Got %s request", "SERVICE_CONTROL_STOP");
			break;
		case SERVICE_CONTROL_SHUTDOWN:
			logger(DEBUG_ALWAYS, LOG_NOTICE, "Got %s request", "SERVICE_CONTROL_SHUTDOWN");
			break;
		default:
			logger(DEBUG_ALWAYS, LOG_WARNING, "Got unexpected request %d", (int)request);
			return ERROR_CALL_NOT_IMPLEMENTED;
	}

	event_exit();
	status.dwWaitHint = 30000;
	status.dwCurrentState = SERVICE_STOP_PENDING;
	SetServiceStatus(statushandle, &status);
	return NO_ERROR;
}

VOID WINAPI run_service(DWORD argc, LPTSTR* argv) {
	extern int main2(int argc, char **argv);

	status.dwServiceType = SERVICE_WIN32;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	status.dwWin32ExitCode = 0;
	status.dwServiceSpecificExitCode = 0;
	status.dwCheckPoint = 0;

	statushandle = RegisterServiceCtrlHandlerEx(identname, controlhandler, NULL);

	if (!statushandle) {
		logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "RegisterServiceCtrlHandlerEx", winerror(GetLastError()));
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
		}
		else
			logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "StartServiceCtrlDispatcher", winerror(GetLastError()));
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
			logger(DEBUG_ALWAYS, LOG_ERR, "Couldn't detach from terminal: %s", strerror(errno));
			return false;
		}
#else
		if(!statushandle)
			exit(!install_service());
#endif
	}

	openlogger(identname, use_logfile?LOGMODE_FILE:(do_detach?LOGMODE_SYSLOG:LOGMODE_STDERR));

	logger(DEBUG_ALWAYS, LOG_NOTICE, "tincd %s (%s %s) starting, debug level %d",
			   VERSION, __DATE__, __TIME__, debug_level);

	return true;
}


