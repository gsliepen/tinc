/*
    names.c -- generate commonly used (file)names
    Copyright (C) 1998-2005 Ivo Timmermans
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

#include "logger.h"
#include "xalloc.h"

char *netname = NULL;
char *confdir = NULL;           /* base configuration directory */
char *confbase = NULL;          /* base configuration directory for this instance of tinc */
char *identname = NULL;         /* program name for syslog */
char *unixsocketname = NULL;    /* UNIX socket location */
char *logfilename = NULL;       /* log file location */
char *pidfilename = NULL;
char *program_name = NULL;

/*
  Set all files and paths according to netname
*/
void make_names(void) {
#ifdef HAVE_MINGW
	HKEY key;
	char installdir[1024] = "";
	DWORD len = sizeof installdir;
#endif

	if(netname && confbase)
		logger(DEBUG_ALWAYS, LOG_INFO, "Both netname and configuration directory given, using the latter...");

	if(netname)
		xasprintf(&identname, "tinc.%s", netname);
	else
		identname = xstrdup("tinc");

#ifdef HAVE_MINGW
	if(!RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\tinc", 0, KEY_READ, &key)) {
		if(!RegQueryValueEx(key, NULL, 0, 0, (LPBYTE)installdir, &len)) {
			confdir = xstrdup(installdir);
			if(!logfilename)
				xasprintf(&logfilename, "%s" SLASH "log" SLASH "%s.log", installdir, identname);
			if(!confbase) {
				if(netname)
					xasprintf(&confbase, "%s" SLASH "%s", installdir, netname);
				else
					xasprintf(&confbase, "%s", installdir);
			}
			if(!pidfilename)
				xasprintf(&pidfilename, "%s" SLASH "pid", confbase);
		}
		RegCloseKey(key);
	}
#endif
	if(!confdir)
		confdir = xstrdup(CONFDIR SLASH "tinc");

	if(!logfilename)
		xasprintf(&logfilename, LOCALSTATEDIR SLASH "log" SLASH "%s.log", identname);

	if(!pidfilename)
		xasprintf(&pidfilename, LOCALSTATEDIR SLASH "run" SLASH "%s.pid", identname);

	if(!unixsocketname) {
		int len = strlen(pidfilename);
		unixsocketname = xmalloc(len + 8);
		strcpy(unixsocketname, pidfilename);
		if(len > 4 && !strcmp(pidfilename + len - 4, ".pid"))
			strcpy(unixsocketname + len - 4, ".socket");
		else
			strcpy(unixsocketname + len, ".socket");
	}

	if(!confbase) {
		if(netname)
			xasprintf(&confbase, CONFDIR SLASH "tinc" SLASH "%s", netname);
		else
			xasprintf(&confbase, CONFDIR SLASH "tinc");
	}
}

void free_names(void) {
	free(identname);
	free(netname);
	free(unixsocketname);
	free(pidfilename);
	free(logfilename);
	free(confbase);
	free(confdir);
}
