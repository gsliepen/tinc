/*
    script.c -- call an external script
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2015 Guus Sliepen <guus@tinc-vpn.org>

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
#include "logger.h"
#include "names.h"
#include "script.h"
#include "xalloc.h"

#ifdef HAVE_PUTENV
static void unputenv(const char *p) {
	const char *e = strchr(p, '=');
	if(!e)
		return;
	int len = e - p;
#ifndef HAVE_UNSETENV
#ifdef HAVE_MINGW
	// Windows requires putenv("FOO=") to unset %FOO%
	len++;
#endif
#endif
	char var[len + 1];
	strncpy(var, p, len);
	var[len] = 0;
#ifdef HAVE_UNSETENV
	unsetenv(var);
#else
	// We must keep what we putenv() around in memory.
	// To do this without memory leaks, keep things in a list and reuse if possible.
	static list_t list = {};
	for list_each(char, data, &list) {
		if(!strcmp(data, var)) {
			putenv(data);
			return;
		}
	}
	char *data = xstrdup(var);
	list_insert_tail(&list, data);
	putenv(data);
#endif
}
#else
static void putenv(const char *p) {}
static void unputenv(const char *p) {}
#endif

bool execute_script(const char *name, char **envp) {
	char scriptname[PATH_MAX];
	char *command;

	snprintf(scriptname, sizeof scriptname, "%s" SLASH "%s%s", confbase, name, scriptextension);

	/* First check if there is a script */

#ifdef HAVE_MINGW
	if(!*scriptextension) {
		const char *pathext = getenv("PATHEXT") ?: ".COM;.EXE;.BAT;.CMD";
		size_t pathlen = strlen(pathext);
		size_t scriptlen = strlen(scriptname);
		char fullname[scriptlen + pathlen + 1];
		char *ext = fullname + scriptlen;
		strncpy(fullname, scriptname, sizeof fullname);

		const char *p = pathext;
		bool found = false;
		while(p && *p) {
			const char *q = strchr(p, ';');
			if(q) {
				memcpy(ext, p, q - p);
				ext[q - p] = 0;
				q++;
			} else {
				strncpy(ext, p, pathlen + 1);
			}
			if((found = !access(fullname, F_OK)))
				break;
			p = q;
		}
		if(!found)
			return true;
	} else
#endif

	if(access(scriptname, F_OK))
		return true;

	logger(DEBUG_STATUS, LOG_INFO, "Executing script %s", name);

	/* Set environment */

	for(int i = 0; envp[i]; i++)
		putenv(envp[i]);

	if(scriptinterpreter)
		xasprintf(&command, "%s \"%s\"", scriptinterpreter, scriptname);
	else
		xasprintf(&command, "\"%s\"", scriptname);

	int status = system(command);

	free(command);

	/* Unset environment */

	for(int i = 0; envp[i]; i++)
		unputenv(envp[i]);

	if(status != -1) {
#ifdef WEXITSTATUS
		if(WIFEXITED(status)) {          /* Child exited by itself */
			if(WEXITSTATUS(status)) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Script %s exited with non-zero status %d",
					   name, WEXITSTATUS(status));
				return false;
			}
		} else if(WIFSIGNALED(status)) { /* Child was killed by a signal */
			logger(DEBUG_ALWAYS, LOG_ERR, "Script %s was killed by signal %d (%s)",
				   name, WTERMSIG(status), strsignal(WTERMSIG(status)));
			return false;
		} else {                         /* Something strange happened */
			logger(DEBUG_ALWAYS, LOG_ERR, "Script %s terminated abnormally", name);
			return false;
		}
#endif
	} else {
		logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "system", strerror(errno));
		return false;
	}

	return true;
}
