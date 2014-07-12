/*
    script.c -- call an external script
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
#include "logger.h"
#include "names.h"
#include "script.h"
#include "xalloc.h"

bool execute_script(const char *name, char **envp) {
#ifdef HAVE_SYSTEM
	char *scriptname;
	char *command;

	xasprintf(&scriptname, "%s" SLASH "%s%s", confbase, name, scriptextension);

	/* First check if there is a script */

#ifdef HAVE_MINGW
	if(!*scriptextension) {
		const char *pathext = getenv("PATHEXT") ?: ".COM;.EXE;.BAT;.CMD";
		char fullname[strlen(scriptname) + strlen(pathext)];
		char *ext = fullname + strlen(scriptname);
		strcpy(fullname, scriptname);

		const char *p = pathext;
		bool found = false;
		while(p && *p) {
			const char *q = strchr(p, ';');
			if(q) {
				memcpy(ext, p, q - p);
				ext[q - p] = 0;
				q++;
			} else {
				strcpy(ext, p);
			}
			if((found = !access(fullname, F_OK)))
				break;
			p = q;
		}
		if(!found) {
			free(scriptname);
			return true;
		}
	} else
#endif

	if(access(scriptname, F_OK)) {
		free(scriptname);
		return true;
	}

	logger(DEBUG_STATUS, LOG_INFO, "Executing script %s", name);

#ifdef HAVE_PUTENV
	/* Set environment */

	for(int i = 0; envp[i]; i++)
		putenv(envp[i]);
#endif

	if(scriptinterpreter)
		xasprintf(&command, "%s \"%s\"", scriptinterpreter, scriptname);
	else
		xasprintf(&command, "\"%s\"", scriptname);

	int status = system(command);

	free(command);
	free(scriptname);

	/* Unset environment */

	for(int i = 0; envp[i]; i++) {
		char *e = strchr(envp[i], '=');
		if(e) {
			char p[e - envp[i] + 1];
			strncpy(p, envp[i], e - envp[i]);
			p[e - envp[i]] = '\0';
			putenv(p);
		}
	}

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
#endif
	return true;
}
