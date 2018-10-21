/*
    script.c -- call an external script
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

#include "conf.h"
#include "device.h"
#include "logger.h"
#include "names.h"
#include "script.h"
#include "xalloc.h"

#ifdef HAVE_PUTENV
static void unputenv(const char *p) {
	const char *e = strchr(p, '=');

	if(!e) {
		return;
	}

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
	static list_t list = {0};

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

static const int min_env_size = 10;

int environment_add(environment_t *env, const char *format, ...) {
	if(env->n >= env->size) {
		env->size = env->n ? env->n * 2 : min_env_size;
		env->entries = xrealloc(env->entries, env->size * sizeof(*env->entries));
	}

	if(format) {
		va_list ap;
		va_start(ap, format);
		vasprintf(&env->entries[env->n], format, ap);
		va_end(ap);
	} else {
		env->entries[env->n] = NULL;
	}

	return env->n++;
}

void environment_update(environment_t *env, int pos, const char *format, ...) {
	free(env->entries[pos]);
	va_list ap;
	va_start(ap, format);
	vasprintf(&env->entries[pos], format, ap);
	va_end(ap);
}

void environment_init(environment_t *env) {
	env->n = 0;
	env->size = min_env_size;
	env->entries = xzalloc(env->size * sizeof(*env->entries));

	if(netname) {
		environment_add(env, "NETNAME=%s", netname);
	}

	if(myname) {
		environment_add(env, "NAME=%s", myname);
	}

	if(device) {
		environment_add(env, "DEVICE=%s", device);
	}

	if(iface) {
		environment_add(env, "INTERFACE=%s", iface);
	}

	if(debug_level >= 0) {
		environment_add(env, "DEBUG=%d", debug_level);
	}
}

void environment_exit(environment_t *env) {
	for(int i = 0; i < env->n; i++) {
		free(env->entries[i]);
	}

	free(env->entries);
}

bool execute_script(const char *name, environment_t *env) {
	char scriptname[PATH_MAX];
	char *command;

	snprintf(scriptname, sizeof(scriptname), "%s" SLASH "%s%s", confbase, name, scriptextension);

	/* First check if there is a script */

#ifdef HAVE_MINGW

	if(!*scriptextension) {
		const char *pathext = getenv("PATHEXT");

		if(!pathext) {
			pathext = ".COM;.EXE;.BAT;.CMD";
		}

		size_t pathlen = strlen(pathext);
		size_t scriptlen = strlen(scriptname);
		char fullname[scriptlen + pathlen + 1];
		char *ext = fullname + scriptlen;
		strncpy(fullname, scriptname, sizeof(fullname));

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

			if((found = !access(fullname, F_OK))) {
				break;
			}

			p = q;
		}

		if(!found) {
			return true;
		}
	} else
#endif

		if(access(scriptname, F_OK)) {
			return true;
		}

	logger(DEBUG_STATUS, LOG_INFO, "Executing script %s", name);

	/* Set environment */

	for(int i = 0; i < env->n; i++) {
		putenv(env->entries[i]);
	}

	if(scriptinterpreter) {
		xasprintf(&command, "%s \"%s\"", scriptinterpreter, scriptname);
	} else {
		xasprintf(&command, "\"%s\"", scriptname);
	}

	int status = system(command);

	free(command);

	/* Unset environment */

	for(int i = 0; i < env->n; i++) {
		unputenv(env->entries[i]);
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

	return true;
}
