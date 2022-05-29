/*
    script.c -- call an external script
    Copyright (C) 1999-2005 Ivo Timmermans,
                  2000-2022 Guus Sliepen <guus@tinc-vpn.org>

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

#ifdef HAVE_LINUX
#include <sys/prctl.h>
#endif

#include "conf.h"
#include "device.h"
#include "logger.h"
#include "names.h"
#include "script.h"
#include "xalloc.h"
#include "sandbox.h"

#ifdef HAVE_PUTENV
static void unputenv(const char *p) {
	const char *e = strchr(p, '=');

	if(!e) {
		return;
	}

	ptrdiff_t len = e - p;
#ifndef HAVE_UNSETENV
#ifdef HAVE_WINDOWS
	// Windows requires putenv("FOO=") to unset %FOO%
	len++;
#endif
#endif
	char *var = alloca(len + 1);
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

		if(vasprintf(&env->entries[env->n], format, ap) == -1) {
			// Assume we are out of memory.
			abort();
		}

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

	if(vasprintf(&env->entries[pos], format, ap) == -1) {
		abort();
	}

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
		free_string(env->entries[i]);
	}

	free(env->entries);
}

static int run_command(const char *scriptname) {
	char buf[8192];

	if(scriptinterpreter) {
		snprintf(buf, sizeof(buf), "%s \"%s\"", scriptinterpreter, scriptname);
	} else {
		snprintf(buf, sizeof(buf), "\"%s\"", scriptname);
	}

	return system(buf);
}

static bool build_script_name(char *buf, size_t len, const char *name) {
	if(!name) {
		return false;
	}

	// If name contains a forward slash, make sure it is the only one, and
	// it forms a separator between the 'hosts' subdirectory and a file inside it.
	// This should prevent attackers from using names like `/ysr/bin/python` or `../../python3`.
	const char *slash = strchr(name, '/');

	if(slash) {
		if(strncmp("hosts/", name, sizeof("hosts/") - 1) || strchr(slash + 1, '/')) {
			return false;
		}
	}

	int wrote = snprintf(buf, len, "%s" SLASH "%s%s", confbase, name, scriptextension);
	return wrote > 0 && (size_t)wrote <= len;
}

#ifdef HAVE_SANDBOX
struct {
	pid_t pid;
	int sock;
} worker;

static void cleanup_script_worker(void) {
	if(worker.sock) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Waiting for script runner to exit");
		close(worker.sock);
		waitpid(worker.pid, NULL, 0);
		worker.sock = 0;
	}
}

void set_script_worker(pid_t pid, int sock) {
	assert(!worker.pid && !worker.sock);
	worker.pid = pid;
	worker.sock = sock;
	atexit(cleanup_script_worker);
}

static const char *known_vars[] = {
	"DEBUG",
	"DEVICE",
	"INTERFACE",
	"INVITATION_FILE",
	"INVITATION_URL",
	"NAME",
	"NETNAME",
	"NODE",
	"REMOTEADDRESS",
	"REMOTEPORT",
	"SUBNET",
	"WEIGHT",
	NULL,
};

static bool is_known_var(const char *var) {
	for(const char **known = known_vars; *known; ++known) {
		if(!strcmp(*known, var)) {
			return true;
		}
	}

	return false;
}

static ssize_t read_unix(int fd, void *data, size_t len) {
	struct iovec iov = {
		.iov_base = data,
		.iov_len = len,
	};
	struct msghdr hdr = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	while(true) {
		ssize_t res = recvmsg(fd, &hdr, 0);

		if(res < 1) {
			if(errno == EINTR) {
				continue;
			}

			return res;
		}

		if(hdr.msg_flags & MSG_TRUNC) {
			logger(DEBUG_ALWAYS, LOG_EMERG, "Script message truncated (possible attack)");
			return -1;
		}

		return res;
	}
}

static bool write_unix(int fd, const void *data, size_t len) {
	ssize_t res = send(fd, data, len, MSG_EOR);
	return res > 0 && (size_t)res == len;
}

#define CMD_MAGIC 0xDEADBEEF

typedef struct {
	uint32_t magic;
	uint32_t current;
	int vars;
} cmd_hdr_t;

typedef struct {
	uint32_t magic;
	uint32_t current;
	int status;
} cmd_result_t;

// Receive script names + environment variables from tincd through the socket,
// build full commands, run them, and send back the result.
// The worker doesn't trust its input and runs some basic checks
// to prevent broken tincd from using it to run arbitrary binaries.
static void script_worker_loop(int sock) {
	char buf[4096];
	errno = 0;

	for(uint32_t current = 0; ; ++current) {
		cmd_hdr_t hdr;

		// Read the current iteration number and make sure it matches the one we expect
		if(read_unix(sock, &hdr, sizeof(hdr)) <= 0 || hdr.magic != CMD_MAGIC || hdr.current != current || hdr.vars < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got empty or invalid header: %s", strerror(errno));
			return;
		}

		// Reset all known environment variables
		for(const char **known = known_vars; *known; ++known) {
			unsetenv(*known);
		}

		for(int i = 0; i < hdr.vars; ++i) {
			// Read environment variable
			ssize_t varlen = read_unix(sock, buf, sizeof(buf) - 1);

			if(varlen <= 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Got incorrect environment variable value: %s", strerror(errno));
				return;
			}

			buf[varlen] = '\0';

			// Check that we received a valid env var expression: NAME=value
			char *var_val = strchr(buf, '=');

			if(!var_val || var_val == buf) {
				logger(DEBUG_ALWAYS, LOG_EMERG, "Got broken environment variable (possible attack)");
				return;
			}

			// Replace '=' with '\0', splitting env var expression into name and value
			*var_val = '\0';

			// Check that tincd didn't pass anything weird or dangerous (like LD_PRELOAD)
			if(!is_known_var(buf)) {
				logger(DEBUG_ALWAYS, LOG_EMERG, "Got unknown environment variable (possible attack)");
				return;
			}

			setenv(buf, var_val + 1, 1);
		}

		// Read script name
		ssize_t namelen = read_unix(sock, buf, sizeof(buf) - 1);

		if(namelen <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Got incorrect command: %s", strerror(errno));
			return;
		}

		buf[namelen] = '\0';

		char scriptname[PATH_MAX];

		// Check it for signs of possible attack (basically paths to anything other
		// than tincd scripts in its configuration directory), and build full command.
		if(!build_script_name(scriptname, sizeof(scriptname), buf)) {
			logger(DEBUG_ALWAYS, LOG_EMERG, "Got invalid script name (possible attack)");
			return;
		}

		const cmd_result_t result = {
			.magic = CMD_MAGIC,
			.current = hdr.current,
			.status = run_command(scriptname),
		};

		// Send current iteration number and command exit status to tincd
		if(!write_unix(sock, &result, sizeof(result))) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not write command result: %s", strerror(errno));
			return;
		}
	}
}

void run_script_worker(uid_t uid, int sock) {
	if(uid && setuid(uid)) {
		fprintf(stderr, "Could not set user ID %d\n", uid);
		exit(EXIT_FAILURE);
	}

#ifdef HAVE_LINUX
	prctl(PR_SET_NAME, "scripts");
#endif

	script_worker_loop(sock);
	close(sock);

	logger(DEBUG_ALWAYS, LOG_NOTICE, "Script worker is terminating");
	exit(EXIT_SUCCESS);
}

static void script_worker_fatal(const char *msg) ATTR_NORETURN;
static void script_worker_fatal(const char *msg) {
	logger(DEBUG_ALWAYS, LOG_EMERG, "Script worker failed: could not %s (%s)", msg, strerror(errno));
	cleanup_script_worker();
	abort();
}
#endif // HAVE_SANDBOX

bool execute_script(const char *name, environment_t *env) {
	if(!sandbox_can(RUN_SCRIPTS, RIGHT_NOW)) {
		return false;
	}

	char scriptname[PATH_MAX];

	if(!build_script_name(scriptname, sizeof(scriptname), name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid script name '%s'", name);
		return false;
	}

	/* First check if there is a script */

#ifdef HAVE_WINDOWS

	if(!*scriptextension) {
		const char *pathext = getenv("PATHEXT");

		if(!pathext) {
			pathext = ".COM;.EXE;.BAT;.CMD";
		}

		size_t pathlen = strlen(pathext);
		size_t scriptlen = strlen(scriptname);

		const size_t fullnamelen = scriptlen + pathlen + 1;
		char *fullname = alloca(fullnamelen);
		char *ext = fullname + scriptlen;
		strncpy(fullname, scriptname, fullnamelen);

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
#endif // HAVE_WINDOWS

		if(access(scriptname, F_OK)) {
			return true;
		}

	logger(DEBUG_STATUS, LOG_INFO, "Executing script %s", name);

#ifdef HAVE_SANDBOX
	static cmd_hdr_t hdr = {.magic = CMD_MAGIC};

	if(worker.sock) {
		hdr.vars = env->n;

		if(!write_unix(worker.sock, &hdr, sizeof(hdr))) {
			script_worker_fatal("send header");
		}

		for(int i = 0; i < env->n; i++) {
			const char *val = env->entries[i];

			if(!write_unix(worker.sock, val, strlen(val))) {
				script_worker_fatal("send env vars");
			}
		}
	} else
#endif
	{
		/* Set environment */
		for(int i = 0; i < env->n; i++) {
			putenv(env->entries[i]);
		}
	}

	int status = 0;

#ifdef HAVE_SANDBOX

	if(worker.sock) {
		if(!write_unix(worker.sock, name, strlen(name))) {
			script_worker_fatal("send name");
		}

		cmd_result_t result;

		if(read_unix(worker.sock, &result, sizeof(result)) <= 0 || result.magic != CMD_MAGIC || result.current != hdr.current) {
			script_worker_fatal("start script");
		}

		status = result.status;
		++hdr.current;
	} else
#endif
	{
		status = run_command(scriptname);

		/* Unset environment */
		for(int i = 0; i < env->n; i++) {
			unputenv(env->entries[i]);
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

	return true;
}
