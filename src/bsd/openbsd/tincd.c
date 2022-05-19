#include "../../system.h"

#include <libgen.h>
#include <assert.h>

#include "sandbox.h"
#include "../../device.h"
#include "../../logger.h"
#include "../../names.h"
#include "../../net.h"
#include "../../sandbox.h"
#include "../../script.h"
#include "../../xalloc.h"
#include "../../proxy.h"

static sandbox_level_t current_level = SANDBOX_NONE;
static bool can_use_new_paths = true;
static bool entered = false;

static bool chrooted(void) {
	return !(confbase && *confbase);
}

static void open_conf_subdir(const char *name, const char *privs) {
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%s", confbase, name);
	allow_path(path, privs);
}

static void open_common_paths(bool can_exec) {
	// Dummy device uses a fake path, skip it
	const char *dev = strcasecmp(device, DEVICE_DUMMY) ? device : NULL;

	const unveil_path_t paths[] = {
		{"/dev/random",  "r"},
		{"/dev/urandom", "r"},
		{confbase,       can_exec ? "rx" : "r"},
		{dev,            "rw"},
		{logfilename,    "rwc"},
		{pidfilename,    "rwc"},
		{unixsocketname, "rwc"},
		{NULL,           NULL},
	};
	allow_paths(paths);

	open_conf_subdir("cache", "rwc");
	open_conf_subdir("hosts", can_exec ? "rwxc" : "rwc");
	open_conf_subdir("invitations", "rwc");
}

static void open_exec_paths(void) {
	// proxyhost was checked previously. If we're here, proxyhost
	// contains the path to the executable, and nothing else.
	const char *proxy_exec = proxytype == PROXY_EXEC ? proxyhost : NULL;

	const unveil_path_t bin_paths[] = {
		{"/bin",            "rx"},
		{"/sbin",           "rx"},
		{"/usr/bin",        "rx"},
		{"/usr/sbin",       "rx"},
		{"/usr/local/bin",  "rx"},
		{"/usr/local/sbin", "rx"},
		{scriptinterpreter, "rx"},
		{proxy_exec,        "rx"},
		{NULL,              NULL},
	};
	allow_paths(bin_paths);
}

static bool sandbox_privs(bool can_exec) {
	// no mcast since multicasting should be set up by now
	char promises[512] =
	        "stdio"  // General I/O, both disk and network
	        " rpath" // Read files and directories
	        " wpath" // Write files and directories
	        " cpath" // Create new ones
	        " dns"   // Resolve domain names
	        " inet"  // Make network connections
	        " unix"; // Control socket connections from tinc CLI

	if(can_exec) {
		// fork() and execve() for scripts and exec proxies
		const char *exec = " proc exec";
		size_t n = strlcat(promises, exec, sizeof(promises));
		assert(n < sizeof(promises));
	}

	return restrict_privs(promises, can_exec ? PROMISES_ALL : PROMISES_NONE);
}

static void sandbox_paths(bool can_exec) {
	if(chrooted()) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "chroot is used. Disabling path sandbox.");
		return;
	}

	open_common_paths(can_exec);
	can_use_new_paths = false;

	if(can_exec) {
		if(proxytype == PROXY_EXEC && !access(proxyhost, X_OK)) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Looks like a shell expression was used for exec proxy. Using weak path sandbox.");
			allow_path("/", "rx");
		} else {
			open_exec_paths();
		}
	}
}

static bool sandbox_can_after_enter(sandbox_action_t action) {
	switch(action) {
	case START_PROCESSES:
		return current_level < SANDBOX_HIGH;

	case USE_NEW_PATHS:
		return can_use_new_paths;

	default:
		abort();
	}
}

bool sandbox_can(sandbox_action_t action, sandbox_time_t when) {
	if(when == AFTER_SANDBOX || entered) {
		return sandbox_can_after_enter(action);
	} else {
		return true;
	}
}

void sandbox_set_level(sandbox_level_t level) {
	assert(!entered);
	current_level = level;
}

bool sandbox_enter() {
	assert(!entered);
	entered = true;

	if(current_level == SANDBOX_NONE) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Sandbox is disabled");
		return true;
	}

	bool can_exec = sandbox_can_after_enter(START_PROCESSES);

	sandbox_paths(can_exec);

	if(sandbox_privs(can_exec)) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Entered sandbox at level %d", current_level);
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Could not enter sandbox. Set a lower level or disable it in tinc.conf");
	current_level = SANDBOX_NONE;

	return false;
}
