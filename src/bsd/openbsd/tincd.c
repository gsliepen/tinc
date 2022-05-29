#include "../../system.h"

#include <assert.h>

#include "sandbox.h"
#include "../../device.h"
#include "../../logger.h"
#include "../../names.h"
#include "../../fs.h"
#include "../../sandbox.h"

static sandbox_level_t current_level = SANDBOX_NONE;
static bool can_use_new_paths = true;
static bool entered = false;

static void open_conf_subdir(tinc_dir_t dir, const char *privs) {
	char path[PATH_MAX];
	conf_subdir(path, dir);
	allow_path(path, privs);
}

static void open_common_paths(void) {
	// Dummy device uses a fake path, skip it
	const char *dev = strcasecmp(device, DEVICE_DUMMY) ? device : NULL;

	const unveil_path_t paths[] = {
		{"/dev/random",      "r"},
		{"/dev/urandom",     "r"},
		{"/etc/resolv.conf", "r"},
		{"/etc/hosts",       "r"},
		{confbase,           "r"},
		{dev,                "rw"},
		{logfilename,        "rwc"},
		{pidfilename,        "rwc"},
		{unixsocketname,     "rwc"},
		{NULL,               NULL},
	};
	allow_paths(paths);

	open_conf_subdir(DIR_CACHE, "rwc");
	open_conf_subdir(DIR_HOSTS, "rwc");
	open_conf_subdir(DIR_INVITATIONS, "rwc");
}

static bool sandbox_privs(void) {
	// no mcast since multicasting should be set up by now
	const char *promises =
	        "stdio"  // General I/O, both disk and network
	        " rpath" // Read files and directories
	        " wpath" // Write files and directories
	        " cpath" // Create new ones
	        " dns"   // Resolve domain names
	        " inet"  // Make network connections
	        " unix"; // Control socket connections from tinc CLI
	return restrict_privs(promises, PROMISES_NONE);
}

static void sandbox_paths(void) {
	if(chrooted()) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "chroot is used. Disabling path sandbox.");
	} else {
		open_common_paths();
		can_use_new_paths = false;
	}
}

static bool sandbox_can_after_enter(sandbox_action_t action) {
	switch(action) {
	case START_PROCESSES:
		return current_level == SANDBOX_NONE;

	case RUN_SCRIPTS:
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

bool sandbox_enabled(void) {
	return current_level > SANDBOX_NONE;
}

bool sandbox_active(void) {
	return sandbox_enabled() && entered;
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

	sandbox_paths();

	if(sandbox_privs()) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Entered sandbox at level %d", current_level);
		return true;
	}

	logger(DEBUG_ALWAYS, LOG_ERR, "Could not enter sandbox. Set a lower level or disable it in tinc.conf");
	current_level = SANDBOX_NONE;

	return false;
}
