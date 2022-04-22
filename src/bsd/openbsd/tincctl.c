#include "../../system.h"

#include "sandbox.h"
#include "../../sandbox.h"

static const char *promises =
        "stdio"  // General I/O
        " rpath" // Read configs & keys
        " wpath" // Write same
        " cpath" // Create same
        " fattr" // chmod() same
        " proc"  // Check that tincd is running with kill()
        " dns"   // Resolve domain names
        " inet"  // Check that port is available
        " unix"  // Control connection to tincd
        " exec"  // Start tincd
#if defined(HAVE_CURSES) || defined(HAVE_READLINE)
        " tty"
#endif
        ;

static sandbox_level_t current_level = SANDBOX_NONE;

void sandbox_set_level(sandbox_level_t level) {
	current_level = level;
}

bool sandbox_enter() {
	if(current_level == SANDBOX_NONE) {
		return true;
	} else {
		return restrict_privs(promises, PROMISES_ALL);
	}
}

bool sandbox_can(sandbox_action_t action, sandbox_time_t when) {
	(void)action;
	(void)when;
	return true;
}
