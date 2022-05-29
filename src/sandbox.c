#include "system.h"

#include "sandbox.h"

// Stubs for platforms without sandbox support to avoid using lots of #ifdefs.

bool sandbox_can(sandbox_action_t action, sandbox_time_t when) {
	(void)action;
	(void)when;
	return true;
}

void sandbox_set_level(sandbox_level_t level) {
	(void)level;
}

bool sandbox_enabled(void) {
	return false;
}

bool sandbox_active(void) {
	return false;
}

bool sandbox_enter(void) {
	// No initialization needed, always return success
	return true;
}
