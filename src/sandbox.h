#ifndef TINC_SANDBOX_H
#define TINC_SANDBOX_H

#include "system.h"

typedef enum sandbox_level_t {
	SANDBOX_NONE,
	SANDBOX_NORMAL,
	SANDBOX_HIGH,
} sandbox_level_t;

typedef enum sandbox_action_t {
	START_PROCESSES, // Start child processes
	USE_NEW_PATHS,   // Access to filesystem paths that were not known at the start of the process
} sandbox_action_t;

typedef enum sandbox_time_t {
	AFTER_SANDBOX, // Check if the action can be performed after entering sandbox
	RIGHT_NOW,     // Check if the action can be performed right now
} sandbox_time_t;

// Check if the current process has enough privileges to perform the action
extern bool sandbox_can(sandbox_action_t action, sandbox_time_t when);

// Set the expected sandbox level. Call sandbox_enter() to actually apply it.
extern void sandbox_set_level(sandbox_level_t level);

// Enter sandbox using the passed level. Returns true if successful.
// Obviously, this is a one-way function, there's no way to reverse it.
extern bool sandbox_enter(void);

#endif // TINC_SANDBOX_H
