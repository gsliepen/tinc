#ifndef TINC_BSD_OPENBSD_SANDBOX_H
#define TINC_BSD_OPENBSD_SANDBOX_H

#include "../../system.h"

typedef struct unveil_path_t {
	const char *path;
	const char *priv;
} unveil_path_t;

// No restrictions
static const char *PROMISES_ALL = NULL;

// Full restrictions; children can call nothing but exit()
static const char *PROMISES_NONE = "";

// Allow access to the paths with the specified privileges. Can be called multiple times.
// This is a thin logging wrapper around unveil(2).
// Paths that are equal to NULL are skipped. The last path in the array must be (NULL, NULL).
// Note that after the last call to this function you should lock access to
// unveil(2) using pledge(2) to prevent the program from undoing the sandbox.
extern void allow_paths(const unveil_path_t paths[]);

// Allow access to a single path. Logging wrapper around unveil().
extern void allow_path(const char *path, const char *priv);

// Restrict privileges. Can be called multiple times to further restrict (but not regain) them.
// It's a thin logging wrapper around unveil(2), see man page for details.
extern bool restrict_privs(const char *promises, const char *execpromises);

#endif // TINC_BSD_OPENBSD_SANDBOX_H
