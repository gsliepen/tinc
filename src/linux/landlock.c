#include "../system.h"

#ifdef HAVE_LINUX_LANDLOCK_H

#include <sys/syscall.h>

#include "landlock.h"
#include "../logger.h"

// Full access without any restrictions
static const uint32_t ACCESS_FULL = FS_EXECUTE |
                                    FS_WRITE_FILE |
                                    FS_READ_FILE |
                                    FS_READ_DIR |
                                    FS_REMOVE_DIR |
                                    FS_REMOVE_FILE |
                                    FS_MAKE_CHAR |
                                    FS_MAKE_DIR |
                                    FS_MAKE_REG |
                                    FS_MAKE_SOCK |
                                    FS_MAKE_FIFO |
                                    FS_MAKE_BLOCK |
                                    FS_MAKE_SYM;

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, uint32_t flags) {
	return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type, const void *rule_attr, uint32_t flags) {
	return (int)syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(int ruleset_fd, uint32_t flags) {
	return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

static void flags_to_str(char *buf, size_t len, uint64_t flags) {
	snprintf(buf, len, "file[%c%c%c%c] dir[%c%c] new[%c%c%c%c%c%c%c]",
	         flags & FS_READ_FILE   ? 'r' : '-',
	         flags & FS_WRITE_FILE  ? 'w' : '-',
	         flags & FS_EXECUTE     ? 'x' : '-',
	         flags & FS_REMOVE_FILE ? 'd' : '-',

	         flags & FS_READ_DIR    ? 'r' : '-',
	         flags & FS_REMOVE_DIR  ? 'd' : '-',

	         flags & FS_MAKE_CHAR   ? 'c' : '-',
	         flags & FS_MAKE_DIR    ? 'd' : '-',
	         flags & FS_MAKE_REG    ? 'r' : '-',
	         flags & FS_MAKE_SOCK   ? 's' : '-',
	         flags & FS_MAKE_FIFO   ? 'f' : '-',
	         flags & FS_MAKE_BLOCK  ? 'b' : '-',
	         flags & FS_MAKE_SYM    ? 'l' : '-');
}

static void print_path(const char *path, uint64_t flags) {
	char buf[512];
	flags_to_str(buf, sizeof(buf), flags);
	logger(DEBUG_ALWAYS, LOG_DEBUG, "Allowing %s with: %s", path, buf);
}

static bool add_rule(int ruleset, const char *path, uint64_t flags) {
	print_path(path, flags);

	const struct landlock_path_beneath_attr attr = {
		.allowed_access = flags,
		.parent_fd = open(path, O_PATH | O_CLOEXEC),
	};

	if(attr.parent_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open path %s: %s", path, strerror(errno));
		return false;
	}

	bool success = !landlock_add_rule(ruleset, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);

	if(!success) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not allow path %s: %s", path, strerror(errno));
	}

	close(attr.parent_fd);
	return success;
}

static bool add_rules(int fd, const landlock_path_t paths[]) {
	bool added_any = false;

	for(const landlock_path_t *p = paths; p->path || p->flags; ++p) {
		if(p->path && p->flags) {
			added_any |= add_rule(fd, p->path, p->flags);
		}
	}

	return added_any;
}

bool allow_paths(const landlock_path_t paths[]) {
	const struct landlock_ruleset_attr ruleset = {.handled_access_fs = ACCESS_FULL};
	int fd = landlock_create_ruleset(&ruleset, sizeof(ruleset), 0);

	if(fd < 0) {
		if(errno == ENOSYS || errno == EOPNOTSUPP) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Path protection is not supported by this kernel");
			return true;
		}

		return false;
	}

	bool success = add_rules(fd, paths) &&
	               !landlock_restrict_self(fd, 0);
	close(fd);

	return success;
}

#endif // HAVE_LINUX_LANDLOCK_H
