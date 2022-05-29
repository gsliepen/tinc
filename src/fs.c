#include "system.h"

#include "fs.h"
#include "names.h"
#include "xalloc.h"

static bool makedir(const char *path, mode_t mode) {
	assert(path);

	if(mkdir(path, mode)) {
		if(errno == EEXIST) {
			chmod(path, mode);
			return true;
		}

		fprintf(stderr, "Could not create directory %s: %s\n", path, strerror(errno));
		return false;
	}

	return true;
}

bool makedirs(tinc_dir_t dirs) {
	if(!dirs) {
		return false;
	}

	char path[PATH_MAX];
	bool need_confbase = dirs & ~((unsigned)DIR_CONFDIR);

	if(need_confbase && (!confbase || !makedir(confbase, 0755))) {
		return false;
	}

	if(dirs & DIR_CONFDIR && !confbase_given && (!confdir || !makedir(confdir, 0755))) {
		return false;
	}

	if(dirs & DIR_INVITATIONS) {
		conf_subdir(path, DIR_INVITATIONS);

		if(!makedir(path, 0700)) {
			return false;
		}
	}

	if(dirs & DIR_CACHE) {
		conf_subdir(path, DIR_CACHE);

		if(!makedir(path, 0755)) {
			return false;
		}
	}

	if(dirs & DIR_HOSTS) {
		conf_subdir(path, DIR_HOSTS);

		if(!makedir(path, 0755)) {
			return false;
		}
	}

	return true;
}


/* Open a file with the desired permissions, minus the umask.
   Also, if we want to create an executable file, we call fchmod()
   to set the executable bits. */

FILE *fopenmask(const char *filename, const char *mode, mode_t perms) {
	mode_t mask = umask(0);
	perms &= ~mask;
	umask(~perms & 0777);
	FILE *f = fopen(filename, mode);

	if(!f) {
		fprintf(stderr, "Could not open %s: %s\n", filename, strerror(errno));
		return NULL;
	}

#ifdef HAVE_FCHMOD

	if(perms & 0444) {
		fchmod(fileno(f), perms);
	}

#endif
	umask(mask);
	return f;
}

char *absolute_path(const char *path) {
#ifdef HAVE_WINDOWS
	// Works for nonexistent paths
	return _fullpath(NULL, path, 0);
#else

	if(!path || !*path) {
		return NULL;
	}

	// If an absolute path was passed, return its copy
	if(*path == '/') {
		return xstrdup(path);
	}

	// Try using realpath. If it fails for any reason
	// other than that the file was not found, bail out.
	char *abs = realpath(path, NULL);

	if(abs || errno != ENOENT) {
		return abs;
	}

	// Since the file does not exist, we're forced to use a fallback.
	// Get current working directory and concatenate it with the argument.
	char cwd[PATH_MAX];

	if(!getcwd(cwd, sizeof(cwd))) {
		return NULL;
	}

	// Remove trailing slash if present since we'll be adding our own
	size_t cwdlen = strlen(cwd);

	if(cwdlen && cwd[cwdlen - 1] == '/') {
		cwd[cwdlen - 1] = '\0';
	}

	// We don't do any normalization because it's complicated, and the payoff is small.
	// If user passed something like '.././../foo' — that's their choice; fopen works either way.
	xasprintf(&abs, "%s/%s", cwd, path);

	if(strlen(abs) >= PATH_MAX) {
		free(abs);
		abs = NULL;
	}

	return abs;
#endif
}

bool chrooted(void) {
	return !(confbase && *confbase);
}

void conf_subdir(char buf[PATH_MAX], tinc_dir_t dir) {
	const char *name = NULL;

	switch(dir) {
	case DIR_CACHE:
		name = "cache";
		break;

	case DIR_HOSTS:
		name = "hosts";
		break;

	case DIR_INVITATIONS:
		name = "invitations";
		break;

	case DIR_CONFBASE:
	case DIR_CONFDIR:
	default:
		abort();
	}

	snprintf(buf, PATH_MAX, "%s" SLASH "%s", confbase, name);
}
