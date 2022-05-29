#include "unittest.h"
#include "../../src/fs.h"
#include "../../src/names.h"
#include "../../src/xalloc.h"

#ifndef HAVE_WINDOWS

#define FAKE_PATH "nonexistentreallyfakepath"

typedef struct {
	const char *arg;
	const char *want;
} testcase_t;

static void test_absolute_path_on_absolute_returns_it(void **state) {
	(void)state;

	const char *paths[] = {"/", "/foo", "/foo/./../bar"};

	for(size_t i = 0; i < sizeof(paths) / sizeof(*paths); ++i) {
		char *got = absolute_path(paths[i]);
		assert_ptr_not_equal(paths[i], got);
		assert_string_equal(paths[i], got);
		free(got);
	}
}

static void test_absolute_path_on_empty_returns_null(void **state) {
	(void)state;
	assert_null(absolute_path(NULL));
	assert_null(absolute_path("\0"));
}

static void test_absolute_path_relative(void **state) {
	(void)state;

	testcase_t cases[] = {
		{".", "/"},
		{"foo", "/foo"},
		{"./"FAKE_PATH, "/./"FAKE_PATH},
		{"../foo/./../"FAKE_PATH, "/../foo/./../"FAKE_PATH},
	};

	for(size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
		char *got = absolute_path(cases[i].arg);
		assert_string_equal(cases[i].want, got);
		free(got);
	}
}

static int setup_path_unix(void **state) {
	(void)state;
	assert_int_equal(0, chdir("/"));
	return 0;
}

const char tmp_template[] = "/tmp/tinc.test.fs.XXXXXX";
char tmp[sizeof(tmp_template)];

static int setup_temp_dir(void **state) {
	(void)state;
	strcpy(tmp, tmp_template);
	assert_ptr_equal(tmp, mkdtemp(tmp));
	confdir = xstrdup(tmp);
	xasprintf(&confbase, "%s/conf", tmp);
	return 0;
}

static int teardown_temp_dir(void **state) {
	(void)state;
	free(confdir);
	free(confbase);
	return 0;
}

static void test_makedir(tinc_dir_t dir, bool exists) {
	char path[PATH_MAX];
	char container[PATH_MAX] = {0};

	switch(dir) {
	case DIR_CONFDIR:
		strcpy(path, tmp);
		break;

	case DIR_CONFBASE:
		sprintf(path, "%s/conf", tmp);
		strcpy(container, tmp);
		break;

	case DIR_CACHE:
		sprintf(path, "%s/conf/cache", tmp);
		sprintf(container, "%s/conf", tmp);
		break;

	case DIR_HOSTS:
		sprintf(path, "%s/conf/hosts", tmp);
		sprintf(container, "%s/conf", tmp);
		break;

	case DIR_INVITATIONS:
		sprintf(path, "%s/conf/invitations", tmp);
		sprintf(container, "%s/conf", tmp);
		break;
	}

	struct stat st;

	if(exists) {
		assert_int_equal(0, stat(path, &st));
	} else {
		assert_int_equal(-1, stat(path, &st));
		assert_int_equal(ENOENT, errno);
	}

	// Deny write access and make sure makedirs() detects that
	if(getuid() && *container) {
		assert_int_equal(0, chmod(tmp, 0));
		assert_false(makedirs(dir));
		assert_int_equal(0, chmod(tmp, 0755));
	}

	// Now test the happy path
	assert_true(makedirs(dir));
	assert_int_equal(0, stat(path, &st));
	assert_true(S_ISDIR(st.st_mode));
	assert_int_equal(0, access(path, R_OK | W_OK));

	// Make sure no other directories were created
	if(*container) {
		DIR *d = opendir(container);
		assert_non_null(d);

		struct dirent *ent;

		while((ent = readdir(d))) {
			if(strcmp(".", ent->d_name) && strcmp("..", ent->d_name)) {
				assert_int_equal(st.st_ino, ent->d_ino);
				assert_true(ent->d_type & DT_DIR);
			}
		}

		closedir(d);
	}
}

static void test_makedirs_cache(void **state) {
	(void)state;
	test_makedir(DIR_CACHE, false);
}

static void test_makedirs_confbase(void **state) {
	(void)state;
	test_makedir(DIR_CONFBASE, false);
}

static void test_makedirs_confdir(void **state) {
	(void)state;
	test_makedir(DIR_CONFDIR, true);
}

static void test_makedirs_hosts(void **state) {
	(void)state;
	test_makedir(DIR_HOSTS, false);
}

static void test_makedirs_invitations(void **state) {
	(void)state;
	test_makedir(DIR_INVITATIONS, false);
}

static int setup_umask(void **state) {
	(void)state;
	umask(0);
	return 0;
}

static void test_fopenmask_existing(void **state) {
	(void)state;

	struct stat st;
	strcpy(tmp, tmp_template);

	int fd = mkstemp(tmp);
	assert_int_not_equal(-1, fd);
	close(fd);

	assert_int_equal(0, chmod(tmp, 0755));
	assert_int_equal(0, stat(tmp, &st));
	assert_int_equal(0755, st.st_mode & 0777);

	FILE *f = fopenmask(tmp, "r", 0700);
	assert_non_null(f);
	fclose(f);

	assert_int_equal(0, stat(tmp, &st));
	assert_int_equal(0700, st.st_mode & 0777);
}

static void test_fopenmask_new(void **state) {
	(void)state;

	struct stat st;
	strcpy(tmp, tmp_template);

	// mktemp() nags about safety and using better alternatives
	int fd = mkstemp(tmp);
	assert_int_not_equal(-1, fd);
	close(fd);
	unlink(tmp);

	FILE *f = fopenmask(tmp, "w", 0750);
	assert_non_null(f);
	fclose(f);

	assert_int_equal(0, stat(tmp, &st));
	assert_int_equal(0750, st.st_mode & 0777);
}

#endif // HAVE_WINDOWS

static void test_makedirs_bad(void **state) {
	(void)state;

	assert_false(makedirs(0));

	confbase = NULL; // free not needed, just make it obvious that confbase is NULL
	assert_false(makedirs(DIR_CACHE));
	assert_false(makedirs(DIR_CONFBASE));
	assert_false(makedirs(DIR_HOSTS));
	assert_false(makedirs(DIR_INVITATIONS));

	confdir = NULL; // same
	assert_false(makedirs(DIR_CONFDIR));
}

int main(void) {
	const struct CMUnitTest tests[] = {
#ifndef HAVE_WINDOWS
		cmocka_unit_test_setup(test_absolute_path_on_absolute_returns_it, setup_path_unix),
		cmocka_unit_test_setup(test_absolute_path_on_empty_returns_null, setup_path_unix),
		cmocka_unit_test_setup(test_absolute_path_relative, setup_path_unix),
		cmocka_unit_test_setup_teardown(test_makedirs_cache, setup_temp_dir, teardown_temp_dir),
		cmocka_unit_test_setup_teardown(test_makedirs_confbase, setup_temp_dir, teardown_temp_dir),
		cmocka_unit_test_setup_teardown(test_makedirs_confdir, setup_temp_dir, teardown_temp_dir),
		cmocka_unit_test_setup_teardown(test_makedirs_hosts, setup_temp_dir, teardown_temp_dir),
		cmocka_unit_test_setup_teardown(test_makedirs_invitations, setup_temp_dir, teardown_temp_dir),
		cmocka_unit_test_setup(test_fopenmask_existing, setup_umask),
		cmocka_unit_test_setup(test_fopenmask_new, setup_umask),
#endif
		cmocka_unit_test(test_makedirs_bad),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
