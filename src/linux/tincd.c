#include "../system.h"

#include <assert.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <libgen.h>

#include "sandbox.h"
#include "../names.h"
#include "../sandbox.h"
#include "../logger.h"
#include "../utils.h"
#include "../fs.h"
#include "../netutl.h"

#ifdef HAVE_LINUX_LANDLOCK_H
#include "landlock.h"
#endif

static sandbox_level_t current_level = SANDBOX_NORMAL;
static bool entered = false;
static bool can_use_new_paths = true;

#define DENY_MEMORY(call, flags) \
	if(seccomp_rule_add(ctx, SCMP_ACT_TRAP, SCMP_SYS(call), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, flags, flags)) < 0) goto exit

// Block attempts to create (or change) memory regions that are both writable and executable.
static bool add_seccomp_memory_wxe(void) {
	bool success = false;
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

	if(!ctx) {
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_DEBUG, "Adding memory W^X filter");

	DENY_MEMORY(mprotect, PROT_EXEC);
	DENY_MEMORY(pkey_mprotect, PROT_EXEC);
	DENY_MEMORY(shmat, SHM_EXEC);
	DENY_MEMORY(mmap, PROT_EXEC | PROT_WRITE);
	DENY_MEMORY(mmap2, PROT_EXEC | PROT_WRITE);

	success = !seccomp_load(ctx);
exit:
	seccomp_release(ctx);
	return success;
}

#define ALLOW_CALL0(call, arg) \
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 1, SCMP_A0(SCMP_CMP_MASKED_EQ, arg, arg)) < 0) return false

#define ALLOW_CALL1(call, arg) \
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, arg, arg)) < 0) return false

#define ALLOW_SOCKET(domain) ALLOW_CALL0(socket, domain)
#define ALLOW_SETSOCKOPT(level) ALLOW_CALL1(setsockopt, level)
#define ALLOW_GETSOCKOPT(level) ALLOW_CALL1(getsockopt, level)
#define ALLOW_IOCTL(req) ALLOW_CALL1(ioctl, req)
#define ALLOW_FCNTL(cmd) ALLOW_CALL1(fcntl, cmd); ALLOW_CALL1(fcntl64, cmd)

static bool allow_syscall_list(scmp_filter_ctx ctx) {
	const int calls[] = {
		// threading
		SCMP_SYS(futex),
		SCMP_SYS(set_robust_list),
#ifdef __NR_futex_time64
		SCMP_SYS(futex_time64),
#endif

		// epoll/select
		SCMP_SYS(_newselect),
		SCMP_SYS(epoll_create),
		SCMP_SYS(epoll_create1),
		SCMP_SYS(epoll_ctl),
		SCMP_SYS(epoll_pwait),
		SCMP_SYS(epoll_wait),
		SCMP_SYS(poll),
		SCMP_SYS(ppoll),
		SCMP_SYS(pselect6),
#ifdef  __NR_ppoll_time64
		SCMP_SYS(ppoll_time64),
#endif
#ifdef  __NR_pselect6_time64
		SCMP_SYS(pselect6_time64),
#endif

		// I/O
		SCMP_SYS(close),
		SCMP_SYS(open),
		SCMP_SYS(openat),
		SCMP_SYS(pipe),
		SCMP_SYS(pipe2),
		SCMP_SYS(read),
		SCMP_SYS(readv),
		SCMP_SYS(select),
		SCMP_SYS(write),
		SCMP_SYS(writev),
		SCMP_SYS(pread64),
#ifdef __NR_preadv
		SCMP_SYS(preadv),
#endif
#ifdef __NR_preadv2
		SCMP_SYS(preadv2),
#endif
#ifdef __NR_pwritev
		SCMP_SYS(pwritev),
#endif
#ifdef __NR_pwritev2
		SCMP_SYS(pwritev2),
#endif

		// network
		SCMP_SYS(accept),
		SCMP_SYS(bind),
		SCMP_SYS(connect),
		SCMP_SYS(getsockname),
		SCMP_SYS(recv),
		SCMP_SYS(recvfrom),
		SCMP_SYS(recvmmsg),
		SCMP_SYS(recvmsg),
		SCMP_SYS(send),
		SCMP_SYS(sendmmsg),
		SCMP_SYS(sendmsg),
		SCMP_SYS(sendto),

		// signals
		SCMP_SYS(rt_sigaction),
		SCMP_SYS(rt_sigprocmask),
		SCMP_SYS(rt_sigreturn),
		SCMP_SYS(signal),
		SCMP_SYS(sigreturn),
		SCMP_SYS(sigaction),

		// misc
		SCMP_SYS(getrandom),
		SCMP_SYS(sysinfo),
		SCMP_SYS(uname),

		// time
		SCMP_SYS(gettimeofday),
		SCMP_SYS(time),
		SCMP_SYS(nanosleep),

#ifdef HAVE_WATCHDOG
		// users/groups (needed by libsystemd)
		SCMP_SYS(getegid),
		SCMP_SYS(geteuid),
		SCMP_SYS(getgid),
		SCMP_SYS(getuid),
#endif

		// process
		SCMP_SYS(exit),
		SCMP_SYS(exit_group),
		SCMP_SYS(getpid),
		SCMP_SYS(getrlimit),
		SCMP_SYS(gettid),
		SCMP_SYS(set_tid_address),
		SCMP_SYS(wait4),
		SCMP_SYS(waitpid),
#ifdef __NR_rseq
		SCMP_SYS(rseq),
#endif

		// memory
		SCMP_SYS(brk),
		SCMP_SYS(madvise),
		SCMP_SYS(mmap),
		SCMP_SYS(mmap2),
		SCMP_SYS(mprotect),
		SCMP_SYS(mremap),
		SCMP_SYS(munmap),

		// filesystem
		SCMP_SYS(_llseek),
		SCMP_SYS(access),
		SCMP_SYS(faccessat),
		SCMP_SYS(fstat),
		SCMP_SYS(fstat64),
		SCMP_SYS(fstatat64),
		SCMP_SYS(getdents),
		SCMP_SYS(getdents64),
		SCMP_SYS(lseek),
		SCMP_SYS(newfstatat),
		SCMP_SYS(rename),
		SCMP_SYS(renameat),
		SCMP_SYS(renameat2),
		SCMP_SYS(stat),
		SCMP_SYS(stat64),
		SCMP_SYS(unlink),
		SCMP_SYS(unlinkat),
#ifdef __NR_statx
		SCMP_SYS(statx),
#endif
	};

	// getsockopt()
	ALLOW_GETSOCKOPT(SOL_SOCKET);
	ALLOW_GETSOCKOPT(IPPROTO_IP);

	// setsockopt()
	ALLOW_SETSOCKOPT(IPPROTO_IP);
	ALLOW_SETSOCKOPT(IPPROTO_IPV6);
	ALLOW_SETSOCKOPT(IPPROTO_TCP);
	ALLOW_SETSOCKOPT(SOL_SOCKET);

	// socket()
	ALLOW_SOCKET(AF_INET);
	ALLOW_SOCKET(AF_INET6);
	ALLOW_SOCKET(AF_NETLINK); // libc
	ALLOW_SOCKET(AF_PACKET);
	ALLOW_SOCKET(AF_UNIX);

	// ioctl()
	ALLOW_IOCTL(FIONREAD); // libc
	ALLOW_IOCTL(SIOCGIFHWADDR);
	ALLOW_IOCTL(SIOCGIFINDEX);
	ALLOW_IOCTL(TCGETS); // libc
	ALLOW_IOCTL(TIOCGWINSZ); // libc
	ALLOW_IOCTL(TUNSETIFF);

	// fcntl()
	ALLOW_FCNTL(F_GETFL);
	ALLOW_FCNTL(F_SETFD);
	ALLOW_FCNTL(F_SETFL);

	for(size_t i = 0; i < sizeof(calls) / sizeof(*calls); ++i) {
		if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, calls[i], 0) < 0) {
			return false;
		}
	}

	return true;
}

static void handle_sigsys(int signum, siginfo_t *si, void *thread_context) ATTR_NORETURN;
static void handle_sigsys(int signum, siginfo_t *si, void *thread_context) {
	(void)signum;
	(void)thread_context;

	int call = si->si_syscall;
	char msg[] = "Syscall XXX blocked by sandbox (possible attack, or your system is not supported yet).";

	// The idea is stolen from memcached since formatting functions cannot be safely used here.
	// Don't forget to update indexes if template is changed.
	msg[8] = (char)('0' + (call / 100) % 10);
	msg[9] = (char)('0' + (call / 10) % 10);
	msg[10] = (char)('0' + call % 10);

	if(write(STDERR_FILENO, msg, strlen(msg)) < 0) {
		// nothing we can do here
	}

	_exit(EXIT_FAILURE);
}

// Allow only syscalls used by tincd.
static bool add_seccomp_used(void) {
	bool success = false;
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);

	if(ctx) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Adding used syscalls filter");
		success = allow_syscall_list(ctx) && !seccomp_load(ctx);
		seccomp_release(ctx);
	}

	if(success) {
		const struct sigaction act = {
			.sa_sigaction = handle_sigsys,
			.sa_flags = SA_SIGINFO,
		};
		success = !sigaction(SIGSYS, &act, NULL);
	}

	return success;
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

static bool disable_escalation(void) {
	return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != -1 &&
	       prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != -1;
}

#ifdef HAVE_LINUX_LANDLOCK_H
// Sandbox can be circumvented by creating and starting new scripts, or writing to old ones.
// The first sceneario should be prevented by blocking all chmod-related syscalls using seccomp-bpf.
// The second one by removing write access to existing scripts using this function.
// Sadly, Landlock picks the most permissive rule and does not allow creating rules for non-existing files
// (unlike unveil() where the most specific rule wins), so we cannot use Landlock here.
static void hosts_scripts_deny_write(const char *hosts) {
	DIR *dir = opendir(hosts);

	if(!dir) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not read directory %s: %s", hosts, strerror(errno));
		return;
	}

	uid_t uid = getuid();
	struct dirent *ent;

	while((ent = readdir(dir))) {
		if(strtailcmp(ent->d_name, "-up") && strtailcmp(ent->d_name, "-down")) {
			continue;
		}

		char fname[PATH_MAX];
		int total = snprintf(fname, sizeof(fname), "%s/%s", hosts, ent->d_name);

		if(total < 0 || (size_t)total >= sizeof(fname)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Path %s too long", fname);
			continue;
		}

		struct stat st;

		if(stat(fname, &st)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not stat file %s: %s", fname, strerror(errno));
			continue;
		}

		if(st.st_uid != uid) {
			continue;
		}

		mode_t nowrite = (st.st_mode & 0777u) & ~(uint32_t)(S_IWUSR | S_IWGRP | S_IWOTH);

		if(chmod(fname, nowrite)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not chmod file %s: %s", fname, strerror(errno));
		}
	}

	closedir(dir);
	logger(DEBUG_ALWAYS, LOG_DEBUG, "Removed write access to host scripts");
}

static bool add_path_rules(void) {
	// Load NSS libraries and open domain resolution configuration files
	str2sockaddr("localhost", "80");

	char cache[PATH_MAX], hosts[PATH_MAX], invitations[PATH_MAX];
	conf_subdir(cache, DIR_CACHE);
	conf_subdir(hosts, DIR_HOSTS);
	conf_subdir(invitations, DIR_INVITATIONS);

	hosts_scripts_deny_write(hosts);

	char *logdir = NULL;

	if(logfilename) {
		char *logf = alloca(strlen(logfilename) + 1);
		strcpy(logf, logfilename);
		logdir = dirname(logf);
	}

	char *pidf = alloca(strlen(pidfilename) + 1);
	strcpy(pidf, pidfilename);

	char *unixf = alloca(strlen(unixsocketname) + 1);
	strcpy(unixf, unixsocketname);

	const landlock_path_t paths[] = {
		// libc domain resolution
		{"/etc",               FS_READ_DIR},
		{"/etc/host.conf",     FS_READ_FILE},
		{"/etc/hosts",         FS_READ_FILE},
		{"/etc/nsswitch.conf", FS_READ_FILE},
		{"/etc/resolv.conf",   FS_READ_FILE},
		{"/lib",               FS_READ_DIR | FS_READ_FILE},
		{"/lib64",             FS_READ_DIR | FS_READ_FILE},
		{"/usr/lib",           FS_READ_DIR | FS_READ_FILE},
		{"/usr/lib32",         FS_READ_DIR | FS_READ_FILE},
		{"/usr/lib64",         FS_READ_DIR | FS_READ_FILE},

		// libc and third-party libraries
		{"/dev/random",        FS_READ_FILE},
		{"/dev/urandom",       FS_READ_FILE},

		// tincd
		{logdir,               FS_MAKE_REG},
		{logfilename,          FS_WRITE_FILE},
		{dirname(pidf),        FS_REMOVE_FILE},
		{dirname(unixf),       FS_REMOVE_FILE},
		{confbase,             FS_READ_FILE | FS_READ_DIR},
		{cache,                FS_READ_FILE | FS_WRITE_FILE | FS_REMOVE_FILE | FS_MAKE_REG | FS_READ_DIR},
		{hosts,                FS_READ_FILE | FS_WRITE_FILE | FS_REMOVE_FILE | FS_MAKE_REG | FS_READ_DIR},
		{invitations,          FS_READ_FILE | FS_WRITE_FILE | FS_REMOVE_FILE | FS_MAKE_REG | FS_READ_DIR},
		{NULL,                 0}
	};
	return allow_paths(paths);
}
#endif // HAVE_LINUX_LANDLOCK_H

bool sandbox_enter(void) {
	assert(!entered);
	entered = true;

	if(current_level == SANDBOX_NONE) {
		logger(DEBUG_ALWAYS, LOG_DEBUG, "Sandbox is disabled");
		return true;
	}

	if(!disable_escalation()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Failed to disable privilege escalation: %s", strerror(errno));
		return false;
	}

#ifdef HAVE_LINUX_LANDLOCK_H

	if(chrooted()) {
		logger(DEBUG_ALWAYS, LOG_NOTICE, "chroot is used, disabling path sandbox.");
	} else {
		if(!add_path_rules()) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Failed to block filesystem access: %s", strerror(errno));
			return false;
		}

		can_use_new_paths = false;
	}

#endif

	if(!add_seccomp_memory_wxe()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not block creating writable & executable memory regions: %s", strerror(errno));
		return false;
	}

	if(!add_seccomp_used()) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error setting up seccomp sandbox: %s", strerror(errno));
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_DEBUG, "Entered sandbox at level %d", current_level);
	return true;
}
