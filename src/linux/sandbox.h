#ifndef TINC_LINUX_SANDBOX_H
#define TINC_LINUX_SANDBOX_H

#include "../system.h"

#include <seccomp.h>

#define ALLOW_CALL(call) \
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(call), 0) < 0) return false

#define DENY_CALL(call) \
	if(seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(call), 0) < 0) return false

#endif // TINC_LINUX_SANDBOX_H
