#include "unittest.h"

/*
    getaddrinfo() is replaced by a fake that understands two kinds of names:
    "slow-<ms>.test" resolves to 127.0.0.1 after <ms> milliseconds,
    "fail-<ms>.test" fails after <ms> milliseconds.
    Anything else goes to the real getaddrinfo().
*/

int __real_getaddrinfo(const char *host, const char *service, const struct addrinfo *hint, struct addrinfo **res);
int __wrap_getaddrinfo(const char *host, const char *service, const struct addrinfo *hint, struct addrinfo **res);

int __wrap_getaddrinfo(const char *host, const char *service, const struct addrinfo *hint, struct addrinfo **res) {
	unsigned int ms;

	if(!host || hint->ai_flags & AI_NUMERICHOST) {
		return __real_getaddrinfo(host, service, hint, res);
	}

	if(sscanf(host, "slow-%u.test", &ms) == 1) {
		sleep_millis(ms);
		struct addrinfo numeric = *hint;
		numeric.ai_family = AF_INET;
		return __real_getaddrinfo("127.0.0.1", service, &numeric, res);
	}

	if(sscanf(host, "fail-%u.test", &ms) == 1) {
		sleep_millis(ms);
		return EAI_NONAME;
	}

	return __real_getaddrinfo(host, service, hint, res);
}
