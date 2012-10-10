/*
 * fake library for ssh
 *
 * This file includes getnameinfo().
 * These funtions are defined in rfc2133.
 *
 * But these functions are not implemented correctly. The minimum subset
 * is implemented for ssh use only. For exapmle, this routine assumes
 * that ai_family is AF_INET. Don't use it for another purpose.
 */

#include "system.h"

#include "fake-getnameinfo.h"
#include "fake-getaddrinfo.h"

#if !HAVE_DECL_GETNAMEINFO

int getnameinfo(const struct sockaddr *sa, size_t salen, char *host, size_t hostlen, char *serv, size_t servlen, int flags) {
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct hostent *hp;
	int len;

	if(sa->sa_family != AF_INET)
		return EAI_FAMILY;

	if(serv && servlen) {
		len = snprintf(serv, servlen, "%d", ntohs(sin->sin_port));
		if(len < 0 || len >= servlen)
			return EAI_MEMORY;
	}

	if(!host || !hostlen)
		return 0;

	if(flags & NI_NUMERICHOST) {
		len = snprintf(host, hostlen, "%s", inet_ntoa(sin->sin_addr));
		if(len < 0 || len >= hostlen)
			return EAI_MEMORY;
		return 0;
	}

	hp = gethostbyaddr((char *)&sin->sin_addr, sizeof(struct in_addr), AF_INET);

	if(!hp || !hp->h_name || !hp->h_name[0])
		return EAI_NODATA;

	len = snprintf(host, hostlen, "%s", hp->h_name);
	if(len < 0 || len >= hostlen)
		return EAI_MEMORY;

	return 0;
}
#endif /* !HAVE_GETNAMEINFO */
