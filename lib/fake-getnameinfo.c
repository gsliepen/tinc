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

#ifndef HAVE_GETNAMEINFO

int getnameinfo(const struct sockaddr *sa, size_t salen, char *host, size_t hostlen, char *serv, size_t servlen, int flags)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct hostent *hp;

	if(serv)
		snprintf(serv, sizeof(tmpserv), "%d", ntohs(sin->sin_port));

	if(!host)
		return 0;

	if(flags & NI_NUMERICHOST) {
		strncpy(host, inet_ntoa(sin->sin_addr), sizeof(host));
		return 0;
	}

	hp = gethostbyaddr((char *)&sin->sin_addr, sizeof(struct in_addr), AF_INET);
	
	if(!hp || !hp->h_name)
		return EAI_NODATA;
	
	if(strlen(hp->h_name) >= hostlen)
		return EAI_MEMORY;

	strncpy(host, hp->h_name, hostlen);
	return 0;
}
#endif /* !HAVE_GETNAMEINFO */
