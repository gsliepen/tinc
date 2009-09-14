/*
 * fake library for ssh
 *
 * This file includes getaddrinfo(), freeaddrinfo() and gai_strerror().
 * These funtions are defined in rfc2133.
 *
 * But these functions are not implemented correctly. The minimum subset
 * is implemented for ssh use only. For exapmle, this routine assumes
 * that ai_family is AF_INET. Don't use it for another purpose.
 */

#include "system.h"

#include "ipv4.h"
#include "ipv6.h"
#include "fake-getaddrinfo.h"
#include "xalloc.h"

#if !HAVE_DECL_GAI_STRERROR
char *gai_strerror(int ecode)
{
	switch (ecode) {
		case EAI_NODATA:
			return "No address associated with hostname";
		case EAI_MEMORY:
			return "Memory allocation failure";
		case EAI_FAMILY:
			return "Address family not supported";
		default:
			return "Unknown error";
	}
}    
#endif /* !HAVE_GAI_STRERROR */

#if !HAVE_DECL_FREEADDRINFO
void freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *next;

	while(ai) {
		next = ai->ai_next;
		free(ai);
		ai = next;
	}
}
#endif /* !HAVE_FREEADDRINFO */

#if !HAVE_DECL_GETADDRINFO
static struct addrinfo *malloc_ai(uint16_t port, uint32_t addr)
{
	struct addrinfo *ai;

	ai = xmalloc_and_zero(sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
	
	ai->ai_addr = (struct sockaddr *)(ai + 1);
	ai->ai_addrlen = sizeof(struct sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((struct sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((struct sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;
	
	return ai;
}

int getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res)
{
	struct addrinfo *prev = NULL;
	struct hostent *hp;
	struct in_addr in = {0};
	int i;
	uint16_t port = 0;

	if(hints && hints->ai_family != AF_INET && hints->ai_family != AF_UNSPEC)
		return EAI_FAMILY;

	if (servname)
		port = htons(atoi(servname));

	if (hints && hints->ai_flags & AI_PASSIVE) {
		*res = malloc_ai(port, htonl(0x00000000));
		return 0;
	}
		
	if (!hostname) {
		*res = malloc_ai(port, htonl(0x7f000001));
		return 0;
	}
	
	hp = gethostbyname(hostname);

	if(!hp || !hp->h_addr_list || !hp->h_addr_list[0])
		return EAI_NODATA;

	for (i = 0; hp->h_addr_list[i]; i++) {
		*res = malloc_ai(port, ((struct in_addr *)hp->h_addr_list[i])->s_addr);

		if(prev)
			prev->ai_next = *res;

		prev = *res;
	}

	return 0;
}
#endif /* !HAVE_GETADDRINFO */
