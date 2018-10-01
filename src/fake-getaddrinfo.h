#ifndef TINC_FAKE_GETADDRINFO_H
#define TINC_FAKE_GETADDRINFO_H

#ifndef EAI_NODATA
#define EAI_NODATA      1
#endif

#ifndef EAI_MEMORY
#define EAI_MEMORY      2
#endif

#ifndef EAI_FAMILY
#define EAI_FAMILY      3
#endif

#ifndef AI_PASSIVE
# define AI_PASSIVE        1
# define AI_CANONNAME      2
#endif

#ifndef NI_NUMERICHOST
# define NI_NUMERICHOST    2
# define NI_NAMEREQD       4
# define NI_NUMERICSERV    8
#endif

#ifndef AI_NUMERICHOST
#define AI_NUMERICHOST 4
#endif

#ifndef HAVE_STRUCT_ADDRINFO
struct addrinfo {
	int     ai_flags;         /* AI_PASSIVE, AI_CANONNAME */
	int     ai_family;        /* PF_xxx */
	int     ai_socktype;      /* SOCK_xxx */
	int     ai_protocol;      /* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	size_t  ai_addrlen;       /* length of ai_addr */
	char    *ai_canonname;    /* canonical name for hostname */
	struct sockaddr *ai_addr; /* binary address */
	struct addrinfo *ai_next; /* next structure in linked list */
};
#endif /* !HAVE_STRUCT_ADDRINFO */

#if !HAVE_DECL_GETADDRINFO
int getaddrinfo(const char *hostname, const char *servname,
                const struct addrinfo *hints, struct addrinfo **res);
#endif /* !HAVE_GETADDRINFO */

#if !HAVE_DECL_GAI_STRERROR
char *gai_strerror(int ecode);
#endif /* !HAVE_GAI_STRERROR */

#if !HAVE_DECL_FREEADDRINFO
void freeaddrinfo(struct addrinfo *ai);
#endif /* !HAVE_FREEADDRINFO */

#endif
