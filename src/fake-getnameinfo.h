#ifndef TINC_FAKE_GETNAMEINFO_H
#define TINC_FAKE_GETNAMEINFO_H

#if !HAVE_DECL_GETNAMEINFO
int getnameinfo(const struct sockaddr *sa, size_t salen, char *host,
                size_t hostlen, char *serv, size_t servlen, int flags);
#endif /* !HAVE_GETNAMEINFO */

#ifndef NI_MAXSERV
# define NI_MAXSERV 32
#endif /* !NI_MAXSERV */
#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif /* !NI_MAXHOST */

#endif
