/*
    dropin.h -- header file for dropin.c
    Copyright (C) 2000,2001 Ivo Timmermans <itimmermans@bigfoot.com>,
                  2000,2001 Guus Sliepen <guus@sliepen.warande.net>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id: dropin.h,v 1.1.2.5 2001/11/16 17:37:08 zarq Exp $
*/

#ifndef __DROPIN_H__
#define __DROPIN_H__

#ifndef HAVE_DAEMON
extern int daemon(int, int);
#endif

#ifndef HAVE_GET_CURRENT_DIR_NAME
extern char* get_current_dir_name(void);
#endif

#ifndef HAVE_ASPRINTF
extern int asprintf(char **, const char *, ...);
#endif

#ifndef HAVE_STRUCT_ADDRINFO
struct addrinfo {
	int	ai_flags;	/* AI_PASSIVE, AI_CANONNAME */
	int	ai_family;	/* PF_xxx */
	int	ai_socktype;	/* SOCK_xxx */
	int	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	size_t	ai_addrlen;	/* length of ai_addr */
	char	*ai_canonname;	/* canonical name for hostname */
	struct sockaddr *ai_addr;	/* binary address */
	struct addrinfo *ai_next;	/* next structure in linked list */
};
#endif /* !HAVE_STRUCT_ADDRINFO */

#ifndef HAVE_GETADDRINFO
int getaddrinfo(const char *hostname, const char *servname, 
                const struct addrinfo *hints, struct addrinfo **res);
#endif /* !HAVE_GETADDRINFO */

#ifndef HAVE_GAI_STRERROR
char *gai_strerror(int ecode);
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
void freeaddrinfo(struct addrinfo *ai);
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETNAMEINFO
int getnameinfo(const struct sockaddr *sa, size_t salen, char *host, 
                size_t hostlen, char *serv, size_t servlen, int flags);
#endif /* !HAVE_GETNAMEINFO */

#ifndef NI_MAXSERV
# define NI_MAXSERV 32
#endif /* !NI_MAXSERV */
#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif /* !NI_MAXHOST */

#ifndef AI_PASSIVE
# define AI_PASSIVE        1
# define AI_CANONNAME      2
#endif

#ifndef NI_NUMERICHOST
# define NI_NUMERICHOST    2
# define NI_NAMEREQD       4
# define NI_NUMERICSERV    8
#endif

#endif /* __DROPIN_H__ */
