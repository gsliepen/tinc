/*
    dropin.c -- a set of drop-in replacements for libc functions
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

    $Id: dropin.c,v 1.1.2.7 2001/11/16 17:36:56 zarq Exp $
*/

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <xalloc.h>

#include <system.h>
#include <errno.h>

#ifndef HAVE_DAEMON
/*
  Replacement for the daemon() function.
  
  The daemon() function is for programs wishing to detach themselves
  from the controlling terminal and run in the background as system
  daemons.

  Unless the argument nochdir is non-zero, daemon() changes the
  current working directory to the root (``/'').

  Unless the argument noclose is non-zero, daemon() will redirect
  standard input, standard output and standard error to /dev/null.
*/
int daemon(int nochdir, int noclose)
{
  pid_t pid;
  int fd;
  
  pid = fork();
  
  /* Check if forking failed */
  if(pid < 0)
    {
      perror("fork");
      exit(-1);
    }

  /* If we are the parent, terminate */
  if(pid)
    exit(0);

  /* Detach by becoming the new process group leader */
  if(setsid() < 0)
    {
      perror("setsid");
      return -1;
    }
  
  /* Change working directory to the root (to avoid keeping mount
     points busy) */
  if(!nochdir)
    {
      chdir("/");
    }
    
  /* Redirect stdin/out/err to /dev/null */
  if(!noclose)
    {
      fd = open("/dev/null", O_RDWR);

      if(fd < 0)
        {
          perror("opening /dev/null");
          return -1;
        }
      else
        {
          dup2(fd, 0);
          dup2(fd, 1);
          dup2(fd, 2);
        }
    }

  return 0;
}
#endif




#ifndef HAVE_GET_CURRENT_DIR_NAME
/*
  Replacement for the GNU get_current_dir_name function:

  get_current_dir_name will malloc(3) an array big enough to hold the
  current directory name.  If the environment variable PWD is set, and
  its value is correct, then that value will be returned.
*/
char *get_current_dir_name(void)
{
  size_t size;
  char *buf;
  char *r;

  /* Start with 100 bytes.  If this turns out to be insufficient to
     contain the working directory, double the size.  */
  size = 100;
  buf = xmalloc(size);

  errno = 0; /* Success */
  r = getcwd(buf, size);
  /* getcwd returns NULL and sets errno to ERANGE if the bufferspace
     is insufficient to contain the entire working directory.  */
  while(r == NULL && errno == ERANGE)
    {
      free(buf);
      size <<= 1; /* double the size */
      buf = xmalloc(size);
      r = getcwd(buf, size);
    }

  return buf;
}
#endif

#ifndef HAVE_ASPRINTF
int asprintf(char **buf, const char *fmt, ...)
{
  int status;
  va_list ap;
  int len;
  
  len = 4096;
  *buf = xmalloc(len);

  va_start(ap, fmt);
  status = vsnprintf (*buf, len, fmt, ap);
  va_end (ap);

  if(status >= 0)
    *buf = xrealloc(*buf, status);

  if(status > len-1)
    {
      len = status;
      va_start(ap, fmt);
      status = vsnprintf (*buf, len, fmt, ap);
      va_end (ap);
    }

  return status;
}
#endif


/*
 * fake library for ssh
 *
 * This file is included in getaddrinfo.c and getnameinfo.c.
 * See getaddrinfo.c and getnameinfo.c.
 */

/* $Id: dropin.c,v 1.1.2.7 2001/11/16 17:36:56 zarq Exp $ */

/* for old netdb.h */
#ifndef EAI_NODATA
#define EAI_NODATA	1
#define EAI_MEMORY	2
#endif

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

#ifndef HAVE_GAI_STRERROR
char *gai_strerror(int ecode)
{
	switch (ecode) {
		case EAI_NODATA:
			return "no address associated with hostname.";
		case EAI_MEMORY:
			return "memory allocation failure.";
		default:
			return "unknown error.";
	}
}    
#endif /* !HAVE_GAI_STRERROR */

#ifndef HAVE_FREEADDRINFO
void freeaddrinfo(struct addrinfo *ai)
{
	struct addrinfo *next;

	do {
		next = ai->ai_next;
		free(ai);
	} while (NULL != (ai = next));
}
#endif /* !HAVE_FREEADDRINFO */

#ifndef HAVE_GETADDRINFO
static struct addrinfo *malloc_ai(int port, u_long addr)
{
	struct addrinfo *ai;

	ai = malloc(sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
	if (ai == NULL)
		return(NULL);
	
	memset(ai, 0, sizeof(struct addrinfo) + sizeof(struct sockaddr_in));
	
	ai->ai_addr = (struct sockaddr *)(ai + 1);
	/* XXX -- ssh doesn't use sa_len */
	ai->ai_addrlen = sizeof(struct sockaddr_in);
	ai->ai_addr->sa_family = ai->ai_family = AF_INET;

	((struct sockaddr_in *)(ai)->ai_addr)->sin_port = port;
	((struct sockaddr_in *)(ai)->ai_addr)->sin_addr.s_addr = addr;
	
	return(ai);
}

int getaddrinfo(const char *hostname, const char *servname, 
                const struct addrinfo *hints, struct addrinfo **res)
{
	struct addrinfo *cur, *prev = NULL;
	struct hostent *hp;
	struct in_addr in;
	int i, port;

	if (servname)
		port = htons(atoi(servname));
	else
		port = 0;

	if (hints && hints->ai_flags & AI_PASSIVE) {
		if (NULL != (*res = malloc_ai(port, htonl(0x00000000))))
			return 0;
		else
			return EAI_MEMORY;
	}
		
	if (!hostname) {
		if (NULL != (*res = malloc_ai(port, htonl(0x7f000001))))
			return 0;
		else
			return EAI_MEMORY;
	}
	
	if (inet_aton(hostname, &in)) {
		if (NULL != (*res = malloc_ai(port, in.s_addr)))
			return 0;
		else
			return EAI_MEMORY;
	}
	
	hp = gethostbyname(hostname);
	if (hp && hp->h_name && hp->h_name[0] && hp->h_addr_list[0]) {
		for (i = 0; hp->h_addr_list[i]; i++) {
			cur = malloc_ai(port, ((struct in_addr *)hp->h_addr_list[i])->s_addr);
			if (cur == NULL) {
				if (*res)
					freeaddrinfo(*res);
				return EAI_MEMORY;
			}
			
			if (prev)
				prev->ai_next = cur;
			else
				*res = cur;

			prev = cur;
		}
		return 0;
	}
	
	return EAI_NODATA;
}
#endif /* !HAVE_GETADDRINFO */


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

#ifndef HAVE_GETNAMEINFO
int getnameinfo(const struct sockaddr *sa, size_t salen, char *host, 
                size_t hostlen, char *serv, size_t servlen, int flags)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	struct hostent *hp;
	char tmpserv[16];

	if (serv) {
		snprintf(tmpserv, sizeof(tmpserv), "%d", ntohs(sin->sin_port));
		if (strlen(tmpserv) >= servlen)
			return EAI_MEMORY;
		else
			strcpy(serv, tmpserv);
	}

	if (host) {
		if (flags & NI_NUMERICHOST) {
			if (strlen(inet_ntoa(sin->sin_addr)) >= hostlen)
				return EAI_MEMORY;

			strcpy(host, inet_ntoa(sin->sin_addr));
			return 0;
		} else {
			hp = gethostbyaddr((char *)&sin->sin_addr, 
				sizeof(struct in_addr), AF_INET);
			if (hp == NULL)
				return EAI_NODATA;
			
			if (strlen(hp->h_name) >= hostlen)
				return EAI_MEMORY;

			strcpy(host, hp->h_name);
			return 0;
		}
	}
	return 0;
}
#endif /* !HAVE_GETNAMEINFO */
