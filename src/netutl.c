/*
    netutl.c -- some supporting network utility code
    Copyright (C) 1998-2002 Ivo Timmermans <itimmermans@bigfoot.com>
                  2000-2002 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: netutl.c,v 1.12.4.34 2002/04/05 09:11:38 guus Exp $
*/

#include "config.h"

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <syslog.h>
#include <arpa/inet.h>

#include <utils.h>
#include <xalloc.h>

#include "errno.h"
#include "conf.h"
#include "net.h"
#include "netutl.h"

#include "system.h"

int hostnames = 0;

/*
  Turn a string into a struct addrinfo.
  Return NULL on failure.
*/
struct addrinfo *str2addrinfo(char *address, char *service, int socktype)
{
  struct addrinfo hint, *ai;
  int err;
cp
  memset(&hint, 0, sizeof(hint));

  hint.ai_family = addressfamily;
  hint.ai_socktype = socktype;

  if((err = getaddrinfo(address, service, &hint, &ai)))
    {
      if(debug_lvl >= DEBUG_ERROR)
        syslog(LOG_WARNING, _("Error looking up %s port %s: %s\n"), address, service, gai_strerror(err));
      cp_trace();
      return NULL;
    }

cp
  return ai;
}

sockaddr_t str2sockaddr(char *address, char *port)
{
  struct addrinfo hint, *ai;
  sockaddr_t result;
  int err;
cp
  memset(&hint, 0, sizeof(hint));

  hint.ai_family = AF_UNSPEC;
  hint.ai_flags = AI_NUMERICHOST;
  hint.ai_socktype = SOCK_STREAM;

  if((err = getaddrinfo(address, port, &hint, &ai) || !ai))
    {
      syslog(LOG_ERR, _("Error looking up %s port %s: %s\n"), address, port, gai_strerror(err));
      cp_trace();
      raise(SIGFPE);
      exit(0);
    }

  result = *(sockaddr_t *)ai->ai_addr;
  freeaddrinfo(ai);
cp
  return result;
}

void sockaddr2str(sockaddr_t *sa, char **addrstr, char **portstr)
{
  char address[NI_MAXHOST];
  char port[NI_MAXSERV];
  char *scopeid;
  int err;
cp
  if((err = getnameinfo(&sa->sa, SALEN(sa->sa), address, sizeof(address), port, sizeof(port), NI_NUMERICHOST|NI_NUMERICSERV)))
    {
      syslog(LOG_ERR, _("Error while translating addresses: %s"), gai_strerror(err));
      cp_trace();
      raise(SIGFPE);
      exit(0);
    }

#ifdef HAVE_LINUX
  if((scopeid = strchr(address, '%')))
    *scopeid = '\0';  /* Descope. */
#endif

  *addrstr = xstrdup(address);
  *portstr = xstrdup(port);
cp
}

char *sockaddr2hostname(sockaddr_t *sa)
{
  char *str;
  char address[NI_MAXHOST] = "unknown";
  char port[NI_MAXSERV] = "unknown";
  int err;
cp
  if((err = getnameinfo(&sa->sa, SALEN(sa->sa), address, sizeof(address), port, sizeof(port), hostnames?0:(NI_NUMERICHOST|NI_NUMERICSERV))))
    {
      syslog(LOG_ERR, _("Error while looking up hostname: %s"), gai_strerror(err));
    }

  asprintf(&str, _("%s port %s"), address, port);
cp
  return str;
}

int sockaddrcmp(sockaddr_t *a, sockaddr_t *b)
{
  int result;
cp
  result = a->sa.sa_family - b->sa.sa_family;
  
  if(result)
    return result;
  
  switch(a->sa.sa_family)
    {
      case AF_UNSPEC:
        return 0;
      case AF_INET:
	result = memcmp(&a->in.sin_addr, &b->in.sin_addr, sizeof(a->in.sin_addr));
	if(result)
	  return result;
	return memcmp(&a->in.sin_port, &b->in.sin_port, sizeof(a->in.sin_port));
      case AF_INET6:
	result = memcmp(&a->in6.sin6_addr, &b->in6.sin6_addr, sizeof(a->in6.sin6_addr));
	if(result)
	  return result;
	return memcmp(&a->in6.sin6_port, &b->in6.sin6_port, sizeof(a->in6.sin6_port));
      default:
        syslog(LOG_ERR, _("sockaddrcmp() was called with unknown address family %d, exitting!"), a->sa.sa_family);
	cp_trace();
        raise(SIGFPE);
        exit(0);
    }
cp
}

void sockaddrunmap(sockaddr_t *sa)
{
  if(sa->sa.sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&sa->in6.sin6_addr))
    {
      sa->in.sin_addr.s_addr = ((uint32_t *)&sa->in6.sin6_addr)[3];
      sa->in.sin_family = AF_INET;
    }
}

/* Subnet mask handling */

int maskcmp(char *a, char *b, int masklen, int len)
{
  int i, m, result;
cp
  for(m = masklen, i = 0; m >= 8; m -= 8, i++)
    if((result = a[i] - b[i]))
      return result;

  if(m)
    return (a[i] & (0x100 - (1 << (8 - m)))) - (b[i] & (0x100 - (1 << (8 - m))));

  return 0;
}

void mask(char *a, int masklen, int len)
{
  int i;
cp
  i = masklen / 8;
  masklen %= 8;
  
  if(masklen)
    a[i++] &= (0x100 - (1 << masklen));
  
  for(; i < len; i++)
    a[i] = 0;
}

void maskcpy(char *a, char *b, int masklen, int len)
{
  int i, m;
cp
  for(m = masklen, i = 0; m >= 8; m -= 8, i++)
    a[i] = b[i];

  if(m)
    {
      a[i] = b[i] & (0x100 - (1 << m));
      i++;
    }

  for(; i < len; i++)
    a[i] = 0;
}

int maskcheck(char *a, int masklen, int len)
{
  int i;
cp
  i = masklen / 8;
  masklen %= 8;
  
  if(masklen)
    if(a[i++] & (char)~(0x100 - (1 << masklen)))
      return -1;
  
  for(; i < len; i++)
    if(a[i] != 0)
      return -1;

  return 0;
}
