/*
    netutl.c -- some supporting network utility code
    Copyright (C) 1998-2001 Ivo Timmermans <itimmermans@bigfoot.com>
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

    $Id: netutl.c,v 1.12.4.18 2001/01/07 17:09:02 guus Exp $
*/

#include "config.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>

#include <utils.h>
#include <xalloc.h>

#include "errno.h"
#include "conf.h"
#include "net.h"
#include "netutl.h"

#include "system.h"

char *hostlookup(unsigned long addr)
{
  char *name;
  struct hostent *host = NULL;
  struct in_addr in;
  config_t const *cfg;
  int lookup_hostname;
cp
  in.s_addr = addr;

  lookup_hostname = 0;
  if((cfg = get_config_val(config, config_hostnames)) != NULL)
    if(cfg->data.val == stupid_true)
      lookup_hostname = 1;

  if(lookup_hostname)
    host = gethostbyaddr((char *)&in, sizeof(in), AF_INET);

  if(!lookup_hostname || !host)
    {
      asprintf(&name, "%s", inet_ntoa(in));
    }
  else
    {
      asprintf(&name, "%s", host->h_name);
    }
cp
  return name;
}

/*
  Turn a string into an IP addy with netmask
  return NULL on failure
*/
ip_mask_t *strtoip(char *str)
{
  ip_mask_t *ip;
  int masker;
  char *q, *p;
  struct hostent *h;
cp
  p = str;
  if((q = strchr(p, '/')))
    {
      *q = '\0';
      q++; /* q now points to netmask part, or NULL if no mask */
    }

  if(!(h = gethostbyname(p)))
    {
      if(debug_lvl >= DEBUG_ERROR)
        syslog(LOG_WARNING, _("Error looking up `%s': %s\n"), p, strerror(errno));
        
      return NULL;
    }

  masker = 0;
  if(q)
    {
      masker = strtol(q, &p, 10);
      if(q == p || (*p))
	return NULL;
    }

  ip = xmalloc(sizeof(*ip));
  ip->address = ntohl(*((ip_t*)(h->h_addr_list[0])));

  ip->mask = masker ? ~((1 << (32 - masker)) - 1) : 0;
cp
  return ip;
}

