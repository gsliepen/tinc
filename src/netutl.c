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

    $Id: netutl.c,v 1.12.4.23 2002/02/11 10:16:18 guus Exp $
*/

#include "config.h"

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

char *hostlookup(unsigned long addr)
{
  char *name;
  struct hostent *host = NULL;
  struct in_addr in;
  int lookup_hostname = 0;
cp
  in.s_addr = addr;

  get_config_bool(lookup_config(config_tree, "Hostnames"), &lookup_hostname);

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
  Turn a string into an IP address
  return NULL on failure
  Should support IPv6 and other stuff in the future.
*/
ipv4_t str2address(char *str)
{
  ipv4_t address;
  struct hostent *h;
cp
  if(!(h = gethostbyname(str)))
    {
      if(debug_lvl >= DEBUG_ERROR)
        syslog(LOG_WARNING, _("Error looking up `%s': %s\n"), str, strerror(errno));
        
      return 0;
    }

  address = ntohl(*((ipv4_t*)(h->h_addr_list[0])));
cp
  return address;
}

char *address2str(ipv4_t address)
{
  char *str;
cp
  asprintf(&str, "%hu.%hu.%hu.%hu",
	   (unsigned short int)((address >> 24) & 255),
	   (unsigned short int)((address >> 16) & 255),
	   (unsigned short int)((address >> 8) & 255),
	   (unsigned short int)(address & 255));
cp
  return str;
}
