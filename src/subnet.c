/*
    subnet.c -- handle subnet lookups and lists
    Copyright (C) 2000 Guus Sliepen <guus@sliepen.warande.net>,
                  2000 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: subnet.c,v 1.1.2.1 2000/10/01 03:21:49 guus Exp $
*/

#include "config.h"
#include "subnet.h"
#include "net.h"

/* Allocating and freeing space for subnets */

subnet_t *new_subnet(void)
{
cp
cp
}

void free_subnet(subnet_t *subnet)
{
cp
cp
}

/* Linked list management */

int subnet_add(conn_list_t *cl, subnet_t *subnet)
{
cp
  subnet->next = cl->subnets->next;
  subnet->prev = NULL;
  subnet->next->prev = subnet
  cl->subnets = subnet;
cp
  return 0;
}

int subnet_del(conn_list_t *cl, subnet_t *subnet)
{
cp
  if(subnet->prev)
    {
      subnet->prev->next = subnet->next;
    }
  else
    {
      subnet->owner->subnets = subnet->next;
    }
  
  subnet->next->prev = subnet->prev;
  free_subnet(subnet);
cp
  return 0;
}

/* Ascii representation of subnets */

subnet_t *str2net(char *subnetstr)
{
cp
cp
}

char *net2str(subnet_t *subnet)
{
cp
cp
}

/* Subnet lookup routines */
