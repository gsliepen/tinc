/*
    conf.c -- configuration code
    Copyright (C) 1998 Emphyrio,
    Copyright (C) 1998,99 Ivo Timmermans <zarq@iname.com>

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
*/

/* foute config read code, GPL, emphyrio 1998 */
/* Mutilated by me -- Ivo */

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xalloc.h>

#include "conf.h"
#include "netutl.h" /* for strtoip */

config_t *config;
int debug_lvl = 0;
int timeout = 0; /* seconds before timeout */

typedef struct internal_config_t {
  char *name;
  enum which_t which;
  int argtype;
} internal_config_t;

/*
  These are all the possible configurable values
*/
static internal_config_t hazahaza[] = {
  { "AllowConnect", allowconnect,   TYPE_BOOL },
  { "ConnectTo",    upstreamip,     TYPE_IP },
  { "ConnectPort",  upstreamport,   TYPE_INT },
  { "ListenPort",   listenport,     TYPE_INT },
  { "MyOwnVPNIP",   myvpnip,        TYPE_IP },
  { "MyVirtualIP",  myvpnip,        TYPE_IP },   /* an alias */
  { "Passphrases",  passphrasesdir, TYPE_NAME },
  { "PingTimeout",  pingtimeout,    TYPE_INT },
  { "TapDevice",    tapdevice,      TYPE_NAME },
  { "KeyExpire",    keyexpire,      TYPE_INT },
  { "ProxyMode",    proxymode,      TYPE_BOOL },
  { NULL, 0, 0 }
};

/*
  Add given value to the list of configs cfg
*/
config_t *
add_config_val(config_t **cfg, int argtype, char *val)
{
  config_t *p;
  char *q;

  p = (config_t*)xmalloc(sizeof(*p));
  p->data.val = 0;
  
  switch(argtype)
    {
    case TYPE_INT:
      p->data.val = strtol(val, &q, 0);
      if(q && *q)
	p->data.val = 0;
      break;
    case TYPE_NAME:
      p->data.ptr = xmalloc(strlen(val) + 1);
      strcpy(p->data.ptr, val);
      break;
    case TYPE_IP:
      p->data.ip = strtoip(val);
      break;
    case TYPE_BOOL:
      if(!strcasecmp("yes", val))
	p->data.val = stupid_true;
      else if(!strcasecmp("no", val))
	p->data.val = stupid_false;
      else
	p->data.val = 0;
    }

  if(p->data.val)
    {
      p->next = *cfg;
      *cfg = p;
      return p;
    }

  free(p);
  return NULL;
}

/*
  Get variable from a section in a configfile. returns -1 on failure.
*/
int
readconfig(const char *fname, FILE *fp)
{
  char line[81];
  char *p, *q;
  int i, lineno = 0;
  config_t *cfg;

  for(;;)
    {
      if(fgets(line, 80, fp) == NULL)
	return 0;
      lineno++;

      if((p = strtok(line, "\t\n\r =")) == NULL)
	continue; /* no tokens on this line */

      if(p[0] == '#')
	continue; /* comment: ignore */

      for(i = 0; hazahaza[i].name != NULL; i++)
	if(!strcasecmp(hazahaza[i].name, p))
	  break;

      if(!hazahaza[i].name)
	{
	  fprintf(stderr, "%s: %d: Invalid variable name `%s'.\n",
		  fname, lineno, p);
	  return -1;
	}

      if(((q = strtok(NULL, "\t\n\r =")) == NULL) || q[0] == '#')
	{
	  fprintf(stderr, "%s: %d: No value given for `%s'.\n",
		  fname, lineno, hazahaza[i].name);
	  return -1;
	}

      cfg = add_config_val(&config, hazahaza[i].argtype, q);
      if(cfg == NULL)
	{
	  fprintf(stderr, "%s: %d: Invalid value `%s' for variable `%s'.\n",
		  fname, lineno, q, hazahaza[i].name);
	  return -1;
	}

      cfg->which = hazahaza[i].which;
      if(!config)
	config = cfg;
    }
}

/*
  wrapper function for readconfig
*/
int
read_config_file(const char *fname)
{
  FILE *fp;

  if((fp = fopen (fname, "r")) == NULL)
    {
      fprintf(stderr, "Could not open %s: %s\n", fname, sys_errlist[errno]);
      return 1;
    }

  if(readconfig(fname, fp))
    return -1;

  fclose (fp);

  return 0;
}

/*
  Look up the value of the config option type
*/
const config_t *
get_config_val(which_t type)
{
  config_t *p;

  for(p = config; p != NULL; p = p->next)
    if(p->which == type)
      return p;

  /* Not found */
  return NULL;
}

