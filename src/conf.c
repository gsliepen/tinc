/*
    conf.c -- configuration code
    Copyright (C) 1998 Robert van der Meulen
    Copyright (C) 1998,1999,2000 Ivo Timmermans <itimmermans@bigfoot.com>
                            2000 Guus Sliepen <guus@sliepen.warande.net>
			    2000 Cris van Pelt <tribbel@arise.dhs.org>

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

    $Id: conf.c,v 1.9.4.24 2000/11/29 14:24:40 zarq Exp $
*/

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <xalloc.h>
#include <utils.h> /* for cp */

#include "conf.h"
#include "netutl.h" /* for strtoip */

#include "system.h"

config_t *config = NULL;
int debug_lvl = 0;
int timeout = 0; /* seconds before timeout */
char *confbase = NULL;           /* directory in which all config files are */
char *netname = NULL;            /* name of the vpn network */

/* Will be set if HUP signal is received. It will be processed when it is safe. */
int sighup = 0;

/*
  These are all the possible configurable values
*/
static internal_config_t hazahaza[] = {
/* Main configuration file keywords */
  { "Name",         config_name,       TYPE_NAME },
  { "ConnectTo",    config_connectto,      TYPE_NAME },
  { "PingTimeout",  config_pingtimeout,    TYPE_INT },
  { "TapDevice",    config_tapdevice,      TYPE_NAME },
  { "PrivateKey",   config_privatekey,     TYPE_NAME },
  { "KeyExpire",    config_keyexpire,      TYPE_INT },
  { "Hostnames",    config_hostnames,    TYPE_BOOL },
  { "Interface",    config_interface,      TYPE_NAME },
  { "InterfaceIP",  config_interfaceip,    TYPE_IP },
/* Host configuration file keywords */
  { "Address",      config_address,        TYPE_NAME },
  { "Port",         config_port,           TYPE_INT },
  { "PublicKey",    config_publickey,      TYPE_NAME },
  { "Subnet",       config_subnet,         TYPE_IP },		/* Use IPv4 subnets only for now */
  { "RestrictHosts", config_restricthosts, TYPE_BOOL },
  { "RestrictSubnets", config_restrictsubnets, TYPE_BOOL },
  { "RestrictAddress", config_restrictaddress, TYPE_BOOL },
  { "RestrictPort", config_restrictport,   TYPE_BOOL },
  { "IndirectData", config_indirectdata,   TYPE_BOOL },
  { "TCPonly",      config_tcponly,        TYPE_BOOL },
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
cp
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

  p->argtype = argtype;

  if(p->data.val)
    {
      p->next = *cfg;
      *cfg = p;
cp
      return p;
    }
  else
    {
      free(p);
cp
      return NULL;
    }
}

/*
  Read exactly one line and strip the trailing newline if any.  If the
  file was on EOF, return NULL. Otherwise, return all the data in a
  dynamically allocated buffer.
*/
char *readline(FILE *fp)
{
  char *newline = NULL;
  char *p;
  char *line; /* The array that contains everything that has been read
                 so far */
  char *idx; /* Read into this pointer, which points to an offset
                within line */
  size_t size, newsize; /* The size of the current array pointed to by
                           line */
  size_t maxlen; /* Maximum number of characters that may be read with
                    fgets.  This is newsize - oldsize. */

  if(feof(fp))
    return NULL;
  
  size = 100;
  maxlen = size;
  line = xmalloc(size);
  idx = line;
  for(;;)
    {
      errno = 0;
      p = fgets(idx, maxlen, fp);
      if(p == NULL)  /* EOF or error */
	{
	  if(feof(fp))
	    break;

	  /* otherwise: error; let the calling function print an error
             message if applicable */
	  free(line);
	  return NULL;
	}

      newline = strchr(p, '\n');
      if(newline == NULL)
	/* We haven't yet read everything to the end of the line */
	{
	  newsize = size << 1;
	  line = xrealloc(line, newsize);
	  idx = &line[size - 1];
	  maxlen = newsize - size + 1;
	  size = newsize;
	}
      else
	{
	  *newline = '\0'; /* kill newline */
	  break;  /* yay */
	}
    }

  return line;
}

/*
  Parse a configuration file and put the results in the configuration tree
  starting at *base.
*/
int read_config_file(config_t **base, const char *fname)
{
  int err = -1;
  FILE *fp;
  char line[MAXBUFSIZE];	/* There really should not be any line longer than this... */
  char *p, *q;
  int i, lineno = 0;
  config_t *cfg;
cp
  if((fp = fopen (fname, "r")) == NULL)
    {
      return -1;
    }

  for(;;)
    {
      if(fgets(line, MAXBUFSIZE, fp) == NULL)
        {
          err = 0;
          break;
        }
        
      lineno++;

      if(!index(line, '\n'))
        {
          syslog(LOG_ERR, _("Line %d too long while reading config file %s"), lineno, fname);
          break;
        }        

      if((p = strtok(line, "\t\n\r =")) == NULL)
	continue; /* no tokens on this line */

      if(p[0] == '#')
	continue; /* comment: ignore */

      for(i = 0; hazahaza[i].name != NULL; i++)
	if(!strcasecmp(hazahaza[i].name, p))
	  break;

      if(!hazahaza[i].name)
	{
	  syslog(LOG_ERR, _("Invalid variable name on line %d while reading config file %s"),
		  lineno, fname);
          break;
	}

      if(((q = strtok(NULL, "\t\n\r =")) == NULL) || q[0] == '#')
	{
	  fprintf(stderr, _("No value for variable on line %d while reading config file %s"),
		  lineno, fname);
	  break;
	}

      cfg = add_config_val(base, hazahaza[i].argtype, q);
      if(cfg == NULL)
	{
	  fprintf(stderr, _("Invalid value for variable on line %d while reading config file %s"),
		  lineno, fname);
	  break;
	}

      cfg->which = hazahaza[i].which;
      if(!config)
	config = cfg;
    }

  fclose (fp);
cp
  return err;
}

int read_server_config()
{
  char *fname;
  int x;
cp
  asprintf(&fname, "%s/tinc.conf", confbase);
  x = read_config_file(&config, fname);
  if(x != 0)
    {
      fprintf(stderr, _("Failed to read `%s': %m\n"),
	      fname);
    }
  free(fname);
cp
  return x;  
}

/*
  Look up the value of the config option type
*/
const config_t *get_config_val(config_t *p, which_t type)
{
cp
  for(; p != NULL; p = p->next)
    if(p->which == type)
      break;
cp
  return p;
}

/*
  Remove the complete configuration tree.
*/
void clear_config(config_t **base)
{
  config_t *p, *next;
cp
  for(p = *base; p != NULL; p = next)
    {
      next = p->next;
      if(p->data.ptr && (p->argtype == TYPE_NAME))
        {
          free(p->data.ptr);
        }
      free(p);
    }
  *base = NULL;
cp
}

#define is_safe_file(p) 1

FILE *ask_and_safe_open(const char* filename, const char* what)
{
  FILE *r;
  char *directory;
  char *fn;
  int len;

  /* Check stdin and stdout */
  if(!isatty(0) || !isatty(1))
    {
      /* Argh, they are running us from a script or something.  Write
         the files to the current directory and let them burn in hell
         for ever. */
      fn = xstrdup(filename);
    }
  else
    {
      /* Ask for a file and/or directory name. */
      fprintf(stdout, _("Please enter a file to save %s to [%s]: "),
	      what, filename);
      fflush(stdout);  /* Don't wait for a newline */
      if((fn = readline(stdin)) == NULL)
	{
	  fprintf(stderr, _("Error while reading stdin: %m\n"));
	  return NULL;
	}
      if(strlen(fn) == 0)
	/* User just pressed enter. */
	fn = xstrdup(filename);
    }

  if((strchr(fn, '/') == NULL) || (fn[0] != '/'))
    {
      /* The directory is a relative path or a filename. */
      char *p;
      
      directory = get_current_dir_name();
      len = strlen(fn) + strlen(directory) + 2; /* 1 for the / */
      p = xmalloc(len);
      snprintf(p, len, "%s/%s", directory, fn);
      free(fn);
      fn = p;
    }

  if(!is_safe_file(fn))
    {
      fprintf(stderr, _("The file `%s' (or any of the leading directories) has unsafe permissions.\n"
			"I will not create or overwrite this file.\n"),
			fn);
      return NULL;
    }

  if((r = fopen(fn, "w")) == NULL)
    {
      fprintf(stderr, _("Error opening file `%s': %m\n"),
	      fn);
    }

  free(fn);
  free(directory);
  
  return r;
}
