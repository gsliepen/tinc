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

    $Id: conf.c,v 1.9.4.34 2000/12/06 13:33:48 zarq Exp $
*/

#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
  { "ConnectTo",    config_connectto,      TYPE_NAME },
  { "Hostnames",    config_hostnames,    TYPE_BOOL },
  { "Interface",    config_interface,      TYPE_NAME },
  { "InterfaceIP",  config_interfaceip,    TYPE_IP },
  { "KeyExpire",    config_keyexpire,      TYPE_INT },
  { "MyVirtualIP",  config_dummy,          TYPE_IP },
  { "MyOwnVPNIP",   config_dummy,          TYPE_IP },
  { "Name",         config_name,       TYPE_NAME },
  { "PingTimeout",  config_pingtimeout,    TYPE_INT },
  { "PrivateKey",   config_privatekey,     TYPE_NAME },
  { "TapDevice",    config_tapdevice,      TYPE_NAME },
  { "VpnMask",      config_dummy,          TYPE_IP },
/* Host configuration file keywords */
  { "Address",      config_address,        TYPE_NAME },
  { "IndirectData", config_indirectdata,   TYPE_BOOL },
  { "Port",         config_port,           TYPE_INT },
  { "PublicKey",    config_publickey,      TYPE_NAME },
  { "RestrictAddress", config_restrictaddress, TYPE_BOOL },
  { "RestrictHosts", config_restricthosts, TYPE_BOOL },
  { "RestrictPort", config_restrictport,   TYPE_BOOL },
  { "RestrictSubnets", config_restrictsubnets, TYPE_BOOL },
  { "Subnet",       config_subnet,         TYPE_IP },		/* Use IPv4 subnets only for now */
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
  
  If line is non-NULL, it will be used as an initial buffer, to avoid
  unnecessary mallocing each time this function is called.  If buf is
  given, and buf needs to be expanded, the var pointed to by buflen
  will be increased.
*/
char *readline(FILE *fp, char **buf, size_t *buflen)
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

  if((buf != NULL) && (buflen != NULL))
    {
      size = *buflen;
      line = *buf;
    }
  else
    {
      size = 100;
      line = xmalloc(size);
    }

  maxlen = size;
  idx = line;
  *idx = 0;
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

  if((buf != NULL) && (buflen != NULL))
    {
      *buflen = size;
      *buf = line;
    }
  return line;
}

/*
  Parse a configuration file and put the results in the configuration tree
  starting at *base.
*/
int read_config_file(config_t **base, const char *fname)
{
  int err = -2; /* Parse error */
  FILE *fp;
  char *buffer, *line;
  char *p, *q;
  int i, lineno = 0;
  config_t *cfg;
  size_t bufsize;
  
cp
  if((fp = fopen (fname, "r")) == NULL)
    return -1;

  bufsize = 100;
  buffer = xmalloc(bufsize);
  
  for(;;)
    {
      
      if((line = readline(fp, &buffer, &bufsize)) == NULL)
	{
	  err = -1;
	  break;
	}

      if(feof(fp))
	{
	  err = 0;
	  break;
	}

      lineno++;

      if((p = strtok(line, "\t =")) == NULL)
	continue; /* no tokens on this line */

      if(p[0] == '#')
	continue; /* comment: ignore */

      for(i = 0; hazahaza[i].name != NULL; i++)
	if(!strcasecmp(hazahaza[i].name, p))
	  break;

      if(!hazahaza[i].name)
	{
	  syslog(LOG_ERR, _("Invalid variable name `%s' on line %d while reading config file %s"),
		  p, lineno, fname);
          break;
	}

      if(((q = strtok(NULL, "\t\n\r =")) == NULL) || q[0] == '#')
	{
	  fprintf(stderr, _("No value for variable `%s' on line %d while reading config file %s"),
		  hazahaza[i].name, lineno, fname);
	  break;
	}

      cfg = add_config_val(base, hazahaza[i].argtype, q);
      if(cfg == NULL)
	{
	  fprintf(stderr, _("Invalid value for variable `%s' on line %d while reading config file %s"),
		  hazahaza[i].name, lineno, fname);
	  break;
	}

      cfg->which = hazahaza[i].which;
      if(!config)
	config = cfg;
    }

  free(buffer);
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
  if(x == -1) /* System error */
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

int isadir(const char* f)
{
  struct stat s;

  if(stat(f, &s) < 0)
    {
      fprintf(stderr, _("Couldn't stat `%s': %m\n"),
	      f);
      return -1;
    }

  return S_ISDIR(s.st_mode);
}

int is_safe_path(const char *file)
{
  char *p;
  struct stat s;

  p = strrchr(file, '/');
  assert(p); /* p has to contain a / */
  *p = '\0';
  if(stat(file, &s) < 0)
    {
      fprintf(stderr, _("Couldn't stat `%s': %m\n"),
	      file);
      return 0;
    }
  if(s.st_uid != geteuid())
    {
      fprintf(stderr, _("`%s' is owned by UID %d instead of %d.\n"),
	      file, s.st_uid, geteuid());
      return 0;
    }
  if(S_ISLNK(s.st_mode))
    {
      fprintf(stderr, _("Warning: `%s' is a symlink\n"),
	      file);
      /* fixme: read the symlink and start again */
    }

  *p = '/';
  if(stat(file, &s) < 0 && errno != ENOENT)
    {
      fprintf(stderr, _("Couldn't stat `%s': %m\n"),
	      file);
      return 0;
    }
  if(errno == ENOENT)
    return 1;
  if(s.st_uid != geteuid())
    {
      fprintf(stderr, _("`%s' is owned by UID %d instead of %d.\n"),
	      file, s.st_uid, geteuid());
      return 0;
    }
  if(S_ISLNK(s.st_mode))
    {
      fprintf(stderr, _("Warning: `%s' is a symlink\n"),
	      file);
      /* fixme: read the symlink and start again */
    }
  if(s.st_mode & 0007)
    {
      /* Accessible by others */
      fprintf(stderr, _("`%s' has unsecure permissions.\n"),
	      file);
      return 0;
    }
  
  return 1;
}

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
      if((fn = readline(stdin, NULL, NULL)) == NULL)
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
      free(directory);
      fn = p;
    }

  if(isadir(fn) > 0) /* -1 is error */
    {
      char *p;

      len = strlen(fn) + strlen(filename) + 2; /* 1 for the / */
      p = xmalloc(len);
      snprintf(p, len, "%s/%s", fn, filename);
      free(fn);
      fn = p;
    }

  umask(0077); /* Disallow everything for group and other */
  
  /* Open it first to keep the inode busy */
  if((r = fopen(fn, "w")) == NULL)
    {
      fprintf(stderr, _("Error opening file `%s': %m\n"),
	      fn);
      free(fn);
      return NULL;
    }

  /* Then check the file for nasty attacks */
  if(!is_safe_path(fn))  /* Do not permit any directories that are
                            readable or writeable by other users. */
    {
      fprintf(stderr, _("The file `%s' (or any of the leading directories) has unsafe permissions.\n"
			"I will not create or overwrite this file.\n"),
			fn);
      fclose(r);
      free(fn);
      return NULL;
    }

  free(fn);
  
  return r;
}
