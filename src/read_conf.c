/*
    read_conf.c -- read the configuration files
    Copyright (C) 1998 Robert van der Meulen
                  1998-2002 Ivo Timmermans <ivo@o2w.nl>
                  2000-2002 Guus Sliepen <guus@sliepen.warande.net>
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

    $Id: read_conf.c,v 1.1 2002/04/28 12:46:26 zarq Exp $
*/

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <xalloc.h>
#include <utils.h> /* for cp */
#include <avl_tree.h>

#include "conf.h"
#include "netutl.h" /* for str2address */
#include "logging.h"

#include "system.h"

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
int read_config_file(avl_tree_t *config_tree, const char *fname)
{
  int err = -2; /* Parse error */
  FILE *fp;
  char *buffer, *line;
  char *variable, *value;
  int lineno = 0, ignore = 0;
  config_t *cfg;
  size_t bufsize;

cp
  if((fp = fopen (fname, "r")) == NULL)
    {
      syslog(LOG_ERR, _("Cannot open config file %s: %s"), fname, strerror(errno));
      return -3;
    }

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

      if((variable = strtok(line, "\t =")) == NULL)
	continue; /* no tokens on this line */

      if(variable[0] == '#')
	continue; /* comment: ignore */

      if(!strcmp(variable, "-----BEGIN"))
        ignore = 1;

      if(!ignore)
        {
          if(((value = strtok(NULL, "\t\n\r =")) == NULL) || value[0] == '#')
	    {
	      syslog(LOG_ERR, _("No value for variable `%s' on line %d while reading config file %s"),
		      variable, lineno, fname);
	      break;
	    }

          cfg = new_config();
          cfg->variable = xstrdup(variable);
          cfg->value = xstrdup(value);
          cfg->file = xstrdup(fname);
          cfg->line = lineno;

          config_add(config_tree, cfg);
       }

      if(!strcmp(variable, "-----END"))
        ignore = 0;
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
  x = read_config_file(config_tree, fname);
  if(x == -1) /* System error: complain */
    {
      syslog(LOG_ERR, _("Failed to read `%s': %s"), fname, strerror(errno));
    }
  free(fname);
cp
  return x;
}

int isadir(const char* f)
{
  struct stat s;

  if(stat(f, &s) < 0)
    return 0;
  else
    return S_ISDIR(s.st_mode);
}

int is_safe_path(const char *file)
{
  char *p;
  const char *f;
  char x;
  struct stat s;
  char l[MAXBUFSIZE];

  if(*file != '/')
    {
      syslog(LOG_ERR, _("`%s' is not an absolute path"), file);
      return 0;
    }

  p = strrchr(file, '/');

  if(p == file)		/* It's in the root */
    p++;

  x = *p;
  *p = '\0';

  f = file;
check1:
  if(lstat(f, &s) < 0)
    {
      syslog(LOG_ERR, _("Couldn't stat `%s': %s"), f, strerror(errno));
      return 0;
    }

  if(s.st_uid != geteuid())
    {
      syslog(LOG_ERR, _("`%s' is owned by UID %d instead of %d"),
	      f, s.st_uid, geteuid());
      return 0;
    }

  if(S_ISLNK(s.st_mode))
    {
      syslog(LOG_WARNING, _("Warning: `%s' is a symlink"),
	      f);

      if(readlink(f, l, MAXBUFSIZE) < 0)
        {
          syslog(LOG_ERR, _("Unable to read symbolic link `%s': %s"), f, strerror(errno));
          return 0;
        }

      f = l;
      goto check1;
    }

  *p = x;
  f = file;

check2:
  if(lstat(f, &s) < 0 && errno != ENOENT)
    {
      syslog(LOG_ERR, _("Couldn't stat `%s': %s"), f, strerror(errno));
      return 0;
    }

  if(errno == ENOENT)
    return 1;

  if(s.st_uid != geteuid())
    {
      syslog(LOG_ERR, _("`%s' is owned by UID %d instead of %d"),
	      f, s.st_uid, geteuid());
      return 0;
    }

  if(S_ISLNK(s.st_mode))
    {
      syslog(LOG_WARNING, _("Warning: `%s' is a symlink"),
	      f);

      if(readlink(f, l, MAXBUFSIZE) < 0)
        {
          syslog(LOG_ERR, _("Unable to read symbolic link `%s': %s"), f, strerror(errno));
          return 0;
        }

      f = l;
      goto check2;
    }

  if(s.st_mode & 0007)
    {
      /* Accessible by others */
      syslog(LOG_ERR, _("`%s' has unsecure permissions"),
	      f);
      return 0;
    }

  return 1;
}

FILE *ask_and_safe_open(const char* filename, const char* what, const char* mode)
{
  FILE *r;
  char *directory;
  char *fn;

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
      fflush(stdout);

      if((fn = readline(stdin, NULL, NULL)) == NULL)
	{
	  fprintf(stderr, _("Error while reading stdin: %s\n"), strerror(errno));
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
      asprintf(&p, "%s/%s", directory, fn);
      free(fn);
      free(directory);
      fn = p;
    }

  umask(0077); /* Disallow everything for group and other */

  /* Open it first to keep the inode busy */
  if((r = fopen(fn, mode)) == NULL)
    {
      fprintf(stderr, _("Error opening file `%s': %s\n"),
	      fn, strerror(errno));
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

int read_connection_config(connection_t *c)
{
  char *fname;
  int x;
cp
  asprintf(&fname, "%s/hosts/%s", confbase, c->name);
  x = read_config_file(c->config_tree, fname);
  free(fname);
cp
  return x;
}
