/* xmalloc.c -- malloc with out of memory checking
   Copyright (C) 1990, 91, 92, 93, 94, 95, 96, 97 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc., Foundation,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.  */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#if STDC_HEADERS
# include <stdlib.h>
#else
void *calloc ();
void *malloc ();
void *realloc ();
void free ();
#endif

#include "dropin.h"
#include "xalloc.h"

#ifndef EXIT_FAILURE
# define EXIT_FAILURE 1
#endif

/* Prototypes for functions defined here.  */
#if defined (__STDC__) && __STDC__
void *xmalloc (size_t n);
void *xcalloc (size_t n, size_t s);
void *xrealloc (void *p, size_t n);
#endif

/* Exit value when the requested amount of memory is not available.
   The caller may set it to some other value.  */
int xalloc_exit_failure = EXIT_FAILURE;

/* FIXME: describe */
char *const xalloc_msg_memory_exhausted = "Memory exhausted";

/* FIXME: describe */
void (*xalloc_fail_func) (int) = NULL;

static void
xalloc_fail (int size)
{
  if (xalloc_fail_func)
    (*xalloc_fail_func) (size);
  fprintf(stderr, "%s\n", xalloc_msg_memory_exhausted);
  exit(xalloc_exit_failure);
}

/* Allocate N bytes of memory dynamically, with error checking.  */

void *
xmalloc (size_t n)
{
  void *p;

  p = malloc (n);
  if (p == NULL)
    xalloc_fail ((int)n);
  return p;
}

/* Allocate N bytes of memory dynamically, and set it all to zero. */

void *
xmalloc_and_zero (size_t n)
{
  void *p;

  p = malloc (n);
  if (p == NULL)
    xalloc_fail ((int)n);
  memset (p, '\0', n);
  return p;
}

/* Change the size of an allocated block of memory P to N bytes,
   with error checking.
   If P is NULL, run xmalloc.  */

void *
xrealloc (void *p, size_t n)
{
  p = realloc (p, n);
  if (p == NULL)
    xalloc_fail (n);
  return p;
}

/* Duplicate a string */

char *xstrdup(const char *s)
{
  char *p;
  
  p = strdup(s);
  if(!p)
    xalloc_fail ((int)strlen(s));
  return p;
}

#ifdef NOT_USED

/* Allocate memory for N elements of S bytes, with error checking.  */

void *
xcalloc (n, s)
     size_t n, s;
{
  void *p;

  p = calloc (n, s);
  if (p == NULL)
    xalloc_fail ();
  return p;
}

#endif /* NOT_USED */

int xasprintf(char **strp, const char *fmt, ...) {
	int result;
	va_list ap;
	va_start(ap, fmt);
	result = xvasprintf(strp, fmt, ap);
	va_end(ap);
	return result;
}

int xvasprintf(char **strp, const char *fmt, va_list ap) {
#ifdef HAVE_MINGW
	char buf[1024];
	int result = vsnprintf(buf, sizeof buf, fmt, ap);
	if(result < 0)
		exit(xalloc_exit_failure);
	*strp = xstrdup(buf);
#else
	int result = vasprintf(strp, fmt, ap);
	if(result < 0) {
		fprintf(stderr, "vasprintf() failed: %s\n", strerror(errno));
  		exit(xalloc_exit_failure);
	}
#endif
	return result;
}
