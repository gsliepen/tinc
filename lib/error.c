/*
    error.c -- generalized error handling
    Copyright (C) 2000 Ivo Timmermans <itimmermans@bigfoot.com>
                  2000 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: error.c,v 1.1 2000/10/19 20:56:49 zarq Exp $
*/

#include "config.h"

#include <stdio.h>

#ifdef STDC_HEADERS
# include <stdarg.h>
#endif

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include <error.h>
#include <system.h>

void error(int severity, const char *message, ...)
{
  va_list v;
  extern int detached;

  va_start(v, message);

#ifdef HAVE_SYSLOG
  if(detached)
    {
      syslog(LOG_ERR, _(message), v);
    }
  else
#endif /* HAVE_SYSLOG */
    {
      vfprintf(stderr, _(message), v);
      fputs("\n", stderr);
    }
  va_end(v);

  if(severity | ERR_FATAL)
    exit(1);
}
