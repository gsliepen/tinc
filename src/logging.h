/*
    logging.h -- header for logging.c
    Copyright (C) 2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2002 Ivo Timmermans <ivo@o2w.nl>

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

    $Id: logging.h,v 1.1 2002/04/13 10:25:38 zarq Exp $
*/

#ifndef __TINC_LOGGING_H__
#define __TINC_LOGGING_H__

#include <stdarg.h>

enum {
  TLOG_DEBUG,
  TLOG_INFO,
  TLOG_NOTICE,
  TLOG_ERROR,
  TLOG_CRITICAL
};

enum {
  DEBUG_NOTHING = 0,		/* Quiet mode, only show starting/stopping of the daemon */
  DEBUG_CONNECTIONS = 1,	/* Show (dis)connects of other tinc daemons via TCP */
  DEBUG_ERROR = 2,		/* Show error messages received from other hosts */
  DEBUG_STATUS = 2,		/* Show status messages received from other hosts */
  DEBUG_PROTOCOL = 3,		/* Show the requests that are sent/received */
  DEBUG_META = 4,		/* Show contents of every request that is sent/received */
  DEBUG_TRAFFIC = 5,		/* Show network traffic information */
  DEBUG_PACKET = 6,		/* Show contents of each packet that is being sent/received */
  DEBUG_SCARY_THINGS = 10	/* You have been warned */
};

typedef void (log_function_t)(int,int,char*,va_list);

extern int debug_lvl;
extern avl_tree_t *log_hooks_tree;

extern void log_message(int, int, char *, ...);
extern void log_add_hook(log_function_t *);
extern void log_del_hook(log_function_t *);
extern log_function_t log_default_hook;

#endif /* __TINC_LOGGING_H__ */
