/*
    process.h -- header file for process.c
    Copyright (C) 1999,2000 Ivo Timmermans <itimmermans@bigfoot.com>,
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

    $Id: process.h,v 1.1.2.2 2000/11/16 22:12:23 zarq Exp $
*/

#ifndef __TINC_PROCESS_H__
#define __TINC_PROCESS_H__

#include "config.h"
#include <list.h>

extern list_t *child_pids;

extern RETSIGTYPE parent_exit(int a);
extern void setup_signals(void);
extern int execute_script(const char *);
extern void check_children(void);
extern int detach(void);

#endif /* __TINC_PROCESS_H__ */
