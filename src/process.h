/*
    process.h -- header file for process.c
    Copyright (C) 1999-2002 Ivo Timmermans <itimmermans@bigfoot.com>,
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

    $Id: process.h,v 1.1.2.10 2002/02/10 21:57:54 guus Exp $
*/

#ifndef __TINC_PROCESS_H__
#define __TINC_PROCESS_H__

#include "config.h"

extern int do_detach;

extern void setup_signals(void);
extern int execute_script(const char *);
extern int detach(void);
extern int kill_other(int);
extern void cleanup_and_exit(int);

#endif /* __TINC_PROCESS_H__ */
