/*
    process.h -- header file for process.c
    Copyright (C) 1999-2003 Ivo Timmermans <ivo@o2w.nl>,
                  2000-2003 Guus Sliepen <guus@sliepen.eu.org>

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

    $Id: process.h,v 1.1.2.16 2003/07/17 15:06:26 guus Exp $
*/

#ifndef __TINC_PROCESS_H__
#define __TINC_PROCESS_H__

extern int do_detach;

extern void setup_signals(void);
extern int execute_script(const char *, char **);
extern int detach(void);
extern int kill_other(int);
extern void cleanup_and_exit(int) __attribute__ ((noreturn));

#endif							/* __TINC_PROCESS_H__ */
