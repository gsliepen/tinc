/*
    daemon.h -- header file for daemon.c
    Copyright (C) 2000 Ivo Timmermans <itimmermans@bigfoot.com>,
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

    $Id: daemon.h,v 1.1.2.1 2000/11/24 23:30:50 guus Exp $
*/

#ifndef __DAEMON_H__
#define __DAEMON_H__

#ifndef HAVE_DAEMON
extern int daemon(int, int);
#endif

#endif /* __DAEMON_H__ */
