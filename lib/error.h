/*
    error.h -- header file for error.h
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

    $Id: error.h,v 1.1 2000/10/19 20:56:49 zarq Exp $
*/

#ifndef __TINC_ERROR_H__
#define __TINC_ERROR_H__

#define ERR_IGNORE  00000  /* Ignore this error */
#define ERR_FATAL   00001  /* Terminate program */
#define ERR_UNLOAD  00002  /* Unload associated module */
#define ERR_WARNING 01000  /* Warning message only */
#define ERR_DEBUG   04000  /* Debug message */

extern void error(int severity, const char *message, ...);

#endif /* __TINC_ERROR_H__ */
