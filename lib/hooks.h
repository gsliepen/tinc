/*
    hooks.h -- header file for hooks.c
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

    $Id: hooks.h,v 1.2 2002/05/07 14:48:41 zarq Exp $
*/

#ifndef __TINC_HOOKS_H__
#define __TINC_HOOKS_H__

#include <stdarg.h>

typedef void (hook_function_t)(const char*,va_list);

void run_hooks(const char *type, ...);
void add_hook(const char *type, hook_function_t *hook);
void del_hook(const char *type, hook_function_t *hook);

#endif /* __TINC_HOOKS_H__ */
