#ifndef TINC_SYSTEM_H
#define TINC_SYSTEM_H

/*
    system.h -- system headers
    Copyright (C) 1998-2005 Ivo Timmermans
                  2003-2006 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "config.h"

#include "have.h"

#ifndef HAVE_STRSIGNAL
# define strsignal(p) ""
#endif

/* Other functions */

#include "dropin.h"

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

#endif
