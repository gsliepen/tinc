/*
    version.c -- version information 
    Copyright (C) 2014      Etienne Dechamps <etienne@edechamps.fr>

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

#include "version.h"
#include "version_git.h"
#include "../config.h"

/* This file is always rebuilt (even if there are no changes) so that the following is updated */
const char* const BUILD_DATE = __DATE__;
const char* const BUILD_TIME = __TIME__;
#ifdef GIT_DESCRIPTION
const char* const BUILD_VERSION = GIT_DESCRIPTION;
#else
const char* const BUILD_VERSION = VERSION;
#endif
