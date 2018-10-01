#ifndef TINC_PIDFILE_H
#define TINC_PIDFILE_H

/*
    pidfile.h - interact with pidfiles
    Copyright (c) 1995  Martin Schulze <Martin.Schulze@Linux.DE>

    This file is part of the sysklogd package, a kernel and system log daemon.

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

#ifndef HAVE_MINGW
/* read_pid
 *
 * Reads the specified pidfile and returns the read pid.
 * 0 is returned if either there's no pidfile, it's empty
 * or no pid can be read.
 */
extern pid_t read_pid(const char *pidfile);

/* check_pid
 *
 * Reads the pid using read_pid and looks up the pid in the process
 * table (using /proc) to determine if the process already exists. If
 * so 1 is returned, otherwise 0.
 */
extern pid_t check_pid(const char *pidfile);

/* write_pid
 *
 * Writes the pid to the specified file. If that fails 0 is
 * returned, otherwise the pid.
 */
extern pid_t write_pid(const char *pidfile);

/* remove_pid
 *
 * Remove the the specified file. The result from unlink(2)
 * is returned
 */
extern int remove_pid(const char *pidfile);
#endif

#endif
