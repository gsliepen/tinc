/*
    pidfile.c - interact with pidfiles
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

/* left unaltered for tinc -- Ivo Timmermans */
/*
 * Sat Aug 19 13:24:33 MET DST 1995: Martin Schulze
 *	First version (v0.2) released
 */

#include "system.h"

#include "pidfile.h"

#ifndef HAVE_MINGW
/* read_pid
 *
 * Reads the specified pidfile and returns the read pid.
 * 0 is returned if either there's no pidfile, it's empty
 * or no pid can be read.
 */
pid_t read_pid (const char *pidfile)
{
  FILE *f;
  long pid;

  if (!(f=fopen(pidfile,"r")))
    return 0;
  if(fscanf(f,"%20ld", &pid) != 1)
    pid = 0;
  fclose(f);
  return pid;
}

/* check_pid
 *
 * Reads the pid using read_pid and looks up the pid in the process
 * table (using /proc) to determine if the process already exists. If
 * so the pid is returned, otherwise 0.
 */
pid_t check_pid (const char *pidfile)
{
  pid_t pid = read_pid(pidfile);

  /* Amazing ! _I_ am already holding the pid file... */
  if ((!pid) || (pid == getpid ()))
    return 0;

  /*
   * The 'standard' method of doing this is to try and do a 'fake' kill
   * of the process.  If an ESRCH error is returned the process cannot
   * be found -- GW
   */
  /* But... errno is usually changed only on error.. */
  errno = 0;
  if (kill(pid, 0) && errno == ESRCH)
	  return 0;

  return pid;
}

/* write_pid
 *
 * Writes the pid to the specified file. If that fails 0 is
 * returned, otherwise the pid.
 */
pid_t write_pid (const char *pidfile)
{
  FILE *f;
  int fd;
  pid_t pid;

  if ((fd = open(pidfile, O_RDWR|O_CREAT, 0644)) == -1) {
      return 0;
  }

  if ((f = fdopen(fd, "r+")) == NULL) {
      close(fd);
      return 0;
  }
  
#ifdef HAVE_FLOCK
  if (flock(fd, LOCK_EX|LOCK_NB) == -1) {
      fclose(f);
      return 0;
  }
#endif

  pid = getpid();
  if (!fprintf(f,"%ld\n", (long)pid)) {
      fclose(f);
      return 0;
  }
  fflush(f);

#ifdef HAVE_FLOCK
  if (flock(fd, LOCK_UN) == -1) {
      fclose(f);
      return 0;
  }
#endif
  fclose(f);

  return pid;
}

/* remove_pid
 *
 * Remove the the specified file. The result from unlink(2)
 * is returned
 */
int remove_pid (const char *pidfile)
{
  return unlink (pidfile);
}
#endif
