/*
    daemon.c -- replacement daemon() for platforms that do not have it
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

    $Id: daemon.c,v 1.1.2.1 2000/11/24 23:30:50 guus Exp $
*/

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

#include <system.h>

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose)
{
  pid_t pid;
  int fd;
  
  pid = fork();
  
  /* Check if forking failed */
    
  if(pid < 0)
    {
      perror("fork");
      exit(-1);
    }

  /* If we are the parent, terminate */
  
  if(pid)
    exit(0);

  /* Detach by becoming the new process group leader */
  
  if(setsid() < 0)
    {
      perror("setsid");
      return -1;
    }
  
  /* Change working directory to the root (to avoid keeping mount points busy) */
  
  if(!nochdir)
    {
      chdir("/");
    }
    
  /* Redirect stdin/out/err to /dev/null */

  if(!noclose)
    {
      fd = open("/dev/null", O_RDWR);

      if(fd < 0)
        {
          perror("opening /dev/null");
          return -1;
        }
        else
        {
          dup2(fd, 0);
          dup2(fd, 1);
          dup2(fd, 2);
        }
    }
}
#endif
