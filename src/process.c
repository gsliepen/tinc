/*
    process.c -- process management functions
    Copyright (C) 1999,2000 Ivo Timmermans <itimmermans@bigfoot.com>,
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

    $Id: process.c,v 1.1.2.8 2000/11/22 17:48:15 zarq Exp $
*/

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <list.h>
#include <pidfile.h>
#include <utils.h>
#include <xalloc.h>

#include "conf.h"
#include "process.h"

#include "system.h"

/* A list containing all our children */
list_t *child_pids = NULL;

/* If zero, don't detach from the terminal. */
int do_detach = 1;

static pid_t ppid;

extern char *identname;
extern char *pidfilename;
extern char **g_argv;

void init_processes(void)
{
cp
  child_pids = list_new();
cp
}

void memory_full(int size)
{
  syslog(LOG_ERR, _("Memory exhausted (couldn't allocate %d bytes), exiting."), size);
  cp_trace();
  exit(1);
}

/*
  Close network connections, and terminate neatly
*/
void cleanup_and_exit(int c)
{
cp
  close_network_connections();

  if(debug_lvl > DEBUG_NOTHING)
    syslog(LOG_INFO, _("Total bytes written: tap %d, socket %d; bytes read: tap %d, socket %d"),
	   total_tap_out, total_socket_out, total_tap_in, total_socket_in);

  closelog();
  kill(ppid, SIGTERM);
  exit(c);
}

/*
  check for an existing tinc for this net, and write pid to pidfile
*/
int write_pidfile(void)
{
  int pid;
cp
  if((pid = check_pid(pidfilename)))
    {
      if(netname)
	fprintf(stderr, _("A tincd is already running for net `%s' with pid %d.\n"),
		netname, pid);
      else
	fprintf(stderr, _("A tincd is already running with pid %d.\n"), pid);
      return 1;
    }

  /* if it's locked, write-protected, or whatever */
  if(!write_pid(pidfilename))
    return 1;
cp
  return 0;
}

/*
  kill older tincd for this net
*/
int kill_other(void)
{
  int pid;
cp
  if(!(pid = read_pid(pidfilename)))
    {
      if(netname)
	fprintf(stderr, _("No other tincd is running for net `%s'.\n"), netname);
      else
	fprintf(stderr, _("No other tincd is running.\n"));
      return 1;
    }

  errno = 0;    /* No error, sometimes errno is only changed on error */
  /* ESRCH is returned when no process with that pid is found */
  if(kill(pid, SIGTERM) && errno == ESRCH)
    fprintf(stderr, _("Removing stale lock file.\n"));
  remove_pid(pidfilename);
cp
  return 0;
}

/*
  Detach from current terminal, write pidfile, kill parent
*/
int detach(void)
{
  int fd;
  pid_t pid;
cp
  setup_signals();

  if(write_pidfile())
    return -1;

  if(do_detach)
    daemon(0, 0);

  openlog(identname, LOG_CONS | LOG_PID, LOG_DAEMON);

  if(debug_lvl > DEBUG_NOTHING)
    syslog(LOG_NOTICE, _("tincd %s (%s %s) starting, debug level %d"),
	   VERSION, __DATE__, __TIME__, debug_lvl);
  else
    syslog(LOG_NOTICE, _("tincd %s starting"), VERSION);

  xalloc_fail_func = memory_full;
cp
  return 0;
}

/*
  Execute the program name, with sane environment.  All output will be
  redirected to syslog.
*/
void _execute_script(const char *name)  __attribute__ ((noreturn));
void _execute_script(const char *name)
{
  int error = 0;
  char *scriptname;
  char *s;
cp
  if(netname)
    {
      asprintf(&s, "NETNAME=%s", netname);
      putenv(s);	/* Don't free s! see man 3 putenv */
    }
#ifdef HAVE_UNSETENV
  else
    {
      unsetenv("NETNAME");
    }
#endif

  if(chdir(confbase) < 0)
    /* This cannot fail since we already read config files from this
       directory. - Guus */
    /* Yes this can fail, somebody could have removed this directory
       when we didn't pay attention. - Ivo */
    {
      if(chdir("/") < 0)
	/* Now if THIS fails, something wicked is going on. - Ivo */
	syslog(LOG_ERR, _("Couldn't chdir to `/': %m"));

      /* Continue anyway. */
    }
  
  asprintf(&scriptname, "%s/%s", confbase, name);

  /* Close all file descriptors */
  closelog();
  fcloseall();

  /* Open standard input */
  if((fd = open("/dev/null", O_RDONLY)) < 0)
    {
      syslog(LOG_ERR, _("Opening `/dev/null' failed: %m"));
      error = 1;
    }
  if(dup2(fd, 0) != 0)
    {
      syslog(LOG_ERR, _("Couldn't assign /dev/null to standard input: %m"));
      error = 1;
    }

  if(!error)
    {
      close(1);  /* fd #1 should be the first available filedescriptor now. */
      /* Standard output directly goes to syslog */
      openlog(name, LOG_CONS | LOG_PID, LOG_DAEMON);
      /* Standard error as well */
      if(dup2(1, 2) < 0)
	{
	  syslog(LOG_ERR, _("System call `%s' failed: %m"),
		 "dup2");
	  error = 1;
	}
    }
  
  if(error && debug_lvl > 1)
    syslog(LOG_INFO, _("This means that any output the script generates will not be shown in syslog."));
  
  execl(scriptname, NULL);
  /* No return on success */
  
  if(errno != ENOENT)  /* Ignore if the file does not exist */
    syslog(LOG_WARNING, _("Error executing `%s': %m"), scriptname);

  /* No need to free things */
  exit(0);
}

/*
  Fork and execute the program pointed to by name.
*/
int execute_script(const char *name)
{
  pid_t pid;
cp
  if((pid = fork()) < 0)
    {
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "fork");
      return -1;
    }

  if(pid)
    {
      list_append(child_pids, &pid);
      return 0;
    }
cp
  /* Child here */
  _execute_script(name);
}

/*
  Check a child (the pointer data is actually an integer, the PID of
  that child.  A non-zero return value means that the child has exited
  and can be removed from our list.
*/
int check_child(void *data)
{
  pid_t pid;
  int status;
cp
  pid = (pid_t) data;
  pid = waitpid(pid, &status, WNOHANG);
  if(WIFEXITED(status))
    {
      if(WIFSIGNALED(status)) /* Child was killed by a signal */
	{
	  syslog(LOG_ERR, _("Child with PID %d was killed by signal %d (%s)"),
		 pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
	  return -1;
	}
      if(WEXITSTATUS(status) != 0)
	{
	  syslog(LOG_INFO, _("Child with PID %d exited with code %d"),
		 WEXITSTATUS(status));
	}
      return -1;
    }
cp
  /* Child is still running */
  return 0;
}

/*
  Check the status of all our children.
*/
void check_children(void)
{
  list_forall_nodes(child_pids, check_child);
}


/*
  Signal handlers.
*/

RETSIGTYPE
sigterm_handler(int a)
{
  if(debug_lvl > DEBUG_NOTHING)
    syslog(LOG_NOTICE, _("Got TERM signal"));

  cleanup_and_exit(0);
}

RETSIGTYPE
sigquit_handler(int a)
{
  if(debug_lvl > DEBUG_NOTHING)
    syslog(LOG_NOTICE, _("Got QUIT signal"));
  cleanup_and_exit(0);
}

RETSIGTYPE
sigsegv_square(int a)
{
  syslog(LOG_ERR, _("Got another SEGV signal: not restarting"));
  exit(0);
}

RETSIGTYPE
sigsegv_handler(int a)
{
  syslog(LOG_ERR, _("Got SEGV signal"));
  cp_trace();

  if(do_detach)
    {
      syslog(LOG_NOTICE, _("Trying to re-execute in 5 seconds..."));
      signal(SIGSEGV, sigsegv_square);
      close_network_connections();
      sleep(5);
      remove_pid(pidfilename);
      execvp(g_argv[0], g_argv);
    }
  else
    {
      syslog(LOG_NOTICE, _("Not restarting."));
      exit(0);
    }
}

RETSIGTYPE
sighup_handler(int a)
{
  if(debug_lvl > DEBUG_NOTHING)
    syslog(LOG_NOTICE, _("Got HUP signal"));
  sighup = 1;
}

RETSIGTYPE
sigint_handler(int a)
{
  if(debug_lvl > DEBUG_NOTHING)
    syslog(LOG_NOTICE, _("Got INT signal, exiting"));
  cleanup_and_exit(0);
}

RETSIGTYPE
sigusr1_handler(int a)
{
  dump_connection_list();
}

RETSIGTYPE
sigusr2_handler(int a)
{
  dump_subnet_list();
}

RETSIGTYPE
sighuh(int a)
{
  syslog(LOG_WARNING, _("Got unexpected signal %d (%s)"), a, strsignal(a));
  cp_trace();
}

void
setup_signals(void)
{
  int i;

  for(i=0;i<32;i++)
    signal(i,sighuh);

  if(signal(SIGTERM, SIG_IGN) != SIG_ERR)
    signal(SIGTERM, sigterm_handler);
  if(signal(SIGQUIT, SIG_IGN) != SIG_ERR)
    signal(SIGQUIT, sigquit_handler);
  if(signal(SIGSEGV, SIG_IGN) != SIG_ERR)
    signal(SIGSEGV, sigsegv_handler);
  if(signal(SIGHUP, SIG_IGN) != SIG_ERR)
    signal(SIGHUP, sighup_handler);
  signal(SIGPIPE, SIG_IGN);
  if(signal(SIGINT, SIG_IGN) != SIG_ERR)
    signal(SIGINT, sigint_handler);
  signal(SIGUSR1, sigusr1_handler);
  signal(SIGUSR2, sigusr2_handler);
  signal(SIGCHLD, SIG_IGN);
}

RETSIGTYPE parent_exit(int a)
{
  exit(0);
}
