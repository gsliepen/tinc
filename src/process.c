/*
    process.c -- process management functions
    Copyright (C) 1999-2001 Ivo Timmermans <itimmermans@bigfoot.com>,
                  2000,2001 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: process.c,v 1.1.2.31 2001/10/31 20:37:54 guus Exp $
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
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>

#include <pidfile.h>
#include <utils.h>
#include <xalloc.h>

#include "conf.h"
#include "process.h"
#include "subnet.h"
#include "device.h"
#include "connection.h"
#include "device.h"

#include "system.h"

/* If zero, don't detach from the terminal. */
int do_detach = 1;

extern char *identname;
extern char *pidfilename;
extern char **g_argv;

sigset_t emptysigset;

static int saved_debug_lvl = 0;

void memory_full(int size)
{
  syslog(LOG_ERR, _("Memory exhausted (couldn't allocate %d bytes), exiting."), size);
  cp_trace();
  exit(1);
}

/* Some functions the less gifted operating systems might lack... */

#ifndef HAVE_FCLOSEALL
int fcloseall(void)
{
  fflush(stdin);
  fflush(stdout);
  fflush(stderr);
  fclose(stdin);
  fclose(stdout);
  fclose(stderr);
}
#endif

/*
  Close network connections, and terminate neatly
*/
void cleanup_and_exit(int c)
{
cp
  close_network_connections();

  if(debug_lvl > DEBUG_NOTHING)
    dump_device_stats();

  syslog(LOG_NOTICE, _("Terminating"));

  closelog();
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
int kill_other(int signal)
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
  if(kill(pid, signal) && errno == ESRCH)
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
cp
  setup_signals();

  /* First check if we can open a fresh new pidfile */
  
  if(write_pidfile())
    return -1;

  /* If we succeeded in doing that, detach */

  closelog();

  if(do_detach)
    {
      if(daemon(0, 0) < 0)
	{
	  fprintf(stderr, _("Couldn't detach from terminal: %s"), strerror(errno));
	  return -1;
	}

      /* Now UPDATE the pid in the pidfile, because we changed it... */
      
      if(!write_pid(pidfilename))
        return -1;
    }
  
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
  char *scriptname;
  char *s;
cp
#ifdef HAVE_UNSETENV
  unsetenv("NETNAME");
  unsetenv("DEVICE");
  unsetenv("INTERFACE");
#endif

  if(netname)
    {
      asprintf(&s, "NETNAME=%s", netname);
      putenv(s);	/* Don't free s! see man 3 putenv */
    }

  if(device)
    {
      asprintf(&s, "DEVICE=%s", device);
      putenv(s);	/* Don't free s! see man 3 putenv */
    }

  if(interface)
    {
      asprintf(&s, "INTERFACE=%s", interface);
      putenv(s);	/* Don't free s! see man 3 putenv */
    }

  chdir("/");
  
  asprintf(&scriptname, "%s/%s", confbase, name);

  /* Close all file descriptors */
  closelog();		/* <- this means we cannot use syslog() here anymore! */
  fcloseall();

  execl(scriptname, NULL);
  /* No return on success */
  
  if(errno != ENOENT)	/* Ignore if the file does not exist */
    exit(1);		/* Some error while trying execl(). */
  else
    exit(0);
}

/*
  Fork and execute the program pointed to by name.
*/
int execute_script(const char *name)
{
  pid_t pid;
  int status;
cp
  if((pid = fork()) < 0)
    {
      syslog(LOG_ERR, _("System call `%s' failed: %m"),
	     "fork");
      return -1;
    }

  if(pid)
    {
      if(debug_lvl >= DEBUG_STATUS)
        syslog(LOG_INFO, _("Executing script %s"), name);

      if(waitpid(pid, &status, 0) == pid)
        {
          if(WIFEXITED(status))		/* Child exited by itself */
            {
              if(WEXITSTATUS(status))
                {
                  syslog(LOG_ERR, _("Process %d (%s) exited with non-zero status %d"), pid, name, WEXITSTATUS(status));
                  return -1;
                }
              else
                return 0;
            }
          else if(WIFSIGNALED(status))	/* Child was killed by a signal */
	    {
	      syslog(LOG_ERR, _("Process %d (%s) was killed by signal %d (%s)"),
		     pid, name, WTERMSIG(status), strsignal(WTERMSIG(status)));
	      return -1;
	    }
          else				/* Something strange happened */
            {
	      syslog(LOG_ERR, _("Process %d (%s) terminated abnormally"), pid, name);
	      return -1;
            }
        }
      else
        {
          syslog(LOG_ERR, _("System call `%s' failed: %m"), "waitpid");
          return -1;
        }
    }
cp
  /* Child here */

  _execute_script(name);
}


/*
  Signal handlers.
*/

RETSIGTYPE
sigterm_handler(int a, siginfo_t *info, void *b)
{
  if(debug_lvl > DEBUG_NOTHING)
    syslog(LOG_NOTICE, _("Got TERM signal"));

  cleanup_and_exit(0);
}

RETSIGTYPE
sigquit_handler(int a, siginfo_t *info, void *b)
{
  if(debug_lvl > DEBUG_NOTHING)
    syslog(LOG_NOTICE, _("Got QUIT signal"));
  cleanup_and_exit(0);
}

RETSIGTYPE
sigsegv_square(int a, siginfo_t *info, void *b)
{
  syslog(LOG_ERR, _("Got another SEGV signal: not restarting"));
  cp_trace();
  exit(1);
}

RETSIGTYPE
sigsegv_handler(int a, siginfo_t *info, void *b)
{
  struct sigaction act;
  syslog(LOG_ERR, _("Got SEGV signal"));
  cp_trace();

  if(do_detach)
    {
      syslog(LOG_NOTICE, _("Trying to re-execute in 5 seconds..."));

      act.sa_handler = NULL;
      act.sa_mask = emptysigset;
      act.sa_flags = SA_SIGINFO;
      act.sa_sigaction = sigsegv_square;

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
sighup_handler(int a, siginfo_t *info, void *b)
{
  if(debug_lvl > DEBUG_NOTHING)
    syslog(LOG_NOTICE, _("Got HUP signal"));
  sighup = 1;
}

RETSIGTYPE
sigint_handler(int a, siginfo_t *info, void *b)
{
  if(saved_debug_lvl)
    {
      syslog(LOG_NOTICE, _("Reverting to old debug level (%d)"),
	     saved_debug_lvl);
      debug_lvl = saved_debug_lvl;
      saved_debug_lvl = 0;
    }
  else
    {
      syslog(LOG_NOTICE, _("Temporarily setting debug level to 5.  Kill me with SIGINT again to go back to level %d."),
	     debug_lvl);
      saved_debug_lvl = debug_lvl;
      debug_lvl = 5;
    }
}

RETSIGTYPE
sigusr1_handler(int a, siginfo_t *info, void *b)
{
  dump_connections();
}

RETSIGTYPE
sigusr2_handler(int a, siginfo_t *info, void *b)
{
  dump_device_stats();
  dump_nodes();
  dump_edges();
  dump_subnets();
}

RETSIGTYPE
unexpected_signal_handler(int a, siginfo_t *info, void *b)
{
  syslog(LOG_WARNING, _("Got unexpected signal %d (%s)"), a, strsignal(a));
  cp_trace();
}

RETSIGTYPE
ignore_signal_handler(int a, siginfo_t *info, void *b)
{
  if(debug_lvl >= DEBUG_SCARY_THINGS)
  {
    syslog(LOG_DEBUG, _("Ignored signal %d (%s)"), a, strsignal(a));
    cp_trace();
  }
}

struct {
  int signal;
  void (*handler)(int, siginfo_t *, void *);
} sighandlers[] = {
  { SIGHUP, sighup_handler },
  { SIGTERM, sigterm_handler },
  { SIGQUIT, sigquit_handler },
  { SIGSEGV, sigsegv_handler },
  { SIGPIPE, ignore_signal_handler },
  { SIGINT, sigint_handler },
  { SIGUSR1, sigusr1_handler },
  { SIGUSR2, sigusr2_handler },
  { SIGCHLD, ignore_signal_handler },
  { SIGALRM, ignore_signal_handler },
  { 0, NULL }
};

void
setup_signals(void)
{
  int i;
  struct sigaction act;

  sigemptyset(&emptysigset);
  act.sa_handler = NULL;
  act.sa_mask = emptysigset;
  act.sa_flags = SA_SIGINFO;

  /* Set a default signal handler for every signal, errors will be
     ignored. */
  for(i = 0; i < NSIG; i++) 
    {
      act.sa_sigaction = unexpected_signal_handler;
      sigaction(i, &act, NULL);
    }

  /* If we didn't detach, allow coredumps */
  if(!do_detach)
    sighandlers[3].handler = SIG_DFL;

  /* Then, for each known signal that we want to catch, assign a
     handler to the signal, with error checking this time. */
  for(i = 0; sighandlers[i].signal; i++)
    {
      act.sa_sigaction = sighandlers[i].handler;
      if(sigaction(sighandlers[i].signal, &act, NULL) < 0)
	fprintf(stderr, _("Installing signal handler for signal %d (%s) failed: %s\n"),
		sighandlers[i].signal, strsignal(sighandlers[i].signal), strerror(errno));
    }
}
