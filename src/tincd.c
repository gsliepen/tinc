/*
    tincd.c -- the main file for tincd
    Copyright (C) 1998,1999,2000 Ivo Timmermans <itimmermans@bigfoot.com>
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

    $Id: tincd.c,v 1.10.4.20 2000/10/29 22:10:44 guus Exp $
*/

#include "config.h"

#include <errno.h>
#include <fcntl.h> 
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#include <pidfile.h>
#include <utils.h>
#include <xalloc.h>

#include "conf.h"
#include "net.h"
#include "netutl.h"
#include "protocol.h"
#include "subnet.h"

#include "system.h"

/* The name this program was run with. */
char *program_name;

/* If nonzero, display usage information and exit. */
static int show_help;

/* If nonzero, print the version on standard output and exit.  */
static int show_version;

/* If nonzero, it will attempt to kill a running tincd and exit. */
static int kill_tincd = 0;

/* If zero, don't detach from the terminal. */
static int do_detach = 1;

/* If nonzero, generate public/private keypair for this host/net. */
static int generate_keys = 0;

char *identname;                 /* program name for syslog */
char *pidfilename;               /* pid file location */
static pid_t ppid;               /* pid of non-detached part */
char **g_argv;                   /* a copy of the cmdline arguments */

void cleanup_and_exit(int);
int detach(void);
int kill_other(void);
void make_names(void);
RETSIGTYPE parent_exit(int a);
void setup_signals(void);
int write_pidfile(void);

static struct option const long_options[] =
{
  { "kill", no_argument, NULL, 'k' },
  { "net", required_argument, NULL, 'n' },
  { "help", no_argument, &show_help, 1 },
  { "version", no_argument, &show_version, 1 },
  { "no-detach", no_argument, &do_detach, 0 },
  { "keygen", optional_argument, NULL, 'K'},
  { NULL, 0, NULL, 0 }
};

static void
usage(int status)
{
  if(status != 0)
    fprintf(stderr, _("Try `%s --help\' for more information.\n"), program_name);
  else
    {
      printf(_("Usage: %s [option]...\n\n"), program_name);
      printf(_("  -c, --config=DIR      Read configuration options from DIR.\n"
	       "  -D, --no-detach       Don't fork and detach.\n"
	       "  -d                    Increase debug level.\n"
	       "  -k, --kill            Attempt to kill a running tincd and exit.\n"
	       "  -n, --net=NETNAME     Connect to net NETNAME.\n"));
      printf(_("  -K, --keygen[=BITS]   Generate public/private RSA keypair.\n"
               "      --help            Display this help and exit.\n"
 	       "      --version         Output version information and exit.\n\n"));
      printf(_("Report bugs to tinc@nl.linux.org.\n"));
    }
  exit(status);
}

void
parse_options(int argc, char **argv, char **envp)
{
  int r;
  int option_index = 0;
  
  while((r = getopt_long(argc, argv, "c:Ddkn:K::", long_options, &option_index)) != EOF)
    {
      switch(r)
        {
        case 0: /* long option */
          break;
	case 'c': /* config file */
	  confbase = xmalloc(strlen(optarg)+1);
	  strcpy(confbase, optarg);
	  break;
	case 'D': /* no detach */
	  do_detach = 0;
	  break;
	case 'd': /* inc debug level */
	  debug_lvl++;
	  break;
	case 'k': /* kill old tincds */
	  kill_tincd = 1;
	  break;
	case 'n': /* net name given */
	  netname = xmalloc(strlen(optarg)+1);
	  strcpy(netname, optarg);
	  break;
	case 'K': /* generate public/private keypair */
          if(optarg)
            {
              generate_keys = atoi(optarg);
              if(generate_keys < 512)
                {
                  fprintf(stderr, _("Invalid argument! BITS must be a number equal to or greater than 512.\n"));
                  usage(1);
                }
              generate_keys &= ~7;	/* Round it to bytes */
            }
          else
            generate_keys = 1024;
	  break;
        case '?':
          usage(1);
        default:
          break;
        }
    }
}

/* This function prettyprints the key generation process */

void indicator(int a, int b, void *p)
{
  switch(a)
  {
    case 0:
      fprintf(stderr, ".");
      break;
    case 1:
      fprintf(stderr, "+");
      break;
    case 2:
      fprintf(stderr, "-");
      break;
    case 3:
      switch(b)
        {
          case 0:
            fprintf(stderr, " p\n");      
            break;
          case 1:
            fprintf(stderr, " q\n");
            break;
          default:
            fprintf(stderr, "?");
         }
       break;
    default:
      fprintf(stderr, "?");
  }
}

/* Generate a public/private RSA keypair, and possibly store it into the configuration file. */

int keygen(int bits)
{
  RSA *rsa_key;

  fprintf(stderr, _("Seeding the PRNG: please press some keys or move\nthe mouse if this program seems to have halted...\n"));
  RAND_load_file("/dev/random", 1024);	/* OpenSSL PRNG state apparently uses 1024 bytes, but it seems pretty sufficient anyway :) */

  fprintf(stderr, _("Generating %d bits keys:\n"), bits);
  rsa_key = RSA_generate_key(bits, 0xFFFF, indicator, NULL);
  if(!rsa_key)
    {
      fprintf(stderr, _("Error during key generation!"));
      return -1;
     }
  else
    fprintf(stderr, _("Done.\n"));

  fprintf(stderr, _("Please copy the private key to tinc.conf and the\npublic key to your host configuration file:\n\n"));
  printf("PublicKey = %s\n", BN_bn2hex(rsa_key->n));
  printf("PrivateKey = %s\n", BN_bn2hex(rsa_key->d));
  
  fflush(stdin);
  return 0;
}

void memory_full(int size)
{
  syslog(LOG_ERR, _("Memory exhausted (last is %s:%d) (couldn't allocate %d bytes), exiting."), cp_file, cp_line, size);
  exit(1);
}

/*
  Detach from current terminal, write pidfile, kill parent
*/
int detach(void)
{
  int fd;
  pid_t pid;

  if(do_detach)
    {
      ppid = getpid();

      if((pid = fork()) < 0)
	{
	  perror("fork");
	  return -1;
	}
      if(pid) /* parent process */
	{
	  signal(SIGTERM, parent_exit);
	  sleep(600); /* wait 10 minutes */
	  exit(1);
	}
    }
  
  if(write_pidfile())
    return -1;

  if(do_detach)
    {
      if((fd = open("/dev/tty", O_RDWR)) >= 0)
	{
	  if(ioctl(fd, TIOCNOTTY, NULL))
	    {
	      perror("ioctl");
	      return -1;
	    }
	  close(fd);
	}

      if(setsid() < 0)
	return -1;

      kill(ppid, SIGTERM);
    }
  
  chdir("/"); /* avoid keeping a mointpoint busy */

  openlog(identname, LOG_CONS | LOG_PID, LOG_DAEMON);

  if(debug_lvl > DEBUG_NOTHING)
    syslog(LOG_NOTICE, _("tincd %s (%s %s) starting, debug level %d"),
	   VERSION, __DATE__, __TIME__, debug_lvl);
  else
    syslog(LOG_NOTICE, _("tincd %s starting"), VERSION);

  xalloc_fail_func = memory_full;

  return 0;
}

/*
  Close network connections, and terminate neatly
*/
void cleanup_and_exit(int c)
{
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

  return 0;
}

/*
  kill older tincd for this net
*/
int kill_other(void)
{
  int pid;

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

  return 0;
}

/*
  Set all files and paths according to netname
*/
void make_names(void)
{
  if(netname)
    {
      if(!pidfilename)
        asprintf(&pidfilename, "/var/run/tinc.%s.pid", netname);
      if(!confbase)
        asprintf(&confbase, "%s/tinc/%s", CONFDIR, netname);
      if(!identname)
        asprintf(&identname, "tinc.%s", netname);
    }
  else
    {
      if(!pidfilename)
        pidfilename = "/var/run/tinc.pid";
      if(!confbase)
        asprintf(&confbase, "%s/tinc", CONFDIR);
      if(!identname)
        identname = "tinc";
    }
}

int
main(int argc, char **argv, char **envp)
{
  program_name = argv[0];

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  /* Do some intl stuff right now */
  
  unknown = _("unknown");

  parse_options(argc, argv, envp);

  if(show_version)
    {
      printf(_("%s version %s (built %s %s, protocol %d)\n"), PACKAGE, VERSION, __DATE__, __TIME__, PROT_CURRENT);
      printf(_("Copyright (C) 1998,1999,2000 Ivo Timmermans, Guus Sliepen and others.\n"
	       "See the AUTHORS file for a complete list.\n\n"
	       "tinc comes with ABSOLUTELY NO WARRANTY.  This is free software,\n"
	       "and you are welcome to redistribute it under certain conditions;\n"
	       "see the file COPYING for details.\n"));

      return 0;
    }

  if(show_help)
    usage(0);

  if(geteuid())
    {
      fprintf(stderr, _("You must be root to run this program. Sorry.\n"));
      return 1;
    }

  g_argv = argv;

  make_names();

  if(generate_keys)
    exit(keygen(generate_keys));

  if(kill_tincd)
    exit(kill_other());

  if(read_server_config())
    return 1;

  setup_signals();

  if(detach())
    exit(0);

  if(debug_lvl >= DEBUG_ERROR)
    ERR_load_crypto_strings();
    
  for(;;)
    {
      if(!setup_network_connections())
        {
          main_loop();
          cleanup_and_exit(1);
        }
      
      syslog(LOG_ERR, _("Unrecoverable error"));
      cp_trace();

      if(do_detach)
        {
          syslog(LOG_NOTICE, _("Restarting in %d seconds!"), MAXTIMEOUT);
          sleep(MAXTIMEOUT);
        }
      else
        {
          syslog(LOG_ERR, _("Not restarting."));
          exit(0);
        }
    }
}

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
  dump_conn_list();
}

RETSIGTYPE
sigusr2_handler(int a)
{
  dump_subnet_list();
/* FIXME: reprogram this.
  if(debug_lvl > DEBUG_NOTHING)
   syslog(LOG_NOTICE, _("Got USR2 signal, forcing new key generation"));
  regenerate_keys();
*/
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
