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

    $Id: tincd.c,v 1.10.4.31 2000/11/20 18:06:17 zarq Exp $
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
#include <string.h>
#include <termios.h>

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_OPENSSL_RAND_H
# include <openssl/rand.h>
#else
# include <rand.h>
#endif

#ifdef HAVE_OPENSSL_RSA_H
# include <openssl/rsa.h>
#else
# include <rsa.h>
#endif

#ifdef HAVE_OPENSSL_ERR_H
# include <openssl/err.h>
#else
# include <err.h>
#endif



#include <utils.h>
#include <xalloc.h>

#include "conf.h"
#include "net.h"
#include "netutl.h"
#include "process.h"
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
extern int do_detach;

/* If nonzero, generate public/private keypair for this host/net. */
static int generate_keys = 0;

char *identname;                 /* program name for syslog */
char *pidfilename;               /* pid file location */
char **g_argv;                   /* a copy of the cmdline arguments */
char **environment;              /* A pointer to the environment on
                                    startup */

void cleanup_and_exit(int);
int kill_other(void);
void make_names(void);
int write_pidfile(void);

static struct option const long_options[] =
{
  { "config", required_argument, NULL, 'c' },
  { "kill", no_argument, NULL, 'k' },
  { "net", required_argument, NULL, 'n' },
  { "help", no_argument, &show_help, 1 },
  { "version", no_argument, &show_version, 1 },
  { "no-detach", no_argument, &do_detach, 0 },
  { "generate-keys", optional_argument, NULL, 'K'},
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
      printf(_("  -c, --config=DIR           Read configuration options from DIR.\n"
	       "  -D, --no-detach            Don't fork and detach.\n"
	       "  -d                         Increase debug level.\n"
	       "  -k, --kill                 Attempt to kill a running tincd and exit.\n"
	       "  -n, --net=NETNAME          Connect to net NETNAME.\n"));
      printf(_("  -K, --generate-keys[=BITS] Generate public/private RSA keypair.\n"
               "      --help                 Display this help and exit.\n"
 	       "      --version              Output version information and exit.\n\n"));
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
      else
        fprintf(stderr, _("Both netname and configuration directory given, using the latter...\n"));
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

  environment = envp;
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

  /* Slllluuuuuuurrrrp! */

  RAND_load_file("/dev/urandom", 1024);

  if(generate_keys)
    exit(keygen(generate_keys));

  if(kill_tincd)
    exit(kill_other());

  if(read_server_config())
    return 1;

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

