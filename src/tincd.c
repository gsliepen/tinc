/*
    tincd.c -- the main file for tincd
    Copyright (C) 1998-2002 Ivo Timmermans <itimmermans@bigfoot.com>
                  2000-2002 Guus Sliepen <guus@sliepen.warande.net>

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

    $Id: tincd.c,v 1.10.4.58 2002/03/11 11:23:04 guus Exp $
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

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

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
int show_help;

/* If nonzero, print the version on standard output and exit.  */
int show_version;

/* If nonzero, it will attempt to kill a running tincd and exit. */
int kill_tincd = 0;

/* If nonzero, generate public/private keypair for this host/net. */
int generate_keys = 0;

/* If nonzero, use null ciphers and skip all key exchanges. */
int bypass_security = 0;

char *identname;                 /* program name for syslog */
char *pidfilename;               /* pid file location */
char **g_argv;                   /* a copy of the cmdline arguments */
char **environment;              /* A pointer to the environment on
                                    startup */

static struct option const long_options[] =
{
  { "config", required_argument, NULL, 'c' },
  { "kill", optional_argument, NULL, 'k' },
  { "net", required_argument, NULL, 'n' },
  { "help", no_argument, &show_help, 1 },
  { "version", no_argument, &show_version, 1 },
  { "no-detach", no_argument, &do_detach, 0 },
  { "generate-keys", optional_argument, NULL, 'K'},
  { "debug", optional_argument, NULL, 'd'},
  { "bypass-security", no_argument, &bypass_security, 1 },
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
               "  -d, --debug[=LEVEL]        Increase debug level or set it to LEVEL.\n"
               "  -k, --kill[=SIGNAL]        Attempt to kill a running tincd and exit.\n"
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

  while((r = getopt_long(argc, argv, "c:Dd::k::n:K::", long_options, &option_index)) != EOF)
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
          if(optarg)
            debug_lvl = atoi(optarg);
          else
            debug_lvl++;
          break;
        case 'k': /* kill old tincds */
          if(optarg)
            {
              if(!strcasecmp(optarg, "HUP"))
                kill_tincd = SIGHUP;
              else if(!strcasecmp(optarg, "TERM"))
                kill_tincd = SIGTERM;
              else if(!strcasecmp(optarg, "KILL"))
                kill_tincd = SIGKILL;
              else if(!strcasecmp(optarg, "USR1"))
                kill_tincd = SIGUSR1;
              else if(!strcasecmp(optarg, "USR2"))
                kill_tincd = SIGUSR2;
              else if(!strcasecmp(optarg, "WINCH"))
                kill_tincd = SIGWINCH;
              else if(!strcasecmp(optarg, "INT"))
                kill_tincd = SIGINT;
              else if(!strcasecmp(optarg, "ALRM"))
                kill_tincd = SIGALRM;
              else
                {
                  kill_tincd = atoi(optarg);
                  if(!kill_tincd)
                    {
                      fprintf(stderr, _("Invalid argument `%s'; SIGNAL must be a number or one of HUP, TERM, KILL, USR1, USR2, WINCH, INT or ALRM.\n"), optarg);
                      usage(1);
                    }
                }
            }
          else
            kill_tincd = SIGTERM;
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
                  fprintf(stderr, _("Invalid argument `%s'; BITS must be a number equal to or greater than 512.\n"),
                          optarg);
                  usage(1);
                }
              generate_keys &= ~7;      /* Round it to bytes */
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

/*
  Generate a public/private RSA keypair, and ask for a file to store
  them in.
*/
int keygen(int bits)
{
  RSA *rsa_key;
  FILE *f;
  char *name = NULL;
  char *filename;

  fprintf(stderr, _("Generating %d bits keys:\n"), bits);
  rsa_key = RSA_generate_key(bits, 0xFFFF, indicator, NULL);

  if(!rsa_key)
    {
      fprintf(stderr, _("Error during key generation!\n"));
      return -1;
    }
  else
    fprintf(stderr, _("Done.\n"));

  get_config_string(lookup_config(config_tree, "Name"), &name);

  if(name)
    asprintf(&filename, "%s/hosts/%s", confbase, name);
  else
    asprintf(&filename, "%s/rsa_key.pub", confbase);

  if((f = ask_and_safe_open(filename, _("public RSA key"), "a")) == NULL)
    return -1;

  if(ftell(f))
    fprintf(stderr, _("Appending key to existing contents.\nMake sure only one key is stored in the file.\n"));

  PEM_write_RSAPublicKey(f, rsa_key);
  fclose(f);
  free(filename);

  asprintf(&filename, "%s/rsa_key.priv", confbase);
  if((f = ask_and_safe_open(filename, _("private RSA key"), "a")) == NULL)
    return -1;

  if(ftell(f))
    fprintf(stderr, _("Appending key to existing contents.\nMake sure only one key is stored in the file.\n"));

  PEM_write_RSAPrivateKey(f, rsa_key, NULL, NULL, 0, NULL, NULL);
  fclose(f);
  free(filename);

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
        asprintf(&pidfilename, LOCALSTATEDIR "/run/tinc.%s.pid", netname);
      if(!confbase)
        asprintf(&confbase, "%s/tinc/%s", CONFDIR, netname);
      else
        syslog(LOG_INFO, _("Both netname and configuration directory given, using the latter..."));
      if(!identname)
        asprintf(&identname, "tinc.%s", netname);
    }
  else
    {
      if(!pidfilename)
        pidfilename = LOCALSTATEDIR "/run/tinc.pid";
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

  environment = envp;
  parse_options(argc, argv, envp);

  if(show_version)
    {
      printf(_("%s version %s (built %s %s, protocol %d)\n"), PACKAGE, VERSION, __DATE__, __TIME__, PROT_CURRENT);
      printf(_("Copyright (C) 1998-2002 Ivo Timmermans, Guus Sliepen and others.\n"
               "See the AUTHORS file for a complete list.\n\n"
               "tinc comes with ABSOLUTELY NO WARRANTY.  This is free software,\n"
               "and you are welcome to redistribute it under certain conditions;\n"
               "see the file COPYING for details.\n"));

      return 0;
    }

  if(show_help)
    usage(0);

#ifdef HAVE_SOLARIS
  openlog("tinc", LOG_CONS, LOG_DAEMON);        /* Catch all syslog() calls issued before detaching */
#else
  openlog("tinc", LOG_PERROR, LOG_DAEMON);      /* Catch all syslog() calls issued before detaching */
#endif

  g_argv = argv;

  make_names();
  init_configuration(&config_tree);

  /* Slllluuuuuuurrrrp! */
cp
  RAND_load_file("/dev/urandom", 1024);

#ifdef HAVE_SSLEAY_ADD_ALL_ALGORITHMS
  SSLeay_add_all_algorithms();
#else
  OpenSSL_add_all_algorithms();
#endif

cp
  if(generate_keys)
    {
      read_server_config();
      exit(keygen(generate_keys));
    }

  if(kill_tincd)
    exit(kill_other(kill_tincd));

  if(read_server_config())
    exit(1);
cp
  if(detach())
    exit(0);
cp
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
          syslog(LOG_NOTICE, _("Restarting in %d seconds!"), maxtimeout);
          sleep(maxtimeout);
        }
      else
        {
          syslog(LOG_ERR, _("Not restarting."));
          exit(1);
        }
    }
}
