/*
    meta.c -- handle the meta communication
    Copyright (C) 2000,2001 Guus Sliepen <guus@sliepen.warande.net>,
                  2000,2001 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: meta.c,v 1.1.2.16 2001/03/12 23:58:19 guus Exp $
*/

#include "config.h"
#include <utils.h>
#include <avl_tree.h>

#include <errno.h>
#include <syslog.h>
#include <sys/signal.h>
#include <unistd.h>
#include <string.h>
/* This line must be below the rest for FreeBSD */
#include <sys/socket.h>

#ifdef HAVE_OPENSSL_EVP_H
# include <openssl/evp.h>
#else
# include <evp.h>
#endif

#include "net.h"
#include "connection.h"
#include "system.h"
#include "protocol.h"

int send_meta(connection_t *cl, char *buffer, int length)
{
  char outbuf[MAXBUFSIZE];
  char *bufp;
  int outlen;
cp
  if(debug_lvl >= DEBUG_META)
    syslog(LOG_DEBUG, _("Sending %d bytes of metadata to %s (%s): %s"), length,
           cl->name, cl->hostname, buffer);

  buffer[length-1]='\n';

  if(cl->status.encryptout)
    {
      EVP_EncryptUpdate(cl->cipher_outctx, outbuf, &outlen, buffer, length);
      bufp = outbuf;
      length = outlen;
    }
  else
      bufp = buffer;

  if(write(cl->meta_socket, bufp, length) < 0)
    {
      syslog(LOG_ERR, _("Sending meta data to %s (%s) failed: %m"), cl->name, cl->hostname);
      return -1;
    }
cp
  return 0;
}

void broadcast_meta(connection_t *cl, char *buffer, int length)
{
  avl_node_t *node;
  connection_t *p;
cp
  for(node = connection_tree->head; node; node = node->next)
    {
      p = (connection_t *)node->data;
      if(p != cl && p->status.meta && p->status.active)
        send_meta(p, buffer, length);
    }
cp
}

int receive_meta(connection_t *cl)
{
  int x, l = sizeof(x);
  int oldlen, i;
  int lenin = 0;
  char inbuf[MAXBUFSIZE];
  char *bufp;
  int decrypted = 0;
cp
  if(getsockopt(cl->meta_socket, SOL_SOCKET, SO_ERROR, &x, &l) < 0)
    {
      syslog(LOG_ERR, _("This is a bug: %s:%d: %d:%m %s (%s)"), __FILE__, __LINE__, cl->meta_socket,
             cl->name, cl->hostname);
      return -1;
    }
  if(x)
    {
      syslog(LOG_ERR, _("Metadata socket error for %s (%s): %s"),
             cl->name, cl->hostname, strerror(x));
      return -1;
    }

  lenin = read(cl->meta_socket, cl->buffer + cl->buflen, MAXBUFSIZE - cl->buflen);

  if(lenin<=0)
    {
      if(lenin==0)
        {
          if(debug_lvl >= DEBUG_CONNECTIONS)
            syslog(LOG_NOTICE, _("Connection closed by %s (%s)"),
                cl->name, cl->hostname);
        }
      else
        if(errno==EINTR)
          return 0;      
        else
          syslog(LOG_ERR, _("Metadata socket read error for %s (%s): %m"),
                 cl->name, cl->hostname);

      return -1;
    }

  oldlen = cl->buflen;
  cl->buflen += lenin;

  while(lenin)
    {
      if(cl->status.decryptin && !decrypted)
        {
          EVP_DecryptUpdate(cl->cipher_inctx, inbuf, &lenin, cl->buffer + oldlen, lenin);
          memcpy(cl->buffer + oldlen, inbuf, lenin);
          decrypted = 1;
        }

      cl->reqlen = 0;

      for(i = oldlen; i < cl->buflen; i++)
        {
          if(cl->buffer[i] == '\n')
            {
              cl->buffer[i] = 0;  /* replace end-of-line by end-of-string so we can use sscanf */
              cl->reqlen = i + 1;
              break;
            }
        }

      if(cl->reqlen)
        {
          if(debug_lvl >= DEBUG_META)
            syslog(LOG_DEBUG, _("Got request from %s (%s): %s"),
	           cl->name, cl->hostname, cl->buffer);

          if(receive_request(cl))
            return -1;

          cl->buflen -= cl->reqlen;
          lenin -= cl->reqlen;
          memmove(cl->buffer, cl->buffer + cl->reqlen, cl->buflen);
          oldlen = 0;
        }
      else
        {
          break;
        }
    }

  if(cl->buflen >= MAXBUFSIZE)
    {
      syslog(LOG_ERR, _("Metadata read buffer overflow for %s (%s)"),
	     cl->name, cl->hostname);
      return -1;
    }

  cl->last_ping_time = time(NULL);
cp  
  return 0;
}
