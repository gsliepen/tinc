/*
    meta.c -- handle the meta communication
    Copyright (C) 2000-2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2000-2002 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: meta.c,v 1.1.2.25 2002/03/01 14:09:31 guus Exp $
*/

#include "config.h"
#include <utils.h>
#include <avl_tree.h>

#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
/* This line must be below the rest for FreeBSD */
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/evp.h>

#include "net.h"
#include "connection.h"
#include "system.h"
#include "protocol.h"

int send_meta(connection_t *c, char *buffer, int length)
{
  char *bufp;
  int outlen;
  char outbuf[MAXBUFSIZE];
cp
  if(debug_lvl >= DEBUG_META)
    syslog(LOG_DEBUG, _("Sending %d bytes of metadata to %s (%s)"), length,
           c->name, c->hostname);

  if(c->status.encryptout)
    {
      EVP_EncryptUpdate(c->outctx, outbuf, &outlen, buffer, length);
      bufp = outbuf;
      length = outlen;
    }
  else
      bufp = buffer;

  if(write(c->socket, bufp, length) < 0)
    {
      syslog(LOG_ERR, _("Sending meta data to %s (%s) failed: %s"), c->name, c->hostname, strerror(errno));
      return -1;
    }
cp
  return 0;
}

void broadcast_meta(connection_t *from, char *buffer, int length)
{
  avl_node_t *node;
  connection_t *c;
cp
  for(node = connection_tree->head; node; node = node->next)
    {
      c = (connection_t *)node->data;
      if(c != from && c->status.active)
        send_meta(c, buffer, length);
    }
cp
}

int receive_meta(connection_t *c)
{
  int x, l = sizeof(x);
  int oldlen, i;
  int lenin, reqlen;
  int decrypted = 0;
  char inbuf[MAXBUFSIZE];
cp
  if(getsockopt(c->socket, SOL_SOCKET, SO_ERROR, &x, &l) < 0)
    {
      syslog(LOG_ERR, _("This is a bug: %s:%d: %d:%s %s (%s)"), __FILE__, __LINE__, c->socket, strerror(errno),
             c->name, c->hostname);
      return -1;
    }
  if(x)
    {
      syslog(LOG_ERR, _("Metadata socket error for %s (%s): %s"),
             c->name, c->hostname, strerror(x));
      return -1;
    }

  /* Strategy:
     - Read as much as possible from the TCP socket in one go.
     - Decrypt it.
     - Check if a full request is in the input buffer.
       - If yes, process request and remove it from the buffer,
         then check again.
       - If not, keep stuff in buffer and exit.
   */

  lenin = read(c->socket, c->buffer + c->buflen, MAXBUFSIZE - c->buflen);

  if(lenin<=0)
    {
      if(lenin==0)
        {
          if(debug_lvl >= DEBUG_CONNECTIONS)
            syslog(LOG_NOTICE, _("Connection closed by %s (%s)"),
                c->name, c->hostname);
        }
      else
        if(errno==EINTR)
          return 0;      
        else
          syslog(LOG_ERR, _("Metadata socket read error for %s (%s): %s"),
                 c->name, c->hostname, strerror(errno));

      return -1;
    }

  oldlen = c->buflen;
  c->buflen += lenin;

  while(lenin)
    {
      /* Decrypt */

      if(c->status.decryptin && !decrypted)
        {
          EVP_DecryptUpdate(c->inctx, inbuf, &lenin, c->buffer + oldlen, lenin);
          memcpy(c->buffer + oldlen, inbuf, lenin);
          decrypted = 1;
        }

      /* Are we receiving a TCPpacket? */

      if(c->tcplen)
        {
          if(c->tcplen <= c->buflen)
            {
              receive_tcppacket(c, c->buffer, c->tcplen);

              c->buflen -= c->tcplen;
              lenin -= c->tcplen;
              memmove(c->buffer, c->buffer + c->tcplen, c->buflen);
              oldlen = 0;
              c->tcplen = 0;
              continue;
            }
          else
            {
              break;
            }
        }

      /* Otherwise we are waiting for a request */

      reqlen = 0;

      for(i = oldlen; i < c->buflen; i++)
        {
          if(c->buffer[i] == '\n')
            {
              c->buffer[i] = '\0';  /* replace end-of-line by end-of-string so we can use sscanf */
              reqlen = i + 1;
              break;
            }
        }

      if(reqlen)
        {
          if(receive_request(c))
            return -1;

          c->buflen -= reqlen;
          lenin -= reqlen;
          memmove(c->buffer, c->buffer + reqlen, c->buflen);
          oldlen = 0;
          continue;
        }
      else
        {
          break;
        }
    }

  if(c->buflen >= MAXBUFSIZE)
    {
      syslog(LOG_ERR, _("Metadata read buffer overflow for %s (%s)"),
	     c->name, c->hostname);
      return -1;
    }

  c->last_ping_time = now;
cp  
  return 0;
}
