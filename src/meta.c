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

    $Id: meta.c,v 1.1.2.19 2001/07/04 08:41:36 guus Exp $
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

#include <openssl/evp.h>

#include "net.h"
#include "connection.h"
#include "system.h"
#include "protocol.h"

int send_meta(connection_t *cl, char *buffer, int length)
{
  char *bufp;
  int outlen;
  char outbuf[MAXBUFSIZE];
cp
  if(debug_lvl >= DEBUG_META)
    syslog(LOG_DEBUG, _("Sending %d bytes of metadata to %s (%s)"), length,
           cl->name, cl->hostname);

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
  int lenin, reqlen;
  int decrypted = 0;
  char inbuf[MAXBUFSIZE];
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

  /* Strategy:
     - Read as much as possible from the TCP socket in one go.
     - Decrypt it.
     - Check if a full request is in the input buffer.
       - If yes, process request and remove it from the buffer,
         then check again.
       - If not, keep stuff in buffer and exit.
   */

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
      /* Decrypt */

      if(cl->status.decryptin && !decrypted)
        {
          EVP_DecryptUpdate(cl->cipher_inctx, inbuf, &lenin, cl->buffer + oldlen, lenin);
          memcpy(cl->buffer + oldlen, inbuf, lenin);
          decrypted = 1;
        }

      /* Are we receiving a TCPpacket? */

      if(cl->tcplen)
        {
          if(cl->tcplen <= cl->buflen)
            {
              receive_tcppacket(cl, cl->buffer, cl->tcplen);

              cl->buflen -= cl->tcplen;
              lenin -= cl->tcplen;
              memmove(cl->buffer, cl->buffer + cl->tcplen, cl->buflen);
              oldlen = 0;
              cl->tcplen = 0;
              continue;
            }
          else
            {
              break;
            }
        }

      /* Otherwise we are waiting for a request */

      reqlen = 0;

      for(i = oldlen; i < cl->buflen; i++)
        {
          if(cl->buffer[i] == '\n')
            {
              cl->buffer[i] = '\0';  /* replace end-of-line by end-of-string so we can use sscanf */
              reqlen = i + 1;
              break;
            }
        }

      if(reqlen)
        {
          if(receive_request(cl))
            return -1;

          cl->buflen -= reqlen;
          lenin -= reqlen;
          memmove(cl->buffer, cl->buffer + reqlen, cl->buflen);
          oldlen = 0;
          continue;
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
