/*
    meta.c -- handle the meta communication
    Copyright (C) 2000 Guus Sliepen <guus@sliepen.warande.net>,
                  2000 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: meta.c,v 1.1.2.1 2000/09/26 14:06:03 guus Exp $
*/

#include "config.h"

int send_meta(conn_list_t *cl, const char *buffer, int length)
{
  char outbuf[MAXBUFSIZE];
  char *bufp;
cp
  if(debug_lvl >= DEBUG_META)
    syslog(LOG_DEBUG, _("Sending %d bytes of metadata to %s (%s): %s"), int length,
           cl->name, cl->hostname, buffer);

  if(cl->status.encryptout)
    {
      if(EVP_EncryptUpdate(cl->cipher_outctx, cl->buffer + cl->buflen, NULL, inbuf, length) != 1)
        {
          syslog(LOG_ERR, _("Error during encryption of outgoing metadata to %s (%s)"), cl->name, cl->hostname);
          return -1;
        }
      bufp = outbuf;
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

int broadcast_meta(conn_list_t *cl, const char *buffer, int length)
{
  conn_list_t *p;
cp
  for(p = conn_list; p != NULL; p = p->next)
    if(p != cl && p->status.meta && p->status.active)
      send_meta(p, buffer, length);
cp
  return 0;
}

int receive_meta(conn_list_t *cl)
{
  int x, l = sizeof(x);
  int oldlen, i;
  int lenin = 0;
  char inbuf[MAXBUFSIZE];
  char *bufp;
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

  if(cl->status.encryptin)
    bufp = inbuf;
  else
    bufp = cl->buffer + cl->buflen;

  lenin = read(cl->meta_socket, bufp, MAXBUFSIZE - cl->buflen);

  if(lenin<=0)
    {
      if(errno==EINTR)
        return 0;      
      if(errno==0)
        {
          if(debug_lvl>DEBUG_CONNECTIONS)
            syslog(LOG_NOTICE, _("Connection closed by %s (%s)"),
                cl->name, cl->hostname);
        }
      else
        syslog(LOG_ERR, _("Metadata socket read error for %s (%s): %m"),
               cl->name, cl->hostname);
      return -1;
    }

  if(cl->status.decryptin)
    {
      if(EVP_DecryptUpdate(cl->cipher_inctx, cl->buffer + cl->buflen, NULL, inbuf, lenin) != 1)
        {
          syslog(LOG_ERR, _("Error during decryption of incoming metadata from %s (%s)"), cl->name, cl->hostname);
          return -1;
        }
    }
    
  oldlen = cl->buflen;
  cl->buflen += lenin;

  for(;;)
    {
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
          if(debug_lvl > DEBUG_META)
            syslog(LOG_DEBUG, _("Got request from %s (%s): %s"),
	           cl->name, cl->hostname, cl->buffer);

          if(receive_request(cl))
            return -1;

          cl->buflen -= cl->reqlen;
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
  cl->want_ping = 0;
cp  
  return 0;
}
