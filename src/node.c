/*
    node.c -- node tree management
    Copyright (C) 2001 Guus Sliepen <guus@sliepen.warande.net>,
                  2001 Ivo Timmermans <itimmermans@bigfoot.com>

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

    $Id: node.c,v 1.1.2.1 2001/10/10 08:49:47 guus Exp $
*/

avl_tree_t *node_tree;		/* Known nodes, sorted by name */

int node_compare(connection_t *a, connection_t *b)
{
  return strcmp(a->name, b->name);
}

void init_nodes(void)
{
cp
  node_tree = avl_alloc_tree((avl_compare_t)node_compare, NULL);
cp
}

void exit_nodes(void)
{
cp
  avl_delete_tree(node_tree);
cp
}

node_t *new_node(void)
{
  node_t *n = (node_t *)xmalloc_and_zero(sizeof(*n));
cp
  n->subnet_tree = avl_alloc_tree((avl_compare_t)subnet_compare, NULL);
  n->queue = list_alloc((list_action_t)free);
cp
  return n;
}

void free_node(node_t *n)
{
cp
  if(n->queue)
    list_delete_list(n->queue);
  if(n->name)
    free(n->name);
  if(n->hostname)
    free(n->hostname);
  if(n->key)
    free(n->key);
  if(n->config)
    clear_config(&n->config);
  free(n);
cp
}

node_t *lookup_node(char *name)
{
  node_t n;
cp
  n.name = name;
  return avl_search(node_tree, &n);
}


int read_host_config(nodet *n)
{
  char *fname;
  int x;
cp
  asprintf(&fname, "%s/hosts/%s", confbase, n->name);
  x = read_config_file(&n->config, fname);
  free(fname);
cp
  return x;
}

void dump_nodes(void)
{
  avl_node_t *node;
  node_t *n;
cp
  syslog(LOG_DEBUG, _("Nodes:"));

  for(node = node_tree->head; node; node = node->next)
    {
      n = (connection_t *)node->data;
      syslog(LOG_DEBUG, _(" %s at %s port %hd options %ld sockets %d, %d status %04x"),
             n->name, n->hostname, n->port, n->options,
             n->socket, n->meta_socket, n->status);
    }
    
  syslog(LOG_DEBUG, _("End of nodes."));
cp
}
