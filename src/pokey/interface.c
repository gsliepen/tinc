/*
    interface.c -- GTK+/GNOME interface functions
    Copyright (C) 2002 Guus Sliepen <guus@sliepen.warande.net>,
                  2002 Ivo Timmermans <ivo@o2w.nl>

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

    $Id: interface.c,v 1.5 2002/05/02 11:50:07 zarq Exp $
*/

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#define log mathlog
#include <math.h>
#undef log

#include <gtk/gtk.h>
#include <glade/glade.h>
#include <libgnomeui/gnome-canvas.h>
#include <libgnomeui/gnome-canvas-rect-ellipse.h>
#include <libgnomeui/gnome-canvas-text.h>
#include <libgnomeui/gnome-canvas-line.h>
#include <libgnomeui/gnome-canvas-util.h>

#include "node.h"
#include "connection.h"
#include "edge.h"
#include "interface.h"
#include "logging.h"

#include <hooks.h>
#include <xalloc.h>

#include "system.h"

/* Node tree & main window stuff */
static GladeXML *xml;
static GtkWidget *nodetree;
static GtkCTreeNode *hosts_ctn;


/* Graph canvas stuff */
static GladeXML *canvas_xml;

static GnomeCanvasGroup *edge_group = NULL;

static int canvas_width;
static int canvas_height;

static GtkWidget *canvas = NULL;

static int canvas_visible = 0;

int build_graph = 0;

static GdkColormap *colormap = NULL;
static GdkColor timecolor;

#define MAX_NODES 25
#define K 10.0

#ifdef INFINITY
#undef INFINITY
#endif
#define INFINITY 1.0e10

node_t *nodes[MAX_NODES];
double x[MAX_NODES];
double y[MAX_NODES];
double k[MAX_NODES][MAX_NODES];
double d[MAX_NODES][MAX_NODES];
double l[MAX_NODES][MAX_NODES];
static const double epsilon = 0.001;

static int inited = 0;

static int number_of_nodes = 0;

static double canvas_zoom = 1.00;


/* Log window stuff */
#ifdef MAXBUFSIZE
#undef MAXBUFSIZE
#endif

#define MAXBUFSIZE 1024

static int log_inited = 0;
static int follow_log = 1;

static int keep_drawing = 1;

static int log_visible = 0;
static GtkWidget *log_window = NULL;


void if_node_add(const char *hooktype, va_list ap);
void if_node_del(const char *hooktype, va_list ap);
void if_subnet_add(const char *hooktype, va_list ap);
void if_subnet_del(const char *hooktype, va_list ap);
void if_edge_add(const char *hooktype, va_list ap);
void if_edge_del(const char *hooktype, va_list ap);
void if_node_visible(const char *hooktype, va_list ap);
void if_node_invisible(const char *hooktype, va_list ap);

void if_node_create(node_t *n);

GtkWidget *create_canvas(void)
{
  canvas_xml = glade_xml_new(INTERFACE_FILE, "GraphWindow");
  if(!canvas_xml)
    {
      log(0, TLOG_ERROR,
	  _("Could not find widget `%s'"),
	  "GraphWindow");
      return NULL;
    }
  
  canvas = glade_xml_get_widget(xml, "canvas1");
  if(!canvas)
    {
      fprintf(stderr, "Could not find widget `canvas1'\n");
      return NULL;
    }
  
  gnome_canvas_set_scroll_region(GNOME_CANVAS(canvas), 0.0, 0.0, 700, 500);

  canvas_width = 300.0;
  canvas_height = 500.0;

  return canvas;
}

void log_gtk(int level, int priority, char *fmt, va_list ap)
{
  char buffer1[MAXBUFSIZE];
  char buffer2[MAXBUFSIZE];
  int len;
  char *p;
  struct tm *tm;
  time_t t;

  if(!log_visible)
    return;

  /* Use vsnprintf instead of vasprintf: faster, no memory
     fragmentation, cleanup is automatic, and there is a limit on the
     input buffer anyway */
  len = vsnprintf(buffer1, MAXBUFSIZE, fmt, ap);

  buffer1[MAXBUFSIZE-1] = '\0';
  if((p = strrchr(buffer1, '\n')))
    *p = '\0';

  t = time(NULL);
  tm = localtime(&t);
  snprintf(buffer2, MAXBUFSIZE, "%02d:%02d:%02d ",
	   tm->tm_hour, tm->tm_min, tm->tm_sec);

  if(!colormap)
    {
      colormap = gdk_colormap_new(gdk_visual_get_system(), FALSE);
      timecolor.red = 0xffff;
      timecolor.green = 0;
      timecolor.blue = 0;
      if(gdk_colormap_alloc_color(colormap, &timecolor, FALSE, TRUE) != TRUE)
	{
	  fprintf(stderr, "Failed to allocate color\n");
	  exit(1);
	}
    }
  
  gtk_text_freeze(GTK_TEXT(log_window));

  if(log_inited)
    gtk_text_insert(GTK_TEXT(log_window), NULL, NULL, NULL, "\n", 1);

  gtk_text_insert(GTK_TEXT(log_window), NULL, &timecolor, NULL, buffer2, strlen(buffer2));
  gtk_text_insert(GTK_TEXT(log_window), NULL, NULL, NULL, buffer1, len);
  gtk_text_thaw(GTK_TEXT(log_window));

  log_inited = 1;
  if(follow_log)
/*     gtk_text_set_point(GTK_TEXT(w), -1); */
    gtk_editable_set_position(GTK_EDITABLE(log_window), gtk_text_get_length(GTK_TEXT(log_window)));
}

void if_hostinfoclosebutton_clicked(GtkWidget *w, gpointer data)
{
  gtk_widget_destroy(GTK_WIDGET(data));
}

void update_hostinfo_dialog(GladeXML *x, node_t *n)
{
  GtkWidget *w;
  char s[100];
  avl_node_t *avlnode;
  char *l[1];

  w = glade_xml_get_widget(x, "HostInfoNameEntry");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoNameEntry"); return; }
  gtk_entry_set_text(GTK_ENTRY(w), n->name);

  w = glade_xml_get_widget(x, "HostInfoHostnameEntry");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoHostnameEntry"); return; }
  gtk_entry_set_text(GTK_ENTRY(w), n->hostname);

  w = glade_xml_get_widget(x, "HostInfoPortEntry");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoPortEntry"); return; }
/*   snprintf(s, sizeof(s)-1, "%hd", "0"); */
  gtk_entry_set_text(GTK_ENTRY(w), "port");

  w = glade_xml_get_widget(x, "HostInfoVersionEntry");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoVersionEntry"); return; }
  gtk_entry_set_text(GTK_ENTRY(w), n->name);

  w = glade_xml_get_widget(x, "HostInfoStatusEntry");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoStatusEntry"); return; }
/*   snprintf(s, sizeof(s)-1, "%x", n->status); */
  gtk_entry_set_text(GTK_ENTRY(w), "0");

  w = glade_xml_get_widget(x, "HostInfoActiveCheckbutton");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoActiveCheckbutton"); return; }
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), n->status.active);

  w = glade_xml_get_widget(x, "HostInfoValidkeyCheckbutton");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoValidkeyCheckbutton"); return; }
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), n->status.validkey);

  w = glade_xml_get_widget(x, "HostInfoWaitingforkeyCheckbutton");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoWaitingforkeyCheckbutton"); return; }
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), n->status.waitingforkey);

  w = glade_xml_get_widget(x, "HostInfoVisitedCheckbutton");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoVisitedCheckbutton"); return; }
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), n->status.visited);

  w = glade_xml_get_widget(x, "HostInfoReachableCheckbutton");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoReachableCheckbutton"); return; }
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), n->status.reachable);

  w = glade_xml_get_widget(x, "HostInfoIndirectCheckbutton");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoIndirectCheckbutton"); return; }
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), n->status.indirect);

  w = glade_xml_get_widget(x, "HostInfoVisibleCheckbutton");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoVisibleCheckbutton"); return; }
/*   gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), n->status.visible); */

  w = glade_xml_get_widget(x, "HostInfoTCPOnlyCheckbutton");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoTCPOnlyCheckbutton"); return; }
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), (n->options & OPTION_TCPONLY) != 0);

  w = glade_xml_get_widget(x, "HostInfoIndirectdataCheckbutton");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoIndirectdataCheckbutton"); return; }
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), (n->options & OPTION_INDIRECT) != 0);

/*   w = glade_xml_get_widget(x, "HostInfoWindow"); */
/*   if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostInfoWindow"); return; } */
/*   glade_xml_signal_connect_data(x, "on_HostInfoCloseButton_clicked", if_hostinfoclosebutton_clicked, (gpointer)w); */
  w = glade_xml_get_widget(x, "HostConnectionsCList");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "HostConnectionsCList"); return; }
  for(avlnode = n->edge_tree->head; avlnode; avlnode = avlnode->next)
    {
      if(((edge_t*)(avlnode->data))->to.node == n)
	l[0] = ((edge_t*)(avlnode->data))->from.node->name;
      else
	l[0] = ((edge_t*)(avlnode->data))->to.node->name;
      gtk_clist_append(GTK_CLIST(w), l);
    }
}

void on_preferences1_activate(GtkMenuItem *mi, gpointer data)
{
  GtkWidget *w;
  GladeXML *x;
  
  x = glade_xml_new(INTERFACE_FILE, "PropertyBox");
  if(x == NULL)
    {
      log(0, TLOG_ERROR,
	  _("Could not find widget `%s'"),
	  "PropertyBox");
      return;
    }
  
  w = glade_xml_get_widget(x, "PropertyBox");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "PropertyBox"); return; }
  glade_xml_signal_autoconnect(x);
}

void on_logcontext_clear_activate(GtkMenuItem *mi, gpointer data)
{
  gtk_editable_delete_text(GTK_EDITABLE(log_window), 0, -1); /* Delete from 0 to end of buffer */
  log_inited = 0;
}

void on_logcontext_follow_activate(GtkMenuItem *mi, gpointer data)
{
  follow_log = !follow_log;
}

void on_logcontext_close1_activate(GtkMenuItem *mi, gpointer data)
{
  
}

void on_messages_button_press_event(GtkWidget *w, GdkEventButton *event, gpointer data)
{
  GladeXML *x;
  GtkWidget *menu;
  
  if (event->button == 3)
    {
      x = glade_xml_new(INTERFACE_FILE, "LogContextMenu");
      if(x == NULL)
	{
	  log(0, TLOG_ERROR,
	      _("Could not find widget `%s'"),
	      "LogContextMenu");
	  return;
	}

      menu = glade_xml_get_widget(x, "LogContextMenu");
      if(!menu) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "LogContextMenu"); return; }
      
      glade_xml_signal_connect_data(x, "on_logcontext_clear_activate", on_logcontext_clear_activate, (gpointer)x);
      glade_xml_signal_connect_data(x, "on_logcontext_follow_activate", on_logcontext_follow_activate, (gpointer)x);
      w = glade_xml_get_widget(x, "LogContextFollow");
      if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "LogContextFollow"); return; }
      GTK_CHECK_MENU_ITEM(w)->active = follow_log;
      gnome_popup_menu_do_popup_modal(menu, NULL, NULL, event, NULL);
      gtk_widget_destroy(menu);
    }
}

void shuffle_nodes(void)
{
  avl_node_t *avlnode;
  double newx, newy;
  
  for(avlnode = node_tree->head; avlnode; avlnode = avlnode->next)
    {
      newx = ((double)random()) / ((double)RAND_MAX) * 500.0;
      newy = ((double)random()) / ((double)RAND_MAX) * 300.0;
      ((struct if_node_data*)((node_t *)(avlnode->data))->data)->x = newx;
      ((struct if_node_data*)((node_t *)(avlnode->data))->data)->y = newy;

      if(!((struct if_node_data*)((node_t*)(avlnode->data)))->visible)
	continue;
      
      x[((struct if_node_data*)((node_t*)(avlnode->data))->data)->id] = newx;
      y[((struct if_node_data*)((node_t*)(avlnode->data))->data)->id] = newy;
    }
  inited = 0;
  build_graph = 1;
}

void on_canvascontext_shuffle_activate(GtkMenuItem *mi, gpointer data)
{
  shuffle_nodes();
}

void on_canvascontext_keep_drawing_activate(GtkMenuItem *mi, gpointer data)
{
  GtkWidget *w;
  
  keep_drawing = !keep_drawing;

  /* No need to fuss with the checkbox in the menu, because that is
     transient.  Do need to update the checkbox at the bottom of the
     window though. */
  w = glade_xml_get_widget(canvas_xml, "KeepDrawingButton");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "KeepDrawingButton"); return; }
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), keep_drawing);
}

void on_canvascontext_minus50_activate(GtkMenuItem *mi, gpointer data)
{
  canvas_zoom *= 0.50;
  gnome_canvas_set_pixels_per_unit(GNOME_CANVAS(canvas), canvas_zoom);
}

void on_canvascontext_minus25_activate(GtkMenuItem *mi, gpointer data)
{
  canvas_zoom *= 0.75;
  gnome_canvas_set_pixels_per_unit(GNOME_CANVAS(canvas), canvas_zoom);
}

void on_canvascontext_minus10_activate(GtkMenuItem *mi, gpointer data)
{
  canvas_zoom *= 0.90;
  gnome_canvas_set_pixels_per_unit(GNOME_CANVAS(canvas), canvas_zoom);
}

void on_canvascontext_default_activate(GtkMenuItem *mi, gpointer data)
{
  canvas_zoom = 1.00;
  gnome_canvas_set_pixels_per_unit(GNOME_CANVAS(canvas), 1.00);
}

void on_canvascontext_plus10_activate(GtkMenuItem *mi, gpointer data)
{
  canvas_zoom *= 1.10;
  gnome_canvas_set_pixels_per_unit(GNOME_CANVAS(canvas), canvas_zoom);
}

void on_canvascontext_plus25_activate(GtkMenuItem *mi, gpointer data)
{
  canvas_zoom *= 1.25;
  gnome_canvas_set_pixels_per_unit(GNOME_CANVAS(canvas), canvas_zoom);
}

void on_canvascontext_plus50_activate(GtkMenuItem *mi, gpointer data)
{
  canvas_zoom *= 1.50;
  gnome_canvas_set_pixels_per_unit(GNOME_CANVAS(canvas), canvas_zoom);
}

void on_canvas_button_press_event(GtkWidget *w, GdkEventButton *event, gpointer data)
{
  GladeXML *x;
  GtkWidget *menu;
  
  if (event->button == 3)
    {
      x = glade_xml_new(INTERFACE_FILE, "CanvasContextMenu");
      if(x == NULL)
	{
	  log(0, TLOG_ERROR,
	      _("Could not find widget `%s'"),
	      "CanvasContextMenu");
	  return;
	}

      menu = glade_xml_get_widget(x, "CanvasContextMenu");
      if(!menu) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "CanvasContextMenu"); return; }
      
      glade_xml_signal_autoconnect(x);
      glade_xml_signal_connect_data(x, "on_canvascontext_shuffle_activate", on_canvascontext_shuffle_activate, (gpointer)x);
      glade_xml_signal_connect_data(x, "on_canvascontext_keep_drawing_activate", on_canvascontext_keep_drawing_activate, (gpointer)x);
      w = glade_xml_get_widget(x, "CanvasContextKeepDrawing");
      if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "CanvasContextKeepDrawing"); return; }
      GTK_CHECK_MENU_ITEM(w)->active = keep_drawing;
      gnome_popup_menu_do_popup_modal(menu, NULL, NULL, event, NULL);
      gtk_widget_destroy(menu);
    }
}

void on_nodetree_button_press_event(GtkWidget *w, GdkEventButton *event, gpointer data)
{
  GtkCTreeNode *node;
  int row, col;
  gpointer lt;
  GladeXML *x;
  
  gtk_clist_get_selection_info(GTK_CLIST(w), event->x, event->y,
                               &row, &col);

  node = gtk_ctree_node_nth(GTK_CTREE(w), row);
  if(node == NULL)
    return;
  lt = gtk_ctree_node_get_row_data(GTK_CTREE(w), node);
  if(event->type == GDK_2BUTTON_PRESS && event->button == 1)
    {
      /* Double left click on an item */
      if(lt == NULL)
        /* this is only a branch, double click wil (un)expand. */
        return;

      if(GTK_CTREE_ROW(node)->parent == hosts_ctn)
	{
	  x = ((struct if_node_data*)(((node_t*)lt)->data))->hi_xml = glade_xml_new(INTERFACE_FILE, "HostInfoWindow");
	  if(x == NULL)
	    {
	      log(0, TLOG_ERROR,
		  _("Could not find widget `%s'"),
		  "HostInfoWindow");
	      return;
	    }
	  glade_xml_signal_autoconnect(x);
	  update_hostinfo_dialog(x, (node_t*)lt);
	}
      else
	{
	  log(0, TLOG_ERROR,
	      "WHERE did you click?!");
	}
      /* so now we have access to all the data we want. */
/*       gldap_show_details(lt); */
      return;
    }
/*   else */
/*     if (event->button == 3) */
/*       { */
/*         GtkWidget *temp_menu; */
/*         temp_menu = gnome_popup_menu_new(data); */
/*         gnome_popup_menu_do_popup_modal(temp_menu, NULL, NULL, event, NULL); */
/*         gtk_widget_destroy(temp_menu); */
/*       } */
}

void on_exit1_activate(GtkMenuItem *mi, gpointer data)
{
  close_network_connections();
  gtk_exit(0);
}

void on_about1_activate(GtkMenuItem *mi, gpointer data)
{
  GladeXML *x;
  x = glade_xml_new(INTERFACE_FILE, "AboutWindow");
  if(x == NULL)
    {
      log(0, TLOG_ERROR,
	  _("Could not find widget `%s'"),
	  "AboutWindow");
      return;
    }
  glade_xml_signal_autoconnect(x);
}

void on_graph_window1_activate(GtkMenuItem *mi, gpointer data)
{
  int i;
  avl_node_t *avlnode;
  double newx, newy;
  
  canvas_xml = glade_xml_new(INTERFACE_FILE, "GraphWindow");
  if(canvas_xml == NULL)
    {
      log(0, TLOG_ERROR,
	  _("Could not find widget `%s'"),
	  "GraphWindow");
      return;
    }
  glade_xml_signal_autoconnect(canvas_xml);
  canvas = glade_xml_get_widget(canvas_xml, "canvas1");
  if(canvas == NULL) { log(0, TLOG_ERROR, _("Could not find widget `%s'"), "canvas1"); return; }

  for(i = 0, avlnode = node_tree->head; avlnode; avlnode = avlnode->next)
    {
      node_t *n = (node_t*)(avlnode->data);
      
      if(!((struct if_node_data*)(n->data))->item)
	if_node_create(n);

      if(!n->status.reachable)
	continue;
      
      newx = 250.0 + 200.0 * sin(i / 10.0 * M_PI);
      newy = 150.0 - 100.0 * cos(i / 10.0 * M_PI);
      gnome_canvas_item_move(GNOME_CANVAS_ITEM(((struct if_node_data*)(n->data))->item), newx - ((struct if_node_data*)(n->data))->x, newy - ((struct if_node_data*)(n->data))->y);
      ((struct if_node_data*)(n->data))->x = newx;
      ((struct if_node_data*)(n->data))->y = newy;
      
      ((struct if_node_data*)(n->data))->id = i;

      gnome_canvas_item_show(GNOME_CANVAS_ITEM(((struct if_node_data*)(n->data))->item));
      gnome_canvas_update_now(GNOME_CANVAS(canvas));
      nodes[i] = n;
      i++;
    }

  number_of_nodes = i;
  
  inited = 0;
  build_graph = 1;
  canvas_visible = 1;
}

void on_log_window1_activate(GtkMenuItem *mi, gpointer data)
{
  GladeXML *x;
  GtkWidget *w;

  x = glade_xml_new(INTERFACE_FILE, "LogWindow");
  if(x == NULL)
    {
      log(0, TLOG_ERROR,
	  _("Could not find widget `%s'"),
	  "LogWindow");
      return;
    }
  log_window = glade_xml_get_widget(x, "Messages");
  if(!log_window)
    {
      log(0, TLOG_ERROR,
	  _("Could not find widget `%s'"),
	  "Messages");
      return;
    }
  w = glade_xml_get_widget(x, "DebugLevelSpinbutton");
  if(!w)
    {
      log(0, TLOG_ERROR,
	  _("Could not find widget `%s'"),
	  "DebugLevelSpinbutton");
      return;
    }
  gtk_spin_button_set_value(GTK_SPIN_BUTTON(w), (float)debug_lvl);
  
  glade_xml_signal_autoconnect(x);
  log_visible = 1;
  log_add_hook(log_gtk);
  log(0, TLOG_NOTICE, "Logging started.\n");

}

void on_debug_level_changed(GtkSpinButton *sb, gpointer data)
{
  debug_lvl = gtk_spin_button_get_value_as_int(sb);
}

void on_logwindow_close_clicked(GtkButton *b, gpointer data)
{
  GladeXML *x;
  GtkWidget *w;

  x = glade_xml_new(INTERFACE_FILE, "LogWindow");
  if(x == NULL)
    {
      log(0, TLOG_ERROR,
	  _("Could not find widget `%s'"),
	  "LogWindow");
      return;
    }
  w = glade_xml_get_widget(x, "LogWindow");
  if(!w)
    {
      log(0, TLOG_ERROR,
	  _("Could not find widget `%s'"),
	  "LogWindow");
      return;
    }
  gtk_widget_destroy(w);
}

void on_spinbutton2_changed(GtkSpinButton *sb, gpointer data)
{
  canvas_zoom = gtk_spin_button_get_value_as_float(sb) / 100.0;
  gnome_canvas_set_pixels_per_unit(GNOME_CANVAS(canvas), canvas_zoom);
}

void on_checkbutton1_toggled(GtkCheckButton *cb, gpointer data)
{
  keep_drawing = !keep_drawing;
}

void on_button19_clicked(GtkWidget *bt, GdkEventButton *ev, gpointer data)
{
  shuffle_nodes();
}

void on_button18_clicked(GtkWidget *bt, GdkEventButton *ev, gpointer data)
{
  GtkWidget *w;

  w = glade_xml_get_widget(canvas_xml, "GraphWindow");
  if(!w) { log(0, TLOG_ERROR, _("Couldn't find widget `%s'"), "GraphWindow"); return; }
  gtk_object_destroy(GTK_OBJECT(w));
  build_graph = 0;
  canvas_visible = 0;
}

int init_interface(void)
{
  char *l[1];

  glade_gnome_init();

  xml = glade_xml_new("pokey.glade", "AppWindow");

  if(!xml)
    {
      log(0, TLOG_ERROR,
	  _("Something bad happened while creating the interface.\n"));
      return -1;
    }

  nodetree = glade_xml_get_widget(xml, "NodeTree");
  if(!nodetree)
    {
      log(0, TLOG_ERROR,
	  _("Could not find widget `%s'"),
	  "NodeTree");
      return -1;
    }

  gtk_clist_freeze(GTK_CLIST(nodetree));
  l[0] = _("Hosts");
  hosts_ctn = gtk_ctree_insert_node(GTK_CTREE(nodetree),
			      NULL, NULL, l, 1,
			      NULL, NULL, NULL, NULL,
			      FALSE, TRUE);
  gtk_clist_thaw(GTK_CLIST(nodetree));

  glade_xml_signal_autoconnect(xml);

  log_del_hook(log_default);

  add_hook("node-add", if_node_add);
  add_hook("node-del", if_node_del);
  add_hook("subnet-add", if_subnet_add);
  add_hook("subnet-del", if_subnet_del);
  add_hook("edge-add", if_edge_add);
  add_hook("edge-del", if_edge_del);
  add_hook("node-visible", if_node_visible);
  add_hook("node-invisible", if_node_invisible);
  
  return 0;
}

static gint item_event(GnomeCanvasItem *item, GdkEvent *event, gpointer data)
{
  static double item_x, old_x, new_x, item_y, old_y, new_y;
  static int dragging = FALSE;
  GdkCursor *fleur;
  node_t *n;
  
  item_x = event->button.x;
  item_y = event->button.y;
  gnome_canvas_item_w2i(item->parent, &item_x, &item_y);
  
  switch(event->type)
    {
    case GDK_BUTTON_PRESS:
      switch(event->button.button)
	{
	case 1:
	  old_x = item_x;
	  old_y = item_y;

	  fleur = gdk_cursor_new(GDK_FLEUR);
	  gnome_canvas_item_grab(item, GDK_POINTER_MOTION_MASK | GDK_BUTTON_RELEASE_MASK, fleur, event->button.time);
	  gdk_cursor_destroy(fleur);
	  dragging = TRUE;
	  break;

	default:
	  break;
	}
      break;

    case GDK_MOTION_NOTIFY:
      if(dragging && (event->motion.state & GDK_BUTTON1_MASK))
	{
	  new_x = item_x,
	  new_y = item_y;
	  gnome_canvas_item_move(item, new_x - old_x, new_y - old_y);
	  old_x = new_x;
	  old_y = new_y;
	}
      break;
      
    case GDK_BUTTON_RELEASE:
      gnome_canvas_item_ungrab(item, event->button.time);
      dragging = FALSE;
      n = (node_t *)gtk_object_get_user_data(GTK_OBJECT(item));
      ((struct if_node_data*)(n->data))->x = item_x;
      ((struct if_node_data*)(n->data))->y = item_y;
      x[((struct if_node_data*)(n->data))->id] = item_x;
      y[((struct if_node_data*)(n->data))->id] = item_y;
      build_graph = 1;
      break;

    default:
      break;
    }
  return FALSE;
}

void if_node_create(node_t *n)
{
  GnomeCanvasGroup *group;
  
  group = gnome_canvas_root(GNOME_CANVAS(canvas));
  group = GNOME_CANVAS_GROUP(gnome_canvas_item_new(group,
						   gnome_canvas_group_get_type(),
						   "x", 0.0,
						   "y", 0.0,
						   NULL));
  
  gnome_canvas_item_new(group, gnome_canvas_ellipse_get_type(),
			"x1", -30.0,
			"y1", -08.0,
			"x2", 30.0,
			"y2", 08.0,
			"fill_color_rgba", 0x5f9ea080,
			"outline_color", "black",
			"width_pixels", 0,
			NULL);
  
  gnome_canvas_item_new(group,
			gnome_canvas_text_get_type(),
			"x", 0.0,
			"y", 0.0,
			"text", n->name,
			"anchor", GTK_ANCHOR_CENTER,
			"fill_color", "white",
			"font", "-*-verdana-medium-r-*-*-10-*-*-*-*-*-iso8859-1",
			NULL);
  
  ((struct if_node_data*)(n->data))->item = GNOME_CANVAS_ITEM(group);
  ((struct if_node_data*)(n->data))->x = ((struct if_node_data*)(n->data))->y = 0.0;
  gtk_object_set_user_data(GTK_OBJECT(group), (gpointer)n);
  
  gtk_signal_connect(GTK_OBJECT(((struct if_node_data*)(n->data))->item), "event", (GtkSignalFunc) item_event, NULL);

  gnome_canvas_item_hide(GNOME_CANVAS_ITEM(((struct if_node_data*)(n->data))->item));
}

void if_node_visible(const char *hooktype, va_list ap)
{
  int i;
  avl_node_t *avlnode;
  double newx, newy;
  node_t *n = va_arg(ap, node_t*);

  if(!n->data)
    return;
  
  if(!((struct if_node_data*)(n->data))->item)
    /* No GnomeCanvasItem has been created for this node yet */
    return;

  if(((struct if_node_data*)(n->data))->visible)
    /* This node is already shown */
    return;

  ((struct if_node_data*)(n->data))->visible = 1;

  newx = 250.0 + 200.0 * sin(number_of_nodes / 10.0 * M_PI);
  newy = 150.0 - 100.0 * cos(number_of_nodes / 10.0 * M_PI);
  gnome_canvas_item_move(GNOME_CANVAS_ITEM(((struct if_node_data*)(n->data))->item), newx - ((struct if_node_data*)(n->data))->x, newy - ((struct if_node_data*)(n->data))->y);
  ((struct if_node_data*)(n->data))->x = newx;
  ((struct if_node_data*)(n->data))->y = newy;
  
  for(i = 0, avlnode = node_tree->head; avlnode; avlnode = avlnode->next, i++)
    {
      if(!((struct if_node_data*)(((node_t*)(avlnode->data))->data))->visible)
	continue;
      
      nodes[i] = (node_t *)(avlnode->data);
      ((struct if_node_data*)(nodes[i]->data))->id = i;
    }
  number_of_nodes = i;

  gnome_canvas_item_show(GNOME_CANVAS_ITEM(((struct if_node_data*)(n->data))->item));
  gnome_canvas_update_now(GNOME_CANVAS(canvas));

  /* (Re)start calculations */
  inited = 0;
  build_graph = 1;
}

void if_node_invisible(const char *hooktype, va_list ap)
{
  int i;
  avl_node_t *avlnode;
  node_t *n = va_arg(ap, node_t*);
  
  if(!((struct if_node_data*)(n->data))->item)
    return;

  if(!((struct if_node_data*)(n->data))->visible)
    /* This node is already invisible */
    return;

  ((struct if_node_data*)(n->data))->visible = 0;

  for(i = 0, avlnode = node_tree->head; avlnode; avlnode = avlnode->next, i++)
    {
      if(!((struct if_node_data*)((node_t*)(avlnode->data))->data)->visible)
	continue;
      
      nodes[i] = (node_t *)(avlnode->data);
      ((struct if_node_data*)(nodes[i]->data))->id = i;
    }
  number_of_nodes = i;
  
  gnome_canvas_item_hide(GNOME_CANVAS_ITEM(((struct if_node_data*)(n->data))->item));
  gnome_canvas_update_now(GNOME_CANVAS(canvas));

  /* (Re)start calculations */
  inited = 0;
  build_graph = 1;
}

void if_node_add(const char *hooktype, va_list ap)
{
  node_t *n = va_arg(ap, node_t*);
  char *l[1];
  struct if_node_data *nd;

  if(!xml)
    return;

  nd = xmalloc_and_zero(sizeof(*nd));
  l[0] = n->name;
  gtk_clist_freeze(GTK_CLIST(nodetree));
  nd->ctn = gtk_ctree_insert_node(GTK_CTREE(nodetree),
				  hosts_ctn, NULL, l, 1,
				  NULL, NULL, NULL, NULL,
				  FALSE, FALSE);
  gtk_clist_thaw(GTK_CLIST(nodetree));
  gtk_ctree_node_set_row_data(GTK_CTREE(nodetree), nd->ctn, n);

  n->data = (void*)nd;

  if(canvas_visible)
    {
      if_node_create(n);
      if_node_visible(hooktype, ap);
    }
}

void if_node_del(const char *hooktype, va_list ap)
{
  node_t *n = va_arg(ap, node_t*);
  struct if_node_data *nd;

  nd = (struct if_node_data*)(n->data);
  if(nd &&nd->ctn)
    {
      gtk_clist_freeze(GTK_CLIST(nodetree));
      gtk_ctree_remove_node(GTK_CTREE(nodetree), nd->ctn);
      gtk_clist_thaw(GTK_CLIST(nodetree));
    }

  if(canvas_visible)
    {
      if_node_invisible(hooktype, ap);
    }

  free(nd);
  n->data = NULL;
}

void if_subnet_add(const char *hooktype, va_list ap)
{
  char *l[1];
  subnet_t *subnet = va_arg(ap, subnet_t*);
  struct if_subnet_data *sd;
  GtkCTreeNode *parent;

  sd = xmalloc_and_zero(sizeof(*sd));
  l[0] = net2str(subnet);
  parent = subnet->owner->data ?
    ((struct if_subnet_data*)(subnet->owner->data))->ctn
      : NULL;

  gtk_clist_freeze(GTK_CLIST(nodetree));
  sd->ctn = gtk_ctree_insert_node(GTK_CTREE(nodetree),
				  parent, NULL, l, 1,
				  NULL, NULL, NULL, NULL,
				  TRUE, FALSE);
  gtk_clist_thaw(GTK_CLIST(nodetree));
  gtk_ctree_node_set_row_data(GTK_CTREE(nodetree), sd->ctn, subnet);

  subnet->data = (void*)sd;
}

void if_subnet_del(const char *hooktype, va_list ap)
{
  subnet_t *subnet = va_arg(ap, subnet_t*);
  struct if_subnet_data *sd;

  sd = (struct if_subnet_data*)(subnet->data);
  if(sd && sd->ctn)
    {
      gtk_clist_freeze(GTK_CLIST(nodetree));
      gtk_ctree_remove_node(GTK_CTREE(nodetree), sd->ctn);
      gtk_clist_thaw(GTK_CLIST(nodetree));
    }
  
  free(sd);
  subnet->data = NULL;
}

void redraw_edges(void)
{
  GnomeCanvasGroup *group;
  GnomeCanvasPoints *points;
  avl_node_t *avlnode;
  edge_t *e;
  struct if_node_data *fd, *td;

  if(edge_group)
    gtk_object_destroy(GTK_OBJECT(edge_group));
  
  group = gnome_canvas_root(GNOME_CANVAS(canvas));
  group = GNOME_CANVAS_GROUP(gnome_canvas_item_new(group,
						   gnome_canvas_group_get_type(),
						   "x", 0.0,
						   "y", 0.0,
						   NULL));
  
  for(avlnode = edge_tree->head; avlnode; avlnode = avlnode->next)
    {
      e = (edge_t *)avlnode->data;
      fd = (struct if_node_data*)(e->from.node->data);
      td = (struct if_node_data*)(e->to.node->data);

/*       if(!e->from.node->status.visible || */
/* 	 !e->to.node->status.visible) */
/* 	/\* We shouldn't draw this line *\/ */
/* 	continue; */
      
      points = gnome_canvas_points_new(2);
      
      points->coords[0] = fd->x;
      points->coords[1] = fd->y;
      points->coords[2] = td->x;
      points->coords[3] = td->y;
      gnome_canvas_item_new(group,
			    gnome_canvas_line_get_type(),
			    "points", points,
			    "fill_color_rgba", 0xe080c080,
			    "width_pixels", 2,
			    NULL);
      gnome_canvas_points_unref(points);
    }

  gnome_canvas_update_now(GNOME_CANVAS(canvas));

  edge_group = group;
}

void if_edge_add(const char *hooktype, va_list ap)
{
  redraw_edges();

  inited = 0;
  build_graph = 1;
}

void if_edge_del(const char *hooktype, va_list ap)
{
  redraw_edges();

  inited = 0;
  build_graph = 1;
}

void if_move_node(node_t *n, double dx, double dy)
{
  double newx, newy;
  
  newx = ((struct if_node_data*)(n->data))->x + dx;
  newy = ((struct if_node_data*)(n->data))->y + dy;
  gnome_canvas_item_move(GNOME_CANVAS_ITEM(((struct if_node_data*)(n->data))->item), newx - ((struct if_node_data*)(n->data))->x, newy - ((struct if_node_data*)(n->data))->y);
  ((struct if_node_data*)(n->data))->x = newx;
  ((struct if_node_data*)(n->data))->y = newy;
}

#define X_MARGIN 50.0
#define X_MARGIN_BUFFER 25.0
#define Y_MARGIN 20.0
#define Y_MARGIN_BUFFER 10.0

void set_zooming(void)
{
  int i;
  double minx, miny, maxx, maxy;
  static double ominx = 0.0, ominy = 0.0, omaxx = 0.0, omaxy = 0.0;

  minx = miny = maxx = maxy = 0.0;
  for(i = 0; i < number_of_nodes; i++)
    {
      if(((struct if_node_data*)(nodes[i]->data))->x < minx)
	minx = ((struct if_node_data*)(nodes[i]->data))->x;
      else
	if(((struct if_node_data*)(nodes[i]->data))->x > maxx)
	  maxx = ((struct if_node_data*)(nodes[i]->data))->x;

      if(((struct if_node_data*)(nodes[i]->data))->y < miny)
	miny = ((struct if_node_data*)(nodes[i]->data))->y;
      else
	if(((struct if_node_data*)(nodes[i]->data))->y > maxy)
	  maxy = ((struct if_node_data*)(nodes[i]->data))->y;
    }

  if(minx > ominx - X_MARGIN_BUFFER && ominx > minx)
    minx = ominx;
  if(maxx < omaxx + X_MARGIN_BUFFER && omaxx < maxx)
    maxx = omaxx;
  if(miny > ominy - Y_MARGIN_BUFFER && ominy > miny)
    miny = ominy;
  if(maxy < omaxy + Y_MARGIN_BUFFER && omaxy < maxy)
    maxy = omaxy;

  ominx = minx; ominy = miny; omaxx = maxx; omaxy = maxy;

/*   ppux = canvas_width / (maxx - minx); */
/*   ppuy = canvas_height / (maxy - miny); */
/*   if(ppux < ppuy) */
/*     ppu = ppux; */
/*   else */
/*     ppu = ppuy; */

/*   gnome_canvas_set_pixels_per_unit(GNOME_CANVAS(canvas), ppu); */
  gnome_canvas_set_scroll_region(GNOME_CANVAS(canvas), minx - X_MARGIN, miny - Y_MARGIN, maxx + X_MARGIN, maxy + Y_MARGIN);
  gnome_canvas_update_now(GNOME_CANVAS(canvas));
}

double calculate_delta_m(int m)
{
  double dedxm, dedym, xmxi, ymyi;
  int i;

  dedxm = dedym = 0.0;
  for(i = 0; i < number_of_nodes; i++)
    {
      if(i == m)
	continue;

      xmxi = x[m] - x[i];
      ymyi = y[m] - y[i];

      dedxm += k[m][i] * (xmxi - ((l[m][i] * xmxi) / sqrt(xmxi * xmxi + ymyi * ymyi)));
      dedym += k[m][i] * (xmxi - ((l[m][i] * xmxi) / sqrt(xmxi * xmxi + ymyi * ymyi)));
    }

  return sqrt(dedxm * dedxm + dedym * dedym);
}

void move_node(int m, double *dx, double *dy)
{
  double d2edxm2, d2edym2, d2edxmdym, dedxm, dedym;
  double xmxi, ymyi, denominator;
  int i;

  d2edxm2 = d2edym2 = d2edxmdym = dedxm = dedym = 0.0;
  for(i = 0; i < number_of_nodes; i++)
    {
      if(i == m)
	continue;
      
      xmxi = x[m] - x[i];
      ymyi = y[m] - y[i];

      denominator = pow(sqrt(xmxi * xmxi + ymyi * ymyi), 3.0);

      d2edxm2 += k[m][i] * (1 - ((l[m][i] * ymyi * ymyi) / denominator));
      d2edxmdym += k[m][i] * l[m][i] * xmxi * ymyi / denominator;
      d2edym2 += k[m][i] * (1 - ((l[m][i] * xmxi * xmxi) / denominator));
      dedxm += k[m][i] * (xmxi - ((l[m][i] * xmxi) / sqrt(xmxi * xmxi + ymyi * ymyi)));
      dedym += k[m][i] * (ymyi - ((l[m][i] * ymyi) / sqrt(xmxi * xmxi + ymyi * ymyi)));
    }

  denominator = ((d2edxm2 * d2edym2) - (d2edxmdym * d2edxmdym));
  *dx = (-(d2edym2 * dedxm) + (d2edxmdym * dedym)) / denominator;
  *dy = ((d2edxmdym * dedxm) - (d2edxm2 * dedym)) / denominator;
}

void if_build_graph(void)
{
  int i, j, p, max_i;
  double delta_m, max_delta_m;
  double dx, dy, s, L, min_d, old_x, old_y;
  edge_t *e;

  if(!keep_drawing)
    return;
  
  if(!inited)
    {
      for(i = 0; i < number_of_nodes; i++)
	{
	  x[i] = ((struct if_node_data*)(nodes[i]->data))->x;
	  y[i] = ((struct if_node_data*)(nodes[i]->data))->y;
	}

      /* Initialize Floyd */
      for(i = 0; i < number_of_nodes; i++)
	{
	  d[i][i] = 0.0;
	  for(j = i + 1; j < number_of_nodes; j++)
	    {
	      e = lookup_edge(nodes[i], nodes[j]);
	      if(e)
		d[i][j] = d[j][i] = (double)e->weight;
	      else
		d[i][j] = d[j][i] = INFINITY;
	    }
	}

      /* Floyd's shortest path algorithm */
      for(i = 0; i < number_of_nodes; i++)
	{
	  for(j = 0; j < number_of_nodes; j++)
	    {
	      if(i == j)
		continue;
	      
	      if(d[j][i] < INFINITY)
		{
		  for(p = 0; p < number_of_nodes; p++)
		    {
		      if(d[i][j] < INFINITY)
			{
			  s = d[j][i] + d[i][p];
			  if(s < d[j][p])
			    {
			      d[j][p] = s;
			    }
			}
		    }
		}
	    }
	}

      min_d = INFINITY;
      for(i = 0; i < number_of_nodes; i++)
	for(j = i + 1; j < number_of_nodes; j++)
	  if(d[i][j] < min_d && d[i][j] > 0.0)
	    min_d = d[i][j];

      L = 5.0 / sqrt(min_d + 1.0);

      for(i = 0; i < number_of_nodes; i++)
	{
	  for(j = i + 1; j < number_of_nodes; j++)
	    {
	      d[i][j] = d[j][i] = sqrt(d[i][j]+1.0);
	      l[i][j] = l[j][i] = L * d[i][j];
	      k[i][j] = k[j][i] = K / (d[i][j] * d[i][j]);
	    }
	}

      inited = 1;
    }

  max_delta_m = 0.0;
  /* Find node with maximal local energy */
  for(i = 0; i < number_of_nodes; i++)
    {
      delta_m = calculate_delta_m(i);
      if(delta_m > max_delta_m)
	{
	  max_delta_m = delta_m;
	  max_i = i;
	}
    }

  if(max_delta_m <= epsilon)
    {
      fprintf(stderr, "Graph building is done; max_delta_m = %f\n", max_delta_m);
      build_graph = 0;
    }
  else
    {
      int iter = 0, maxiter = 20;
      delta_m = max_delta_m;
      old_x = x[max_i];
      old_y = y[max_i];
      while(delta_m > epsilon && iter < maxiter)
	{
	  move_node(max_i, &dx, &dy);
	  x[max_i] += dx;
	  y[max_i] += dy;
	  delta_m = calculate_delta_m(max_i);
	  iter++;
	}
	  
      if_move_node(nodes[max_i], x[max_i] - old_x, y[max_i] - old_y);
	  
      redraw_edges();

      set_zooming();
    }

/*   build_graph = 0; */
}
