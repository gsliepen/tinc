#include "config.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <math.h>

#include <gtk/gtk.h>
#include <glade/glade.h>
#include <libgnomeui/gnome-canvas.h>
#include <libgnomeui/gnome-canvas-rect-ellipse.h>
#include <libgnomeui/gnome-canvas-text.h>
#include <libgnomeui/gnome-canvas-line.h>
#include <libgnomeui/gnome-canvas-util.h>

#include "node.h"
#include "edge.h"
#include "interface.h"

#include <xalloc.h>

#include "system.h"

extern GladeXML *xml;

#ifdef MAXBUFSIZE
#undef MAXBUFSIZE
#endif

#define MAXBUFSIZE 1024

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
const double epsilon = 0.001;

static int inited = 0;

static int number_of_nodes = 0;

static GtkWidget *nodetree;
static GtkCTreeNode *subnets_ctn, *hosts_ctn, *conns_ctn;

static GnomeCanvasGroup *edge_group = NULL;

static int canvas_width;
static int canvas_height;

static GtkWidget *canvas = NULL;

GtkWidget *create_canvas(void)
{
  GtkWidget *w;

  gtk_widget_push_visual(gdk_rgb_get_visual());
  gtk_widget_push_colormap(gdk_rgb_get_cmap());
  
  canvas = gnome_canvas_new_aa();
  
  gtk_widget_pop_visual();
  gtk_widget_pop_colormap();
  
  gnome_canvas_set_scroll_region(GNOME_CANVAS(canvas), 0, 0, 500, 300);
  
  w = glade_xml_get_widget(xml, "scrolledwindow3");
  if(!w)
    {
      fprintf(stderr, "Could not find widget `scrolledwindow3'\n");
      return NULL;
    }
  gtk_container_add(GTK_CONTAINER(w), canvas);
  gtk_widget_show_all(w);

  canvas_width = 300.0;
  canvas_height = 500.0;

  return canvas;
}

int init_interface(void)
{
  char *l[1];
  GtkArg p;

  if(!xml)
    return -1;

  nodetree = glade_xml_get_widget(xml, "NodeTree");
  if(!nodetree)
    {
      fprintf(stderr, _("Could not find widget `NodeTree'\n"));
      return -1;
    }

  gtk_clist_freeze(GTK_CLIST(nodetree));

  l[0] = _("Hosts");
  hosts_ctn = gtk_ctree_insert_node(GTK_CTREE(nodetree),
			      NULL, NULL, l, 1,
			      NULL, NULL, NULL, NULL,
			      FALSE, TRUE);
  l[0] = _("Subnets");
  subnets_ctn = gtk_ctree_insert_node(GTK_CTREE(nodetree),
			      NULL, NULL, l, 1,
			      NULL, NULL, NULL, NULL,
			      FALSE, TRUE);
  l[0] = _("Connections");
  conns_ctn = gtk_ctree_insert_node(GTK_CTREE(nodetree),
			      NULL, NULL, l, 1,
			      NULL, NULL, NULL, NULL,
			      FALSE, TRUE);
  
  gtk_clist_thaw(GTK_CLIST(nodetree));

  create_canvas();
  
  return 0;
}

void log_message(int severity, const char *fmt, ...)
{
  va_list args;
  char buffer1[MAXBUFSIZE];
  char buffer2[MAXBUFSIZE];
  GtkWidget *w;
  int len;
  char *p;
  struct tm *tm;
  time_t t;
  static int inited = 0;

  if(!xml)
    return;
  
  w = glade_xml_get_widget(xml, "Messages");
  if(!w)
    return;

  /* Use vsnprintf instead of vasprintf: faster, no memory
     fragmentation, cleanup is automatic, and there is a limit on the
     input buffer anyway */
  va_start(args, fmt);
  len = vsnprintf(buffer1, MAXBUFSIZE, fmt, args);
  va_end(args);

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
  
  gtk_text_freeze(GTK_TEXT(w));

  if(inited)
    gtk_text_insert(GTK_TEXT(w), NULL, NULL, NULL, "\n", 1);

  gtk_text_insert(GTK_TEXT(w), NULL, &timecolor, NULL, buffer2, strlen(buffer2));
  gtk_text_insert(GTK_TEXT(w), NULL, NULL, NULL, buffer1, len);
  gtk_text_thaw(GTK_TEXT(w));

  inited = 1;
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
      n->x = item_x;
      n->y = item_y;
      x[n->id] = item_x;
      y[n->id] = item_y;
      build_graph = 1;
      break;

    default:
      break;
    }
  return FALSE;
}

GtkCTreeNode *if_node_add(node_t *n)
{
  char *l[1];
  GtkCTreeNode *ctn;

  if(!xml)
    return NULL;

  l[0] = n->name;
  gtk_clist_freeze(GTK_CLIST(nodetree));
  n->host_ctn = gtk_ctree_insert_node(GTK_CTREE(nodetree),
				      hosts_ctn, NULL, l, 1,
				      NULL, NULL, NULL, NULL,
				      FALSE, FALSE);
  gtk_clist_thaw(GTK_CLIST(nodetree));

  if_graph_add_node(n);

  inited = 0;
  build_graph = 1;

  return ctn;
}

void if_node_del(node_t *n)
{
  gtk_clist_freeze(GTK_CLIST(nodetree));
  if(n->host_ctn)
    gtk_ctree_remove_node(GTK_CTREE(nodetree), n->host_ctn);
  if(n->conn_ctn)
    gtk_ctree_remove_node(GTK_CTREE(nodetree), n->conn_ctn);
  if(n->subnet_ctn)
    gtk_ctree_remove_node(GTK_CTREE(nodetree), n->subnet_ctn);
  gtk_clist_thaw(GTK_CLIST(nodetree));
}

void if_subnet_add(subnet_t *subnet)
{
  char *l[1];
  
  l[0] = net2str(subnet);
  gtk_clist_freeze(GTK_CLIST(nodetree));
  gtk_ctree_insert_node(GTK_CTREE(nodetree),
			subnets_ctn, NULL, l, 1,
			NULL, NULL, NULL, NULL,
			TRUE, FALSE);
  gtk_clist_thaw(GTK_CLIST(nodetree));
}

void if_subnet_del(subnet_t *subnet)
{
}

void redraw_edges(void)
{
  GnomeCanvasGroup *group;
  GnomeCanvasPoints *points;
  avl_node_t *avlnode;
  edge_t *e;

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
/*       char s[12]; */
      e = (edge_t *)avlnode->data;
      
      points = gnome_canvas_points_new(2);
      
      points->coords[0] = e->from.node->x;
      points->coords[1] = e->from.node->y;
      points->coords[2] = e->to.node->x;
      points->coords[3] = e->to.node->y;
      gnome_canvas_item_new(group,
			    gnome_canvas_line_get_type(),
			    "points", points,
			    "fill_color_rgba", 0xe080c0ff,
			    "width_pixels", 2,
			    NULL);
      gnome_canvas_points_unref(points);
/*       snprintf(s, sizeof(s) - 1, "%d", e->weight); */
/*       gnome_canvas_item_new(group, */
/* 			    gnome_canvas_text_get_type(), */
/* 			    "x", (e->from.node->x + e->to.node->x) / 2, */
/* 			    "y", (e->from.node->y + e->to.node->y) / 2, */
/* 			    "text", s, */
/* 			    "anchor", GTK_ANCHOR_CENTER, */
/* 			    "fill_color", "black", */
/* 			    "font", "-*-verdana-medium-r-*-*-8-*-*-*-*-*-iso8859-1", */
/* 			    /\* 			"font", "fixed", *\/ */
/* 			    NULL); */
    }

  edge_group = group;
}

void if_edge_add(edge_t *e)
{
  redraw_edges();
  if_graph_add_edge(e);
  inited = 0;
  build_graph = 1;

}

void if_edge_del(edge_t *e)
{
  redraw_edges();
  inited = 0;
  build_graph = 1;

}

void if_graph_add_node(node_t *n)
{
  GnomeCanvasGroup *group;
  double newx, newy;
  
  if(!canvas)
    if(!create_canvas())
      return;
  
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
			"fill_color_rgba", 0x5f9ea0ff,
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
/* 			"font", "fixed", */
			NULL);
  
  n->item = GNOME_CANVAS_ITEM(group);
  gtk_object_set_user_data(GTK_OBJECT(group), (gpointer)n);
  
  /* TODO: Use this to get more detailed info on a node (For example
     popup a dialog with more info, select the node in the left
     pane, whatever.) */
  gtk_signal_connect(GTK_OBJECT(n->item), "event", (GtkSignalFunc) item_event, NULL);

  newx = 250.0 + 200.0 * sin(number_of_nodes / 10.0 * M_PI);
  newy = 150.0 - 100.0 * cos(number_of_nodes / 10.0 * M_PI);
/*   newx = (double)random() / (double)RAND_MAX * 300.0 + 100.0; */
/*   newy = (double)random() / (double)RAND_MAX * 200.0 + 50.0; */
  gnome_canvas_item_move(GNOME_CANVAS_ITEM(n->item), newx, newy);
  n->x = newx;
  n->y = newy;

  x[number_of_nodes] = newx;
  y[number_of_nodes] = newy;
  nodes[number_of_nodes] = n;
  n->id = number_of_nodes;
  
  number_of_nodes++;

  gnome_canvas_update_now(GNOME_CANVAS(canvas));
}

void if_move_node(node_t *n, double dx, double dy)
{
  double newx, newy;
  
  newx = n->x + dx;
  newy = n->y + dy;
  gnome_canvas_item_move(GNOME_CANVAS_ITEM(n->item), newx - n->x, newy - n->y);
  n->x = newx;
  n->y = newy;
}

void if_graph_add_edge(edge_t *e)
{
/*   e->from.node->ifn->nat++; */
/*   e->to.node->ifn->nat++; */

/*   avl_insert(e->from.node->ifn->attractors, e->to.node); */
/*   avl_insert(e->to.node->ifn->attractors, e->from.node); */

  redraw_edges();

  build_graph = 1;
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
  double ppu, ppux, ppuy;

  minx = miny = maxx = maxy = 0.0;
  for(i = 0; i < number_of_nodes; i++)
    {
      if(nodes[i]->x < minx)
	minx = nodes[i]->x;
      else
	if(nodes[i]->x > maxx)
	  maxx = nodes[i]->x;

      if(nodes[i]->y < miny)
	miny = nodes[i]->y;
      else
	if(nodes[i]->y > maxy)
	  maxy = nodes[i]->y;
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
  double dx, dy, s, L, max_d, old_x, old_y;
  edge_t *e;

  if(!inited)
    {
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

      max_d = 0.0;
      for(i = 0; i < number_of_nodes; i++)
	for(j = i + 1; j < number_of_nodes; j++)
	  if(d[i][j] > max_d && d[i][j] < INFINITY)
	    max_d = d[i][j];

      L = 300.0 / log(max_d);

      for(i = 0; i < number_of_nodes; i++)
	{
	  for(j = i + 1; j < number_of_nodes; j++)
	    {
	      d[i][j] = d[j][i] = log(d[i][j]+1.0);
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
    build_graph = 0;
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
