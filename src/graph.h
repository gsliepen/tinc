/*
    graph.h -- header for graph.c
    Copyright (C) 2001-2003 Guus Sliepen <guus@sliepen.eu.org>,
                  2001-2003 Ivo Timmermans <ivo@o2w.nl>

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

    $Id: graph.h,v 1.1.2.5 2003/07/12 17:41:45 guus Exp $
*/

extern void graph(void);
extern void mst_kruskal(void);
extern void sssp_bfs(void);
