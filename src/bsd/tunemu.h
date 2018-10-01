/*
 *  tunemu - Tun device emulation for Darwin
 *  Copyright (C) 2009 Friedrich Schöller <friedrich.schoeller@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef TUNEMU_H
#define TUNEMU_H

typedef char tunemu_device[7];

extern char tunemu_error[];

int tunemu_open(tunemu_device dev);
int tunemu_close(int fd);
int tunemu_read(int fd, char *buffer, int length);
int tunemu_write(int fd, char *buffer, int length);

#endif
