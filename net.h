/*
 * Copyright 2026 Various Authors
 * Copyright 2004-2005 Timo Hirvonen
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef CMUS_NET_H
#define CMUS_NET_H

#include <sys/types.h>
#include <unistd.h>

int net_tls_connect(int fd, const char *hostname, int timeout_ms);
int net_has_pending(int fd);

ssize_t net_read(int fd, void *buf, size_t count);
ssize_t net_write(int fd, const void *buf, size_t count);
off_t net_lseek(int fd, off_t offset, int whence);
int net_close(int fd);

#endif
