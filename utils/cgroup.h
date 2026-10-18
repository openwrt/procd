/*
 * Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef __PROCD_CGROUP_H
#define __PROCD_CGROUP_H

#include <stdbool.h>

#define CGROUP_DRAIN_TIMEOUT_MSEC	1000

int cgroup_join(const char *path);
int cgroup_kill(const char *path);
bool cgroup_populated(int fd);

#endif
