/*
 * Copyright (C) 2026 Nick Hainke <vincent@systemli.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __PROCD_VRF_H
#define __PROCD_VRF_H

int vrf_attach(int cgroup_fd, const char *vrf_name);
void vrf_detach(int cgroup_fd);

#endif
