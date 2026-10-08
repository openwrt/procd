/*
 * Copyright (C) 2021 Daniel Golle <daniel@makrotopia.org>
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

#ifndef _JAIL_CGROUPS_BPF_H
#define _JAIL_CGROUPS_BPF_H

#include <stdbool.h>

void cgroups_devices_seal(void);
void cgroups_devices_update_begin(void);
void cgroups_devices_update_rollback(void);
bool cgroups_devices_differ(void);
void cgroups_devices_free(void);
int parseOCIlinuxcgroups_devices(struct blob_attr *msg);
int attach_cgroups_ebpf(int cgroup_dirfd);

#endif
