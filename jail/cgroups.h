/*
 * Copyright (C) 2020 Daniel Golle <daniel@makrotopia.org>
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

#ifndef _JAIL_CGROUPS_H
#define _JAIL_CGROUPS_H

void cgroups_init(const char *p);
int parseOCIlinuxcgroups(struct blob_attr *msg);
void cgroups_apply(pid_t pid);
void cgroups_free(void);
void cgroups_prepare(void);

#endif
