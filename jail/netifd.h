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

#ifndef _JAIL_NETIFD_H
#define _JAIL_NETIFD_H
#include <libubus.h>

int jail_network_start(struct ubus_context *new_ctx, char *new_jail_name, pid_t new_ns_pid);
int jail_network_stop(void);

#endif
