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

#ifndef __JAIL_STATUS_H
#define __JAIL_STATUS_H

#include <stdint.h>

#define JAIL_STATUS_FD 3

enum jail_status_type {
	JAIL_STATUS_CREATED = 1,
	JAIL_STATUS_RUNNING,
	JAIL_STATUS_STOPPED,
};

#define JAIL_STATUS_F_REAPED		(1 << 0)
#define JAIL_STATUS_F_REQUESTED		(1 << 1)
#define JAIL_STATUS_F_STARTED		(1 << 2)
#define JAIL_STATUS_F_ESCALATED		(1 << 3)
#define JAIL_STATUS_F_RESTARTING	(1 << 4)
#define JAIL_STATUS_F_REGISTERED	(1 << 5)

struct jail_status {
	uint32_t type;
	uint32_t flags;
	int32_t exit_status;
	uint32_t runtime;
};

#endif
