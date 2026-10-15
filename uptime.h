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

#ifndef __UPTIME_H
#define __UPTIME_H

#include <stdint.h>
#include <time.h>

static inline uint64_t uptime_get(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_BOOTTIME, &ts);

	return ts.tv_sec;
}

#endif
