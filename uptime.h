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

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static inline uint64_t uptime_get(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_BOOTTIME, &ts);

	return ts.tv_sec;
}

static inline bool boot_id_get(char *buf, size_t len)
{
	ssize_t n;
	int fd;

	fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;

	n = read(fd, buf, len - 1);
	close(fd);
	if (n <= 0)
		return false;

	buf[n] = '\0';
	buf[strcspn(buf, "\n")] = '\0';

	return true;
}

#endif
