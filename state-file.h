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

#ifndef __STATE_FILE_H
#define __STATE_FILE_H

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static inline int fd_write_all(int fd, const char *buf, size_t len)
{
	ssize_t ret;

	while (len) {
		ret = write(fd, buf, len);
		if (ret < 0)
			return errno;

		buf += ret;
		len -= ret;
	}

	return 0;
}

static inline int file_write_atomic(const char *path, const char *buf, size_t len, mode_t mode)
{
	char tmp[PATH_MAX];
	int fd, err;

	if (snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path) >= (int)sizeof(tmp))
		return -ENAMETOOLONG;

	fd = mkstemp(tmp);
	if (fd < 0)
		return -errno;

	err = 0;
	if (fchmod(fd, mode))
		err = errno;

	if (!err)
		err = fd_write_all(fd, buf, len);

	if (close(fd) && !err)
		err = errno;

	if (!err && rename(tmp, path))
		err = errno;

	if (!err)
		return 0;

	unlink(tmp);

	return -err;
}

#endif
