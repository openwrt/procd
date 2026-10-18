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

#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libubox/utils.h>

#include "cgroup.h"

int cgroup_join(const char *path)
{
	char procs[256], dir[256];
	struct stat sb;
	int fd, ret;

	if (stat("/sys/fs/cgroup/cgroup.subtree_control", &sb))
		return 0;

	ret = snprintf(procs, sizeof(procs), "%s/cgroup.procs", path);
	if (ret < 0 || (size_t)ret >= sizeof(procs))
		return -ENAMETOOLONG;

	snprintf(dir, sizeof(dir), "%s", path);
	if (mkdir_p(dir, 0700))
		return -EPERM;

	fd = open(procs, O_WRONLY);
	if (fd == -1)
		return -EIO;

	ret = dprintf(fd, "%d", getpid());
	close(fd);
	if (ret < 0)
		return -EIO;

	return 0;
}

int cgroup_kill(const char *path)
{
	char kill_path[256];
	int fd, ret;

	ret = snprintf(kill_path, sizeof(kill_path), "%s/cgroup.kill", path);
	if (ret < 0 || (size_t)ret >= sizeof(kill_path))
		return -ENAMETOOLONG;

	fd = open(kill_path, O_WRONLY);
	if (fd < 0)
		return 0;

	ret = (write(fd, "1", 1) < 0) ? -errno : 0;
	close(fd);

	return ret;
}

bool cgroup_populated(int fd)
{
	char buf[128];
	ssize_t len;
	char *val;

	if (lseek(fd, 0, SEEK_SET) < 0)
		return false;

	len = read(fd, buf, sizeof(buf) - 1);
	if (len <= 0)
		return false;

	buf[len] = '\0';
	val = strstr(buf, "populated ");
	if (!val)
		return false;

	return val[strlen("populated ")] == '1';
}
