/*
 * Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2013 John Crispin <blogic@openwrt.org>
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

#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "init.h"

static void
early_dev(void)
{
	mkdev("*", 0600);
	mknod("/dev/null", 0666, makedev(1, 3));
}

static void
early_console(const char *dev)
{
	struct stat s;
	int dd;

	if (stat(dev, &s)) {
		ERROR("Failed to stat %s\n", dev);
		return;
	}

	dd = open(dev, O_RDWR);
	if (dd < 0)
		dd = open("/dev/null", O_RDWR);

	dup2(dd, STDIN_FILENO);
	dup2(dd, STDOUT_FILENO);
	dup2(dd, STDERR_FILENO);

	if (dd != STDIN_FILENO &&
	    dd != STDOUT_FILENO &&
	    dd != STDERR_FILENO)
		close(dd);

	fcntl(STDERR_FILENO, F_SETFL, fcntl(STDERR_FILENO, F_GETFL) | O_NONBLOCK);
}

static void
early_mounts(void)
{
	mount("proc", "/proc", "proc", MS_NOATIME, 0);
	mount("sysfs", "/sys", "sysfs", MS_NOATIME, 0);
	mount("none", "/sys/fs/cgroup", "cgroup", 0, 0);
	mount("tmpfs", "/dev", "tmpfs", MS_NOATIME, "mode=0755,size=512K");
	mkdir("/dev/shm", 0755);
	mkdir("/dev/pts", 0755);
	mount("devpts", "/dev/pts", "devpts", MS_NOATIME, "mode=600");
	early_dev();

	early_console("/dev/console");
	if (mount_zram_on_tmp())
		mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOATIME, NULL);
	else
		mkdev("*", 0600);
	mkdir("/tmp/run", 0777);
	mkdir("/tmp/lock", 0777);
	mkdir("/tmp/state", 0777);
	symlink("/tmp", "/var");
}

static void
early_env(void)
{
	setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
}

void
early(void)
{
	if (getpid() != 1)
		return;

	early_mounts();
	early_env();

	LOG("Console is alive\n");
}
