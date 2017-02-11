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
#include <sys/sysmacros.h>

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include "../utils/utils.h"
#include "init.h"
#include "../libc-compat.h"

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

	if (stat(dev, &s)) {
		ERROR("Failed to stat %s\n", dev);
		return;
	}

	if (patch_stdio(dev)) {
		ERROR("Failed to setup i/o redirection\n");
		return;
	}

	fcntl(STDERR_FILENO, F_SETFL, fcntl(STDERR_FILENO, F_GETFL) | O_NONBLOCK);
}

static void
early_mounts(void)
{
	unsigned int oldumask = umask(0);

	mount("proc", "/proc", "proc", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID, 0);
	mount("sysfs", "/sys", "sysfs", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID, 0);
	mount("cgroup", "/sys/fs/cgroup", "cgroup",  MS_NODEV | MS_NOEXEC | MS_NOSUID, 0);
	mount("tmpfs", "/dev", "tmpfs", MS_NOATIME | MS_NOSUID, "mode=0755,size=512K");
	ignore(symlink("/tmp/shm", "/dev/shm"));
	mkdir("/dev/pts", 0755);
	mount("devpts", "/dev/pts", "devpts", MS_NOATIME | MS_NOEXEC | MS_NOSUID, "mode=600");
	early_dev();

	early_console("/dev/console");
	if (mount_zram_on_tmp()) {
		mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOATIME, 0);
		mkdir("/tmp/shm", 01777);
	} else {
		mkdir("/tmp/shm", 01777);
		mount("tmpfs", "/tmp/shm", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOATIME,
				"mode=01777");
	}
	mkdir("/tmp/run", 0755);
	mkdir("/tmp/lock", 0755);
	mkdir("/tmp/state", 0755);
	umask(oldumask);
}

static void
early_env(void)
{
	setenv("PATH", EARLY_PATH, 1);
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
