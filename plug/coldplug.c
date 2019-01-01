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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>

#include <stdlib.h>
#include <unistd.h>

#include "../procd.h"
#include "../libc-compat.h"

#include "hotplug.h"
#include "../container.h"

static struct uloop_process udevtrigger;

static void coldplug_complete(struct uloop_timeout *t)
{
	DEBUG(4, "Coldplug complete\n");
	hotplug_last_event(NULL);
	procd_state_next();
}

static void udevtrigger_complete(struct uloop_process *proc, int ret)
{
	DEBUG(4, "Finished udevtrigger\n");
	hotplug_last_event(coldplug_complete);
}

void procd_coldplug(void)
{
	char *argv[] = { "udevtrigger", NULL };
	unsigned int oldumask = umask(0);

	if (!is_container()) {
		umount2("/dev/pts", MNT_DETACH);
		umount2("/dev/", MNT_DETACH);
		mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755,size=512K");
		mkdir("/dev/pts", 0755);
		mount("devpts", "/dev/pts", "devpts", MS_NOEXEC | MS_NOSUID, 0);
	}

	ignore(symlink("/tmp/shm", "/dev/shm"));
	umask(oldumask);
	udevtrigger.cb = udevtrigger_complete;
	udevtrigger.pid = fork();
	if (!udevtrigger.pid) {
		execvp(argv[0], argv);
		ERROR("Failed to start coldplug: %m\n");
		exit(EXIT_FAILURE);
	}

	if (udevtrigger.pid <= 0) {
		ERROR("Failed to start new coldplug instance: %m\n");
		return;
	}

	uloop_process_add(&udevtrigger);

	DEBUG(4, "Launched coldplug instance, pid=%d\n", (int) udevtrigger.pid);
}
