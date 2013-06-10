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

#include <unistd.h>
#include <unistd.h>

#include "procd.h"
#include "hotplug.h"
#include "watchdog.h"

static struct uloop_process preinit;

static void spawn_procd(struct uloop_process *proc, int ret)
{
	char *wdt_fd = watchdog_fd();
	char *argv[] = { "/sbin/procd", NULL };
	struct stat s;

	if (!stat("/tmp/sysupgrade", &s))
		while (true)
			sleep(1);

	unsetenv("INITRAMFS");
	unsetenv("PREINIT");
	DEBUG(1, "Exec to real procd now\n");
	if (wdt_fd)
		setenv("WDTFD", wdt_fd, 1);
	execvp(argv[0], argv);
}

void procd_preinit(void)
{
	char *argv[] = { "/bin/sh", "/etc/preinit", NULL };

	LOG("- preinit -\n");

	setenv("PREINIT", "1", 1);
	preinit.cb = spawn_procd;
	preinit.pid = fork();
	if (!preinit.pid) {
		execvp(argv[0], argv);
		ERROR("Failed to start preinit\n");
		exit(-1);
	}

	if (preinit.pid <= 0) {
		ERROR("Failed to start new preinit instance\n");
		return;
	}

	uloop_process_add(&preinit);
	DEBUG(2, "Launched preinit instance, pid=%d\n", (int) preinit.pid);
}
