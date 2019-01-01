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
#define _GNU_SOURCE

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <fcntl.h>

#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "init.h"
#include "../watchdog.h"
#include "../sysupgrade.h"

static struct uloop_process preinit_proc;
static struct uloop_process plugd_proc;

static void
check_dbglvl(void)
{
	FILE *fp = fopen("/tmp/debug_level", "r");
	int lvl = 0;

	if (!fp)
		return;
	if (fscanf(fp, "%d", &lvl) == EOF)
		ERROR("failed to read debug level: %m\n");
	fclose(fp);
	unlink("/tmp/debug_level");

	if (lvl > 0 && lvl < 5)
		debug = lvl;
}

static void
check_sysupgrade(void)
{
	char *prefix = NULL, *path = NULL, *command = NULL;
	size_t n;

	if (chdir("/"))
		return;

	FILE *sysupgrade = fopen("/tmp/sysupgrade", "r");
	if (!sysupgrade)
		return;

	n = 0;
	if (getdelim(&prefix, &n, 0, sysupgrade) < 0)
		goto fail;
	n = 0;
	if (getdelim(&path, &n, 0, sysupgrade) < 0)
		goto fail;
	n = 0;
	if (getdelim(&command, &n, 0, sysupgrade) < 0)
		goto fail;

	fclose(sysupgrade);

	sysupgrade_exec_upgraded(prefix, path, NULL, command, NULL);

	while (true)
		sleep(1);

fail:
	fclose(sysupgrade);
	free(prefix);
	free(path);
	free(command);
}

static void
spawn_procd(struct uloop_process *proc, int ret)
{
	char *wdt_fd = watchdog_fd();
	char *argv[] = { "/sbin/procd", NULL};
	char dbg[2];

	if (plugd_proc.pid > 0)
		kill(plugd_proc.pid, SIGKILL);

	unsetenv("INITRAMFS");
	unsetenv("PREINIT");
	unlink("/tmp/.preinit");

	check_sysupgrade();

	DEBUG(2, "Exec to real procd now\n");
	if (wdt_fd)
		setenv("WDTFD", wdt_fd, 1);
	check_dbglvl();
	if (debug > 0) {
		snprintf(dbg, 2, "%d", debug);
		setenv("DBGLVL", dbg, 1);
	}

	execvp(argv[0], argv);
}

static void
plugd_proc_cb(struct uloop_process *proc, int ret)
{
	proc->pid = 0;
}

void
preinit(void)
{
	char *init[] = { "/bin/sh", "/etc/preinit", NULL };
	char *plug[] = { "/sbin/procd", "-h", "/etc/hotplug-preinit.json", NULL };
	int fd;

	LOG("- preinit -\n");

	plugd_proc.cb = plugd_proc_cb;
	plugd_proc.pid = fork();
	if (!plugd_proc.pid) {
		execvp(plug[0], plug);
		ERROR("Failed to start plugd: %m\n");
		exit(EXIT_FAILURE);
	}
	if (plugd_proc.pid <= 0) {
		ERROR("Failed to start new plugd instance: %m\n");
		return;
	}
	uloop_process_add(&plugd_proc);

	setenv("PREINIT", "1", 1);

	fd = creat("/tmp/.preinit", 0600);

	if (fd < 0)
		ERROR("Failed to create sentinel file: %m\n");
	else
		close(fd);

	preinit_proc.cb = spawn_procd;
	preinit_proc.pid = fork();
	if (!preinit_proc.pid) {
		execvp(init[0], init);
		ERROR("Failed to start preinit: %m\n");
		exit(EXIT_FAILURE);
	}
	if (preinit_proc.pid <= 0) {
		ERROR("Failed to start new preinit instance: %m\n");
		return;
	}
	uloop_process_add(&preinit_proc);

	DEBUG(4, "Launched preinit instance, pid=%d\n", (int) preinit_proc.pid);
}
