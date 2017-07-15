/*
 * Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2013 John Crispin <blogic@openwrt.org>
 * Copyright (C) 2017 Matthias Schiffer <mschiffer@universe-factory.net>
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


#include "watchdog.h"
#include "sysupgrade.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


void sysupgrade_exec_upgraded(const char *prefix, char *path, char *command)
{
	char *wdt_fd = watchdog_fd();
	char *argv[] = { "/sbin/upgraded", NULL, NULL, NULL};
	int ret;

	ret = chroot(prefix);
	if (ret < 0) {
		fprintf(stderr, "Failed to chroot for upgraded exec.\n");
		return;
	}

	argv[1] = path;
	argv[2] = command;

	if (wdt_fd) {
		watchdog_set_cloexec(false);
		setenv("WDTFD", wdt_fd, 1);
	}
	execvp(argv[0], argv);

	/* Cleanup on failure */
	fprintf(stderr, "Failed to exec upgraded.\n");
	unsetenv("WDTFD");
	watchdog_set_cloexec(true);
	ret = chroot(".");
	if (ret < 0) {
		fprintf(stderr, "Failed to reset chroot, exiting.\n");
		exit(EXIT_FAILURE);
	}
}
