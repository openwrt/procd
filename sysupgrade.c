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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libubox/blobmsg.h>

void sysupgrade_exec_upgraded(const char *prefix, char *path, char *command,
			      struct blob_attr *options)
{
	char *wdt_fd = watchdog_fd();
	char *argv[] = { "/sbin/upgraded", NULL, NULL, NULL};
	struct blob_attr *option;
	int rem;
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

	blobmsg_for_each_attr(option, options, rem) {
		const char *prefix = "UPGRADE_OPT_";
		char value[11];
		char *name;
		char *c;
		int tmp;

		if (asprintf(&name, "%s%s", prefix, blobmsg_name(option)) <= 0)
			continue;
		for (c = name + strlen(prefix); *c; c++) {
			if (isalnum(*c) || *c == '_') {
				*c = toupper(*c);
			} else {
				c = NULL;
				break;
			}
		}

		if (!c) {
			fprintf(stderr, "Option \"%s\" contains invalid characters\n",
				blobmsg_name(option));
			free(name);
			continue;
		}

		switch (blobmsg_type(option)) {
		case BLOBMSG_TYPE_INT32:
			tmp = blobmsg_get_u32(option);
			break;
		case BLOBMSG_TYPE_INT16:
			tmp = blobmsg_get_u16(option);
			break;
		case BLOBMSG_TYPE_INT8:
			tmp = blobmsg_get_u8(option);
			break;
		default:
			fprintf(stderr, "Option \"%s\" has unsupported type: %d\n",
				blobmsg_name(option), blobmsg_type(option));
			free(name);
			continue;
		}
		snprintf(value, sizeof(value), "%u", tmp);

		setenv(name, value, 1);

		free(name);
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
