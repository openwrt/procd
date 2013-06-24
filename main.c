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

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

#include "procd.h"
#include "hotplug.h"
#include "watchdog.h"

static int usage(const char *prog)
{
	ERROR("Usage: %s [options]\n"
		"Options:\n"
		"    -s <path>:		Path to ubus socket\n"
		"    -d:		Enable debug messages\n"
		"\n", prog);
	return 1;
}


static int main_procd_init(int argc, char **argv)
{
	procd_signal_preinit();
	procd_early();
	debug_init();
	watchdog_init();
	system("/sbin/kmodloader /etc/modules-boot.d/");
	uloop_init();
	hotplug("/etc/hotplug-preinit.json");
	procd_preinit();
	uloop_run();
	return 0;
}

int main(int argc, char **argv)
{
	int ch;

	if (!strcmp(basename(*argv), "init"))
		return main_procd_init(argc, argv);

	while ((ch = getopt(argc, argv, "ds:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		case 'd':
			debug++;
			break;
		default:
			return usage(argv[0]);
		}
	}
	umask(0);
	uloop_init();
	procd_signal();
	if (getpid() != 1)
		procd_connect_ubus();
	else
		procd_state_next();
	uloop_run();

	return 0;
}
