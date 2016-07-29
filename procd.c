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
#include <sys/reboot.h>

#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

#include "procd.h"
#include "watchdog.h"
#include "plug/hotplug.h"

unsigned int debug;

static int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		"	-s <path>	Path to ubus socket\n"
		"	-h <path>	run as hotplug daemon\n"
		"	-d <level>	Enable debug messages\n"
		"	-S		Print messages to stdout\n"
		"\n", prog);
	return 1;
}

int main(int argc, char **argv)
{
	int ch;
	char *dbglvl = getenv("DBGLVL");
	int ulog_channels = ULOG_KMSG;

	if (dbglvl) {
		debug = atoi(dbglvl);
		unsetenv("DBGLVL");
	}

	while ((ch = getopt(argc, argv, "d:s:h:S")) != -1) {
		switch (ch) {
		case 'h':
			return hotplug_run(optarg);
		case 's':
			ubus_socket = optarg;
			break;
		case 'd':
			debug = atoi(optarg);
			break;
		case 'S':
			ulog_channels = ULOG_STDIO;
			break;
		default:
			return usage(argv[0]);
		}
	}

	ulog_open(ulog_channels, LOG_DAEMON, "procd");

	setsid();
	uloop_init();
	procd_signal();
	if (getpid() != 1)
		procd_connect_ubus();
	else
		procd_state_next();
	uloop_run();
	uloop_done();

	return 0;
}
