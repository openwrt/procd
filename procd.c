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

static struct udebug ud;
static struct udebug_buf udb;
static bool udebug_enabled;

static void procd_udebug_vprintf(const char *format, va_list ap)
{
	if (!udebug_enabled)
		return;

	udebug_entry_init(&udb);
	udebug_entry_vprintf(&udb, format, ap);
	udebug_entry_add(&udb);
}

void procd_udebug_printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	procd_udebug_vprintf(format, ap);
	va_end(ap);
}

void procd_udebug_set_enabled(bool val)
{
	static const struct udebug_buf_meta meta = {
		.name = "procd_log",
		.format = UDEBUG_FORMAT_STRING,
	};

	if (udebug_enabled == val)
		return;

	udebug_enabled = val;
	if (!val) {
		ulog_udebug(NULL);
		udebug_buf_free(&udb);
		udebug_free(&ud);
		return;
	}

	udebug_init(&ud);
	udebug_auto_connect(&ud, NULL);
	udebug_buf_init(&udb, 1024, 64 * 1024);
	udebug_buf_add(&ud, &udb, &meta);
	ulog_udebug(&udb);
}


static int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		"	-s <path>	Path to ubus socket\n"
		"	-h <path>	run as hotplug daemon\n"
		"	-d <level>	Enable debug messages\n"
		"	-I <path>	Path to init.d directory\n"
		"	-R <path>	Path to rc.d directory\n"
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

	while ((ch = getopt(argc, argv, "d:s:h:I:R:S")) != -1) {
		switch (ch) {
		case 'h':
			return hotplug_run(optarg);
		case 's':
			ubus_socket = optarg;
			break;
		case 'd':
			debug = atoi(optarg);
			break;
		case 'I':
			init_d_path = optarg;
			break;
		case 'R':
			rc_d_path = optarg;
			break;
		case 'S':
			ulog_channels = ULOG_STDIO;
			break;
		default:
			return usage(argv[0]);
		}
	}

	ulog_open(ulog_channels, LOG_DAEMON, "procd");
	ulog_threshold(LOG_DEBUG + 1);

	setsid();
	uloop_init();
	procd_signal();
	procd_udebug_set_enabled(true);
	if (getpid() != 1)
		procd_connect_ubus();
	else
		procd_state_next();
	uloop_run();
	uloop_done();

	return 0;
}
