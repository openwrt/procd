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

#include <libubox/uloop.h>
#include <libubus.h>

#include <limits.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <regex.h>
#include <unistd.h>
#include <stdio.h>

#if defined(WITH_SELINUX)
#include <selinux/selinux.h>
#endif

#include "../utils/utils.h"
#include "init.h"
#include "../watchdog.h"

unsigned int debug = 0;

static void
signal_shutdown(int signal, siginfo_t *siginfo, void *data)
{
	fprintf(stderr, "reboot\n");
	fflush(stderr);
	sync();
	sleep(2);
	reboot(RB_AUTOBOOT);
	while (1)
		;
}

static struct sigaction sa_shutdown = {
	.sa_sigaction = signal_shutdown,
	.sa_flags = SA_SIGINFO
};

static void
cmdline(void)
{
	char line[20];
	char* res;
	long	r;

	res = get_cmdline_val("init_debug", line, sizeof(line));
	if (res != NULL) {
		r = strtol(line, NULL, 10);
		if ((r != LONG_MIN) && (r != LONG_MAX))
			debug = (int) r;
	}
}

#if defined(WITH_SELINUX)
static int
selinux(char **argv)
{
	int enforce = 0;
	int ret;

	/* SELinux already initialized */
	if (getenv("SELINUX_INIT"))
		return 0;

	putenv("SELINUX_INIT=1");

	ret = selinux_init_load_policy(&enforce);
	if (ret == 0)
		execv(argv[0], argv);

	if (enforce > 0) {
		fprintf(stderr, "Cannot load SELinux policy, but system in enforcing mode. Halting.\n");
		return 1;
	}

	return 0;
}
#else
static int
selinux(char **argv)
{
	return 0;
}
#endif

int
main(int argc, char **argv)
{
	pid_t pid;

	ulog_open(ULOG_KMSG, LOG_DAEMON, "init");

	sigaction(SIGTERM, &sa_shutdown, NULL);
	sigaction(SIGUSR1, &sa_shutdown, NULL);
	sigaction(SIGUSR2, &sa_shutdown, NULL);
	sigaction(SIGPWR, &sa_shutdown, NULL);

	if (selinux(argv))
		exit(-1);
	early();
	cmdline();
	watchdog_init(1);

	pid = fork();
	if (!pid) {
		char *kmod[] = { "/sbin/kmodloader", "/etc/modules-boot.d/", NULL };

		if (debug < 3)
			patch_stdio("/dev/null");

		execvp(kmod[0], kmod);
		ERROR("Failed to start kmodloader: %m\n");
		exit(EXIT_FAILURE);
	}
	if (pid <= 0) {
		ERROR("Failed to start kmodloader instance: %m\n");
	} else {
		const struct timespec req = {0, 10 * 1000 * 1000};
		int i;

		for (i = 0; i < 1200; i++) {
			if (waitpid(pid, NULL, WNOHANG) > 0)
				break;
			nanosleep(&req, NULL);
			watchdog_ping();
		}
	}
	uloop_init();
	preinit();
	uloop_run();

	return 0;
}
