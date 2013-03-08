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

#include <linux/watchdog.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>

#include <libubox/uloop.h>

#include "procd.h"
#include "watchdog.h"

#define WDT_PATH	"/dev/watchdog"

static struct uloop_timeout wdt_timeout;
static int wdt_fd = -1;
static int wdt_frequency = 5;

static void watchdog_timeout_cb(struct uloop_timeout *t)
{
	DEBUG(2, "Ping\n");
	if (write(wdt_fd, "X", 1) < 0)
		perror("WDT failed to write\n");
	uloop_timeout_set(t, wdt_frequency * 1000);
}

int watchdog_timeout(int timeout)
{
	if (wdt_fd < 0)
		return 0;

	if (timeout) {
		DEBUG(2, "Set watchdog timeout: %ds\n", timeout);
		ioctl(wdt_fd, WDIOC_SETTIMEOUT, &timeout);
	}
	ioctl(wdt_fd, WDIOC_GETTIMEOUT, &timeout);

	return timeout;
}

int watchdog_frequency(int frequency)
{
	if (wdt_fd < 0)
		return 0;

	if (frequency) {
		DEBUG(2, "Set watchdog frequency: %ds\n", frequency);
		wdt_frequency = frequency;
	}

	return wdt_frequency;
}

char* watchdog_fd(void)
{
	static char fd_buf[3];

	if (wdt_fd < 0)
		return NULL;
	snprintf(fd_buf, sizeof(fd_buf), "%d", wdt_fd);

	return fd_buf;
}

void watchdog_init(void)
{
	char *env = getenv("WDTFD");

	wdt_timeout.cb = watchdog_timeout_cb;
	if (env) {
		LOG("- watchdog -\n");
		DEBUG(1, "Watchdog handover: fd=%s\n", env);
		wdt_fd = atoi(env);
		fcntl(wdt_fd, F_SETFD, fcntl(wdt_fd, F_GETFD) | FD_CLOEXEC);
		unsetenv("WDTFD");
	} else {
		wdt_fd = open("/dev/watchdog", O_WRONLY);
		if (getpid() != 1)
			fcntl(wdt_fd, F_SETFD, fcntl(wdt_fd, F_GETFD) | FD_CLOEXEC);
	}
	if (wdt_fd < 0)
		return;
	watchdog_timeout(30);
	watchdog_timeout_cb(&wdt_timeout);

	DEBUG(2, "Opened watchdog with timeout %ds\n", watchdog_timeout(0));
}
