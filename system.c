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

#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>

#include <libubox/uloop.h>

#include "procd.h"
#include "watchdog.h"

#define HOSTNAME_PATH	"/proc/sys/kernel/hostname"

static struct blob_buf b;
static char *board_name;
static char *board_model;

static int system_info(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct timespec ts;
	struct utsname uts;

	blob_buf_init(&b, 0);
	if (board_name && board_model) {
		blobmsg_add_string(&b, "boardname", board_name);
		blobmsg_add_string(&b, "boardmodel", board_model);
	}
	if (!uname(&uts)) {
		blobmsg_add_string(&b, "hostname", uts.nodename);
		blobmsg_add_string(&b, "machine", uts.machine);
		blobmsg_add_string(&b, "kernel", uts.release);
	}
	if (!clock_gettime(CLOCK_MONOTONIC, &ts))
		blobmsg_add_u32(&b, "uptime", ts.tv_sec);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

enum {
	WDT_FREQUENCY,
	WDT_TIMEOUT,
	__WDT_MAX
};

static const struct blobmsg_policy watchdog_policy[__WDT_MAX] = {
	[WDT_FREQUENCY] = { .name = "frequency", .type = BLOBMSG_TYPE_INT32 },
	[WDT_TIMEOUT] = { .name = "timeout", .type = BLOBMSG_TYPE_INT32 },
};

static int watchdog_set(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__WDT_MAX];

	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_parse(watchdog_policy, __WDT_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[WDT_FREQUENCY]) {
		unsigned int timeout = watchdog_timeout(0);
		unsigned int freq = blobmsg_get_u32(tb[WDT_FREQUENCY]);

		if (freq) {
			if (freq > timeout / 2)
				freq = timeout / 2;
			watchdog_frequency(freq);
		}
	}

	if (tb[WDT_TIMEOUT]) {
		unsigned int timeout = blobmsg_get_u32(tb[WDT_TIMEOUT]);
		unsigned int frequency = watchdog_frequency(0);

		if (timeout <= frequency)
			timeout = frequency * 2;
		 watchdog_timeout(timeout);
	}

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "status", (watchdog_fd() >= 0) ? ("running") : ("offline"));
	blobmsg_add_u32(&b, "timeout", watchdog_timeout(0));
	blobmsg_add_u32(&b, "frequency", watchdog_frequency(0));
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static const struct ubus_method system_methods[] = {
	UBUS_METHOD_NOARG("info", system_info),
	UBUS_METHOD("watchdog", watchdog_set, watchdog_policy),
};

static struct ubus_object_type system_object_type =
	UBUS_OBJECT_TYPE("system", system_methods);

static struct ubus_object system_object = {
	.name = "system",
	.type = &system_object_type,
	.methods = system_methods,
	.n_methods = ARRAY_SIZE(system_methods),
};

static char* load_file_content(const char *file)
{
	char buf[32];
	int fd, r;

	fd = open(file, O_RDONLY);
	if (!fd)
		return NULL;
	r = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (r < 1)
		return NULL;
	if (buf[r - 1] == '\n')
		buf[r - 1] = '\0';
	else
		buf[r] = '\0';

	return strdup(buf);
}

void ubus_init_system(struct ubus_context *ctx)
{
	int ret;

	if (!board_model)
		board_model = load_file_content("/tmp/sysinfo/model");
	if (!board_name);
		board_name = load_file_content("/tmp/sysinfo/board_name");
	ret = ubus_add_object(ctx, &system_object);
	if (ret)
		ERROR("Failed to add object: %s\n", ubus_strerror(ret));
}
