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

#include <time.h>
#include <unistd.h>
#include <stdio.h>

#include <libubox/blobmsg_json.h>
#include <libubox/usock.h>
#include <libubox/uloop.h>
#include "libubus.h"

enum {
	LOG_MSG,
	LOG_ID,
	LOG_PRIO,
	LOG_SOURCE,
	LOG_TIME,
	__LOG_MAX
};

static const struct blobmsg_policy log_policy[] = {
	[LOG_MSG] = { .name = "msg", .type = BLOBMSG_TYPE_STRING },
	[LOG_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
	[LOG_PRIO] = { .name = "priority", .type = BLOBMSG_TYPE_INT32 },
	[LOG_SOURCE] = { .name = "source", .type = BLOBMSG_TYPE_INT32 },
	[LOG_TIME] = { .name = "time", .type = BLOBMSG_TYPE_INT64 },
};

enum {
	WATCH_ID,
	WATCH_COUNTER,
	__WATCH_MAX
};

static struct ubus_subscriber log_event;
static struct uloop_fd sender;

static void log_handle_remove(struct ubus_context *ctx, struct ubus_subscriber *s,
			uint32_t id)
{
	fprintf(stderr, "Object %08x went away\n", id);
}

static int log_notify(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__LOG_MAX];
	char buf[256];
	char *str;
	time_t t;
	char *c;

	blobmsg_parse(log_policy, ARRAY_SIZE(log_policy), tb, blob_data(msg), blob_len(msg));
	if (!tb[LOG_ID] || !tb[LOG_PRIO] || !tb[LOG_SOURCE] || !tb[LOG_TIME])
		return 1;

	t = blobmsg_get_u64(tb[LOG_TIME]) / 1000;
	c = ctime(&t);
	c[strlen(c) - 1] = '\0';
	str = blobmsg_format_json(msg, true);
	snprintf(buf, sizeof(buf), "%s - %s: %s\n",
		c, (blobmsg_get_u32(tb[LOG_SOURCE])) ? ("syslog") : ("kernel"), method);
	write(sender.fd, buf, strlen(buf));

	free(str);

	return 0;
}

static void follow_log(struct ubus_context *ctx, int id, const char *url, const char *port)
{
	int ret;

	uloop_init();
	ubus_add_uloop(ctx);

	log_event.remove_cb = log_handle_remove;
	log_event.cb = log_notify;
	ret = ubus_register_subscriber(ctx, &log_event);
	if (ret)
		fprintf(stderr, "Failed to add watch handler: %s\n", ubus_strerror(ret));

	ret = ubus_subscribe(ctx, &log_event, id);
	if (ret)
		fprintf(stderr, "Failed to add watch handler: %s\n", ubus_strerror(ret));

	if (url && port) {
		sender.fd = usock(USOCK_TCP | USOCK_NUMERIC, url, port);
		if (sender.fd < 0) {
			fprintf(stderr, "failed to connect: %s\n", strerror(errno));
			exit(-1);
		} else {
			uloop_fd_add(&sender, ULOOP_READ);
		}
	} else {
		sender.fd = STDOUT_FILENO;
	}

	uloop_run();
	ubus_free(ctx);
	uloop_done();
}

enum {
	READ_LINE,
	__READ_MAX
};

static const struct blobmsg_policy read_policy[] = {
	[READ_LINE] = { .name = "lines", .type = BLOBMSG_TYPE_ARRAY },
};

static void read_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *cur;
	struct blob_attr *_tb[__READ_MAX];
	time_t t;
	int rem;

	if (!msg)
		return;

	blobmsg_parse(read_policy, ARRAY_SIZE(read_policy), _tb, blob_data(msg), blob_len(msg));
	if (!_tb[READ_LINE])
		return;
	blobmsg_for_each_attr(cur, _tb[READ_LINE], rem) {
		struct blob_attr *tb[__LOG_MAX];
		char *c;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE)
			continue;

		blobmsg_parse(log_policy, ARRAY_SIZE(log_policy), tb, blobmsg_data(cur), blobmsg_data_len(cur));
		if (!tb[LOG_MSG] || !tb[LOG_ID] || !tb[LOG_PRIO] || !tb[LOG_SOURCE] || !tb[LOG_TIME])
			continue;

		t = blobmsg_get_u64(tb[LOG_TIME]);
		c = ctime(&t);
		c[strlen(c) - 1] = '\0';
		printf("%s - %s: %s\n",
			c, (blobmsg_get_u32(tb[LOG_SOURCE])) ? ("syslog") : ("kernel"),
			blobmsg_get_string(tb[LOG_MSG]));
	}
}

static int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		"    -s <path>		Path to ubus socket\n"
		"    -l	<count>		Got only the last 'count' messages\n"
		"    -r	<server> <port>	Stream message to a server\n"
		"    -f			Follow log messages\n"
		"\n", prog);
	return 1;
}

int main(int argc, char **argv)
{
	struct ubus_context *ctx;
	uint32_t id;
	const char *ubus_socket = NULL, *url = NULL, *port = NULL;
	int ch, ret, subscribe = 0, lines = 0;
	static struct blob_buf b;

	while ((ch = getopt(argc, argv, "fs:l:r:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		case 'r':
			url = optarg++;
			port = argv[optind++];
			break;
		case 'f':
			subscribe = 1;
			break;
		case 'l':
			lines = atoi(optarg);
			break;
		default:
			return usage(*argv);
		}
	}

	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	ret = ubus_lookup_id(ctx, "log", &id);
	if (ret)
		fprintf(stderr, "Failed to find log object: %s\n", ubus_strerror(ret));

	if (!subscribe || lines) {
		blob_buf_init(&b, 0);
		if (lines)
			blobmsg_add_u32(&b, "lines", lines);
		ubus_invoke(ctx, id, "read", b.head, read_cb, 0, 3000);
	}

	if (subscribe)
		follow_log(ctx, id, url, port);

	return 0;
}
