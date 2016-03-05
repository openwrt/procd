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

#include <sys/resource.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "procd.h"

char *ubus_socket = NULL;
static struct ubus_context *ctx;
static struct uloop_timeout ubus_timer;
static int timeout;

static void reset_timeout(void)
{
	timeout = 50;
}

static void timeout_retry(void)
{
	uloop_timeout_set(&ubus_timer, timeout);
	timeout *= 2;
	if (timeout > 1000)
		timeout = 1000;
}

static void
ubus_reconnect_cb(struct uloop_timeout *timeout)
{
	if (!ubus_reconnect(ctx, ubus_socket)) {
		ubus_add_uloop(ctx);
		return;
	}

	timeout_retry();
}

static void
ubus_disconnect_cb(struct ubus_context *ctx)
{
	ubus_timer.cb = ubus_reconnect_cb;
	reset_timeout();
	timeout_retry();
}

static void
ubus_connect_cb(struct uloop_timeout *timeout)
{
	ctx = ubus_connect(ubus_socket);

	if (!ctx) {
		DEBUG(4, "Connection to ubus failed\n");
		timeout_retry();
		return;
	}

	ctx->connection_lost = ubus_disconnect_cb;
	ubus_init_service(ctx);
	ubus_init_system(ctx);
	watch_ubus(ctx);

	DEBUG(2, "Connected to ubus, id=%08x\n", ctx->local_id);
	reset_timeout();
	ubus_add_uloop(ctx);
	procd_state_ubus_connect();
}

void
procd_connect_ubus(void)
{
	ubus_timer.cb = ubus_connect_cb;
	reset_timeout();
	timeout_retry();
}
