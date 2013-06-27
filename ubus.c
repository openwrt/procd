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
static struct uloop_process ubus_proc;
static bool ubus_connected = false;
static struct uloop_timeout retry;
static int reconnect = 1;

static void procd_ubus_connection_lost(struct ubus_context *old_ctx);

static void ubus_proc_cb(struct uloop_process *proc, int ret)
{
	/* nothing to do here */
}

static void procd_restart_ubus(void)
{
	char *argv[] = { "ubusd", NULL, ubus_socket, NULL };

	if (ubus_proc.pending) {
		ERROR("Killing existing ubus instance, pid=%d\n", (int) ubus_proc.pid);
		kill(ubus_proc.pid, SIGKILL);
		uloop_process_delete(&ubus_proc);
	}

	if (ubus_socket)
		argv[1] = "-s";

	ubus_proc.pid = fork();
	if (!ubus_proc.pid) {
		setpriority(PRIO_PROCESS, 0, -20);
		execvp(argv[0], argv);
		exit(-1);
	}

	if (ubus_proc.pid <= 0) {
		ERROR("Failed to start new ubus instance\n");
		return;
	}

	DEBUG(1, "Launched new ubus instance, pid=%d\n", (int) ubus_proc.pid);
	uloop_process_add(&ubus_proc);
}

static void procd_ubus_try_connect(void)
{
	if (ctx) {
		ubus_connected = !ubus_reconnect(ctx, ubus_socket);
		return;
	}
	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		ubus_connected = false;
		DEBUG(2, "Connection to ubus failed\n");
		return;
	}

	ctx->connection_lost = procd_ubus_connection_lost;
	ubus_connected = true;
	ubus_init_service(ctx);
	ubus_init_system(ctx);
	if (getpid() == 1)
		ubus_init_log(ctx);
}

static void
procd_ubus_reconnect_timer(struct uloop_timeout *timeout)
{
	procd_ubus_try_connect();
	if (ubus_connected) {
		DEBUG(1, "Connected to ubus, id=%08x\n", ctx->local_id);
		ubus_add_uloop(ctx);
		return;
	}

	uloop_timeout_set(&retry, 1000);
	procd_restart_ubus();
}

static void procd_ubus_connection_lost(struct ubus_context *old_ctx)
{
	retry.cb = procd_ubus_reconnect_timer;
	procd_restart_ubus();
	uloop_timeout_set(&retry, 1000);
}

void procd_connect_ubus(void)
{
	ubus_proc.cb = ubus_proc_cb;
	procd_ubus_connection_lost(NULL);
}

void procd_reconnect_ubus(int _reconnect)
{
	reconnect = _reconnect;
}

