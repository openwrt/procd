#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <libubus.h>

#include "procd.h"

char *ubus_socket = NULL;
static struct ubus_context *ctx;
static struct uloop_process ubus_proc;
static bool ubus_connected = false;

static void procd_ubus_connection_lost(struct ubus_context *old_ctx);

static void ubus_proc_cb(struct uloop_process *proc, int ret)
{
	/* nothing to do here */
}

static void procd_restart_ubus(void)
{
	char *argv[] = { "ubusd", NULL, ubus_socket, NULL };

	if (ubus_proc.pending) {
		DPRINTF("Killing existing ubus instance, pid=%d\n", (int) ubus_proc.pid);
		kill(ubus_proc.pid, SIGKILL);
		uloop_process_delete(&ubus_proc);
	}

	if (ubus_socket)
		argv[1] = "-s";

	ubus_proc.pid = fork();
	if (!ubus_proc.pid) {
		execvp(argv[0], argv);
		exit(-1);
	}

	if (ubus_proc.pid <= 0) {
		DPRINTF("Failed to start new ubus instance\n");
		return;
	}

	DPRINTF("Launched new ubus instance, pid=%d\n", (int) ubus_proc.pid);
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
		DPRINTF("Connection to ubus failed\n");
		return;
	}

	ctx->connection_lost = procd_ubus_connection_lost;
	ubus_connected = true;
}

static void procd_ubus_connection_lost(struct ubus_context *old_ctx)
{
	procd_ubus_try_connect();
	while (!ubus_connected) {
		procd_restart_ubus();
		sleep(1);
		procd_ubus_try_connect();
	}

	DPRINTF("Connected to ubus, id=%08x\n", ctx->local_id);
	ubus_add_uloop(ctx);
}

void procd_connect_ubus(void)
{
	ubus_proc.cb = ubus_proc_cb;
	procd_ubus_connection_lost(NULL);
}

