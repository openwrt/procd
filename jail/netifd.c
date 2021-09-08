/*
 * Copyright (C) 2021 Daniel Golle <daniel@makrotopia.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * launch private ubus and netifd instances for containers with managed
 * network namespace.
 */

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>

#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <pwd.h>

#include <linux/limits.h>

#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "netifd.h"
#include "log.h"

#define INOTIFY_SZ (sizeof(struct inotify_event) + PATH_MAX + 1)

static char ubusd_path[] = "/sbin/ubusd";
static char netifd_path[] = "/sbin/netifd";

static char *jail_name, *ubus_sock_path, *ubus_sock_dir;

static char *inotify_buffer;
static struct uloop_fd fd_inotify_read;
struct ubus_context *ctx;
static struct passwd *ubus_pw;
static pid_t ns_pid;

static void run_ubusd(struct uloop_timeout *t)
{
	static struct blob_buf req;
	void *ins, *in, *cmd;
	uint32_t id;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", jail_name);
	ins = blobmsg_open_table(&req, "instances");
	in = blobmsg_open_table(&req, "ubus");
	cmd = blobmsg_open_array(&req, "command");
	blobmsg_add_string(&req, "", ubusd_path);
	blobmsg_add_string(&req, "", "-s");
	blobmsg_add_string(&req, "", ubus_sock_path);
	blobmsg_close_array(&req, cmd);

	if (ubus_pw) {
		blobmsg_add_string(&req, "user", "ubus");
		blobmsg_add_string(&req, "group", "ubus");
	}

	blobmsg_close_table(&req, in);
	blobmsg_close_table(&req, ins);

	if (!ubus_lookup_id(ctx, "container", &id))
		ubus_invoke(ctx, id, "add", req.head, NULL, NULL, 3000);

	blob_buf_free(&req);
}


static void run_netifd(struct uloop_timeout *t)
{
	static struct blob_buf req;
	void *ins, *in, *cmd, *jail, *setns, *setnso, *namespaces, *mount;
	char *resolvconf_dir, *resolvconf;
	uint32_t id;

	uloop_fd_delete(&fd_inotify_read);
	close(fd_inotify_read.fd);

	if (asprintf(&resolvconf_dir, "/tmp/resolv.conf-%s.d", jail_name) == -1)
		return;

	if (asprintf(&resolvconf, "%s/resolv.conf.auto", resolvconf_dir) == -1) {
		free(resolvconf_dir);
		return;
	}

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", jail_name);
	ins = blobmsg_open_table(&req, "instances");
	in = blobmsg_open_table(&req, "netifd");

	cmd = blobmsg_open_array(&req, "command");
	blobmsg_add_string(&req, "", netifd_path);
	blobmsg_add_string(&req, "", "-r");
	blobmsg_add_string(&req, "", resolvconf);
	blobmsg_add_string(&req, "", "-s");
	blobmsg_add_string(&req, "", ubus_sock_path);
	blobmsg_close_array(&req, cmd);

	jail = blobmsg_open_table(&req, "jail");

	setns = blobmsg_open_array(&req, "setns");
	setnso = blobmsg_open_table(&req, "");
	blobmsg_add_u32(&req, "pid", ns_pid);
	namespaces = blobmsg_open_array(&req, "namespaces");
	blobmsg_add_string(&req, "", "net");
	blobmsg_add_string(&req, "", "ipc");
	blobmsg_add_string(&req, "", "uts");
	blobmsg_close_array(&req, namespaces);
	blobmsg_close_table(&req, setnso);
	blobmsg_close_array(&req, setns);

	mount = blobmsg_open_table(&req, "mount");
	blobmsg_add_string(&req, ubus_sock_dir, "1");
	blobmsg_add_string(&req, resolvconf_dir, "1");
	blobmsg_add_string(&req, "/etc/hotplug.d", "0");
	blobmsg_add_string(&req, "/lib/functions.sh", "0");
	blobmsg_add_string(&req, "/lib/netifd", "0");
	blobmsg_add_string(&req, "/lib/network", "0");
	blobmsg_add_string(&req, "/usr/bin/logger", "0");
	blobmsg_add_string(&req, "/usr/bin/jshn", "0");
	blobmsg_add_string(&req, "/usr/share/libubox/jshn.sh", "0");
	blobmsg_add_string(&req, "/sbin/hotplug-call", "0");
	blobmsg_add_string(&req, "/sbin/udhcpc", "0");
	blobmsg_close_table(&req, mount);

	blobmsg_add_u8(&req, "log", 1);
	blobmsg_add_u8(&req, "procfs", 1);
	blobmsg_add_u8(&req, "sysfs", 1);

	blobmsg_add_u8(&req, "requirejail", 1);

	blobmsg_close_table(&req, jail);

	blobmsg_add_u8(&req, "stdout", 1);
	blobmsg_add_u8(&req, "stderr", 1);

	blobmsg_close_table(&req, in);
	blobmsg_close_table(&req, ins);

	if (!ubus_lookup_id(ctx, "container", &id))
		ubus_invoke(ctx, id, "add", req.head, NULL, NULL, 3000);

	blob_buf_free(&req);
	free(resolvconf_dir);
	free(resolvconf);

	uloop_end();
}

static int kill_jail_instance(char *instance)
{
	static struct blob_buf req;
	uint32_t id;
	int ret = 0;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", jail_name);
	blobmsg_add_string(&req, "instance", instance);

	if (ubus_lookup_id(ctx, "container", &id) ||
		ubus_invoke(ctx, id, "delete", req.head, NULL, NULL, 3000)) {
		ret = EIO;
	}

	blob_buf_free(&req);

	return ret;
}

static struct uloop_timeout netifd_start_timeout = { .cb = run_netifd, };

static void inotify_read_handler(struct uloop_fd *u, unsigned int events)
{
	int rc;
	char *p;
	struct inotify_event *in;

	/* read inotify events */
	while ((rc = read(u->fd, inotify_buffer, INOTIFY_SZ)) == -1 && errno == EINTR);

	if (rc <= 0)
		return;

	/* process events from buffer */
	for (p = inotify_buffer;
	    rc - (p - inotify_buffer) >= (int)sizeof(struct inotify_event);
	    p += sizeof(struct inotify_event) + in->len) {
		in = (struct inotify_event*)p;

		if (in->len < 4)
			continue;

		if (!strncmp("ubus", in->name, in->len))
			uloop_timeout_add(&netifd_start_timeout);
        }
}

static struct uloop_timeout ubus_start_timeout = { .cb = run_ubusd, };

int jail_network_start(struct ubus_context *new_ctx, char *new_jail_name, pid_t new_ns_pid)
{
	ubus_pw = getpwnam("ubus");
	int ret = 0;

	ctx = new_ctx;
	ns_pid = new_ns_pid;
	jail_name = new_jail_name;

	asprintf(&ubus_sock_dir, "/var/containers/ubus-%s", jail_name);
	if (!ubus_sock_dir) {
		ret = ENOMEM;
		goto errout_dir;
	}

	asprintf(&ubus_sock_path, "%s/ubus", ubus_sock_dir);
	if (!ubus_sock_path) {
		ret = ENOMEM;
		goto errout_path;
	}

	mkdir_p(ubus_sock_dir, 0755);
	if (ubus_pw) {
		ret = chown(ubus_sock_dir, ubus_pw->pw_uid, ubus_pw->pw_gid);
		if (ret) {
			ret = errno;
			goto errout;
		}
	}

	fd_inotify_read.fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	fd_inotify_read.cb = inotify_read_handler;
	if (fd_inotify_read.fd == -1) {
		ERROR("failed to initialize inotify handler\n");
		ret = EIO;
		goto errout;
	}
	uloop_fd_add(&fd_inotify_read, ULOOP_READ);

	inotify_buffer = calloc(1, INOTIFY_SZ);
	if (!inotify_buffer) {
		ret = ENOMEM;
		goto errout_inotify;
	}

	if (inotify_add_watch(fd_inotify_read.fd, ubus_sock_dir, IN_CREATE) == -1) {
		ERROR("failed to add inotify watch on %s\n", ubus_sock_dir);
		free(inotify_buffer);
		ret = EIO;
		goto errout_inotify;
	}

	uloop_timeout_add(&ubus_start_timeout);
	uloop_run();

	return 0;

errout_inotify:
	close(fd_inotify_read.fd);
errout:
	free(ubus_sock_path);
errout_path:
	free(ubus_sock_dir);
errout_dir:
	return ret;
}

int jail_network_stop(void)
{
	int ret;

	ret = kill_jail_instance("netifd");
	if (ret)
		return ret;

	ret = kill_jail_instance("ubus");
	if (ret)
		return ret;

	return 0;
}
