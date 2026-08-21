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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <fcntl.h>

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
#include "jail.h"

#define INOTIFY_SZ (sizeof(struct inotify_event) + PATH_MAX + 1)

static const char ubusd_path[] = "/sbin/ubusd";
static const char netifd_path[] = "/sbin/netifd";
static const char ubus_sock_name[] = "ubus.sock";

static char *jail_name, *ubus_sock_path, *ubus_sock_dir, *uci_config_network = NULL;
static bool netifd_start_done;

static char *inotify_buffer;
static struct uloop_fd fd_inotify_read;
static struct passwd *ubus_pw;
static pid_t ns_pid;

static struct ubus_context *host_ubus_ctx = NULL;
static struct ubus_context *jail_ubus_ctx = NULL;

static struct ubus_subscriber config_watch_subscribe;

static const char loopback_network[] =
	"config interface 'loopback'\n"
	"\toption device 'lo'\n"
	"\toption proto 'static'\n"
	"\toption ipaddr '127.0.0.1'\n"
	"\toption netmask '255.0.0.0'\n";

static int gen_jail_uci_network(void)
{
	char *src = NULL, buf[4096];
	FILE *in, *out;
	size_t n;
	int ret = 0;

	if (!uci_config_network)
		return 0;

	out = fopen(uci_config_network, "w");
	if (!out)
		return errno;

	if (asprintf(&src, "/tmp/run/uxc-net/%s.network", jail_name) == -1) {
		fclose(out);
		return ENOMEM;
	}

	in = fopen(src, "r");
	free(src);

	if (in) {
		while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
			if (fwrite(buf, 1, n, out) != n) {
				ret = EIO;
				break;
			}
		fclose(in);
	} else {
		fputs(loopback_network, out);
	}

	fclose(out);

	return ret;
}

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

	if (!ubus_lookup_id(host_ubus_ctx, "container", &id))
		ubus_invoke(host_ubus_ctx, id, "add", req.head, NULL, NULL, 3000);

	blob_buf_free(&req);
}

static void run_netifd(struct uloop_timeout *t)
{
	static struct blob_buf req;
	void *ins, *in, *cmd, *jail, *setns, *setnso, *namespaces, *mount, *pathenv;
	char *resolvconf_dir, *resolvconf, *ucimount, *ubusmount;
	char uci_dir[] = "/var/containers/ujail-uci-XXXXXX";

	uint32_t id;
	bool running = false;

	uloop_fd_delete(&fd_inotify_read);
	close(fd_inotify_read.fd);

	jail_ubus_ctx = ubus_connect(ubus_sock_path);
	if (!jail_ubus_ctx)
		return;

	if (asprintf(&resolvconf_dir, "/tmp/resolv.conf-%s.d", jail_name) == -1)
		return;

	if (asprintf(&resolvconf, "%s/resolv.conf.auto", resolvconf_dir) == -1)
		goto netifd_out_resolvconf_dir;

	if (!mkdtemp(uci_dir))
		goto netifd_out_resolvconf;

	if (asprintf(&uci_config_network, "%s/network", uci_dir) == -1)
		goto netifd_out_ucidir;

	if (asprintf(&ucimount, "%s:/etc/config", uci_dir) == -1)
		goto netifd_out_ucinetconf;

	if (asprintf(&ubusmount, "%s:/var/run/ubus", ubus_sock_dir) == -1)
		goto netifd_out_ucimount;

	if (gen_jail_uci_network())
		goto netifd_out_ubusmount;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", jail_name);
	ins = blobmsg_open_table(&req, "instances");
	in = blobmsg_open_table(&req, "netifd");

	cmd = blobmsg_open_array(&req, "command");
	blobmsg_add_string(&req, "", netifd_path);
	blobmsg_add_string(&req, "", "-r");
	blobmsg_add_string(&req, "", resolvconf);
	blobmsg_close_array(&req, cmd);

	pathenv = blobmsg_open_table(&req, "env");
	blobmsg_add_string(&req, "PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
	blobmsg_close_table(&req, pathenv);

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
	blobmsg_add_string(&req, ubusmount, "1");
	blobmsg_add_string(&req, resolvconf_dir, "1");
	blobmsg_add_string(&req, ucimount, "0");
	blobmsg_add_string(&req, "/bin/cat", "0");
	blobmsg_add_string(&req, "/bin/ipcalc.sh", "0");
	blobmsg_add_string(&req, "/bin/kill", "0");
	blobmsg_add_string(&req, "/bin/ubus", "0");
	blobmsg_add_string(&req, "/etc/hotplug.d", "0");
	blobmsg_add_string(&req, "/lib/config/uci.sh", "0");
	blobmsg_add_string(&req, "/lib/functions", "0");
	blobmsg_add_string(&req, "/lib/functions.sh", "0");
	blobmsg_add_string(&req, "/lib/netifd", "0");
	blobmsg_add_string(&req, "/lib/network", "0");
	blobmsg_add_string(&req, "/usr/bin/awk", "0");
	blobmsg_add_string(&req, "/usr/bin/cut", "0");
	blobmsg_add_string(&req, "/usr/bin/jshn", "0");
	blobmsg_add_string(&req, "/usr/bin/killall", "0");
	blobmsg_add_string(&req, "/usr/bin/logger", "0");
	blobmsg_add_string(&req, "/usr/bin/md5sum", "0");
	blobmsg_add_string(&req, "/usr/bin/ucode", "0");
	blobmsg_add_string(&req, "/usr/lib/ucode", "0");
	blobmsg_add_string(&req, "/usr/share/libubox/jshn.sh", "0");
	blobmsg_add_string(&req, "/usr/share/schema", "0");
	blobmsg_add_string(&req, "/usr/share/ucode/wifi", "0");
	blobmsg_add_string(&req, "/sbin/hotplug-call", "0");
	blobmsg_add_string(&req, "/sbin/uci", "0");
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

	if (!ubus_lookup_id(host_ubus_ctx, "container", &id))
		running = !ubus_invoke(host_ubus_ctx, id, "add", req.head, NULL, NULL, 3000);

	if (!running)
		blob_buf_free(&req);
netifd_out_ubusmount:
	free(ubusmount);
netifd_out_ucimount:
	free(ucimount);
netifd_out_ucinetconf:
	if (!running) {
		unlink(uci_config_network);
		free(uci_config_network);
	}
netifd_out_ucidir:
	if (!running)
		rmdir(uci_dir);
netifd_out_resolvconf:
	free(resolvconf);
netifd_out_resolvconf_dir:
	free(resolvconf_dir);

	netifd_start_done = running;
	uloop_end();
}

static struct uloop_timeout netifd_start_timeout = { .cb = run_netifd, };

static void netifd_start_giveup(struct uloop_timeout *t)
{
	ERROR("timed out waiting for jail netifd to start\n");
	uloop_end();
}

static struct uloop_timeout netifd_giveup_timeout = { .cb = netifd_start_giveup, };

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

		if (!strncmp(ubus_sock_name, in->name, in->len))
			uloop_timeout_add(&netifd_start_timeout);
        }
}

static void netns_updown(struct ubus_context *ubus, const char *name, bool start, int netns_fd)
{
	static struct blob_buf req;
	uint32_t id;

	if (!ubus)
		return;

	blob_buf_init(&req, 0);
	if (name)
		blobmsg_add_string(&req, "jail", name);

	blobmsg_add_u8(&req, "start", start);

	if (ubus_lookup_id(ubus, "network", &id) ||
	    ubus_invoke_fd(ubus, id, "netns_updown", req.head, NULL, NULL, 3000, netns_fd)) {
		INFO("ubus request failed\n");
	}

	blob_buf_free(&req);
}

int jail_network_attach(struct ubus_context *ctx, const char *name, pid_t pid)
{
	int netns_fd;

	netns_fd = ns_open_pid("net", pid);
	if (netns_fd < 0)
		return ESRCH;

	netns_updown(ctx, name, true, netns_fd);
	close(netns_fd);

	return 0;
}

static void jail_network_reload(struct uloop_timeout *t)
{
	uint32_t id;

	if (!jail_ubus_ctx)
		return;

	if (gen_jail_uci_network())
		return;

	if (ubus_lookup_id(jail_ubus_ctx, "network", &id))
		return;

	ubus_invoke(jail_ubus_ctx, id, "reload", NULL, NULL, NULL, 3000);
}

static const struct blobmsg_policy service_watch_policy = { "config", BLOBMSG_TYPE_STRING };
static struct uloop_timeout jail_network_reload_timeout = { .cb = jail_network_reload, };

static int config_watch_notify_cb(struct ubus_context *ctx, struct ubus_object *obj,
			   struct ubus_request_data *req, const char *method,
			   struct blob_attr *msg)
{
	struct blob_attr *attr;
	const char *config;

	if (strcmp(method, "config.change"))
		return 0;

	blobmsg_parse(&service_watch_policy, 1, &attr, blob_data(msg), blob_len(msg));
	if (!attr)
		return 1;

	config = blobmsg_get_string(attr);
	if (strcmp(config, "network"))
		return 0;

	uloop_timeout_add(&jail_network_reload_timeout);

	return 0;
}

static void watch_ubus_service(void)
{
	uint32_t id;

	config_watch_subscribe.cb = config_watch_notify_cb;
	if (ubus_register_subscriber(host_ubus_ctx, &config_watch_subscribe)) {
		ERROR("failed to register ubus subscriber\n");
		return;
	}

	if (ubus_lookup_id(host_ubus_ctx, "service", &id))
		return;

	if (!ubus_subscribe(host_ubus_ctx, &config_watch_subscribe, id))
		return;

	ERROR("failed to subscribe %d\n", id);
}

static struct uloop_timeout ubus_start_timeout = { .cb = run_ubusd, };

static int jail_netifd_arm(void)
{
	fd_inotify_read.fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	fd_inotify_read.cb = inotify_read_handler;
	if (fd_inotify_read.fd == -1) {
		ERROR("failed to initialize inotify handler\n");
		return EIO;
	}
	uloop_fd_add(&fd_inotify_read, ULOOP_READ);

	inotify_buffer = calloc(1, INOTIFY_SZ);
	if (!inotify_buffer)
		goto err_close;

	if (inotify_add_watch(fd_inotify_read.fd, ubus_sock_dir, IN_CREATE) == -1) {
		ERROR("failed to add inotify watch on %s\n", ubus_sock_dir);
		free(inotify_buffer);
		goto err_close;
	}

	watch_ubus_service();

	return 0;

err_close:
	close(fd_inotify_read.fd);
	return EIO;
}

int jail_network_start(struct ubus_context *new_ctx, char *new_jail_name, pid_t new_ns_pid, bool start_netifd)
{
	int ret;

	ubus_pw = getpwnam("ubus");
	host_ubus_ctx = new_ctx;
	ns_pid = new_ns_pid;
	jail_name = new_jail_name;

	if (asprintf(&ubus_sock_dir, "/var/containers/ubus-%s", jail_name) == -1) {
		ret = ENOMEM;
		goto errout_dir;
	}

	if (asprintf(&ubus_sock_path, "%s/%s", ubus_sock_dir, ubus_sock_name) == -1) {
		ret = ENOMEM;
		goto errout_path;
	}

	mkdir_p(ubus_sock_dir, 0755);
	if (ubus_pw && chown(ubus_sock_dir, ubus_pw->pw_uid, ubus_pw->pw_gid)) {
		ret = errno;
		goto errout;
	}

	unlink(ubus_sock_path);

	if (!start_netifd) {
		run_ubusd(NULL);
		return 0;
	}

	ret = jail_netifd_arm();
	if (ret)
		goto errout;

	netifd_start_done = false;
	uloop_timeout_add(&ubus_start_timeout);
	uloop_timeout_set(&netifd_giveup_timeout, 5000);
	uloop_run();
	uloop_timeout_cancel(&netifd_giveup_timeout);

	if (!netifd_start_done)
		ERROR("jail netifd did not come up; container network may be degraded\n");

	return 0;

errout:
	free(ubus_sock_path);
errout_path:
	free(ubus_sock_dir);
errout_dir:
	return ret;
}

static int jail_delete_instance(const char *instance)
{
	static struct blob_buf req;
	uint32_t id;

	if (ubus_lookup_id(host_ubus_ctx, "container", &id))
		return -1;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", jail_name);
	blobmsg_add_string(&req, "instance", instance);

	return ubus_invoke(host_ubus_ctx, id, "delete", req.head, NULL, NULL, 3000);
}

int jail_network_teardown(void)
{
	if (jail_ubus_ctx) {
		ubus_free(jail_ubus_ctx);
		jail_ubus_ctx = NULL;
	}

	jail_delete_instance("netifd");
	jail_delete_instance("ubus");

	if (uci_config_network) {
		unlink(uci_config_network);
		rmdir(dirname(uci_config_network));
		free(uci_config_network);
		uci_config_network = NULL;
	}

	if (ubus_sock_path) {
		free(ubus_sock_path);
		ubus_sock_path = NULL;
	}
	if (ubus_sock_dir) {
		rmdir(ubus_sock_dir);
		free(ubus_sock_dir);
		ubus_sock_dir = NULL;
	}

	return 0;
}
