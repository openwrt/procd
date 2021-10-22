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
#include <uci.h>

#include "netifd.h"
#include "log.h"
#include "jail.h"

#define INOTIFY_SZ (sizeof(struct inotify_event) + PATH_MAX + 1)

static const char ubusd_path[] = "/sbin/ubusd";
static const char netifd_path[] = "/sbin/netifd";
static const char uci_net[] = "network";

static char *jail_name, *ubus_sock_path, *ubus_sock_dir, *uci_config_network = NULL;

static char *inotify_buffer;
static struct uloop_fd fd_inotify_read;
static struct passwd *ubus_pw;
static pid_t ns_pid;

static struct ubus_context *host_ubus_ctx = NULL;
static struct ubus_context *jail_ubus_ctx = NULL;

static struct ubus_subscriber config_watch_subscribe;

/* generate /etc/config/network for jail'ed netifd */
static int gen_jail_uci_network(void)
{
	struct uci_context *uci_ctx = uci_alloc_context();
	struct uci_package *pkg = NULL;
	struct uci_element *e, *t;
	bool has_loopback = false;
	int ret = 0;
	FILE *ucinetf;

	/* if no network configuration is active just return */
	if (!uci_config_network)
		goto uci_out;

	/* open output uci network config file */
	ucinetf = fopen(uci_config_network, "w");
	if (!ucinetf) {
		ret = errno;
		goto uci_out;
	}

	/* load network uci package */
	if (uci_load(uci_ctx, uci_net, &pkg) != UCI_OK) {
		char *err;
		uci_get_errorstr(uci_ctx, &err, uci_net);
		fprintf(stderr, "unable to load configuration (%s)\n", err);
		free(err);
		ret = EIO;
		goto ucinetf_out;
	}

	/* remove all sections which don't match jail */
	uci_foreach_element_safe(&pkg->sections, t, e) {
		struct uci_section *s = uci_to_section(e);
		struct uci_option *o = uci_lookup_option(uci_ctx, s, "jail");
		struct uci_ptr ptr = { .p = pkg, .s = s };

		/* keep match, but remove 'jail' option and rename 'jail_ifname' */
		if (o && o->type == UCI_TYPE_STRING && !strcmp(o->v.string, jail_name)) {
			ptr.o = o;
			struct uci_option *jio = uci_lookup_option(uci_ctx, s, "jail_device");
			if (!jio)
				jio = uci_lookup_option(uci_ctx, s, "jail_ifname");

			if (jio) {
				struct uci_ptr ren_ptr = { .p = pkg, .s = s, .o = jio, .value = "device" };
				struct uci_option *host_device = uci_lookup_option(uci_ctx, s, "device");
				struct uci_option *legacy_ifname = uci_lookup_option(uci_ctx, s, "ifname");
				if (host_device && legacy_ifname) {
					struct uci_ptr delif_ptr = { .p = pkg, .s = s, .o = legacy_ifname };
					uci_delete(uci_ctx, &delif_ptr);
				}

				struct uci_ptr renif_ptr = { .p = pkg, .s = s, .o = host_device?:legacy_ifname, .value = "host_device" };
				uci_rename(uci_ctx, &renif_ptr);
				uci_rename(uci_ctx, &ren_ptr);
			}
		}

		uci_delete(uci_ctx, &ptr);
	}

	/* check if device 'lo' is defined by any remaining interfaces */
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		if (strcmp(s->type, "interface"))
			continue;

		const char *devname = uci_lookup_option_string(uci_ctx, s, "device");
		if (devname && !strcmp(devname, "lo")) {
			has_loopback = true;
			break;
		}
	}

	/* create loopback interface section if not defined */
	if (!has_loopback) {
		struct uci_ptr ptr = { .p = pkg, .section = "loopback", .value = "interface" };
		uci_set(uci_ctx, &ptr);
		uci_reorder_section(uci_ctx, ptr.s, 0);
		struct uci_ptr ptr1 = { .p = pkg, .s = ptr.s, .option = "device", .value = "lo" };
		struct uci_ptr ptr2 = { .p = pkg, .s = ptr.s, .option = "proto", .value = "static" };
		struct uci_ptr ptr3 = { .p = pkg, .s = ptr.s, .option = "ipaddr", .value = "127.0.0.1" };
		struct uci_ptr ptr4 = { .p = pkg, .s = ptr.s, .option = "netmask", .value = "255.0.0.0" };
		uci_set(uci_ctx, &ptr1);
		uci_set(uci_ctx, &ptr2);
		uci_set(uci_ctx, &ptr3);
		uci_set(uci_ctx, &ptr4);
	}

	ret = uci_export(uci_ctx, ucinetf, pkg, false);

ucinetf_out:
	fclose(ucinetf);

uci_out:
	uci_free_context(uci_ctx);

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
	void *ins, *in, *cmd, *jail, *setns, *setnso, *namespaces, *mount;
	char *resolvconf_dir, *resolvconf, *ucimount;
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

	if (gen_jail_uci_network())
		goto netifd_out_ucimount;

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
	blobmsg_add_string(&req, ucimount, "0");
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

	if (!ubus_lookup_id(host_ubus_ctx, "container", &id))
		running = !ubus_invoke(host_ubus_ctx, id, "add", req.head, NULL, NULL, 3000);

	if (!running)
		blob_buf_free(&req);
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

	uloop_end();
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

int jail_network_start(struct ubus_context *new_ctx, char *new_jail_name, pid_t new_ns_pid)
{
	ubus_pw = getpwnam("ubus");
	int ret = 0;
	int netns_fd;

	host_ubus_ctx = new_ctx;
	ns_pid = new_ns_pid;
	jail_name = new_jail_name;

	if (asprintf(&ubus_sock_dir, "/var/containers/ubus-%s", jail_name) == -1) {
		ret = ENOMEM;
		goto errout_dir;
	}

	if (asprintf(&ubus_sock_path, "%s/ubus", ubus_sock_dir) == -1) {
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

	watch_ubus_service();

	netns_fd = ns_open_pid("net", ns_pid);
	if (netns_fd < 0) {
		ret = ESRCH;
		goto errout_inotify;
	}

	netns_updown(host_ubus_ctx, jail_name, true, netns_fd);

	close(netns_fd);
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

int jail_network_stop(void)
{
	int host_netns = open("/proc/self/ns/net", O_RDONLY);

	if (host_netns < 0)
		return errno;

	netns_updown(jail_ubus_ctx, NULL, false, host_netns);

	close(host_netns);
	ubus_free(jail_ubus_ctx);

	jail_delete_instance("netifd");
	jail_delete_instance("ubus");

	if (uci_config_network) {
		unlink(uci_config_network);
		rmdir(dirname(uci_config_network));
		free(uci_config_network);
	}

	free(ubus_sock_path);
	rmdir(ubus_sock_dir);
	free(ubus_sock_dir);

	return 0;
}
