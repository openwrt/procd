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
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include "procd.h"
#include "service.h"
#include "instance.h"
#include "md5.h"

enum {
	INSTANCE_ATTR_COMMAND,
	INSTANCE_ATTR_ENV,
	INSTANCE_ATTR_DATA,
	INSTANCE_ATTR_NETDEV,
	INSTANCE_ATTR_FILE,
	INSTANCE_ATTR_TRIGGER,
	INSTANCE_ATTR_NICE,
	__INSTANCE_ATTR_MAX
};

static const struct blobmsg_policy instance_attr[__INSTANCE_ATTR_MAX] = {
	[INSTANCE_ATTR_COMMAND] = { "command", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_ENV] = { "env", BLOBMSG_TYPE_TABLE },
	[INSTANCE_ATTR_DATA] = { "data", BLOBMSG_TYPE_TABLE },
	[INSTANCE_ATTR_NETDEV] = { "netdev", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_FILE] = { "file", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_TRIGGER] = { "triggers", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_NICE] = { "nice", BLOBMSG_TYPE_INT32 },
};

struct instance_netdev {
	struct blobmsg_list_node node;
	int ifindex;
};

struct instance_file {
	struct blobmsg_list_node node;
	uint32_t md5[4];
};

static void
instance_run(struct service_instance *in)
{
	struct blobmsg_list_node *var;
	struct blob_attr *cur;
	char **argv;
	int argc = 1; /* NULL terminated */
	int rem, fd;

	if (in->nice)
		setpriority(PRIO_PROCESS, 0, in->nice);

	blobmsg_for_each_attr(cur, in->command, rem)
		argc++;

	blobmsg_list_for_each(&in->env, var)
		setenv(blobmsg_name(var->data), blobmsg_data(var->data), 1);

	argv = alloca(sizeof(char *) * argc);
	argc = 0;

	blobmsg_for_each_attr(cur, in->command, rem)
		argv[argc++] = blobmsg_data(cur);

	argv[argc] = NULL;
	fd = open("/dev/null", O_RDWR);
	if (fd > -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	}
	execvp(argv[0], argv);
	exit(127);
}

void
instance_start(struct service_instance *in)
{
	int pid;

	if (in->proc.pending)
		return;

	in->restart = false;
	if (!in->valid)
		return;

	pid = fork();
	if (pid < 0)
		return;

	if (!pid) {
		uloop_done();
		instance_run(in);
		return;
	}

	DEBUG(1, "Started instance %s::%s\n", in->srv->name, in->name);
	in->proc.pid = pid;
	uloop_process_add(&in->proc);
}

static void
instance_timeout(struct uloop_timeout *t)
{
	struct service_instance *in;

	in = container_of(t, struct service_instance, timeout);
	kill(in->proc.pid, SIGKILL);
	uloop_process_delete(&in->proc);
	in->proc.cb(&in->proc, -1);
}

static void
instance_exit(struct uloop_process *p, int ret)
{
	struct service_instance *in;

	in = container_of(p, struct service_instance, proc);
	DEBUG(1, "Instance %s::%s exit with error code %d\n", in->srv->name, in->name, ret);
	uloop_timeout_cancel(&in->timeout);
	if (in->restart)
		instance_start(in);
}

void
instance_stop(struct service_instance *in, bool restart)
{
	if (!in->proc.pending)
		return;

	kill(in->proc.pid, SIGTERM);
}

static bool
instance_config_changed(struct service_instance *in, struct service_instance *in_new)
{
	if (!in->valid)
		return true;

	if (!blob_attr_equal(in->command, in_new->command))
		return true;

	if (!blobmsg_list_equal(&in->env, &in_new->env))
		return true;

	if (!blobmsg_list_equal(&in->data, &in_new->data))
		return true;

	if (!blobmsg_list_equal(&in->netdev, &in_new->netdev))
		return true;

	if (!blobmsg_list_equal(&in->file, &in_new->file))
		return true;

	if (in->nice != in_new->nice)
		return true;

	return false;
}

static bool
instance_netdev_cmp(struct blobmsg_list_node *l1, struct blobmsg_list_node *l2)
{
	struct instance_netdev *n1 = container_of(l1, struct instance_netdev, node);
	struct instance_netdev *n2 = container_of(l2, struct instance_netdev, node);

	return n1->ifindex == n2->ifindex;
}

static void
instance_netdev_update(struct blobmsg_list_node *l)
{
	struct instance_netdev *n = container_of(l, struct instance_netdev, node);

	n->ifindex = if_nametoindex(n->node.avl.key);
}

static bool
instance_file_cmp(struct blobmsg_list_node *l1, struct blobmsg_list_node *l2)
{
	struct instance_file *f1 = container_of(l1, struct instance_file, node);
	struct instance_file *f2 = container_of(l2, struct instance_file, node);

	return !memcmp(f1->md5, f2->md5, sizeof(f1->md5));
}

static void
instance_file_update(struct blobmsg_list_node *l)
{
	struct instance_file *f = container_of(l, struct instance_file, node);
	md5_ctx_t md5;
	char buf[256];
	int len, fd;

	memset(f->md5, 0, sizeof(f->md5));

	fd = open(l->avl.key, O_RDONLY);
	if (fd < 0)
		return;

	md5_begin(&md5);
	do {
		len = read(fd, buf, sizeof(buf));
		if (len < 0) {
			if (errno == EINTR)
				continue;

			break;
		}
		if (!len)
			break;

		md5_hash(buf, len, &md5);
	} while(1);

	md5_end(f->md5, &md5);
	close(fd);
}

static bool
instance_fill_array(struct blobmsg_list *l, struct blob_attr *cur, blobmsg_update_cb cb, bool array)
{
	struct blobmsg_list_node *node;

	if (!cur)
		return true;

	if (!blobmsg_check_attr_list(cur, BLOBMSG_TYPE_STRING))
		return false;

	blobmsg_list_fill(l, blobmsg_data(cur), blobmsg_data_len(cur), array);
	if (cb) {
		blobmsg_list_for_each(l, node)
			cb(node);
	}
	return true;
}

static bool
instance_config_parse(struct service_instance *in)
{
	struct blob_attr *tb[__INSTANCE_ATTR_MAX];
	struct blob_attr *cur, *cur2;
	int argc = 0;
	int rem;

	blobmsg_parse(instance_attr, __INSTANCE_ATTR_MAX, tb,
		blobmsg_data(in->config), blobmsg_data_len(in->config));

	cur = tb[INSTANCE_ATTR_COMMAND];
	if (!cur)
		return false;

	if (!blobmsg_check_attr_list(cur, BLOBMSG_TYPE_STRING))
		return false;

	blobmsg_for_each_attr(cur2, cur, rem) {
		argc++;
		break;
	}
	if (!argc)
		return false;

	in->command = cur;
	in->trigger = tb[INSTANCE_ATTR_TRIGGER];

	if (in->trigger) {
		trigger_add(in->trigger, in);
	}
	if ((cur = tb[INSTANCE_ATTR_NICE])) {
		in->nice = (int8_t) blobmsg_get_u32(cur);
		if (in->nice < -20 || in->nice > 20)
			return false;
	}

	if (!instance_fill_array(&in->env, tb[INSTANCE_ATTR_ENV], NULL, false))
		return false;

	if (!instance_fill_array(&in->data, tb[INSTANCE_ATTR_DATA], NULL, false))
		return false;

	if (!instance_fill_array(&in->netdev, tb[INSTANCE_ATTR_NETDEV], instance_netdev_update, true))
		return false;

	if (!instance_fill_array(&in->file, tb[INSTANCE_ATTR_FILE], instance_file_update, true))
		return false;

	return true;
}

static void
instance_config_cleanup(struct service_instance *in)
{
	blobmsg_list_free(&in->env);
	blobmsg_list_free(&in->data);
	blobmsg_list_free(&in->netdev);
}

static void
instance_config_move(struct service_instance *in, struct service_instance *in_src)
{
	instance_config_cleanup(in);
	blobmsg_list_move(&in->env, &in_src->env);
	blobmsg_list_move(&in->data, &in_src->data);
	blobmsg_list_move(&in->netdev, &in_src->netdev);
	in->trigger = in_src->trigger;
	in->command = in_src->command;
	in->name = in_src->name;
	in->node.avl.key = in_src->node.avl.key;

	free(in->config);
	in->config = in_src->config;
	in_src->config = NULL;
}

bool
instance_update(struct service_instance *in, struct service_instance *in_new)
{
	bool changed = instance_config_changed(in, in_new);
	bool running = in->proc.pending;

	if (!changed && running)
		return false;

	if (!running) {
		if (changed)
			instance_config_move(in, in_new);
		instance_start(in);
	} else {
		in->restart = true;
		instance_stop(in, true);
		instance_config_move(in, in_new);
	}
	return true;
}

void
instance_free(struct service_instance *in)
{
	uloop_process_delete(&in->proc);
	uloop_timeout_cancel(&in->timeout);
	trigger_del(in);
	instance_config_cleanup(in);
	free(in->config);
	free(in);
}

void
instance_init(struct service_instance *in, struct service *s, struct blob_attr *config)
{
	config = blob_memdup(config);
	in->srv = s;
	in->name = blobmsg_name(config);
	in->config = config;
	in->timeout.cb = instance_timeout;
	in->proc.cb = instance_exit;

	blobmsg_list_init(&in->netdev, struct instance_netdev, node, instance_netdev_cmp);
	blobmsg_list_init(&in->file, struct instance_file, node, instance_file_cmp);
	blobmsg_list_simple_init(&in->env);
	blobmsg_list_simple_init(&in->data);
	in->valid = instance_config_parse(in);
}

void instance_dump(struct blob_buf *b, struct service_instance *in, int verbose)
{
	void *i;

	i = blobmsg_open_table(b, in->name);
	blobmsg_add_u8(b, "running", in->proc.pending);
	if (in->proc.pending)
		blobmsg_add_u32(b, "pid", in->proc.pid);
	blobmsg_add_blob(b, in->command);
	if (verbose && in->trigger)
		blobmsg_add_blob(b, in->trigger);
	blobmsg_close_table(b, i);
}
