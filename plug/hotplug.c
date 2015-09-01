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

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/types.h>
#include <linux/netlink.h>

#include <libubox/blobmsg_json.h>
#include <libubox/json_script.h>
#include <libubox/uloop.h>
#include <json-c/json.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>

#include "../procd.h"

#include "hotplug.h"

#define HOTPLUG_WAIT	500

struct cmd_handler;
struct cmd_queue {
	struct list_head list;

	struct blob_attr *msg;
	struct blob_attr *data;
	int timeout;

	void (*handler)(struct blob_attr *msg, struct blob_attr *data);
	void (*start)(struct blob_attr *msg, struct blob_attr *data);
	void (*complete)(struct blob_attr *msg, struct blob_attr *data, int ret);
};

struct button_timeout {
	struct list_head list;
	struct uloop_timeout timeout;
	char *name;
	int seen;
	struct blob_attr *data;
};

static LIST_HEAD(cmd_queue);
static LIST_HEAD(button_timer);
static struct uloop_process queue_proc;
static struct uloop_timeout last_event;
static struct blob_buf b, button_buf;
static char *rule_file;
static struct blob_buf script;
static struct cmd_queue *current;

static void queue_add(struct cmd_handler *h, struct blob_attr *msg, struct blob_attr *data);
static void handle_button_complete(struct blob_attr *msg, struct blob_attr *data, int ret);

static void button_free(struct button_timeout *b)
{
	uloop_timeout_cancel(&b->timeout);
	list_del(&b->list);
	free(b->data);
	free(b->name);
	free(b);
}

static void button_timeout_remove(char *button)
{
	struct button_timeout *b, *c;

	if (!list_empty(&button_timer)) list_for_each_entry_safe(b, c, &button_timer, list) {
		if (!strcmp(b->name, button))
			button_free(b);
	}
}

static char *hotplug_msg_find_var(struct blob_attr *msg, const char *name)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, msg, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		if (strcmp(blobmsg_name(cur), name) != 0)
			continue;

		return blobmsg_data(cur);
	}

	return NULL;
}

static void mkdir_p(char *dir)
{
	char *l = strrchr(dir, '/');

	if (l) {
		*l = '\0';
		mkdir_p(dir);
		*l = '/';
		mkdir(dir, 0755);
	}
}

static void handle_makedev(struct blob_attr *msg, struct blob_attr *data)
{
	unsigned int oldumask = umask(0);
	static struct blobmsg_policy mkdev_policy[2] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[2];
	char *minor = hotplug_msg_find_var(msg, "MINOR");
	char *major = hotplug_msg_find_var(msg, "MAJOR");
	char *subsystem = hotplug_msg_find_var(msg, "SUBSYSTEM");

	blobmsg_parse_array(mkdev_policy, 2, tb, blobmsg_data(data), blobmsg_data_len(data));
	if (tb[0] && tb[1] && minor && major && subsystem) {
		mode_t m = S_IFCHR;
		char *d = strdup(blobmsg_get_string(tb[0]));

		d = dirname(d);
		mkdir_p(d);
		free(d);

		if (!strcmp(subsystem, "block"))
			m = S_IFBLK;
		mknod(blobmsg_get_string(tb[0]),
				m | strtoul(blobmsg_data(tb[1]), NULL, 8),
				makedev(atoi(major), atoi(minor)));
	}
	umask(oldumask);
}

static void handle_rm(struct blob_attr *msg, struct blob_attr *data)
{
	static struct blobmsg_policy rm_policy = {
		.type = BLOBMSG_TYPE_STRING,
	};
	struct blob_attr *tb;

	blobmsg_parse_array(&rm_policy, 1, &tb, blobmsg_data(data), blobmsg_data_len(data));
	if (tb)
		unlink(blobmsg_data(tb));
}

static void handle_exec(struct blob_attr *msg, struct blob_attr *data)
{
	char *argv[8];
	struct blob_attr *cur;
	int rem, fd;
	int i = 0;

	blobmsg_for_each_attr(cur, msg, rem)
		setenv(blobmsg_name(cur), blobmsg_data(cur), 1);

	blobmsg_for_each_attr(cur, data, rem) {
		argv[i] = blobmsg_data(cur);
		i++;
		if (i == 7)
			break;
	}

	if (debug < 3) {
		fd = open("/dev/null", O_RDWR);
		if (fd > -1) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > STDERR_FILENO)
				close(fd);
		}
	}

	if (i > 0) {
		argv[i] = NULL;
		execvp(argv[0], &argv[0]);
	}
	exit(-1);
}

static void handle_button_start(struct blob_attr *msg, struct blob_attr *data)
{
	char *button = hotplug_msg_find_var(msg, "BUTTON");

	if (button)
		button_timeout_remove(button);
}

static void handle_firmware(struct blob_attr *msg, struct blob_attr *data)
{
	char *dir = blobmsg_get_string(blobmsg_data(data));
	char *file = hotplug_msg_find_var(msg, "FIRMWARE");
	char *dev = hotplug_msg_find_var(msg, "DEVPATH");
	struct stat s = { 0 };
	char *path, loadpath[256], syspath[256];
	int fw, src, load, len;
	static char buf[4096];

	DEBUG(2, "Firmware request for %s/%s\n", dir, file);

	if (!file || !dir || !dev) {
		ERROR("Request for unknown firmware %s/%s\n", dir, file);
		exit(-1);
	}

	path = alloca(strlen(dir) + strlen(file) + 2);
	sprintf(path, "%s/%s", dir, file);

	if (stat(path, &s)) {
		ERROR("Could not find firmware %s\n", path);
		src = -1;
		s.st_size = 0;
		goto send_to_kernel;
	}

	src = open(path, O_RDONLY);
	if (src < 0) {
		ERROR("Failed to open %s\n", path);
		s.st_size = 0;
		goto send_to_kernel;
	}

send_to_kernel:
	snprintf(loadpath, sizeof(loadpath), "/sys/%s/loading", dev);
	load = open(loadpath, O_WRONLY);
	if (!load) {
		ERROR("Failed to open %s\n", loadpath);
		exit(-1);
	}
	if (write(load, "1", 1) == -1) {
		ERROR("Failed to write to %s\n", loadpath);
		exit(-1);
	}
	close(load);

	snprintf(syspath, sizeof(syspath), "/sys/%s/data", dev);
	fw = open(syspath, O_WRONLY);
	if (fw < 0) {
		ERROR("Failed to open %s\n", syspath);
		exit(-1);
	}

	len = s.st_size;
	while (len) {
		len = read(src, buf, sizeof(buf));
		if (len <= 0)
			break;

		if (write(fw, buf, len) == -1) {
			ERROR("failed to write firmware file %s/%s to %s\n", dir, file, dev);
			break;
		}
	}

	if (src >= 0)
		close(src);
	close(fw);

	load = open(loadpath, O_WRONLY);
	if (write(load, "0", 1) == -1)
		ERROR("failed to write to %s\n", loadpath);
	close(load);

	DEBUG(2, "Done loading %s\n", path);

	exit(-1);
}

enum {
	HANDLER_MKDEV = 0,
	HANDLER_RM,
	HANDLER_EXEC,
	HANDLER_BUTTON,
	HANDLER_FW,
};

static struct cmd_handler {
	char *name;
	int atomic;
	void (*handler)(struct blob_attr *msg, struct blob_attr *data);
	void (*start)(struct blob_attr *msg, struct blob_attr *data);
	void (*complete)(struct blob_attr *msg, struct blob_attr *data, int ret);
} handlers[] = {
	[HANDLER_MKDEV] = {
		.name = "makedev",
		.atomic = 1,
		.handler = handle_makedev,
	},
	[HANDLER_RM] = {
		.name = "rm",
		.atomic = 1,
		.handler = handle_rm,
	},
	[HANDLER_EXEC] = {
		.name = "exec",
		.handler = handle_exec,
	},
	[HANDLER_BUTTON] = {
		.name = "button",
		.handler = handle_exec,
		.start = handle_button_start,
		.complete = handle_button_complete,
	},
	[HANDLER_FW] = {
		.name = "load-firmware",
		.handler = handle_firmware,
	},
};

static void queue_next(void)
{
	struct cmd_queue *c;

	if (queue_proc.pending || list_empty(&cmd_queue))
		return;

	c = list_first_entry(&cmd_queue, struct cmd_queue, list);

	queue_proc.pid = fork();
	if (!queue_proc.pid) {
		uloop_done();
		c->handler(c->msg, c->data);
		exit(0);
	}
	if (c->start)
		c->start(c->msg, c->data);
	list_del(&c->list);
	if (c->complete)
		current = c;
	else
		free(c);
	if (queue_proc.pid <= 0) {
		queue_next();
		return;
	}

	uloop_process_add(&queue_proc);

	DEBUG(4, "Launched hotplug exec instance, pid=%d\n", (int) queue_proc.pid);
}

static void queue_proc_cb(struct uloop_process *c, int ret)
{
	DEBUG(4, "Finished hotplug exec instance, pid=%d\n", (int) c->pid);

	if (current) {
		current->complete(current->msg, current->data, ret);
		free(current);
		current = NULL;
	}
	queue_next();
}

static void queue_add(struct cmd_handler *h, struct blob_attr *msg, struct blob_attr *data)
{
	struct cmd_queue *c = NULL;
	struct blob_attr *_msg, *_data;

	c = calloc_a(sizeof(struct cmd_queue),
		&_msg, blob_pad_len(msg),
		&_data, blob_pad_len(data),
		NULL);

	c->msg = _msg;
	c->data = _data;

	if (!c)
		return;

	memcpy(c->msg, msg, blob_pad_len(msg));
	memcpy(c->data, data, blob_pad_len(data));
	c->handler = h->handler;
	c->complete = h->complete;
	c->start = h->start;
	list_add_tail(&c->list, &cmd_queue);
	queue_next();
}

static void handle_button_timeout(struct uloop_timeout *t)
{
	struct button_timeout *b;
	char seen[16];

	b = container_of(t, struct button_timeout, timeout);
	blob_buf_init(&button_buf, 0);
	blobmsg_add_string(&button_buf, "BUTTON", b->name);
	blobmsg_add_string(&button_buf, "ACTION", "timeout");
	snprintf(seen, sizeof(seen), "%d", b->seen);
	blobmsg_add_string(&button_buf, "SEEN", seen);
	queue_add(&handlers[HANDLER_EXEC], button_buf.head, b->data);
	button_free(b);
}

static void handle_button_complete(struct blob_attr *msg, struct blob_attr *data, int ret)
{
	char *name = hotplug_msg_find_var(msg, "BUTTON");
	struct button_timeout *b;
	int timeout = ret >> 8;

	if (!timeout)
		return;

	b = malloc(sizeof(*b));
	if (!b || !name)
		return;

	memset(b, 0, sizeof(*b));

	b->data = malloc(blob_pad_len(data));
	b->name = strdup(name);
	b->seen = timeout;

	memcpy(b->data, data, blob_pad_len(data));
	b->timeout.cb = handle_button_timeout;

	uloop_timeout_set(&b->timeout, timeout * 1000);
	list_add(&b->list, &button_timer);
}

static const char* rule_handle_var(struct json_script_ctx *ctx, const char *name, struct blob_attr *vars)
{
	const char *str, *sep;

	if (!strcmp(name, "DEVICENAME") || !strcmp(name, "DEVNAME")) {
		str = json_script_find_var(ctx, vars, "DEVPATH");
		if (!str)
			return NULL;

		sep = strrchr(str, '/');
		if (sep)
			return sep + 1;

		return str;
	}

	return NULL;
}

static struct json_script_file *
rule_handle_file(struct json_script_ctx *ctx, const char *name)
{
	json_object *obj;

	obj = json_object_from_file((char*)name);
	if (!obj)
		return NULL;

	blob_buf_init(&script, 0);
	blobmsg_add_json_element(&script, "", obj);

	return json_script_file_from_blobmsg(name, blob_data(script.head), blob_len(script.head));
}

static void rule_handle_command(struct json_script_ctx *ctx, const char *name,
				struct blob_attr *data, struct blob_attr *vars)
{
	struct blob_attr *cur;
	int rem, i;

	if (debug > 3) {
		DEBUG(4, "Command: %s", name);
		blobmsg_for_each_attr(cur, data, rem)
			DEBUG(4, " %s", (char *) blobmsg_data(cur));
		DEBUG(4, "\n");

		DEBUG(4, "Message:");
		blobmsg_for_each_attr(cur, vars, rem)
			DEBUG(4, " %s=%s", blobmsg_name(cur), (char *) blobmsg_data(cur));
		DEBUG(4, "\n");
	}

	for (i = 0; i < ARRAY_SIZE(handlers); i++)
		if (!strcmp(handlers[i].name, name)) {
			if (handlers[i].atomic)
				handlers[i].handler(vars, data);
			else
				queue_add(&handlers[i], vars, data);
			break;
		}

	if (last_event.cb)
		uloop_timeout_set(&last_event, HOTPLUG_WAIT);
}

static void rule_handle_error(struct json_script_ctx *ctx, const char *msg,
				struct blob_attr *context)
{
	char *s;

	s = blobmsg_format_json(context, false);
	ERROR("ERROR: %s in block: %s\n", msg, s);
	free(s);
}

static struct json_script_ctx jctx = {
	.handle_var = rule_handle_var,
	.handle_error = rule_handle_error,
	.handle_command = rule_handle_command,
	.handle_file = rule_handle_file,
};

static void hotplug_handler_debug(struct blob_attr *data)
{
	char *str;

	if (debug < 3)
		return;

	str = blobmsg_format_json(data, true);
	DEBUG(3, "%s\n", str);
	free(str);
}

static void hotplug_handler(struct uloop_fd *u, unsigned int ev)
{
	int i = 0;
	static char buf[4096];
	int len = recv(u->fd, buf, sizeof(buf), MSG_DONTWAIT);
	void *index;
	if (len < 1)
		return;

	blob_buf_init(&b, 0);
	index = blobmsg_open_table(&b, NULL);
	while (i < len) {
		int l = strlen(buf + i) + 1;
		char *e = strstr(&buf[i], "=");

		if (e) {
			*e = '\0';
			blobmsg_add_string(&b, &buf[i], &e[1]);
		}
		i += l;
	}
	blobmsg_close_table(&b, index);
	hotplug_handler_debug(b.head);
	json_script_run(&jctx, rule_file, blob_data(b.head));
}

static struct uloop_fd hotplug_fd = {
	.cb = hotplug_handler,
};

void hotplug_last_event(uloop_timeout_handler handler)
{
	last_event.cb = handler;
	if (handler)
		uloop_timeout_set(&last_event, HOTPLUG_WAIT);
	else
		uloop_timeout_cancel(&last_event);
}

void hotplug(char *rules)
{
	struct sockaddr_nl nls;
	int nlbufsize = 512 * 1024;

	rule_file = strdup(rules);
	memset(&nls,0,sizeof(struct sockaddr_nl));
	nls.nl_family = AF_NETLINK;
	nls.nl_pid = getpid();
	nls.nl_groups = -1;

	if ((hotplug_fd.fd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT)) == -1) {
		ERROR("Failed to open hotplug socket: %s\n", strerror(errno));
		exit(1);
	}
	if (bind(hotplug_fd.fd, (void *)&nls, sizeof(struct sockaddr_nl))) {
		ERROR("Failed to bind hotplug socket: %s\n", strerror(errno));
		exit(1);
	}

	if (setsockopt(hotplug_fd.fd, SOL_SOCKET, SO_RCVBUFFORCE, &nlbufsize, sizeof(nlbufsize)))
		ERROR("Failed to resize receive buffer: %s\n", strerror(errno));

	json_script_init(&jctx);
	queue_proc.cb = queue_proc_cb;
	uloop_fd_add(&hotplug_fd, ULOOP_READ);
}

int hotplug_run(char *rules)
{
	uloop_init();
	hotplug(rules);
	uloop_run();

	return 0;
}

void hotplug_shutdown(void)
{
	uloop_fd_delete(&hotplug_fd);
	close(hotplug_fd.fd);
}
