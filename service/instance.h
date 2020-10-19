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

#ifndef __PROCD_INSTANCE_H
#define __PROCD_INSTANCE_H

#include <libubox/vlist.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include "../utils/utils.h"

#define RESPAWN_ERROR	(5 * 60)
#define SIGNALLED_OFFSET 128

struct jail {
	bool procfs;
	bool sysfs;
	bool ubus;
	bool log;
	bool ronly;
	bool netns;
	bool userns;
	bool cgroupsns;
	bool console;
	char *name;
	char *hostname;
	struct blobmsg_list mount;
	int argc;
};

typedef enum instance_watchdog {
	INSTANCE_WATCHDOG_MODE_DISABLED,
	INSTANCE_WATCHDOG_MODE_PASSIVE,
	INSTANCE_WATCHDOG_MODE_ACTIVE,
	__INSTANCE_WATCHDOG_MODE_MAX,
} instance_watchdog_mode_t;

struct watchdog {
	instance_watchdog_mode_t mode;
	uint32_t freq;
	struct uloop_timeout timeout;
};

struct service_instance {
	struct vlist_node node;
	struct service *srv;
	const char *name;

	int8_t nice;
	bool valid;

	char *user;
	uid_t uid;
	gid_t pw_gid;
	char *group;
	gid_t gr_gid;

	bool halt;
	bool restart;
	bool respawn;
	int respawn_count;
	int reload_signal;
	struct timespec start;

	bool trace;
	bool has_jail;
	bool require_jail;
	bool immediately;
	bool no_new_privs;
	struct jail jail;
	char *seccomp;
	char *capabilities;
	char *pidfile;
	char *extroot;
	char *overlaydir;
	char *tmpoverlaysize;
	char *bundle;
	int syslog_facility;
	int exit_code;

	uint32_t term_timeout;
	uint32_t respawn_timeout;
	uint32_t respawn_threshold;
	uint32_t respawn_retry;

	struct blob_attr *config;
	struct uloop_process proc;
	struct uloop_timeout timeout;
	struct ustream_fd _stdout;
	struct ustream_fd _stderr;
	struct ustream_fd console;
	struct ustream_fd console_client;

	struct blob_attr *command;
	struct blob_attr *trigger;
	struct blobmsg_list env;
	struct blobmsg_list data;
	struct blobmsg_list netdev;
	struct blobmsg_list file;
	struct blobmsg_list limits;
	struct blobmsg_list errors;

	struct watchdog watchdog;
};

void instance_start(struct service_instance *in);
void instance_stop(struct service_instance *in, bool halt);
void instance_update(struct service_instance *in, struct service_instance *in_new);
void instance_init(struct service_instance *in, struct service *s, struct blob_attr *config);
void instance_free(struct service_instance *in);
void instance_dump(struct blob_buf *b, struct service_instance *in, int debug);

#endif
