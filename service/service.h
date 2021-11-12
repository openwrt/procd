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

#ifndef __PROCD_SERVICE_H
#define __PROCD_SERVICE_H

#include <libubox/avl.h>
#include <libubox/vlist.h>
#include <libubox/list.h>
#include "../utils/utils.h"

extern struct avl_tree services;
extern struct avl_tree containers;

struct vrule {
	struct avl_node avl;
	char *option;
	char *rule;
};

struct validate {
	struct avl_node avl;
	struct list_head list;

	char *package;
	char *type;

	struct avl_tree rules;
};

struct service {
	struct avl_node avl;
	const char *name;
	bool deleted;
	bool autostart;
	bool container;

	struct blob_attr *trigger;
	struct vlist_tree instances;
	struct list_head validators;
	struct blob_attr *data;
	struct blobmsg_list data_blob;
};

void service_validate_add(struct service *s, struct blob_attr *attr);
void service_validate_dump(struct blob_buf *b, struct service *s);
void service_validate_dump_all(struct blob_buf *b, char *p, char *s);
int service_start_early(char *name, char *cmdline, char *user, char *group);
void service_stopped(struct service *s);
void service_validate_del(struct service *s);
void service_event(const char *type, const char *service, const char *instance);
void service_stop_all(void);



#endif
