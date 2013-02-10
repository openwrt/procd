#ifndef __PROCD_HOTPLUG_H
#define __PROCD_HOTPLUG_H

#include <libubox/avl.h>
#include <libubox/blob.h>
#include <libubox/blobmsg.h>
#include <libubox/utils.h>

struct rule_file {
	struct avl_node avl;
	struct blob_attr data[];
};

struct rule_handler {
	const char *name;
	int (*handler)(struct blob_attr *cur, struct blob_attr *msg);
};

struct rule_file *rule_file_get(const char *filename);
void rule_file_free_all(void);
void rule_error(struct blob_attr *cur, const char *msg);
void rule_process_msg(struct rule_file *f, struct blob_attr *msg);
void rule_handle_command(const char *name, struct blob_attr *data);

#endif
