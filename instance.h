#ifndef __PROCD_INSTANCE_H
#define __PROCD_INSTANCE_H

#include <libubox/vlist.h>
#include <libubox/uloop.h>
#include "utils.h"

struct service_instance {
	struct vlist_node node;
	struct service *srv;
	const char *name;

	bool valid;
	bool restart;
	struct blob_attr *config;
	struct uloop_process proc;
	struct uloop_timeout timeout;

	struct blob_attr *command;
	struct blobmsg_list env;
	struct blobmsg_list data;
};

void instance_start(struct service_instance *in);
void instance_stop(struct service_instance *in, bool restart);
bool instance_update(struct service_instance *in, struct service_instance *in_new);
void instance_init(struct service_instance *in, struct service *s, struct blob_attr *config);
void instance_free(struct service_instance *in);
void instance_dump(struct blob_buf *b, struct service_instance *in);

#endif
