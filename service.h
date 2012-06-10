#ifndef __PROCD_SERVICE_H
#define __PROCD_SERVICE_H

#include <libubox/avl.h>
#include <libubox/vlist.h>

extern struct avl_tree services;

struct service {
	struct avl_node avl;
	const char *name;

	struct blob_attr *config;
	struct vlist_tree instances;
};

#endif
