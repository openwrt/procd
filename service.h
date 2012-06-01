#include <libubox/avl.h>
#include <libubox/vlist.h>

extern struct avl_tree services;

struct service {
	struct avl_node avl;
	const char *name;

	struct blob_attr *config;
	struct vlist_tree instances;
};

struct service_instance {
	struct vlist_node node;
	const char *name;

	struct blob_attr *config;
	struct uloop_process proc;
};

