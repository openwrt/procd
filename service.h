#include <libubox/avl.h>
#include <libubox/vlist.h>

struct service {
	struct avl_node avl;
	const char *name;

	struct vlist_tree instances;
};

struct service_instance {
	struct vlist_node node;
	const char *name;

	struct blob_attr *config;
	struct uloop_process proc;
};


