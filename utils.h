#ifndef __PROCD_UTILS_H
#define __PROCD_UTILS_H

#include <libubox/avl.h>
#include <libubox/blob.h>
#include <libubox/blobmsg.h>

struct blobmsg_list {
	struct avl_tree avl;
	int node_offset;
	int node_len;
};

struct blobmsg_list_node {
	struct avl_node avl;
	struct blob_attr *data;
};

#define blobmsg_list_simple_init(list) \
	__blobmsg_list_init(list, 0, sizeof(struct blobmsg_list_node))

#define blobmsg_list_init(list, type, field) \
	__blobmsg_list_init(list, offsetof(type, field), sizeof(type))

void __blobmsg_list_init(struct blobmsg_list *list, int offset, int len);
int blobmsg_list_fill(struct blobmsg_list *list, void *data, int len);
void blobmsg_list_free(struct blobmsg_list *list);
bool blobmsg_list_equal(struct blobmsg_list *l1, struct blobmsg_list *l2);
void blobmsg_list_move(struct blobmsg_list *list, struct blobmsg_list *src);

#endif
