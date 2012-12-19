#ifndef __PROCD_UTILS_H
#define __PROCD_UTILS_H

#include <libubox/avl.h>
#include <libubox/blob.h>
#include <libubox/blobmsg.h>

struct blobmsg_list_node {
	struct avl_node avl;
	struct blob_attr *data;
};

typedef bool (*blobmsg_list_cmp)(struct blobmsg_list_node *l1, struct blobmsg_list_node *l2);
typedef void (*blobmsg_update_cb)(struct blobmsg_list_node *n);

struct blobmsg_list {
	struct avl_tree avl;
	int node_offset;
	int node_len;

	blobmsg_list_cmp cmp;
};

#define blobmsg_list_simple_init(list) \
	__blobmsg_list_init(list, 0, sizeof(struct blobmsg_list_node), NULL)

#define blobmsg_list_init(list, type, field, cmp) \
	__blobmsg_list_init(list, offsetof(type, field), sizeof(type), cmp)

#define blobmsg_list_for_each(list, element) \
	avl_for_each_element(&(list)->avl, element, avl)

void __blobmsg_list_init(struct blobmsg_list *list, int offset, int len, blobmsg_list_cmp cmp);
int blobmsg_list_fill(struct blobmsg_list *list, void *data, int len, bool array);
void blobmsg_list_free(struct blobmsg_list *list);
bool blobmsg_list_equal(struct blobmsg_list *l1, struct blobmsg_list *l2);
void blobmsg_list_move(struct blobmsg_list *list, struct blobmsg_list *src);

#endif
