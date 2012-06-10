#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include "utils.h"

void
__blobmsg_list_init(struct blobmsg_list *list, int offset, int len)
{
	avl_init(&list->avl, avl_strcmp, false, NULL);
	list->node_offset = offset;
	list->node_len = len;
}

int
blobmsg_list_fill(struct blobmsg_list *list, void *data, int len)
{
	struct avl_tree *tree = &list->avl;
	struct blobmsg_list_node *node;
	struct blob_attr *cur;
	void *ptr;
	int count = 0;
	int rem = len;

	__blob_for_each_attr(cur, data, rem) {
		if (!blobmsg_check_attr(cur, true))
			continue;

		ptr = calloc(1, list->node_len);
		if (!ptr)
			return -1;

		node = (void *) ((char *)ptr + list->node_offset);
		node->avl.key = blobmsg_name(cur);
		node->data = cur;
		if (avl_insert(tree, &node->avl)) {
			free(ptr);
			continue;
		}

		count++;
	}

	return count;
}

void
blobmsg_list_free(struct blobmsg_list *list)
{
	struct blobmsg_list_node *node, *tmp;
	void *ptr;

	avl_remove_all_elements(&list->avl, node, avl, tmp) {
		ptr = ((char *) node - list->node_offset);
		free(ptr);
	}
}
