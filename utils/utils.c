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

#define _GNU_SOURCE
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include "utils.h"
#include <regex.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "../log.h"

void
__blobmsg_list_init(struct blobmsg_list *list, int offset, int len, blobmsg_list_cmp cmp)
{
	avl_init(&list->avl, avl_strcmp, false, NULL);
	list->node_offset = offset;
	list->node_len = len;
	list->cmp = cmp;
}

int
blobmsg_list_fill(struct blobmsg_list *list, void *data, int len, bool array)
{
	struct avl_tree *tree = &list->avl;
	struct blobmsg_list_node *node;
	struct blob_attr *cur;
	void *ptr;
	int count = 0;
	int rem = len;

	__blob_for_each_attr(cur, data, rem) {
		if (!blobmsg_check_attr(cur, !array))
			continue;

		ptr = calloc(1, list->node_len);
		if (!ptr)
			return -1;

		node = (void *) ((char *)ptr + list->node_offset);
		if (array)
			node->avl.key = blobmsg_data(cur);
		else
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
blobmsg_list_move(struct blobmsg_list *list, struct blobmsg_list *src)
{
	struct blobmsg_list_node *node, *tmp;
	void *ptr;

	avl_remove_all_elements(&src->avl, node, avl, tmp) {
		if (avl_insert(&list->avl, &node->avl)) {
			ptr = ((char *) node - list->node_offset);
			free(ptr);
		}
	}
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

bool
blobmsg_list_equal(struct blobmsg_list *l1, struct blobmsg_list *l2)
{
	struct blobmsg_list_node *n1, *n2;
	int count = l1->avl.count;

	if (count != l2->avl.count)
		return false;

	n1 = avl_first_element(&l1->avl, n1, avl);
	n2 = avl_first_element(&l2->avl, n2, avl);

	while (count-- > 0) {
		int len;

		len = blob_len(n1->data);
		if (len != blob_len(n2->data))
			return false;

		if (memcmp(n1->data, n2->data, len) != 0)
			return false;

		if (l1->cmp && !l1->cmp(n1, n2))
			return false;

		if (!count)
			break;

		n1 = avl_next_element(n1, avl);
		n2 = avl_next_element(n2, avl);
	}

	return true;
}

char* get_cmdline_val(const char* name, char* out, int len)
{
	char line[CMDLINE_SIZE + 1], *c, *sptr;
	int fd = open("/proc/cmdline", O_RDONLY);
	ssize_t r = read(fd, line, sizeof(line) - 1);
	close(fd);

	if (r <= 0)
		return NULL;

	line[r] = 0;

	for (c = strtok_r(line, " \t\n", &sptr); c;
			c = strtok_r(NULL, " \t\n", &sptr)) {
		char *sep = strchr(c, '=');
		ssize_t klen = sep - c;
		if (klen < 0 || strncmp(name, c, klen) || name[klen] != 0)
			continue;

		strncpy(out, &sep[1], len);
		out[len-1] = 0;
		return out;
	}

	return NULL;
}

int patch_fd(const char *device, int fd, int flags)
{
	int dfd, nfd;

	if (device == NULL)
		device = "/dev/null";

	if (*device != '/') {
		dfd = open("/dev", O_PATH|O_DIRECTORY);

		if (dfd < 0)
			return -1;

		nfd = openat(dfd, device, flags);

		close(dfd);
	} else {
		nfd = open(device, flags);
	}

	if (nfd < 0 && strcmp(device, "/dev/null"))
		nfd = open("/dev/null", flags);

	if (nfd < 0)
		return -1;

	fd = dup2(nfd, fd);

	if (nfd > STDERR_FILENO)
		close(nfd);

	return (fd < 0) ? -1 : 0;
}

int patch_stdio(const char *device)
{
	int fd, rv = 0;
	const char *fdname[3] = { "stdin", "stdout", "stderr" };

	for (fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
		if (patch_fd(device, fd, fd ? O_WRONLY : O_RDONLY)) {
			ERROR("Failed to redirect %s to %s: %d (%s)\n",
			      fdname[fd], device, errno, strerror(errno));
			rv = -1;
		}
	}

	return rv;
}
