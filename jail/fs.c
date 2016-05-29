/*
 * Copyright (C) 2015 John Crispin <blogic@openwrt.org>
 * Copyright (C) 2015 Etienne Champetier <champetier.etienne@gmail.com>
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

#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include <libubox/avl.h>
#include <libubox/avl-cmp.h>

#include "elf.h"
#include "fs.h"
#include "jail.h"
#include "log.h"

struct mount {
        struct avl_node avl;
        const char *path;
        int readonly;
        int error;
};

struct avl_tree mounts;

int add_mount(const char *path, int readonly, int error)
{
	assert(path != NULL);

	if (avl_find(&mounts, path))
		return 1;

	struct mount *m;
	m = calloc(1, sizeof(struct mount));
	assert(m != NULL);
	m->avl.key = m->path = strdup(path);
	m->readonly = readonly;
	m->error = error;

	avl_insert(&mounts, &m->avl);
	DEBUG("adding mount %s ro(%d) err(%d)\n", m->path, m->readonly, m->error != 0);
	return 0;
}

int mount_all(const char *jailroot) {
	struct library *l;
	struct mount *m;

	avl_for_each_element(&libraries, l, avl)
		add_mount(l->path, 1, -1);

	avl_for_each_element(&mounts, m, avl)
		if (mount_bind(jailroot, m->path, m->readonly, m->error))
			return -1;

	return 0;
}

void mount_list_init(void) {
	avl_init(&mounts, avl_strcmp, false, NULL);
}

static int add_script_interp(const char *path, const char *map, int size)
{
	int start = 2;
	while (start < size && map[start] != '/') {
		start++;
	}
	if (start >= size) {
		ERROR("bad script interp (%s)\n", path);
		return -1;
	}
	int stop = start + 1;
	while (stop < size && map[stop] > 0x20 && map[stop] <= 0x7e) {
		stop++;
	}
	if (stop >= size || (stop-start) > PATH_MAX) {
		ERROR("bad script interp (%s)\n", path);
		return -1;
	}
	char buf[PATH_MAX];
	strncpy(buf, map+start, stop-start);
	return add_path_and_deps(buf, 1, -1, 0);
}

int add_path_and_deps(const char *path, int readonly, int error, int lib)
{
	assert(path != NULL);

	if (lib == 0 && path[0] != '/') {
		ERROR("%s is not an absolute path\n", path);
		return error;
	}

	char *map = NULL;
	int fd, ret = -1;
	if (path[0] == '/') {
		if (avl_find(&mounts, path))
			return 0;
		fd = open(path, O_RDONLY|O_CLOEXEC);
		if (fd == -1)
			return error;
		add_mount(path, readonly, error);
	} else {
		if (avl_find(&libraries, path))
			return 0;
		char *fullpath;
		fd = lib_open(&fullpath, path);
		if (fd == -1)
			return error;
		if (fullpath) {
			alloc_library(fullpath, path);
			free(fullpath);
		}
	}

	struct stat s;
	if (fstat(fd, &s) == -1) {
		ERROR("fstat(%s) failed: %s\n", path, strerror(errno));
		ret = error;
		goto out;
	}

	if (!S_ISREG(s.st_mode)) {
		ret = 0;
		goto out;
	}

	/* too small to be an ELF or a script -> "normal" file */
	if (s.st_size < 4) {
		ret = 0;
		goto out;
	}

	map = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		ERROR("failed to mmap %s\n", path);
		ret = -1;
		goto out;
	}

	if (map[0] == '#' && map[1] == '!') {
		ret = add_script_interp(path, map, s.st_size);
		goto out;
	}

	if (map[0] == ELFMAG0 && map[1] == ELFMAG1 && map[2] == ELFMAG2 && map[3] == ELFMAG3) {
		ret = elf_load_deps(path, map);
		goto out;
	}

	ret = 0;

out:
	if (fd >= 0)
		close(fd);
	if (map)
		munmap(map, s.st_size);

	return ret;
}
