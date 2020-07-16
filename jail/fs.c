/*
 * Copyright (C) 2015 John Crispin <blogic@openwrt.org>
 * Copyright (C) 2015 Etienne Champetier <champetier.etienne@gmail.com>
 * Copyright (C) 2020 Daniel Golle <daniel@makrotopia.org>
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
#include <libgen.h>

#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>

#include "elf.h"
#include "fs.h"
#include "jail.h"
#include "log.h"

#define UJAIL_NOAFILE "/tmp/.ujailnoafile"

struct mount {
	struct avl_node avl;
	const char *source;
	const char *target;
	const char *filesystemtype;
	unsigned long mountflags;
	const char *optstr;
	int error;
};

struct avl_tree mounts;

int mkdir_p(char *dir, mode_t mask)
{
	char *l = strrchr(dir, '/');
	int ret;

	if (!l)
		return 0;

	*l = '\0';

	if (mkdir_p(dir, mask))
		return -1;

	*l = '/';

	ret = mkdir(dir, mask);
	if (ret && errno == EEXIST)
		return 0;

	if (ret)
		ERROR("mkdir(%s, %d) failed: %m\n", dir, mask);

	return ret;
}

static int do_mount(const char *root, const char *source, const char *target, const char *filesystemtype,
		    unsigned long orig_mountflags, const char *optstr, int error)
{
	struct stat s;
	char new[PATH_MAX];
	int fd;
	bool is_bind = (orig_mountflags & MS_BIND);
	bool is_mask = (source == (void *)(-1));
	unsigned long mountflags = orig_mountflags;

	if (source && is_bind && stat(source, &s)) {
		ERROR("stat(%s) failed: %m\n", source);
		return error;
	}

	snprintf(new, sizeof(new), "%s%s", root, target?target:source);

	if (is_mask) {
		if (stat(new, &s))
			return 0; /* doesn't exists, nothing to mask */

		if (S_ISDIR(s.st_mode)) {/* use empty 0-sized tmpfs for directories */
			if (mount(NULL, new, "tmpfs", MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_NOATIME, "size=0,mode=000"))
				return error;
		} else {
			/* mount-bind 0-sized file having mode 000 */
			if (mount(UJAIL_NOAFILE, new, NULL, MS_BIND, NULL))
				return error;

			if (mount(UJAIL_NOAFILE, new, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_NOATIME, NULL))
				return error;
		}

		DEBUG("masked path %s\n", new);
		return 0;
	}


	if (!is_bind || (source && S_ISDIR(s.st_mode))) {
		mkdir_p(new, 0755);
	} else if (is_bind && source) {
		mkdir_p(dirname(new), 0755);
		snprintf(new, sizeof(new), "%s%s", root, target?target:source);
		fd = creat(new, 0644);
		if (fd == -1) {
			ERROR("creat(%s) failed: %m\n", new);
			return error;
		}
		close(fd);
	}

	if (is_bind) {
		if (mount(source?:new, new, filesystemtype, MS_BIND | (mountflags & MS_REC), optstr)) {
			if (error)
				ERROR("failed to mount -B %s %s: %m\n", source, new);

			return error;
		}
		mountflags |= MS_REMOUNT;
	}

	if (mount(source?:(is_bind?new:NULL), new, filesystemtype, mountflags, optstr)) {
		if (error)
			ERROR("failed to mount %s %s: %m\n", source, new);

		return error;
	}

	DEBUG("mount %s%s %s (%s)\n", (mountflags & MS_BIND)?"-B ":"", source, new,
	      (mountflags & MS_RDONLY)?"ro":"rw");

	return 0;
}

int add_mount(const char *source, const char *target, const char *filesystemtype,
	      unsigned long mountflags, const char *optstr, int error)
{
	assert(target != NULL);

	if (avl_find(&mounts, target))
		return 1;

	struct mount *m;
	m = calloc(1, sizeof(struct mount));
	assert(m != NULL);
	m->avl.key = m->target = strdup(target);
	if (source) {
		if (source != (void*)(-1))
			m->source = strdup(source);
		else
			m->source = (void*)(-1);
	}
	if (filesystemtype)
		m->filesystemtype = strdup(filesystemtype);
	m->mountflags = mountflags;
	m->error = error;

	avl_insert(&mounts, &m->avl);
	DEBUG("adding mount %s %s bind(%d) ro(%d) err(%d)\n", (m->source == (void*)(-1))?"mask":m->source, m->target,
		!!(m->mountflags & MS_BIND), !!(m->mountflags & MS_RDONLY), m->error != 0);

	return 0;
}

int add_mount_bind(const char *path, int readonly, int error)
{
	unsigned long mountflags = MS_BIND;

	if (readonly)
		mountflags |= MS_RDONLY;

	return add_mount(path, path, NULL, mountflags, NULL, error);
}

enum {
	OCI_MOUNT_SOURCE,
	OCI_MOUNT_DESTINATION,
	OCI_MOUNT_TYPE,
	OCI_MOUNT_OPTIONS,
	__OCI_MOUNT_MAX,
};

static const struct blobmsg_policy oci_mount_policy[] = {
	[OCI_MOUNT_SOURCE] = { "source", BLOBMSG_TYPE_STRING },
	[OCI_MOUNT_DESTINATION] = { "destination", BLOBMSG_TYPE_STRING },
	[OCI_MOUNT_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[OCI_MOUNT_OPTIONS] = { "options", BLOBMSG_TYPE_ARRAY },
};

struct mount_opt {
	struct list_head list;
	char *optstr;
};

#ifndef MS_LAZYTIME
#define MS_LAZYTIME (1 << 25)
#endif

static int parseOCImountopts(struct blob_attr *msg, unsigned long *mount_flags, char **mount_data, int *error)
{
	struct blob_attr *cur;
	int rem;
	unsigned long mf = 0;
	char *tmp;
	struct list_head fsopts = LIST_HEAD_INIT(fsopts);
	size_t len = 0;
	struct mount_opt *opt;

	blobmsg_for_each_attr(cur, msg, rem) {
		tmp = blobmsg_get_string(cur);
		if (!strcmp("ro", tmp))
			mf |= MS_RDONLY;
		else if (!strcmp("rw", tmp))
			mf &= ~MS_RDONLY;
		else if (!strcmp("bind", tmp))
			mf = MS_BIND;
		else if (!strcmp("rbind", tmp))
			mf |= MS_BIND | MS_REC;
		else if (!strcmp("sync", tmp))
			mf |= MS_SYNCHRONOUS;
		else if (!strcmp("async", tmp))
			mf &= ~MS_SYNCHRONOUS;
		else if (!strcmp("atime", tmp))
			mf &= ~MS_NOATIME;
		else if (!strcmp("noatime", tmp))
			mf |= MS_NOATIME;
		else if (!strcmp("defaults", tmp))
			mf = 0; /* rw, suid, dev, exec, auto, nouser, and async */
		else if (!strcmp("dev", tmp))
			mf &= ~MS_NODEV;
		else if (!strcmp("nodev", tmp))
			mf |= MS_NODEV;
		else if (!strcmp("iversion", tmp))
			mf |= MS_I_VERSION;
		else if (!strcmp("noiversion", tmp))
			mf &= ~MS_I_VERSION;
		else if (!strcmp("diratime", tmp))
			mf &= ~MS_NODIRATIME;
		else if (!strcmp("nodiratime", tmp))
			mf |= MS_NODIRATIME;
		else if (!strcmp("dirsync", tmp))
			mf |= MS_DIRSYNC;
		else if (!strcmp("exec", tmp))
			mf &= ~MS_NOEXEC;
		else if (!strcmp("noexec", tmp))
			mf |= MS_NOEXEC;
		else if (!strcmp("mand", tmp))
			mf |= MS_MANDLOCK;
		else if (!strcmp("nomand", tmp))
			mf &= ~MS_MANDLOCK;
		else if (!strcmp("relatime", tmp))
			mf |= MS_RELATIME;
		else if (!strcmp("norelatime", tmp))
			mf &= ~MS_RELATIME;
		else if (!strcmp("strictatime", tmp))
			mf |= MS_STRICTATIME;
		else if (!strcmp("nostrictatime", tmp))
			mf &= ~MS_STRICTATIME;
		else if (!strcmp("lazytime", tmp))
			mf |= MS_LAZYTIME;
		else if (!strcmp("nolazytime", tmp))
			mf &= ~MS_LAZYTIME;
		else if (!strcmp("suid", tmp))
			mf &= ~MS_NOSUID;
		else if (!strcmp("nosuid", tmp))
			mf |= MS_NOSUID;
		else if (!strcmp("remount", tmp))
			mf |= MS_REMOUNT;
		else if(!strcmp("nofail", tmp))
			*error = 0;
		else if (!strcmp("auto", tmp) ||
			 !strcmp("noauto", tmp) ||
			 !strcmp("user", tmp) ||
			 !strcmp("group", tmp) ||
			 !strcmp("_netdev", tmp))
			DEBUG("ignoring built-in mount option %s\n", tmp);
		else {
			/* filesystem-specific free-form option */
			opt = calloc(1, sizeof(*opt));
			opt->optstr = tmp;
			list_add_tail(&opt->list, &fsopts);
		}
	};

	*mount_flags = mf;

	list_for_each_entry(opt, &fsopts, list) {
		if (len)
			++len;

		len += strlen(opt->optstr);
	};

	if (!len)
		return 0;

	*mount_data = calloc(len + 1, sizeof(char));
	if (!mount_data)
		return ENOMEM;

	len = 0;
	list_for_each_entry(opt, &fsopts, list) {
		if (len)
			strcat(*mount_data, ",");

		strcat(*mount_data, opt->optstr);
		++len;
	};

	list_del(&fsopts);

	DEBUG("mount flags(%08lx) fsopts(\"%s\")\n", mf, *mount_data?:"");

	return 0;
}

int parseOCImount(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_MOUNT_MAX];
	unsigned long mount_flags = 0;
	char *mount_data = NULL;
	int ret, err = -1;

	blobmsg_parse(oci_mount_policy, __OCI_MOUNT_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_MOUNT_DESTINATION])
		return EINVAL;

	if (tb[OCI_MOUNT_OPTIONS]) {
		ret = parseOCImountopts(tb[OCI_MOUNT_OPTIONS], &mount_flags, &mount_data, &err);
		if (ret)
			return ret;
	}

	return add_mount(tb[OCI_MOUNT_SOURCE] ? blobmsg_get_string(tb[OCI_MOUNT_SOURCE]) : NULL,
		  blobmsg_get_string(tb[OCI_MOUNT_DESTINATION]),
		  tb[OCI_MOUNT_TYPE] ? blobmsg_get_string(tb[OCI_MOUNT_TYPE]) : NULL,
		  mount_flags, mount_data, err);
}

static void build_noafile(void) {
	int fd;

	fd = creat(UJAIL_NOAFILE, 0000);
	if (fd == -1)
		return;

	close(fd);
	return;
}

int mount_all(const char *jailroot) {
	struct library *l;
	struct mount *m;

	build_noafile();

	avl_for_each_element(&libraries, l, avl)
		add_mount_bind(l->path, 1, -1);

	avl_for_each_element(&mounts, m, avl)
		if (do_mount(jailroot, m->source, m->target, m->filesystemtype, m->mountflags, m->optstr, m->error))
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
		add_mount_bind(path, readonly, error);
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
		ERROR("fstat(%s) failed: %m\n", path);
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
		ERROR("failed to mmap %s: %m\n", path);
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
