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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <libgen.h>

#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>
#include <libubox/utils.h>

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
	unsigned long propflags;
	const char *optstr;
	int error;
	bool inner;
};

struct avl_tree mounts;

static int do_mount(const char *root, const char *orig_source, const char *target, const char *filesystemtype,
		    unsigned long orig_mountflags, unsigned long propflags, const char *optstr, int error, bool inner)
{
	struct stat s;
	char new[PATH_MAX];
	char *source = (char *)orig_source;
	int fd, ret = 0;
	bool is_bind = (orig_mountflags & MS_BIND);
	bool is_mask = (source == (void *)(-1));
	unsigned long mountflags = orig_mountflags;

	assert(!(inner && is_mask));
	assert(!(inner && !orig_source));

	if (source && is_bind && stat(source, &s)) {
		if (error)
			ERROR("stat(%s) failed: %m\n", source);
		return error;
	}

	if (inner)
		if (asprintf(&source, "%s%s", root, orig_source) < 0)
			return ENOMEM;

	snprintf(new, sizeof(new), "%s%s", root, target?target:source);

	if (is_mask) {
		if (stat(new, &s))
			return 0; /* doesn't exists, nothing to mask */

		if (S_ISDIR(s.st_mode)) {/* use empty 0-sized tmpfs for directories */
			if (mount("none", new, "tmpfs", MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_NOATIME, "size=0,mode=000"))
				return error;
		} else {
			/* mount-bind 0-sized file having mode 000 */
			if (mount(UJAIL_NOAFILE, new, "bind", MS_BIND, NULL))
				return error;

			if (mount(UJAIL_NOAFILE, new, "bind", MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_NOATIME, NULL))
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
		fd = open(new, O_CREAT|O_WRONLY|O_TRUNC|O_EXCL, 0644);
		if (fd >= 0)
			close(fd);

		if (error && fd < 0 && errno != EEXIST) {
			ERROR("failed to create mount target %s: %m\n", new);

			ret = errno;
			goto free_source_out;
		}
	}

	if (is_bind) {
		if (mount(source?:new, new, filesystemtype?:"bind", MS_BIND | (mountflags & MS_REC), optstr)) {
			if (error)
				ERROR("failed to mount -B %s %s: %m\n", source, new);

			ret = error;
			goto free_source_out;
		}
		mountflags |= MS_REMOUNT;
	}

	const char *hack_fstype = ((!filesystemtype || strcmp(filesystemtype, "cgroup"))?filesystemtype:"cgroup2");
	if (mount(source?:(is_bind?new:NULL), new, hack_fstype?:"none", mountflags, optstr)) {
		if (error)
			ERROR("failed to mount %s %s: %m\n", source, new);

		ret = error;
		goto free_source_out;
	}

	DEBUG("mount %s%s %s (%s)\n", (mountflags & MS_BIND)?"-B ":"", source, new,
	      (mountflags & MS_RDONLY)?"ro":"rw");

	if (propflags && mount("none", new, "none", propflags, NULL)) {
		if (error)
			ERROR("failed to mount --make-... %s \n", new);

		ret = error;
	}

free_source_out:
	if (inner)
		free(source);

	return ret;
}

static int _add_mount(const char *source, const char *target, const char *filesystemtype,
		      unsigned long mountflags, unsigned long propflags, const char *optstr,
		      int error, bool inner)
{
	assert(target != NULL);

	if (avl_find(&mounts, target))
		return 1;

	struct mount *m;
	m = calloc(1, sizeof(struct mount));
	if (!m)
		return ENOMEM;

	m->avl.key = m->target = strdup(target);
	if (source) {
		if (source != (void*)(-1))
			m->source = strdup(source);
		else
			m->source = (void*)(-1);
	}
	if (filesystemtype)
		m->filesystemtype = strdup(filesystemtype);

	if (optstr)
		m->optstr = strdup(optstr);

	m->mountflags = mountflags;
	m->propflags = propflags;
	m->error = error;
	m->inner = inner;

	avl_insert(&mounts, &m->avl);
	DEBUG("adding mount %s %s bind(%d) ro(%d) err(%d)\n", (m->source == (void*)(-1))?"mask":m->source, m->target,
		!!(m->mountflags & MS_BIND), !!(m->mountflags & MS_RDONLY), m->error != 0);

	return 0;
}

int add_mount(const char *source, const char *target, const char *filesystemtype,
	      unsigned long mountflags, unsigned long propflags, const char *optstr, int error)
{
	return _add_mount(source, target, filesystemtype, mountflags, propflags, optstr, error, false);
}

int add_mount_inner(const char *source, const char *target, const char *filesystemtype,
	      unsigned long mountflags, unsigned long propflags, const char *optstr, int error)
{
	return _add_mount(source, target, filesystemtype, mountflags, propflags, optstr, error, true);
}

static int _add_mount_bind(const char *path, const char *path2, int readonly, int error)
{
	unsigned long mountflags = MS_BIND;

	if (readonly)
		mountflags |= MS_RDONLY;

	return add_mount(path, path2, NULL, mountflags, 0, NULL, error);
}

int add_mount_bind(const char *path, int readonly, int error)
{
	return _add_mount_bind(path, path, readonly, error);
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

static int parseOCImountopts(struct blob_attr *msg, unsigned long *mount_flags, unsigned long *propagation_flags, char **mount_data, int *error)
{
	struct blob_attr *cur;
	int rem;
	unsigned long mf = 0;
	unsigned long pf = 0;
	char *tmp;
	struct list_head fsopts = LIST_HEAD_INIT(fsopts);
	size_t len = 0;
	struct mount_opt *opt, *tmpopt;

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
		/* propagation flags */
		else if (!strcmp("private", tmp))
			pf |= MS_PRIVATE;
		else if (!strcmp("rprivate", tmp))
			pf |= MS_PRIVATE | MS_REC;
		else if (!strcmp("slave", tmp))
			pf |= MS_SLAVE;
		else if (!strcmp("rslave", tmp))
			pf |= MS_SLAVE | MS_REC;
		else if (!strcmp("shared", tmp))
			pf |= MS_SHARED;
		else if (!strcmp("rshared", tmp))
			pf |= MS_SHARED | MS_REC;
		else if (!strcmp("unbindable", tmp))
			pf |= MS_UNBINDABLE;
		else if (!strcmp("runbindable", tmp))
			pf |= MS_UNBINDABLE | MS_REC;
		/* special case: 'nofail' */
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
	*propagation_flags = pf;

	list_for_each_entry(opt, &fsopts, list) {
		if (len)
			++len;

		len += strlen(opt->optstr);
	};

	if (len) {
		*mount_data = calloc(len + 1, sizeof(char));
		if (!(*mount_data))
			return ENOMEM;

		len = 0;
		list_for_each_entry(opt, &fsopts, list) {
			if (len)
				strcat(*mount_data, ",");

			strcat(*mount_data, opt->optstr);
			++len;
		}

		list_for_each_entry_safe(opt, tmpopt, &fsopts, list) {
			list_del(&opt->list);
			free(opt);
		}
	}

	DEBUG("mount flags(%08lx) propagation(%08lx) fsopts(\"%s\")\n", mf, pf, *mount_data?:"");

	return 0;
}

int parseOCImount(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_MOUNT_MAX];
	unsigned long mount_flags = 0;
	unsigned long propagation_flags = 0;
	char *mount_data = NULL;
	int ret, err = -1;

	blobmsg_parse(oci_mount_policy, __OCI_MOUNT_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_MOUNT_DESTINATION])
		return EINVAL;

	if (tb[OCI_MOUNT_OPTIONS]) {
		ret = parseOCImountopts(tb[OCI_MOUNT_OPTIONS], &mount_flags, &propagation_flags, &mount_data, &err);
		if (ret)
			return ret;
	}

	ret = add_mount(tb[OCI_MOUNT_SOURCE] ? blobmsg_get_string(tb[OCI_MOUNT_SOURCE]) : NULL,
		  blobmsg_get_string(tb[OCI_MOUNT_DESTINATION]),
		  tb[OCI_MOUNT_TYPE] ? blobmsg_get_string(tb[OCI_MOUNT_TYPE]) : NULL,
		  mount_flags, propagation_flags, mount_data, err);

	if (mount_data)
		free(mount_data);

	return ret;
}

static void build_noafile(void) {
	int fd;

	fd = creat(UJAIL_NOAFILE, 0000);
	if (fd < 0)
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
		if (do_mount(jailroot, m->source, m->target, m->filesystemtype, m->mountflags,
			     m->propflags, m->optstr, m->error, m->inner))
			return -1;

	return 0;
}

void mount_free(void) {
	struct mount *m, *tmp;

	avl_remove_all_elements(&mounts, m, avl, tmp) {
		if (m->source != (void*)(-1))
			free((void*)m->source);
		free((void*)m->target);
		free((void*)m->filesystemtype);
		free((void*)m->optstr);
		free(m);
	}
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

int add_2paths_and_deps(const char *path, const char *path2, int readonly, int error, int lib)
{
	assert(path != NULL);
	assert(path2 != NULL);

	if (lib == 0 && path[0] != '/') {
		ERROR("%s is not an absolute path\n", path);
		return error;
	}

	char *map = NULL;
	int fd, ret = -1;
	if (path[0] == '/') {
		if (avl_find(&mounts, path2))
			return 0;
		fd = open(path, O_RDONLY|O_CLOEXEC);
		if (fd < 0)
			return error;
		_add_mount_bind(path, path2, readonly, error);
	} else {
		if (avl_find(&libraries, path))
			return 0;
		char *fullpath;
		fd = lib_open(&fullpath, path);
		if (fd < 0)
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
