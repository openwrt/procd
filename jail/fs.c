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
#include <sys/syscall.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/mount.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>

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

/*
 * mnt_already_visible() requires a new mount's atime class to match
 * the host's existing instance or the kernel refuses it with EPERM
 * ("Mount too revealing"). Detect the mountpoint's actual atime class
 * instead of hardcoding one, so the new mount can never conflict.
 */
unsigned long detect_atime_flag(const char *mountpoint)
{
	FILE *f;
	char *line = NULL;
	size_t linelen = 0;
	unsigned long ret = MS_RELATIME; /* kernel default if nothing else is known */
	size_t mplen = strlen(mountpoint);

	f = fopen("/proc/self/mountinfo", "r");
	if (!f)
		return ret;

	while (getline(&line, &linelen, f) != -1) {
		/* mountinfo(5): field 5 is the mountpoint, field 6 its options */
		char *saveptr = NULL;
		char *field;
		int idx = 0;
		char *mp_field = NULL, *opts_field = NULL;

		for (field = strtok_r(line, " \t\n", &saveptr); field;
		     field = strtok_r(NULL, " \t\n", &saveptr), idx++) {
			if (idx == 4)
				mp_field = field;
			else if (idx == 5) {
				opts_field = field;
				break;
			}
		}

		if (!mp_field || !opts_field)
			continue;

		if (strlen(mp_field) != mplen || strcmp(mp_field, mountpoint))
			continue;

		/* last matching entry wins: it's the topmost/currently-effective one */
		if (strstr(opts_field, "noatime"))
			ret = MS_NOATIME;
		else if (strstr(opts_field, "relatime"))
			ret = MS_RELATIME;
		else
			/* strictatime is the absence of noatime/relatime, not a token */
			ret = MS_STRICTATIME;
	}

	free(line);
	fclose(f);

	return ret;
}

#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP 0x00100000
#endif

#ifndef MOUNT_ATTR__ATIME
#define MOUNT_ATTR__ATIME	0x00000070
#endif
#ifndef MOUNT_ATTR_RELATIME
#define MOUNT_ATTR_RELATIME	0x00000000
#endif
#ifndef MOUNT_ATTR_NOATIME
#define MOUNT_ATTR_NOATIME	0x00000010
#endif
#ifndef MOUNT_ATTR_STRICTATIME
#define MOUNT_ATTR_STRICTATIME	0x00000020
#endif
#ifndef MOUNT_ATTR_NODIRATIME
#define MOUNT_ATTR_NODIRATIME	0x00000080
#endif

int sys_openat2(int dfd, const char *path, struct open_how *how, size_t size)
{
	return syscall(SYS_openat2, dfd, path, how, size);
}

static int jailroot_dirfd = -1;

static unsigned int idmap_host_offset;

void jail_set_idmap_offset(unsigned int offset)
{
	idmap_host_offset = offset;
}

static int write_mappings_file(pid_t pid, const char *which, struct blob_attr *mappings)
{
	enum {
		OCI_LINUX_UIDGIDMAP_CONTAINERID,
		OCI_LINUX_UIDGIDMAP_HOSTID,
		OCI_LINUX_UIDGIDMAP_SIZE,
		__OCI_LINUX_UIDGIDMAP_MAX,
	};
	static const struct blobmsg_policy policy[] = {
		[OCI_LINUX_UIDGIDMAP_CONTAINERID] = { "containerID", BLOBMSG_TYPE_INT32 },
		[OCI_LINUX_UIDGIDMAP_HOSTID] = { "hostID", BLOBMSG_TYPE_INT32 },
		[OCI_LINUX_UIDGIDMAP_SIZE] = { "size", BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *tb[__OCI_LINUX_UIDGIDMAP_MAX];
	struct blob_attr *cur;
	char path[64];
	char *buf = NULL;
	size_t buflen = 0;
	FILE *mem;
	ssize_t w;
	int rem, fd, ret = 0, saved_err;

	mem = open_memstream(&buf, &buflen);
	if (!mem)
		return errno;

	blobmsg_for_each_attr(cur, mappings, rem) {
		blobmsg_parse(policy, __OCI_LINUX_UIDGIDMAP_MAX, tb,
			      blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[OCI_LINUX_UIDGIDMAP_CONTAINERID] ||
		    !tb[OCI_LINUX_UIDGIDMAP_HOSTID] ||
		    !tb[OCI_LINUX_UIDGIDMAP_SIZE]) {
			fclose(mem);
			free(buf);
			return EINVAL;
		}
		fprintf(mem, "%u %u %u\n",
			blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_CONTAINERID]),
			blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_HOSTID]) + idmap_host_offset,
			blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_SIZE]));
	}
	fclose(mem);

	if (!buflen) {
		free(buf);
		return 0;
	}

	snprintf(path, sizeof(path), "/proc/%d/%s", pid, which);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		ret = errno;
		free(buf);
		return ret;
	}

	w = write(fd, buf, buflen);
	if (w < 0)
		ret = errno;
	else if ((size_t)w != buflen)
		ret = EIO;

	saved_err = ret;
	close(fd);
	free(buf);
	return saved_err;
}

int build_userns_fd(struct blob_attr *uidmappings, struct blob_attr *gidmappings)
{
	int sync[2];
	pid_t pid;
	char path[64];
	char buf;
	int fd = -1;
	int ret, saved_err = 0;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sync) < 0)
		return -errno;

	pid = fork();
	if (pid < 0) {
		ret = -errno;
		close(sync[0]);
		close(sync[1]);
		return ret;
	}

	if (pid == 0) {
		close(sync[0]);
		if (unshare(CLONE_NEWUSER) < 0)
			_exit(EXIT_FAILURE);
		if (send(sync[1], "R", 1, MSG_NOSIGNAL) != 1)
			_exit(EXIT_FAILURE);
		if (read(sync[1], &buf, 1) < 0) {
		}
		_exit(EXIT_SUCCESS);
	}

	close(sync[1]);
	if (read(sync[0], &buf, 1) != 1 || buf != 'R') {
		saved_err = EIO;
		goto out;
	}

	if (uidmappings && (ret = write_mappings_file(pid, "uid_map", uidmappings))) {
		saved_err = ret;
		goto out;
	}
	if (gidmappings) {
		int gfd;
		snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
		gfd = open(path, O_WRONLY | O_CLOEXEC);
		if (gfd >= 0) {
			(void)!write(gfd, "deny", 4);
			close(gfd);
		}
		if ((ret = write_mappings_file(pid, "gid_map", gidmappings))) {
			saved_err = ret;
			goto out;
		}
	}

	snprintf(path, sizeof(path), "/proc/%d/ns/user", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		saved_err = errno;

out:
	(void)send(sync[0], "X", 1, MSG_NOSIGNAL);
	close(sync[0]);
	waitpid(pid, NULL, 0);
	if (fd < 0) {
		errno = saved_err ? saved_err : EIO;
		return -errno;
	}
	return fd;
}

struct mount {
	struct avl_node avl;
	struct list_head list;
	const char *source;
	const char *target;
	const char *filesystemtype;
	unsigned long mountflags;
	unsigned long propflags;
	const char *optstr;
	int error;
	bool inner;
	int source_fd;
	bool idmap;
	bool idmap_recursive;
	bool volume;
	bool mounted;
	int idmap_treefd;
	struct blob_attr *uidmappings;
	struct blob_attr *gidmappings;
};

/* open_tree()/move_mount()/mount_setattr() have no glibc wrappers yet;
 * struct ujail_mount_attr is declared in fs.h */
int sys_open_tree(int dfd, const char *path, unsigned flags)
{
	return syscall(SYS_open_tree, dfd, path, flags);
}

int sys_move_mount(int from_dfd, const char *from_path, int to_dfd, const char *to_path, unsigned flags)
{
	return syscall(SYS_move_mount, from_dfd, from_path, to_dfd, to_path, flags);
}

int sys_mount_setattr(int dfd, const char *path, unsigned flags, struct ujail_mount_attr *attr, size_t size)
{
	return syscall(SYS_mount_setattr, dfd, path, flags, attr, size);
}

struct avl_tree mounts;
static LIST_HEAD(mounts_order);

/* same masking as do_mount()'s is_mask branch, applied immediately
 * against an absolute path instead of queued through jail_root.
 *
 * UJAIL_NOAFILE lives under the pre-pivot root, gone by the time this
 * runs; JAIL_NOAFILE, a locked bind of procd's read-only noafile
 * queued for deferred-userns jails, is used instead. */
int mask_path_now(const char *path)
{
	struct stat s;

	if (stat(path, &s))
		return 0; /* doesn't exist, nothing to mask */

	if (S_ISDIR(s.st_mode)) {
		if (mount("none", path, "tmpfs", MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RELATIME, "size=0,mode=000"))
			return -1;
	} else {
		if (mount(JAIL_NOAFILE, path, "bind", MS_BIND, NULL))
			return -1;
		if (mount(JAIL_NOAFILE, path, "bind", MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RELATIME, NULL))
			return -1;
	}

	DEBUG("masked path %s\n", path);
	return 0;
}

static void mountinfo_unescape(char *s)
{
	char *r = s, *w = s;

	while (*r) {
		if (r[0] == '\\' && r[1] >= '0' && r[1] <= '7' &&
		    r[2] >= '0' && r[2] <= '7' && r[3] >= '0' && r[3] <= '7') {
			*w++ = (char)(((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
			r += 4;
		} else {
			*w++ = *r++;
		}
	}
	*w = '\0';
}

static unsigned long mountinfo_current_flags(const char *path)
{
	unsigned long flags = MS_RELATIME;
	bool found = false;
	FILE *f;
	char *line = NULL;
	size_t linecap = 0;

	f = fopen("/proc/self/mountinfo", "re");
	if (!f)
		return flags;

	while (getline(&line, &linecap, f) >= 0) {
		char *mp, *opts, *save = NULL, *optsave = NULL;
		char *tok;
		unsigned long this_flags;

		strtok_r(line, " ", &save);
		strtok_r(NULL, " ", &save);
		strtok_r(NULL, " ", &save);
		strtok_r(NULL, " ", &save);
		mp = strtok_r(NULL, " ", &save);
		opts = strtok_r(NULL, " ", &save);
		if (!mp || !opts)
			continue;
		mountinfo_unescape(mp);
		if (strcmp(mp, path))
			continue;

		this_flags = 0;
		for (tok = strtok_r(opts, ",", &optsave); tok;
		     tok = strtok_r(NULL, ",", &optsave)) {
			if (!strcmp(tok, "ro"))
				this_flags |= MS_RDONLY;
			else if (!strcmp(tok, "nosuid"))
				this_flags |= MS_NOSUID;
			else if (!strcmp(tok, "nodev"))
				this_flags |= MS_NODEV;
			else if (!strcmp(tok, "noexec"))
				this_flags |= MS_NOEXEC;
			else if (!strcmp(tok, "noatime"))
				this_flags |= MS_NOATIME;
			else if (!strcmp(tok, "relatime"))
				this_flags |= MS_RELATIME;
			else if (!strcmp(tok, "nodiratime"))
				this_flags |= MS_NODIRATIME;
		}

		/* last match wins: it's the topmost/effective entry */
		flags = this_flags;
		found = true;
	}
	free(line);
	fclose(f);

	if (!found)
		return MS_RELATIME;

	return flags;
}

static bool fs_userns;

void jail_fs_set_userns(bool enabled)
{
	fs_userns = enabled;
}

static bool mount_opts_has(const char *opts, const char *needle);

static int do_mount(const char *root, const char *orig_source, const char *target, const char *filesystemtype,
		    unsigned long orig_mountflags, unsigned long propflags, const char *optstr, int error, bool inner,
		    int source_fd)
{
	struct stat s;
	char new[PATH_MAX];
	char tmpfs_data[512];
	const char *mount_data;
	char *source = (char *)orig_source;
	int fd, ret = 0;
	bool is_bind = (orig_mountflags & MS_BIND);
	bool is_mask = (source == (void *)(-1));
	bool use_fd = false;
	unsigned long mountflags = orig_mountflags;

	assert(!(inner && is_mask));
	assert(!(inner && !orig_source));

	if (source && is_bind && stat(source, &s)) {
		if (source_fd >= 0 && !fstatat(source_fd, "", &s, AT_EMPTY_PATH)) {
			use_fd = true;
		} else {
			if (error)
				ERROR("stat(%s) failed: %m\n", source);
			return error;
		}
	}

	if (inner)
		if (asprintf(&source, "%s%s", root, orig_source) < 0)
			return ENOMEM;

	snprintf(new, sizeof(new), "%s%s", root, target?target:source);

	if (is_mask) {
		if (stat(new, &s))
			return 0; /* doesn't exists, nothing to mask */

		if (S_ISDIR(s.st_mode)) {/* use empty 0-sized tmpfs for directories */
			if (mount("none", new, "tmpfs", MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RELATIME, "size=0,mode=000"))
				return error;
		} else {
			/* mount-bind 0-sized file having mode 000 */
			if (mount(UJAIL_NOAFILE, new, "bind", MS_BIND, NULL))
				return error;

			if (mount(UJAIL_NOAFILE, new, "bind", MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RELATIME, NULL))
				return error;
		}

		DEBUG("masked path %s\n", new);
		return 0;
	}


	if (!is_bind || (source && S_ISDIR(s.st_mode))) {
		mkdir_p(new, 0755);
	} else if (is_bind && source) {
		const char *target_rel = target ? target : source;
		struct open_how how = {
			.flags = O_CREAT | O_WRONLY | O_TRUNC | O_EXCL | O_CLOEXEC,
			.mode = 0644,
			.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
		};

		assert(target_rel);
		mkdir_p(dirname(new), 0755);
		snprintf(new, sizeof(new), "%s%s", root, target?target:source);
		while (*target_rel == '/')
			++target_rel;
		fd = (jailroot_dirfd >= 0)
		     ? sys_openat2(jailroot_dirfd, target_rel, &how, sizeof(how))
		     : open(new, O_CREAT|O_WRONLY|O_TRUNC|O_EXCL|O_CLOEXEC, 0644);
		if (fd >= 0)
			close(fd);

		if (error && fd < 0 && errno != EEXIST) {
			ERROR("failed to create mount target %s: %m\n", new);

			ret = errno;
			goto free_source_out;
		}
	}

	if (is_bind) {
		if (use_fd) {
			if (sys_move_mount(source_fd, "", AT_FDCWD, new, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
				if (error)
					ERROR("move_mount(%s -> %s): %m\n", source, new);
				ret = error;
				goto free_source_out;
			}
		} else if (mount(source?:new, new, filesystemtype?:"bind", MS_BIND | (mountflags & MS_REC), optstr)) {
			if (error)
				ERROR("failed to mount -B %s %s: %m\n", source, new);

			ret = error;
			goto free_source_out;
		}
		mountflags |= MS_REMOUNT;
	}

	mount_data = optstr;
	if (filesystemtype && !strcmp(filesystemtype, "tmpfs") && !fs_userns &&
	    !mount_opts_has(optstr ?: "", "swap") && !mount_opts_has(optstr ?: "", "noswap")) {
		if (optstr && *optstr)
			snprintf(tmpfs_data, sizeof(tmpfs_data), "%s,noswap", optstr);
		else
			snprintf(tmpfs_data, sizeof(tmpfs_data), "noswap");
		mount_data = tmpfs_data;
	}

	const char *hack_fstype = ((!filesystemtype || strcmp(filesystemtype, "cgroup"))?filesystemtype:"cgroup2");
	if (mount(source?:(is_bind?new:NULL), new, hack_fstype?:"none", mountflags, mount_data)) {
		int mount_errno = errno;

		if ((mountflags & MS_REMOUNT) && mount_errno == EPERM) {
			/* Not a heuristic: re-read the kernel-enforced flags from
			 * mountinfo and only proceed once the security-relevant
			 * ones (ro/nosuid/nodev/noexec) are confirmed in effect. */
			unsigned long retry_flags = mountflags | mountinfo_current_flags(new);

			if (retry_flags != mountflags &&
			    !mount(source?:(is_bind?new:NULL), new, hack_fstype?:"none", retry_flags, mount_data))
				goto mount_ok;

			unsigned long lockable_flags = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC;
			unsigned long wanted = orig_mountflags & lockable_flags;
			unsigned long got = mountinfo_current_flags(new) & lockable_flags;

			if ((wanted & ~got) == 0) {
				WARNING("remount(%s) to apply flags failed: %s (tolerated - "
				"the flags actually in effect already satisfy the "
				"request; expected under CLONE_NEWUSER for host-owned "
				"bind sources)\n", new, strerror(mount_errno));
				goto mount_ok;
			}

			if (error) {
				errno = mount_errno;
				ERROR("failed to enforce mount restrictions on %s %s: %m "
				      "(missing flags: %s%s%s%s)\n", source, new,
				      (wanted & ~got & MS_RDONLY) ? "ro " : "",
				      (wanted & ~got & MS_NOSUID) ? "nosuid " : "",
				      (wanted & ~got & MS_NODEV) ? "nodev " : "",
				      (wanted & ~got & MS_NOEXEC) ? "noexec " : "");
				ret = error;
				goto free_source_out;
			}

			WARNING("remount(%s) to apply mount restrictions failed and could not "
				"be verified in effect; continuing best-effort since "
				"this mount was not marked as critical\n", new);
			goto mount_ok;
		}

		errno = mount_errno;
		if (error)
			ERROR("failed to mount %s %s: %m\n", source, new);

		ret = error;
		goto free_source_out;
	}

mount_ok:
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

static bool nullable_str_eq(const char *a, const char *b)
{
	if (a == b)
		return true;
	if (!a || !b)
		return false;
	return !strcmp(a, b);
}

static int _add_mount(const char *source, const char *target, const char *filesystemtype,
		      unsigned long mountflags, unsigned long propflags, const char *optstr,
		      int error, bool inner)
{
	struct mount *m;

	assert(target != NULL);

	m = avl_find_element(&mounts, target, m, avl);
	if (m) {
		bool source_match;
		if (m->source == (void *)(-1) || source == (void *)(-1))
			source_match = (m->source == source);
		else
			source_match = nullable_str_eq(m->source, source);

		if (source_match &&
		    nullable_str_eq(m->filesystemtype, filesystemtype) &&
		    nullable_str_eq(m->optstr, optstr) &&
		    m->mountflags == mountflags &&
		    m->propflags == propflags &&
		    m->error == error &&
		    m->inner == inner)
			return 0;

		return EEXIST;
	}

	m = calloc(1, sizeof(struct mount));
	if (!m)
		return ENOMEM;

	m->idmap_treefd = -1;
	m->source_fd = -1;
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
	m->source_fd = -1;

	avl_insert(&mounts, &m->avl);
	list_add_tail(&m->list, &mounts_order);
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

int add_mount_fd(int fd, const char *target, int error)
{
	struct mount *m;

	if (avl_find(&mounts, target))
		return 1;

	m = calloc(1, sizeof(struct mount));
	if (!m)
		return ENOMEM;

	m->avl.key = m->target = strdup(target);
	m->mountflags = MS_BIND;
	m->error = error;
	m->source_fd = fd;

	avl_insert(&mounts, &m->avl);
	list_add_tail(&m->list, &mounts_order);
	DEBUG("adding mount fd:%d %s bind(1) ro(?) err(%d)\n", fd, target, error != 0);

	return 0;
}

int add_mount_volume(const char *source, const char *target, int error)
{
	struct mount *m;
	int ret;

	ret = add_mount(source, target, NULL,
			MS_BIND | MS_NOEXEC | MS_NOSUID | MS_NODEV, 0, NULL, error);
	if (ret && ret != EEXIST)
		return ret;

	m = avl_find_element(&mounts, target, m, avl);
	if (m)
		m->volume = true;

	return ret;
}

char *resolve_mount_source(const char *source)
{
	char *real;

	if (!source)
		return NULL;

	if (source[0] != '/')
		return strdup(source);

	real = realpath(source, NULL);
	return real ? real : strdup(source);
}

enum {
	OCI_MOUNT_SOURCE,
	OCI_MOUNT_DESTINATION,
	OCI_MOUNT_TYPE,
	OCI_MOUNT_OPTIONS,
	OCI_MOUNT_UIDMAPPINGS,
	OCI_MOUNT_GIDMAPPINGS,
	__OCI_MOUNT_MAX,
};

static const struct blobmsg_policy oci_mount_policy[] = {
	[OCI_MOUNT_SOURCE] = { "source", BLOBMSG_TYPE_STRING },
	[OCI_MOUNT_DESTINATION] = { "destination", BLOBMSG_TYPE_STRING },
	[OCI_MOUNT_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[OCI_MOUNT_OPTIONS] = { "options", BLOBMSG_TYPE_ARRAY },
	[OCI_MOUNT_UIDMAPPINGS] = { "uidMappings", BLOBMSG_TYPE_ARRAY },
	[OCI_MOUNT_GIDMAPPINGS] = { "gidMappings", BLOBMSG_TYPE_ARRAY },
};

struct mount_opt {
	struct list_head list;
	char *optstr;
};

#ifndef MS_LAZYTIME
#define MS_LAZYTIME (1 << 25)
#endif

static int parseOCImountopts(struct blob_attr *msg, unsigned long *mount_flags, unsigned long *propagation_flags, char **mount_data, int *error, bool *idmap, bool *idmap_recursive)
{
	struct blob_attr *cur;
	int rem;
	unsigned long mf = 0;
	unsigned long pf = 0;
	char *tmp;
	struct list_head fsopts = LIST_HEAD_INIT(fsopts);
	size_t len = 0;
	struct mount_opt *opt, *tmpopt;

	*idmap = false;
	*idmap_recursive = false;

	blobmsg_for_each_attr(cur, msg, rem) {
		tmp = blobmsg_get_string(cur);
		if (!strcmp("idmap", tmp)) {
			*idmap = true;
			continue;
		} else if (!strcmp("ridmap", tmp)) {
			*idmap = true;
			*idmap_recursive = true;
			continue;
		} else if (!strcmp("ro", tmp))
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

static bool is_proc_or_sys_path(const char *path)
{
	if (!strcmp(path, "/proc") || !strcmp(path, "/sys"))
		return true;

	if (!strncmp(path, "/proc/", 6))
		return true;

	if (!strncmp(path, "/sys/", 5))
		return true;

	return false;
}

static bool mount_opts_has(const char *opts, const char *needle)
{
	size_t nlen = strlen(needle);
	const char *p = opts;

	while (p && *p) {
		const char *end = strchr(p, ',');
		size_t plen = end ? (size_t)(end - p) : strlen(p);

		if (plen == nlen && !strncmp(p, needle, nlen))
			return true;
		if (!end)
			break;
		p = end + 1;
	}
	return false;
}

int parseOCImount(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_MOUNT_MAX];
	unsigned long mount_flags = 0;
	unsigned long propagation_flags = 0;
	char *mount_data = NULL;
	char *destination, *abs_destination = NULL;
	char *rsrc = NULL;
	bool idmap = false, idmap_recursive = false;
	int ret, err = -1;

	blobmsg_parse(oci_mount_policy, __OCI_MOUNT_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_MOUNT_DESTINATION])
		return EINVAL;

	if (tb[OCI_MOUNT_OPTIONS]) {
		ret = parseOCImountopts(tb[OCI_MOUNT_OPTIONS], &mount_flags, &propagation_flags, &mount_data, &err, &idmap, &idmap_recursive);
		if (ret)
			return ret;
	}

	destination = blobmsg_get_string(tb[OCI_MOUNT_DESTINATION]);
	if (destination[0] != '/') {
		if (asprintf(&abs_destination, "/%s", destination) < 0) {
			free(mount_data);
			return ENOMEM;
		}
		destination = abs_destination;
	}

	if (is_proc_or_sys_path(destination) &&
	    ((mount_flags & MS_BIND) ||
	     (tb[OCI_MOUNT_TYPE] && !strcmp(blobmsg_get_string(tb[OCI_MOUNT_TYPE]), "bind"))) &&
	    !(mount_flags & MS_RDONLY)) {
		ERROR("OCI mount config requests a writable bind mount onto %s; "
		      "refusing to allow write access to /proc or /sys\n",
		      destination);
		free(abs_destination);
		if (mount_data)
			free(mount_data);
		return EPERM;
	}

	if (tb[OCI_MOUNT_SOURCE])
		rsrc = resolve_mount_source(blobmsg_get_string(tb[OCI_MOUNT_SOURCE]));

	ret = add_mount(rsrc,
		  destination,
		  tb[OCI_MOUNT_TYPE] ? blobmsg_get_string(tb[OCI_MOUNT_TYPE]) : NULL,
		  mount_flags, propagation_flags, mount_data, err);

	free(rsrc);

	if (!ret && (idmap || tb[OCI_MOUNT_UIDMAPPINGS] || tb[OCI_MOUNT_GIDMAPPINGS])) {
		struct mount *m = avl_find_element(&mounts, destination, m, avl);
		if (m) {
			m->idmap = idmap || tb[OCI_MOUNT_UIDMAPPINGS] || tb[OCI_MOUNT_GIDMAPPINGS];
			m->idmap_recursive = idmap_recursive;
			if (tb[OCI_MOUNT_UIDMAPPINGS]) {
				free(m->uidmappings);
				m->uidmappings = blob_memdup(tb[OCI_MOUNT_UIDMAPPINGS]);
				if (!m->uidmappings) {
					free(abs_destination);
					free(mount_data);
					return ENOMEM;
				}
			}
			if (tb[OCI_MOUNT_GIDMAPPINGS]) {
				free(m->gidmappings);
				m->gidmappings = blob_memdup(tb[OCI_MOUNT_GIDMAPPINGS]);
				if (!m->gidmappings) {
					free(abs_destination);
					free(mount_data);
					return ENOMEM;
				}
			}
		}
	}

	free(abs_destination);
	if (mount_data)
		free(mount_data);

	return ret;
}

bool mount_is_defined(const char *target)
{
	struct mount *m;

	m = avl_find_element(&mounts, target, m, avl);

	return m != NULL;
}

static struct blob_attr *single_idmap(uint32_t container_id)
{
	struct blob_buf b = {};
	void *arr, *tbl;
	struct blob_attr *ret;

	blob_buf_init(&b, 0);
	arr = blobmsg_open_array(&b, "m");
	tbl = blobmsg_open_table(&b, NULL);
	blobmsg_add_u32(&b, "containerID", container_id);
	blobmsg_add_u32(&b, "hostID", 0);
	blobmsg_add_u32(&b, "size", 1);
	blobmsg_close_table(&b, tbl);
	blobmsg_close_array(&b, arr);
	ret = blob_memdup(blobmsg_data(b.head));
	blob_buf_free(&b);

	return ret;
}

int fs_mount_enable_idmap(const char *target, uint32_t uid, uint32_t gid)
{
	struct mount *m = avl_find_element(&mounts, target, m, avl);

	if (!m)
		return ENOENT;

	free(m->uidmappings);
	free(m->gidmappings);
	m->uidmappings = single_idmap(uid);
	m->gidmappings = single_idmap(gid);
	if (!m->uidmappings || !m->gidmappings)
		return ENOMEM;

	m->idmap = true;
	m->idmap_recursive = false;

	return 0;
}

static void build_noafile(void) {
	int fd;

	fd = creat(UJAIL_NOAFILE, 0000);
	if (fd < 0)
		return;

	close(fd);
	return;
}

static int do_mount_fd(const char *root, int fd, const char *target, int error)
{
	char new[PATH_MAX];
	struct stat s;

	snprintf(new, sizeof(new), "%s%s", root, target);

	if (fstat(fd, &s)) {
		if (error)
			ERROR("fstat(fd:%d) failed: %m\n", fd);
		close(fd);
		return error;
	}

	if (S_ISDIR(s.st_mode)) {
		mkdir_p(new, 0755);
	} else {
		mkdir_p(dirname(new), 0755);
		snprintf(new, sizeof(new), "%s%s", root, target);
		int cfd = open(new, O_CREAT|O_WRONLY|O_TRUNC|O_EXCL, 0644);
		if (cfd >= 0)
			close(cfd);
		if (error && cfd < 0 && errno != EEXIST) {
			ERROR("failed to create mount target %s: %m\n", new);
			close(fd);
			return errno;
		}
	}

	if (sys_move_mount(fd, "", AT_FDCWD, new, MOVE_MOUNT_F_EMPTY_PATH)) {
		if (error)
			ERROR("move_mount() to %s failed: %m\n", new);
		close(fd);
		return error;
	}

	close(fd);
	DEBUG("move_mount fd to %s\n", new);
	return 0;
}

static int idmap_mount_target(const char *root, struct mount *m, char *target, size_t tlen)
{
	struct stat s;
	const char *target_rel;
	struct open_how how = {
		.flags = O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
		.mode = 0644,
		.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
	};
	int fd;

	snprintf(target, tlen, "%s%s", root, m->target);

	if (stat(m->source, &s)) {
		if (m->error)
			ERROR("stat(%s) failed: %m\n", m->source);
		return -1;
	}

	if (S_ISDIR(s.st_mode)) {
		mkdir_p(target, 0755);
		return 0;
	}

	target_rel = m->target;
	assert(target_rel);
	mkdir_p(dirname(strdupa(target)), 0755);
	snprintf(target, tlen, "%s%s", root, m->target);
	while (*target_rel == '/')
		++target_rel;
	fd = (jailroot_dirfd >= 0)
	     ? sys_openat2(jailroot_dirfd, target_rel, &how, sizeof(how))
	     : open(target, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
	if (fd >= 0)
		close(fd);

	return 0;
}

static int idmap_tree_fd(const char *source, int source_fd, int userns_fd, unsigned long mountflags, bool recursive)
{
	struct ujail_mount_attr attr = { 0 };
	unsigned int open_flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;
	unsigned int setattr_flags = AT_EMPTY_PATH;
	int treefd;

	if (recursive) {
		open_flags |= AT_RECURSIVE;
		setattr_flags |= AT_RECURSIVE;
	}

	if (source_fd >= 0)
		treefd = sys_open_tree(source_fd, "", open_flags | AT_EMPTY_PATH);
	else
		treefd = sys_open_tree(AT_FDCWD, source, open_flags);
	if (treefd < 0) {
		ERROR("open_tree(%s): %m\n", source);
		return -1;
	}

	attr.attr_set = MOUNT_ATTR_IDMAP;
	if (mountflags & MS_RDONLY)
		attr.attr_set |= MOUNT_ATTR_RDONLY;
	if (mountflags & MS_NOSUID)
		attr.attr_set |= MOUNT_ATTR_NOSUID;
	if (mountflags & MS_NODEV)
		attr.attr_set |= MOUNT_ATTR_NODEV;
	if (mountflags & MS_NOEXEC)
		attr.attr_set |= MOUNT_ATTR_NOEXEC;
	if (mountflags & MS_NODIRATIME)
		attr.attr_set |= MOUNT_ATTR_NODIRATIME;
	if (mountflags & (MS_NOATIME | MS_RELATIME | MS_STRICTATIME)) {
		attr.attr_clr |= MOUNT_ATTR__ATIME;
		if (mountflags & MS_NOATIME)
			attr.attr_set |= MOUNT_ATTR_NOATIME;
		else if (mountflags & MS_STRICTATIME)
			attr.attr_set |= MOUNT_ATTR_STRICTATIME;
		else
			attr.attr_set |= MOUNT_ATTR_RELATIME;
	}
	attr.userns_fd = userns_fd;

	if (sys_mount_setattr(treefd, "", setattr_flags, &attr, sizeof(attr)) < 0) {
		ERROR("mount_setattr(IDMAP, %s): %m\n", source);
		close(treefd);
		return -1;
	}

	return treefd;
}

static int do_idmap_mount(const char *root, struct mount *m)
{
	char target[PATH_MAX];
	int treefd, userns_fd, ret = m->error;

	if (!m->source || m->source == (void *)(-1)) {
		ERROR("idmap mount %s requires a source\n", m->target);
		return m->error;
	}

	userns_fd = build_userns_fd(m->uidmappings, m->gidmappings);
	if (userns_fd < 0) {
		ERROR("build_userns_fd: %s\n", strerror(-userns_fd));
		return m->error;
	}

	if (idmap_mount_target(root, m, target, sizeof(target)))
		goto out_close;

	treefd = idmap_tree_fd(m->source, m->source_fd, userns_fd, m->mountflags, m->idmap_recursive);
	if (treefd < 0)
		goto out_close;

	if (sys_move_mount(treefd, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
		if (m->error)
			ERROR("move_mount(%s -> %s): %m\n", m->source, target);
		close(treefd);
		goto out_close;
	}

	if (m->propflags && mount("none", target, "none", m->propflags, NULL)) {
		if (m->error)
			ERROR("mount(propagation %#lx, %s): %m\n", m->propflags, target);
		close(treefd);
		goto out_close;
	}

	DEBUG("idmap mount %s %s\n", m->source, target);
	close(treefd);
	ret = 0;

out_close:
	close(userns_fd);
	return ret;
}

static int do_move_idmap_mount(const char *root, struct mount *m)
{
	char target[PATH_MAX];
	int ret = m->error;

	if (idmap_mount_target(root, m, target, sizeof(target)))
		goto out;

	if (sys_move_mount(m->idmap_treefd, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH) < 0) {
		ERROR("move_mount(%s -> %s): %m\n", m->source, target);
		goto out;
	}

	if (m->propflags && mount("none", target, "none", m->propflags, NULL)) {
		ERROR("mount(propagation %#lx, %s): %m\n", m->propflags, target);
		goto out;
	}

	DEBUG("idmap volume %s %s\n", m->source, target);
	ret = 0;

out:
	close(m->idmap_treefd);
	m->idmap_treefd = -1;
	return ret;
}

int jail_idmap_build(const char *extroot,
		     struct blob_attr *uidmap, struct blob_attr *gidmap,
		     int *fds, int maxfds)
{
	int userns_fd;
	int n = 0;
	int fd;

	if (!extroot)
		return 0;

	userns_fd = build_userns_fd(uidmap, gidmap);
	if (userns_fd < 0) {
		ERROR("build_userns_fd: %s\n", strerror(-userns_fd));
		return -1;
	}

	if (n >= maxfds)
		goto err;
	fd = idmap_tree_fd(extroot, -1, userns_fd, 0, false);
	if (fd < 0)
		goto err;
	fds[n++] = fd;

	close(userns_fd);
	return n;

err:
	close(userns_fd);
	while (n > 0)
		close(fds[--n]);
	return -1;
}

bool jail_dir_is_fresh(const char *path)
{
	struct dirent *e;
	char lf[PATH_MAX];
	bool fresh = true, seen_lf = false;
	DIR *d, *l;

	d = opendir(path);
	if (!d)
		return false;

	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		if (!seen_lf && !strcmp(e->d_name, "lost+found")) {
			seen_lf = true;
			continue;
		}
		fresh = false;
		break;
	}
	closedir(d);

	if (!fresh || !seen_lf)
		return fresh;

	snprintf(lf, sizeof(lf), "%s/lost+found", path);
	l = opendir(lf);
	if (!l)
		return fresh;
	while ((e = readdir(l))) {
		if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
			fresh = false;
			break;
		}
	}
	closedir(l);

	return fresh;
}

void jail_chown_fresh_volumes(uid_t uid, gid_t gid)
{
	struct mount *m;
	char lf[PATH_MAX];

	avl_for_each_element(&mounts, m, avl) {
		if (!m->volume || !m->source || m->source == (void *)(-1))
			continue;
		if (!jail_dir_is_fresh(m->source))
			continue;
		if (chown(m->source, uid, gid))
			ERROR("chown(fresh volume %s -> %u:%u): %m\n", m->source, uid, gid);
		snprintf(lf, sizeof(lf), "%s/lost+found", m->source);
		if (chown(lf, uid, gid) && errno != ENOENT)
			ERROR("chown(%s -> %u:%u): %m\n", lf, uid, gid);
	}
}

int jail_idmap_assign(bool have_extroot, bool have_overlay, const int *fds, int nfds,
		      int *extroot_fd, int *overlay_fd)
{
	struct mount *m;
	int i = 0;

	if (have_extroot && i < nfds)
		*extroot_fd = fds[i++];

	if (have_overlay && i < nfds)
		*overlay_fd = fds[i++];

	avl_for_each_element(&mounts, m, avl) {
		if (!m->volume)
			continue;
		if (i >= nfds)
			break;
		m->idmap_treefd = fds[i++];
	}

	return i;
}

void mount_stage_dev(const char *jail_dev)
{
	struct mount *m;
	struct stat s;
	char path[PATH_MAX];
	bool is_dir;
	int fd;

	avl_for_each_element(&mounts, m, avl) {
		if (strncmp(m->target, "/dev/", 5))
			continue;
		if (m->source == (void *)(-1))
			continue;

		snprintf(path, sizeof(path), "%s%s", jail_dev, m->target + 4);

		is_dir = !(m->mountflags & MS_BIND) ||
			 (m->source && !stat(m->source, &s) && S_ISDIR(s.st_mode));
		if (is_dir) {
			mkdir_p(path, 0755);
		} else {
			mkdir_p(dirname(strdupa(path)), 0755);
			fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
			if (fd >= 0)
				close(fd);
		}
	}
}

static bool mount_target_covers(const struct mount *outer, const struct mount *inner)
{
	size_t len = strlen(outer->target);

	if (!strcmp(outer->target, "/"))
		return strcmp(inner->target, "/") != 0;

	return !strncmp(inner->target, outer->target, len) && inner->target[len] == '/';
}

static int mount_one(const char *jailroot, const char *jail_dev, struct mount *m)
{
	char devtarget[PATH_MAX];
	struct mount *outer;

	if (m->mounted)
		return 0;

	m->mounted = true;

	/* whatever this one sits on has to be established first */
	list_for_each_entry(outer, &mounts_order, list)
		if (!outer->mounted && mount_target_covers(outer, m) &&
		    mount_one(jailroot, jail_dev, outer))
			return -1;

	if (jail_dev && m->filesystemtype && !strcmp(m->filesystemtype, "tmpfs") &&
	    !strcmp(m->target, "/dev")) {
		snprintf(devtarget, sizeof(devtarget), "%s%s", jailroot, m->target);
		mkdir_p(devtarget, 0755);
		if (mount(jail_dev, devtarget, NULL, MS_BIND | MS_REC, NULL)) {
			ERROR("mount(MS_BIND, %s -> %s): %m\n", jail_dev, devtarget);
			return -1;
		}

		return 0;
	}

	if (m->idmap_treefd >= 0)
		return do_move_idmap_mount(jailroot, m) ? -1 : 0;

	if (m->idmap)
		return do_idmap_mount(jailroot, m) ? -1 : 0;

	if (m->source_fd >= 0)
		return do_mount_fd(jailroot, m->source_fd, m->target, m->error) ? -1 : 0;

	if (do_mount(jailroot, m->source, m->target, m->filesystemtype, m->mountflags,
		     m->propflags, m->optstr, m->error, m->inner, m->source_fd))
		return -1;

	return 0;
}

int mount_all(const char *jailroot, const char *jail_dev) {
	struct library *l;
	struct mount *m;
	int ret = 0;

	build_noafile();

	jailroot_dirfd = open(jailroot, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (jailroot_dirfd < 0)
		ERROR("mount_all: open(%s, O_PATH|O_DIRECTORY): %m\n", jailroot);

	avl_for_each_element(&libraries, l, avl)
		add_mount_bind(l->path, 1, -1);

	/* the spec has the runtime establish the mounts in the order they are listed */
	list_for_each_entry(m, &mounts_order, list) {
		if (mount_one(jailroot, jail_dev, m)) {
			ret = -1;
			break;
		}
	}

	if (jailroot_dirfd >= 0) {
		close(jailroot_dirfd);
		jailroot_dirfd = -1;
	}

	return ret;
}

void mount_free(void) {
	struct mount *m, *tmp;

	avl_remove_all_elements(&mounts, m, avl, tmp) {
		list_del(&m->list);
		if (m->source != (void*)(-1))
			free((void*)m->source);
		if (m->source_fd >= 0)
			close(m->source_fd);
		free((void*)m->target);
		free((void*)m->filesystemtype);
		free((void*)m->optstr);
		free(m->uidmappings);
		free(m->gidmappings);
		free(m);
	}
}

void mount_list_init(void) {
	avl_init(&mounts, avl_strcmp, false, NULL);
	INIT_LIST_HEAD(&mounts_order);
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
	char *fullpath = NULL;
	int fd, ret = -1;
	struct mount *bm = NULL;
	if (path[0] == '/') {
		if (avl_find(&mounts, path2))
			return 0;
		fd = open(path, O_RDONLY|O_CLOEXEC);
		if (fd < 0)
			return error;
		_add_mount_bind(path, path2, readonly, error);
		bm = avl_find_element(&mounts, path2, bm, avl);
		if (bm && bm->source_fd < 0)
			bm->source_fd = sys_open_tree(AT_FDCWD, path,
						      OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	} else {
		if (avl_find(&libraries, path))
			return 0;
		fd = lib_open(&fullpath, path);
		if (fd < 0)
			return error;
		if (fullpath)
			alloc_library(fullpath, path);
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
		/* Pass the resolved fullpath, not the bare soname, so
		 * elf_load_deps() can expand a $ORIGIN-relative DT_RPATH/
		 * DT_RUNPATH in this object against its real directory. */
		ret = elf_load_deps(fullpath ? fullpath : path, map, s.st_size);
		goto out;
	}

	ret = 0;

out:
	if (fd >= 0)
		close(fd);
	if (map)
		munmap(map, s.st_size);
	free(fullpath);

	return ret;
}

int add_2paths_nodeps(const char *path, const char *path2, int readonly, int error)
{
	struct mount *bm = NULL;

	if (path[0] != '/') {
		ERROR("%s is not an absolute path\n", path);
		return error;
	}

	if (avl_find(&mounts, path2))
		return 0;

	if (_add_mount_bind(path, path2, readonly, error))
		return error;

	bm = avl_find_element(&mounts, path2, bm, avl);
	if (bm && bm->source_fd < 0)
		bm->source_fd = sys_open_tree(AT_FDCWD, path,
					      OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);

	return 0;
}
