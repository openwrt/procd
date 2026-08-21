/*
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
#ifndef _JAIL_FS_H_
#define _JAIL_FS_H_

#include <fcntl.h>
#include <sys/mount.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <libubox/blobmsg.h>

#include "../container.h"

#define JAIL_NOAFILE "/dev/.ujailnoafile"

int sys_openat2(int dfd, const char *path, struct open_how *how, size_t size);
int build_userns_fd(struct blob_attr *uidmappings, struct blob_attr *gidmappings);
int jail_idmap_build(const char *extroot,
		     struct blob_attr *uidmap, struct blob_attr *gidmap,
		     int *fds, int maxfds);
int jail_idmap_assign(bool have_extroot, bool have_overlay, const int *fds, int nfds,
		      int *extroot_fd, int *overlay_fd);
bool jail_dir_is_fresh(const char *path);
void jail_chown_fresh_volumes(uid_t uid, gid_t gid);
void jail_set_idmap_offset(unsigned int offset);

int add_mount(const char *source, const char *target, const char *filesystemtype,
	      unsigned long mountflags, unsigned long propflags, const char *optstr, int error);
int add_mount_inner(const char *source, const char *target, const char *filesystemtype,
	      unsigned long mountflags, unsigned long propflags, const char *optstr, int error);
int add_mount_bind(const char *path, int readonly, int error);
int add_mount_volume(const char *source, const char *target, int error);
int fs_mount_enable_idmap(const char *target, uint32_t uid, uint32_t gid);
char *resolve_mount_source(const char *source);
int add_mount_fd(int fd, const char *target, int error);
int mask_path_now(const char *path);

/* open_tree()/mount_setattr() wrappers - no glibc wrappers yet.
 * Fields must match the kernel's struct mount_attr layout exactly
 * (__u64, not unsigned long - many OpenWrt targets are 32-bit). */
#include <stdint.h>
struct ujail_mount_attr {
	uint64_t attr_set, attr_clr, propagation, userns_fd;
};
int sys_open_tree(int dfd, const char *path, unsigned flags);
int sys_move_mount(int from_dfd, const char *from_path, int to_dfd,
		   const char *to_path, unsigned flags);
int sys_mount_setattr(int dfd, const char *path, unsigned flags, struct ujail_mount_attr *attr, size_t size);

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
int parseOCImount(struct blob_attr *msg);
bool mount_is_defined(const char *target);
int add_2paths_and_deps(const char *path, const char *path2, int readonly, int error, int lib);
unsigned long detect_atime_flag(const char *mountpoint);
int add_2paths_nodeps(const char *path, const char *path2, int readonly, int error);

static inline int add_path_and_deps(const char *path, int readonly, int error, int lib)
{
	return add_2paths_and_deps(path, path, readonly, error, lib);
}

void mount_stage_dev(const char *jail_dev);
int mount_all(const char *jailroot, const char *jail_dev);
void mount_list_init(void);
void mount_free(void);
void jail_fs_set_userns(bool enabled);

#endif
