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

#include <sys/mount.h>
#include <libubox/blobmsg.h>

int mkdir_p(char *dir, mode_t mask);
int add_mount(const char *source, const char *target, const char *filesystemtype,
	      unsigned long mountflags, const char *optstr, int error);
int add_mount_inner(const char *source, const char *target, const char *filesystemtype,
	      unsigned long mountflags, const char *optstr, int error);
int add_mount_bind(const char *path, int readonly, int error);
int parseOCImount(struct blob_attr *msg);
int add_path_and_deps(const char *path, int readonly, int error, int lib);
int mount_all(const char *jailroot);
void mount_list_init(void);

#endif
