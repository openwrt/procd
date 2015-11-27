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

int add_mount(const char *path, int readonly, int error);
int add_path_and_deps(const char *path, int readonly, int error, int lib);
int mount_all(const char *jailroot);
void mount_list_init(void);

#endif
