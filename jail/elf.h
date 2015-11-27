/*
 * Copyright (C) 2015 John Crispin <blogic@openwrt.org>
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
#ifndef _JAIL_ELF_H_
#define _JAIL_ELF_H_

#include <libubox/avl.h>
#include <libubox/avl-cmp.h>

struct library {
	struct avl_node avl;
	char *name;
	char *path;
};

struct library_path {
	struct list_head list;
	char *path;
};

extern struct avl_tree libraries;

void alloc_library(const char *path, const char *name);
int elf_load_deps(const char *path, const char *map);
const char* find_lib(const char *file);
void init_library_search(void);
int lib_open(char **fullpath, const char *file);

#endif
