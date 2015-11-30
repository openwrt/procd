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

#define _GNU_SOURCE

#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glob.h>
#include <elf.h>
#include <linux/limits.h>

#include <libubox/utils.h>

#include "elf.h"
#include "fs.h"
#include "log.h"

struct avl_tree libraries;
static LIST_HEAD(library_paths);

static void alloc_library_path(const char *path)
{
	struct stat s;
	if (stat(path, &s))
		return;

	struct library_path *p;
	char *_path;

	p = calloc_a(sizeof(*p),
		&_path, strlen(path) + 1);
	if (!p)
		return;

	p->path = strcpy(_path, path);

	list_add_tail(&p->list, &library_paths);
	DEBUG("adding ld.so path %s\n", path);
}

/*
 * path = full path
 * name = soname/avl key
 */
void alloc_library(const char *path, const char *name)
{
	struct library *l;
	char *_name, *_path;

	l = calloc_a(sizeof(*l),
		&_path, strlen(path) + 1,
		&_name, strlen(name) + 1);
	if (!l)
		return;

	l->avl.key = l->name = strcpy(_name, name);
	l->path = strcpy(_path, path);

	avl_insert(&libraries, &l->avl);
	DEBUG("adding library %s (%s)\n", path, name);
}

int lib_open(char **fullpath, const char *file)
{
	struct library_path *p;
	char path[PATH_MAX];
	int fd = -1;

	*fullpath = NULL;

	list_for_each_entry(p, &library_paths, list) {
		snprintf(path, sizeof(path), "%s/%s", p->path, file);
		fd = open(path, O_RDONLY|O_CLOEXEC);
		if (fd >= 0) {
			*fullpath = strdup(path);
			break;
		}
	}

	return fd;
}

const char* find_lib(const char *file)
{
	struct library *l;

	l = avl_find_element(&libraries, file, l, avl);
	if (!l)
		return NULL;

	return l->path;
}

static int elf64_find_section(const char *map, unsigned int type, unsigned int *offset, unsigned int *size, unsigned int *vaddr)
{
	Elf64_Ehdr *e;
	Elf64_Phdr *ph;
	int i;

	e = (Elf64_Ehdr *) map;
	ph = (Elf64_Phdr *) (map + e->e_phoff);

	for (i = 0; i < e->e_phnum; i++) {
		if (ph[i].p_type == type) {
			*offset = ph[i].p_offset;
			if (size)
				*size = ph[i].p_filesz;
			if (vaddr)
				*vaddr = ph[i].p_vaddr;
			return 0;
		}
	}

	return -1;
}

static int elf32_find_section(const char *map, unsigned int type, unsigned int *offset, unsigned int *size, unsigned int *vaddr)
{
	Elf32_Ehdr *e;
	Elf32_Phdr *ph;
	int i;

	e = (Elf32_Ehdr *) map;
	ph = (Elf32_Phdr *) (map + e->e_phoff);

	for (i = 0; i < e->e_phnum; i++) {
		if (ph[i].p_type == type) {
			*offset = ph[i].p_offset;
			if (size)
				*size = ph[i].p_filesz;
			if (vaddr)
				*vaddr = ph[i].p_vaddr;
			return 0;
		}
	}

	return -1;
}

static int elf_find_section(const char *map, unsigned int type, unsigned int *offset, unsigned int *size, unsigned int *vaddr)
{
	int clazz = map[EI_CLASS];

	if (clazz == ELFCLASS32)
		return elf32_find_section(map, type, offset, size, vaddr);
	else if (clazz == ELFCLASS64)
		return elf64_find_section(map, type, offset, size, vaddr);

	ERROR("unknown elf format %d\n", clazz);

	return -1;
}

static int elf32_scan_dynamic(const char *map, int dyn_offset, int dyn_size, int load_offset)
{
	Elf32_Dyn *dynamic = (Elf32_Dyn *) (map + dyn_offset);
	const char *strtab = NULL;

	while ((void *) dynamic < (void *) (map + dyn_offset + dyn_size)) {
		Elf32_Dyn *curr = dynamic;

		dynamic++;
		if (curr->d_tag != DT_STRTAB)
			continue;

		strtab = map + (curr->d_un.d_ptr - load_offset);
		break;
	}

	if (!strtab)
		return -1;

	dynamic = (Elf32_Dyn *) (map + dyn_offset);
	while ((void *) dynamic < (void *) (map + dyn_offset + dyn_size)) {
		Elf32_Dyn *curr = dynamic;

		dynamic++;
		if (curr->d_tag != DT_NEEDED)
			continue;

		if (add_path_and_deps(&strtab[curr->d_un.d_val], 1, -1, 1))
			return -1;
	}

	return 0;
}

static int elf64_scan_dynamic(const char *map, int dyn_offset, int dyn_size, int load_offset)
{
	Elf64_Dyn *dynamic = (Elf64_Dyn *) (map + dyn_offset);
	const char *strtab = NULL;

	while ((void *) dynamic < (void *) (map + dyn_offset + dyn_size)) {
		Elf64_Dyn *curr = dynamic;

		dynamic++;
		if (curr->d_tag != DT_STRTAB)
			continue;

		strtab = map + (curr->d_un.d_ptr - load_offset);
		break;
	}

	if (!strtab)
		return -1;

	dynamic = (Elf64_Dyn *) (map + dyn_offset);
	while ((void *) dynamic < (void *) (map + dyn_offset + dyn_size)) {
		Elf64_Dyn *curr = dynamic;

		dynamic++;
		if (curr->d_tag != DT_NEEDED)
			continue;

		if (add_path_and_deps(&strtab[curr->d_un.d_val], 1, -1, 1))
			return -1;
	}

	return 0;
}

int elf_load_deps(const char *path, const char *map)
{
	unsigned int dyn_offset, dyn_size;
	unsigned int load_offset, load_vaddr;
	unsigned int interp_offset;

	if (elf_find_section(map, PT_LOAD, &load_offset, NULL, &load_vaddr)) {
		ERROR("failed to load the .load section from %s\n", path);
		return -1;
	}

	if (elf_find_section(map, PT_DYNAMIC, &dyn_offset, &dyn_size, NULL)) {
		ERROR("failed to load the .dynamic section from %s\n", path);
		return -1;
	}

	if (elf_find_section(map, PT_INTERP, &interp_offset, NULL, NULL) == 0) {
		add_path_and_deps(map+interp_offset, 1, -1, 0);
	}

	int clazz = map[EI_CLASS];

	if (clazz == ELFCLASS32)
		return elf32_scan_dynamic(map, dyn_offset, dyn_size, load_vaddr - load_offset);
	else if (clazz == ELFCLASS64)
		return elf64_scan_dynamic(map, dyn_offset, dyn_size, load_vaddr - load_offset);

	ERROR("unknown elf format %d\n", clazz);
	return -1;
}

static void load_ldso_conf(const char *conf)
{
	FILE* fp = fopen(conf, "r");
	char line[PATH_MAX];

	if (!fp) {
		DEBUG("failed to open %s\n", conf);
		return;
	}

	while (!feof(fp)) {
		int len;

		if (!fgets(line, sizeof(line), fp))
			break;
		len = strlen(line);
		if (len < 2)
			continue;
		if (*line == '#')
			continue;
		if (line[len - 1] == '\n')
			line[len - 1] = '\0';
		if (!strncmp(line, "include ", 8)) {
			char *sep = strstr(line, " ");
			glob_t gl;
			int i;

			if (!sep)
				continue;;
			while (*sep == ' ')
				sep++;
			if (glob(sep, GLOB_NOESCAPE | GLOB_MARK, NULL, &gl)) {
				ERROR("glob failed on %s\n", sep);
				continue;
			}
			for (i = 0; i < gl.gl_pathc; i++)
				load_ldso_conf(gl.gl_pathv[i]);
			globfree(&gl);
		} else {
			alloc_library_path(line);
		}
	}

	fclose(fp);
}

void init_library_search(void)
{
	avl_init(&libraries, avl_strcmp, false, NULL);
	alloc_library_path("/lib");
	alloc_library_path("/lib64");
	alloc_library_path("/usr/lib");
	load_ldso_conf("/etc/ld.so.conf");
}
