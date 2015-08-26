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
#include <sys/mman.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <glob.h>
#include <elf.h>

#include <libubox/utils.h>

#include "elf.h"

struct avl_tree libraries;
static LIST_HEAD(library_paths);

void alloc_library_path(const char *path)
{
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

static void alloc_library(const char *path, const char *name)
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
	DEBUG("adding library %s/%s\n", path, name);
}

static int elf_open(char **dir, char *file)
{
	struct library_path *p;
	char path[256];
	int fd = -1;

	*dir = NULL;

	list_for_each_entry(p, &library_paths, list) {
		if (strlen(p->path))
			snprintf(path, sizeof(path), "%s/%s", p->path, file);
		else
			strncpy(path, file, sizeof(path));
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			*dir = p->path;
			break;
		}
	}

	if (fd == -1)
		fd = open(file, O_RDONLY);

	return fd;
}

char* find_lib(char *file)
{
	struct library *l;
	static char path[256];
	const char *p;

	l = avl_find_element(&libraries, file, l, avl);
	if (!l)
		return NULL;

	p = l->path;
	if (strstr(p, "local"))
		p = "/lib";

	snprintf(path, sizeof(path), "%s/%s", p, file);

	return path;
}

static int elf64_find_section(char *map, unsigned int type, unsigned int *offset, unsigned int *size, unsigned int *vaddr)
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

static int elf32_find_section(char *map, unsigned int type, unsigned int *offset, unsigned int *size, unsigned int *vaddr)
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

static int elf_find_section(char *map, unsigned int type, unsigned int *offset, unsigned int *size, unsigned int *vaddr)
{
	int clazz = map[EI_CLASS];

	if (clazz == ELFCLASS32)
		return elf32_find_section(map, type, offset, size, vaddr);
	else if (clazz == ELFCLASS64)
		return elf64_find_section(map, type, offset, size, vaddr);

	ERROR("unknown elf format %d\n", clazz);

	return -1;
}

static int elf32_scan_dynamic(char *map, int dyn_offset, int dyn_size, int load_offset)
{
	Elf32_Dyn *dynamic = (Elf32_Dyn *) (map + dyn_offset);
	char *strtab = NULL;

	while ((void *) dynamic < (void *) (map + dyn_offset + dyn_size)) {
		Elf32_Dyn *curr = dynamic;

		dynamic++;
		if (curr->d_tag != DT_STRTAB)
			continue;

		strtab = map + (curr->d_un.d_val - load_offset);
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

		if (elf_load_deps(&strtab[curr->d_un.d_val]))
			return -1;
	}

	return 0;
}

static int elf64_scan_dynamic(char *map, int dyn_offset, int dyn_size, int load_offset)
{
	Elf64_Dyn *dynamic = (Elf64_Dyn *) (map + dyn_offset);
	char *strtab = NULL;

	while ((void *) dynamic < (void *) (map + dyn_offset + dyn_size)) {
		Elf64_Dyn *curr = dynamic;

		dynamic++;
		if (curr->d_tag != DT_STRTAB)
			continue;

		strtab = map + (curr->d_un.d_val - load_offset);
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

		if (elf_load_deps(&strtab[curr->d_un.d_val]))
			return -1;
	}

	return 0;
}

int elf_load_deps(char *library)
{
	unsigned int dyn_offset, dyn_size;
	unsigned int load_offset, load_vaddr;
	struct stat s;
	char *map = NULL, *dir = NULL;
	int clazz, fd, ret = -1;

	if (avl_find(&libraries, library))
		return 0;

	fd = elf_open(&dir, library);

	if (fd < 0) {
		ERROR("failed to open %s\n", library);
		return -1;
	}

	if (fstat(fd, &s) == -1) {
		ERROR("failed to stat %s\n", library);
		ret = -1;
		goto err_out;
	}

	map = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		ERROR("failed to mmap %s\n", library);
		ret = -1;
		goto err_out;
	}

	if (elf_find_section(map, PT_LOAD, &load_offset, NULL, &load_vaddr)) {
		ERROR("failed to load the .load section from %s\n", library);
		ret = -1;
		goto err_out;
	}

	if (elf_find_section(map, PT_DYNAMIC, &dyn_offset, &dyn_size, NULL)) {
		ERROR("failed to load the .dynamic section from %s\n", library);
		ret = -1;
		goto err_out;
	}

	if (dir) {
		alloc_library(dir, library);
	} else {
		char *elf = strdup(library);

		alloc_library(dirname(elf), basename(library));
		free(elf);
	}
	clazz = map[EI_CLASS];

	if (clazz == ELFCLASS32)
		ret = elf32_scan_dynamic(map, dyn_offset, dyn_size, load_vaddr - load_offset);
	else if (clazz == ELFCLASS64)
		ret = elf64_scan_dynamic(map, dyn_offset, dyn_size, load_vaddr - load_offset);

err_out:
	if (map)
		munmap(map, s.st_size);
	close(fd);

	return ret;
}

void load_ldso_conf(const char *conf)
{
	FILE* fp = fopen(conf, "r");
	char line[256];

	if (!fp) {
		DEBUG("failed to open %s\n", conf);
		return;
	}

	while (!feof(fp)) {
		int len;

		if (!fgets(line, 256, fp))
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
			struct stat s;

			if (stat(line, &s))
				continue;
			alloc_library_path(line);
		}
	}

	fclose(fp);
}
