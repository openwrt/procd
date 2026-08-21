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
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <glob.h>
#include <elf.h>
#include <linux/limits.h>
#include <unistd.h>
#include <stdlib.h>

#include <libubox/utils.h>

#include "elf.h"
#include "fs.h"
#include "log.h"

struct avl_tree libraries;
static LIST_HEAD(library_paths);

/* DT_RPATH search dirs: transitive, inherited by dependencies-of-dependencies. */
static LIST_HEAD(rpath_scope);

/* DT_RUNPATH search dirs: NON-transitive (applies only to the defining
 * object's direct DT_NEEDED entries), so it's reset and restored on every
 * scan call regardless of whether that object defines its own.
 */
static LIST_HEAD(runpath_scope);

/* Trailing-slash-stripped length of `path`, keeping the one slash of root
 * ("/"), so stored dirs are canonical and path_exists_in() can dedup by
 * plain length+content comparison (e.g. "/foo" == "/foo/").
 */
static size_t normalized_len(const char *path)
{
	size_t len = strlen(path);

	while (len > 1 && path[len - 1] == '/')
		len--;

	return len;
}

static void alloc_library_path(const char *path)
{
	struct stat s;
	if (stat(path, &s))
		return;

	struct library_path *p;
	char *_path;
	size_t len = normalized_len(path);

	p = calloc_a(sizeof(*p),
		&_path, len + 1);
	if (!p)
		return;

	p->path = _path;
	memcpy(p->path, path, len);
	p->path[len] = '\0';

	list_add_tail(&p->list, &library_paths);
	DEBUG("adding ld.so path %s\n", p->path);
}

static bool path_exists_in(struct list_head *list, const char *path)
{
	struct library_path *p;
	size_t len = normalized_len(path);

	list_for_each_entry(p, list, list)
		if (strlen(p->path) == len && !memcmp(p->path, path, len))
			return true;

	return false;
}

/*
 * If `path` exists and isn't already in `target` or `own`, append it to
 * `own` (list_add_tail, not list_add: preserves left-to-right RPATH/RUNPATH
 * order once `own` is later spliced onto the front of `target`).
 */
static void alloc_library_path_front(struct list_head *own, struct list_head *target, const char *path)
{
	struct stat s;
	struct library_path *p;
	char *_path;
	size_t len;

	if (stat(path, &s))
		return;

	if (path_exists_in(target, path) || path_exists_in(own, path))
		return;

	len = normalized_len(path);

	p = calloc_a(sizeof(*p),
		&_path, len + 1);
	if (!p)
		return;

	p->path = _path;
	memcpy(p->path, path, len);
	p->path[len] = '\0';

	list_add_tail(&p->list, own);
	DEBUG("adding rpath/runpath dir %s\n", p->path);
}

/*
 * Expand an RPATH/RUNPATH string ($ORIGIN, empty-token==cwd, ":"-separated)
 * and prepend its directories onto `target`, preserving left-to-right order.
 * Returns a boundary marker usable with free_scope_dirs() to later remove
 * exactly the entries added here.
 */
static struct list_head *add_rpath_dirs(struct list_head *target, const char *rpath, const char *binpath)
{
	struct list_head *boundary = target->next;
	LIST_HEAD(own);
	char origin_dir[PATH_MAX] = "";
	char cwd[PATH_MAX];
	bool have_cwd = false;
	char *copy, *rest, *tok;
	char *slash;

	if (!rpath || !*rpath)
		return boundary;

	snprintf(origin_dir, sizeof(origin_dir), "%s", binpath);
	slash = strrchr(origin_dir, '/');
	if (slash)
		*slash = '\0';
	else
		origin_dir[0] = '\0';

	copy = strdup(rpath);
	if (!copy)
		return boundary;

	rest = copy;
	while ((tok = strsep(&rest, ":")) != NULL) {
		char resolved[PATH_MAX];
		size_t originlen = 0;

		if (!*tok) {
			if (!have_cwd) {
				if (!getcwd(cwd, sizeof(cwd)))
					continue;
				have_cwd = true;
			}
			alloc_library_path_front(&own, target, cwd);
			continue;
		}

		if (!strncmp(tok, "$ORIGIN", 7) &&
		    (tok[7] == '\0' || tok[7] == '/'))
			originlen = 7;
		else if (!strncmp(tok, "${ORIGIN}", 9) &&
			 (tok[9] == '\0' || tok[9] == '/'))
			originlen = 9;

		if (originlen) {
			snprintf(resolved, sizeof(resolved), "%s%s", origin_dir, tok + originlen);
			alloc_library_path_front(&own, target, resolved);
		} else {
			alloc_library_path_front(&own, target, tok);
		}
	}

	free(copy);

	list_splice(&own, target);

	return boundary;
}

/*
 * Free every entry that was added to `target` in front of `boundary`
 * (i.e. everything a matching add_rpath_dirs() call spliced in), restoring
 * `target` to exactly the state it had before that call.
 */
static void free_scope_dirs(struct list_head *target, struct list_head *boundary)
{
	while (target->next != boundary) {
		struct library_path *p = list_entry(target->next, struct library_path, list);
		list_del(&p->list);
		free(p);
	}
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

	list_for_each_entry(p, &runpath_scope, list) {
		snprintf(path, sizeof(path), "%s/%s", p->path, file);
		fd = open(path, O_RDONLY|O_CLOEXEC);
		if (fd >= 0) {
			*fullpath = strdup(path);
			return fd;
		}
	}

	list_for_each_entry(p, &rpath_scope, list) {
		snprintf(path, sizeof(path), "%s/%s", p->path, file);
		fd = open(path, O_RDONLY|O_CLOEXEC);
		if (fd >= 0) {
			*fullpath = strdup(path);
			return fd;
		}
	}

	list_for_each_entry(p, &library_paths, list) {
		snprintf(path, sizeof(path), "%s/%s", p->path, file);
		fd = open(path, O_RDONLY|O_CLOEXEC);
		if (fd >= 0) {
			*fullpath = strdup(path);
			return fd;
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

static int elf64_find_section(const char *map, unsigned long map_size, unsigned int type, unsigned long *offset, unsigned long *size, unsigned long *vaddr)
{
	Elf64_Ehdr *e;
	Elf64_Phdr *ph;
	unsigned long phoff, phnum, i;

	if (map_size < sizeof(Elf64_Ehdr))
		return -1;

	e = (Elf64_Ehdr *) map;
	phoff = e->e_phoff;
	phnum = e->e_phnum;

	if (e->e_phentsize != sizeof(Elf64_Phdr))
		return -1;

	if (phoff >= map_size || phnum > (map_size - phoff) / sizeof(Elf64_Phdr))
		return -1;

	ph = (Elf64_Phdr *) (map + phoff);

	for (i = 0; i < phnum; i++) {
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

static int elf32_find_section(const char *map, unsigned long map_size, unsigned int type, unsigned long *offset, unsigned long *size, unsigned long *vaddr)
{
	Elf32_Ehdr *e;
	Elf32_Phdr *ph;
	unsigned long phoff, phnum, i;

	if (map_size < sizeof(Elf32_Ehdr))
		return -1;

	e = (Elf32_Ehdr *) map;
	phoff = e->e_phoff;
	phnum = e->e_phnum;

	if (e->e_phentsize != sizeof(Elf32_Phdr))
		return -1;

	if (phoff >= map_size || phnum > (map_size - phoff) / sizeof(Elf32_Phdr))
		return -1;

	ph = (Elf32_Phdr *) (map + phoff);

	for (i = 0; i < phnum; i++) {
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

static int elf_find_section(const char *map, unsigned long map_size, unsigned int type, unsigned long *offset, unsigned long *size, unsigned long *vaddr)
{
	int clazz;

	if (map_size < 1 + EI_CLASS)
		return -1;

	clazz = map[EI_CLASS];

	if (clazz == ELFCLASS32)
		return elf32_find_section(map, map_size, type, offset, size, vaddr);
	else if (clazz == ELFCLASS64)
		return elf64_find_section(map, map_size, type, offset, size, vaddr);

	ERROR("unknown elf format %d\n", clazz);

	return -1;
}

/*
 * Resolve a DT_* string-table offset into a NUL-terminated C string,
 * rejecting anything (bad DT_STRSZ/d_val) that would read outside the
 * mapped file.
 */
static const char *dyn_str(const char *map, unsigned long map_size,
			    const char *strtab, unsigned long str_size,
			    unsigned long d_val)
{
	unsigned long tab_off;
	const char *s, *tab_end;

	if (!strtab)
		return NULL;

	if (strtab < map)
		return NULL;

	tab_off = (unsigned long) (strtab - map);
	if (tab_off > map_size)
		return NULL;

	if (str_size > map_size - tab_off)
		str_size = map_size - tab_off;

	if (d_val >= str_size)
		return NULL;

	s = strtab + d_val;
	tab_end = strtab + str_size;
	if (!memchr(s, '\0', (size_t) (tab_end - s)))
		return NULL;

	return s;
}

/*
 * DT_RPATH/DT_RUNPATH are read and pushed onto their scope lists before the
 * DT_NEEDED pass below, so this object's own dependencies resolve through
 * them too, as a real runtime linker would.
 */
static int elf32_scan_dynamic(const char *map, unsigned long map_size, unsigned long dyn_offset, unsigned long dyn_size, long load_offset, const char *path)
{
	Elf32_Dyn *dyn_arr = (Elf32_Dyn *) (map + dyn_offset);
	unsigned long dyn_count, di;
	const char *strtab = NULL;
	unsigned long str_size = 0;
	unsigned long rpath_val = 0, runpath_val = 0;
	bool have_rpath = false, have_runpath = false;
	const char *rpath, *runpath;
	struct list_head *rpath_boundary = NULL;
	struct library_path *p, *ptmp;
	int ret = 0;

	/*
	 * A well-formed PT_DYNAMIC segment is a whole array of Elf32_Dyn
	 * entries (ELF spec); reject anything else outright instead of
	 * silently truncating, and iterate by validated index rather than
	 * pointer comparison so a partial trailing entry can never be
	 * dereferenced past the segment/map bounds.
	 */
	if (dyn_size % sizeof(Elf32_Dyn) != 0) {
		ERROR("PT_DYNAMIC size is not a multiple of Elf32_Dyn in %s\n", path);
		return -1;
	}
	dyn_count = dyn_size / sizeof(Elf32_Dyn);

	for (di = 0; di < dyn_count; di++) {
		Elf32_Dyn *curr = &dyn_arr[di];
		unsigned long strtab_off;

		switch (curr->d_tag) {
		case DT_STRTAB:
			strtab_off = (unsigned long) curr->d_un.d_ptr - load_offset;
			if (strtab_off >= map_size)
				continue;
			strtab = map + strtab_off;
			break;
		case DT_STRSZ:
			str_size = curr->d_un.d_val;
			break;
		case DT_RPATH:
			rpath_val = curr->d_un.d_val;
			have_rpath = true;
			break;
		case DT_RUNPATH:
			runpath_val = curr->d_un.d_val;
			have_runpath = true;
			break;
		default:
			break;
		}
	}

	if (!strtab)
		return -1;

	/* DT_RUNPATH tag presence alone suppresses DT_RPATH (ld.so(8)),
	 * regardless of whether DT_RUNPATH's value itself resolves. */
	rpath = (have_rpath && !have_runpath) ? dyn_str(map, map_size, strtab, str_size, rpath_val) : NULL;
	runpath = have_runpath ? dyn_str(map, map_size, strtab, str_size, runpath_val) : NULL;

	LIST_HEAD(saved_runpath);
	list_splice_init(&runpath_scope, &saved_runpath);
	if (runpath)
		add_rpath_dirs(&runpath_scope, runpath, path);

	if (rpath)
		rpath_boundary = add_rpath_dirs(&rpath_scope, rpath, path);

	for (di = 0; di < dyn_count; di++) {
		Elf32_Dyn *curr = &dyn_arr[di];
		const char *needed;

		if (curr->d_tag != DT_NEEDED)
			continue;

		needed = dyn_str(map, map_size, strtab, str_size, curr->d_un.d_val);
		if (!needed) {
			ERROR("corrupt DT_NEEDED entry in %s\n", path);
			ret = -1;
			break;
		}

		if (add_path_and_deps(needed, 1, -1, 1)) {
			ret = -1;
			break;
		}
	}

	if (rpath)
		free_scope_dirs(&rpath_scope, rpath_boundary);

	list_for_each_entry_safe(p, ptmp, &runpath_scope, list)
		free(p);
	INIT_LIST_HEAD(&runpath_scope);
	list_splice_init(&saved_runpath, &runpath_scope);

	return ret;
}

static int elf64_scan_dynamic(const char *map, unsigned long map_size, unsigned long dyn_offset, unsigned long dyn_size, long load_offset, const char *path)
{
	Elf64_Dyn *dyn_arr = (Elf64_Dyn *) (map + dyn_offset);
	unsigned long dyn_count, di;
	const char *strtab = NULL;
	unsigned long str_size = 0;
	unsigned long rpath_val = 0, runpath_val = 0;
	bool have_rpath = false, have_runpath = false;
	const char *rpath, *runpath;
	struct list_head *rpath_boundary = NULL;
	struct library_path *p, *ptmp;
	int ret = 0;

	/*
	 * A well-formed PT_DYNAMIC segment is a whole array of Elf64_Dyn
	 * entries (ELF spec); reject anything else outright instead of
	 * silently truncating, and iterate by validated index rather than
	 * pointer comparison so a partial trailing entry can never be
	 * dereferenced past the segment/map bounds.
	 */
	if (dyn_size % sizeof(Elf64_Dyn) != 0) {
		ERROR("PT_DYNAMIC size is not a multiple of Elf64_Dyn in %s\n", path);
		return -1;
	}
	dyn_count = dyn_size / sizeof(Elf64_Dyn);

	for (di = 0; di < dyn_count; di++) {
		Elf64_Dyn *curr = &dyn_arr[di];
		unsigned long strtab_off;

		switch (curr->d_tag) {
		case DT_STRTAB:
			strtab_off = (unsigned long) curr->d_un.d_ptr - load_offset;
			if (strtab_off >= map_size)
				continue;
			strtab = map + strtab_off;
			break;
		case DT_STRSZ:
			str_size = curr->d_un.d_val;
			break;
		case DT_RPATH:
			rpath_val = curr->d_un.d_val;
			have_rpath = true;
			break;
		case DT_RUNPATH:
			runpath_val = curr->d_un.d_val;
			have_runpath = true;
			break;
		default:
			break;
		}
	}

	if (!strtab)
		return -1;

	/* DT_RUNPATH tag presence alone suppresses DT_RPATH (ld.so(8)),
	 * regardless of whether DT_RUNPATH's value itself resolves. */
	rpath = (have_rpath && !have_runpath) ? dyn_str(map, map_size, strtab, str_size, rpath_val) : NULL;
	runpath = have_runpath ? dyn_str(map, map_size, strtab, str_size, runpath_val) : NULL;

	LIST_HEAD(saved_runpath);
	list_splice_init(&runpath_scope, &saved_runpath);
	if (runpath)
		add_rpath_dirs(&runpath_scope, runpath, path);

	if (rpath)
		rpath_boundary = add_rpath_dirs(&rpath_scope, rpath, path);

	for (di = 0; di < dyn_count; di++) {
		Elf64_Dyn *curr = &dyn_arr[di];
		const char *needed;

		if (curr->d_tag != DT_NEEDED)
			continue;

		needed = dyn_str(map, map_size, strtab, str_size, curr->d_un.d_val);
		if (!needed) {
			ERROR("corrupt DT_NEEDED entry in %s\n", path);
			ret = -1;
			break;
		}

		if (add_path_and_deps(needed, 1, -1, 1)) {
			ret = -1;
			break;
		}
	}

	if (rpath)
		free_scope_dirs(&rpath_scope, rpath_boundary);

	list_for_each_entry_safe(p, ptmp, &runpath_scope, list)
		free(p);
	INIT_LIST_HEAD(&runpath_scope);
	list_splice_init(&saved_runpath, &runpath_scope);

	return ret;
}

int elf_load_deps(const char *path, const char *map, unsigned long map_size)
{
	unsigned long dyn_offset, dyn_size;
	unsigned long load_offset, load_vaddr;
	unsigned long interp_offset;

	if (elf_find_section(map, map_size, PT_INTERP, &interp_offset, NULL, NULL) == 0) {
		if (interp_offset < map_size &&
		    memchr(map + interp_offset, '\0', map_size - interp_offset))
			add_path_and_deps(map+interp_offset, 1, -1, 0);
		else
			ERROR("corrupt PT_INTERP entry in %s\n", path);
	}

	if (elf_find_section(map, map_size, PT_LOAD, &load_offset, NULL, &load_vaddr)) {
		DEBUG("failed to load the .load section from %s\n", path);
		return 0;
	}

	if (elf_find_section(map, map_size, PT_DYNAMIC, &dyn_offset, &dyn_size, NULL)) {
		DEBUG("failed to load the .dynamic section from %s\n", path);
		return 0;
	}

	if (dyn_offset >= map_size || dyn_size > map_size - dyn_offset) {
		ERROR("PT_DYNAMIC out of bounds in %s\n", path);
		return -1;
	}

	int clazz = map[EI_CLASS];

	if (clazz == ELFCLASS32)
		return elf32_scan_dynamic(map, map_size, dyn_offset, dyn_size, load_vaddr - load_offset, path);
	else if (clazz == ELFCLASS64)
		return elf64_scan_dynamic(map, map_size, dyn_offset, dyn_size, load_vaddr - load_offset, path);

	ERROR("unknown elf format %d\n", clazz);
	return -1;
}

static char *elf_map_file(const char *path, size_t *size)
{
	struct stat s;
	void *map;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &s) || s.st_size < (off_t)sizeof(Elf64_Ehdr)) {
		close(fd);
		return NULL;
	}

	map = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED)
		return NULL;

	*size = s.st_size;
	return map;
}

#define ELF_DYNSYM_VALUE(BITS) \
static unsigned long elf##BITS##_dynsym_value(const char *map, unsigned long map_size, const char *want) \
{ \
	Elf##BITS##_Dyn *dyn; \
	Elf##BITS##_Sym *symtab = NULL; \
	const char *strtab = NULL; \
	unsigned long dyn_off, dyn_size, load_off, load_vaddr, delta; \
	unsigned long syment = sizeof(Elf##BITS##_Sym), nsyms = 0, i; \
	\
	if (elf##BITS##_find_section(map, map_size, PT_LOAD, &load_off, NULL, &load_vaddr)) \
		return 0; \
	if (elf##BITS##_find_section(map, map_size, PT_DYNAMIC, &dyn_off, &dyn_size, NULL)) \
		return 0; \
	delta = load_vaddr - load_off; \
	\
	for (dyn = (Elf##BITS##_Dyn *)(map + dyn_off); \
	     (char *)dyn < map + dyn_off + dyn_size; dyn++) { \
		if (dyn->d_tag == DT_SYMTAB) \
			symtab = (Elf##BITS##_Sym *)(map + (dyn->d_un.d_ptr - delta)); \
		else if (dyn->d_tag == DT_STRTAB) \
			strtab = map + (dyn->d_un.d_ptr - delta); \
		else if (dyn->d_tag == DT_SYMENT) \
			syment = dyn->d_un.d_val; \
		else if (dyn->d_tag == DT_HASH) \
			nsyms = ((const uint32_t *)(map + (dyn->d_un.d_ptr - delta)))[1]; \
	} \
	\
	if (!symtab || !strtab) \
		return 0; \
	if (!nsyms) \
		nsyms = ((const char *)strtab - (const char *)symtab) / syment; \
	\
	for (i = 0; i < nsyms; i++) { \
		Elf##BITS##_Sym *sym = (Elf##BITS##_Sym *)((const char *)symtab + i * syment); \
		if (sym->st_value && !strcmp(strtab + sym->st_name, want)) \
			return sym->st_value; \
	} \
	\
	return 0; \
}
ELF_DYNSYM_VALUE(32)
ELF_DYNSYM_VALUE(64)

unsigned long elf_dynsym_value(const char *path, const char *sym)
{
	unsigned long val = 0;
	size_t size = 0;
	char *map;
	int clazz;

	map = elf_map_file(path, &size);
	if (!map)
		return 0;

	clazz = map[EI_CLASS];
	if (clazz == ELFCLASS32)
		val = elf32_dynsym_value(map, size, sym);
	else if (clazz == ELFCLASS64)
		val = elf64_dynsym_value(map, size, sym);

	munmap(map, size);
	return val;
}

int elf_interp(const char *path, char *out, size_t outlen)
{
	unsigned long off, size_pt;
	size_t size = 0;
	char *map;
	int ret = -1;

	map = elf_map_file(path, &size);
	if (!map)
		return -1;

	if (!elf_find_section(map, size, PT_INTERP, &off, &size_pt, NULL) && off < size) {
		snprintf(out, outlen, "%s", map + off);
		ret = 0;
	}

	munmap(map, size);
	return ret;
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

void free_library_search(void)
{
	struct library_path *p, *ptmp;
	struct library *l, *tmp;

	list_for_each_entry_safe(p, ptmp, &library_paths, list)
		free(p);

	/* rpath_scope/runpath_scope should already be empty here (every
	 * scoped push in elf32/64_scan_dynamic has a matching pop); free
	 * defensively in case that ever stops holding. */
	list_for_each_entry_safe(p, ptmp, &rpath_scope, list)
		free(p);

	list_for_each_entry_safe(p, ptmp, &runpath_scope, list)
		free(p);

	avl_remove_all_elements(&libraries, l, avl, tmp)
		free(l);
}
