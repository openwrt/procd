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
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <unistd.h>
#include <values.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <libgen.h>
#include <glob.h>
#include <elf.h>
#include <sched.h>

#include "elf.h"

#include <libubox/utils.h>
#include <libubox/list.h>
#include <libubox/uloop.h>

#define STACK_SIZE	(1024 * 1024)
#define OPT_ARGS	"P:S:n:r:w:psuldo"

struct extra {
	struct list_head list;

	const char *path;
	const char *name;
	int readonly;
};

static LIST_HEAD(extras);

extern int pivot_root(const char *new_root, const char *put_old);

int debug = 0;

static char child_stack[STACK_SIZE];

static int mkdir_p(char *dir, mode_t mask)
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
		ERROR("mkdir failed on %s: %s\n", dir, strerror(errno));

	return ret;
}

static int mount_bind(const char *root, const char *path, const char *name, int readonly, int error)
{
	const char *p = path;
	struct stat s;
	char old[256];
	char new[256];
	int fd;

	if (strstr(p, "local"))
		p = "/lib";

	snprintf(old, sizeof(old), "%s/%s", path, name);
	snprintf(new, sizeof(new), "%s%s", root, p);

	mkdir_p(new, 0755);

	snprintf(new, sizeof(new), "%s%s/%s", root, p, name);

	if (stat(old, &s)) {
		ERROR("%s does not exist\n", old);
		return error;
	}

	if (S_ISDIR(s.st_mode)) {
		mkdir_p(new, 0755);
	} else {
		fd = creat(new, 0644);
		if (fd == -1) {
			ERROR("failed to create %s: %s\n", new, strerror(errno));
			return -1;
		}
		close(fd);
	}

	if (mount(old, new, NULL, MS_BIND, NULL)) {
		ERROR("failed to mount -B %s %s: %s\n", old, new, strerror(errno));
		return -1;
	}

	if (readonly && mount(old, new, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL)) {
		ERROR("failed to remount ro %s: %s\n", new, strerror(errno));
		return -1;
	}

	DEBUG("mount -B %s %s\n", old, new);

	return 0;
}

static int build_jail(const char *path)
{
	struct library *l;
	struct extra *m;
	int ret = 0;

	mkdir(path, 0755);

	if (mount("tmpfs", path, "tmpfs", MS_NOATIME, "mode=0744")) {
		ERROR("tmpfs mount failed %s\n", strerror(errno));
		return -1;
	}

	avl_for_each_element(&libraries, l, avl)
		if (mount_bind(path, l->path, l->name, 1, -1))
			return -1;

	list_for_each_entry(m, &extras, list)
		if (mount_bind(path, m->path, m->name, m->readonly, 0))
			return -1;

	return ret;
}

static void _umount(const char *root, const char *path)
{
	char *buf = NULL;

	if (asprintf(&buf, "%s%s", root, path) < 0) {
		ERROR("failed to alloc umount buffer: %s\n", strerror(errno));
	} else {
		DEBUG("umount %s\n", buf);
		umount(buf);
		free(buf);
	}
}

static int stop_jail(const char *root)
{
	struct library *l;
	struct extra *m;

	avl_for_each_element(&libraries, l, avl) {
		char path[256];
		char *p = l->path;

		if (strstr(p, "local"))
			p = "/lib";

		snprintf(path, sizeof(path), "%s%s/%s", root, p, l->name);
		DEBUG("umount %s\n", path);
		umount(path);
	}

	list_for_each_entry(m, &extras, list) {
		char path[256];

		snprintf(path, sizeof(path), "%s%s/%s", root, m->path, m->name);
		DEBUG("umount %s\n", path);
		umount(path);
	}

	_umount(root, "/proc");
	_umount(root, "/sys");

	DEBUG("umount %s\n", root);
	umount(root);
	rmdir(root);

	return 0;
}

#define MAX_ENVP	8
static char** build_envp(const char *seccomp, int debug)
{
	static char *envp[MAX_ENVP];
	static char preload_var[64];
	static char seccomp_var[64];
	static char debug_var[] = "LD_DEBUG=all";
	char *preload_lib = find_lib("libpreload-seccomp.so");
	int count = 0;

	if (seccomp && !preload_lib) {
		ERROR("failed to add preload-lib to env\n");
		return NULL;
	}
	if (seccomp) {
		snprintf(seccomp_var, sizeof(seccomp_var), "SECCOMP_FILE=%s", seccomp);
		envp[count++] = seccomp_var;
		snprintf(preload_var, sizeof(preload_var), "LD_PRELOAD=%s", preload_lib);
		envp[count++] = preload_var;
	}
	if (debug)
		envp[count++] = debug_var;

	return envp;
}

static int spawn(const char *path, char **argv, const char *seccomp)
{
	pid_t pid = fork();

	if (pid < 0) {
		ERROR("failed to spawn %s: %s\n", *argv, strerror(errno));
		return -1;
	} else if (!pid) {
		char **envp = build_envp(seccomp, 0);

		INFO("spawning %s\n", *argv);
		execve(*argv, argv, envp);
		ERROR("failed to spawn child %s: %s\n", *argv, strerror(errno));
		exit(-1);
	}

	return pid;
}

static int usage(void)
{
	fprintf(stderr, "jail <options> -D <binary> <params ...>\n");
	fprintf(stderr, "  -P <path>\tpath where the jail will be staged\n");
	fprintf(stderr, "  -S <file>\tseccomp filter\n");
	fprintf(stderr, "  -n <name>\tthe name of the jail\n");
	fprintf(stderr, "  -r <file>\treadonly files that should be staged\n");
	fprintf(stderr, "  -w <file>\twriteable files that should be staged\n");
	fprintf(stderr, "  -p\t\tjail has /proc\t\n");
	fprintf(stderr, "  -s\t\tjail has /sys\t\n");
	fprintf(stderr, "  -l\t\tjail has /dev/log\t\n");
	fprintf(stderr, "  -u\t\tjail has a ubus socket\t\n");

	return -1;
}

static int child_running = 1;

static void child_process_handler(struct uloop_process *c, int ret)
{
	INFO("child (%d) exited: %d\n", c->pid, ret);
	uloop_end();
	child_running = 0;
}

struct uloop_process child_process = {
	.cb = child_process_handler,
};

static int spawn_child(void *arg)
{
	char *path = get_current_dir_name();
	int procfs = 0, sysfs = 0;
	char *seccomp = NULL;
	char **argv = arg;
	int argc = 0, ch;
	char *mpoint;
	int ronly = 0;

	while (argv[argc])
		argc++;

	optind = 0;
	while ((ch = getopt(argc, argv, OPT_ARGS)) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'S':
			seccomp = optarg;
			break;
		case 'p':
			procfs = 1;
			break;
		case 'o':
			ronly = 1;
			break;
		case 's':
			sysfs = 1;
			break;
		case 'n':
			if (sethostname(optarg, strlen(optarg)))
				ERROR("failed to sethostname: %s\n", strerror(errno));
			break;
		}
	}

	if (asprintf(&mpoint, "%s/old", path) < 0) {
		ERROR("failed to alloc pivot path: %s\n", strerror(errno));
		return -1;
	}
	mkdir_p(mpoint, 0755);
	if (pivot_root(path, mpoint) == -1) {
		ERROR("pivot_root failed:%s\n", strerror(errno));
		return -1;
	}
	free(mpoint);
	umount2("/old", MNT_DETACH);
	rmdir("/old");
	if (procfs) {
		mkdir("/proc", 0755);
		mount("proc", "/proc", "proc", MS_NOATIME, 0);
	}
	if (sysfs) {
		mkdir("/sys", 0755);
		mount("sysfs", "/sys", "sysfs", MS_NOATIME, 0);
	}
	if (ronly)
		mount(NULL, "/", NULL, MS_RDONLY | MS_REMOUNT, 0);

	uloop_init();

	child_process.pid = spawn(path, &argv[optind], seccomp);
	uloop_process_add(&child_process);
	uloop_run();
	uloop_done();
	if (child_running) {
		kill(child_process.pid, SIGTERM);
		waitpid(child_process.pid, NULL, 0);
	}

	return 0;
}

static int namespace_running = 1;

static void namespace_process_handler(struct uloop_process *c, int ret)
{
	INFO("namespace (%d) exited: %d\n", c->pid, ret);
	uloop_end();
	namespace_running = 0;
}

struct uloop_process namespace_process = {
	.cb = namespace_process_handler,
};

static void spawn_namespace(const char *path, int argc, char **argv)
{
	char *dir = get_current_dir_name();

	uloop_init();
	if (chdir(path)) {
		ERROR("failed to chdir() into the jail\n");
		return;
	}
	namespace_process.pid = clone(spawn_child,
			child_stack + STACK_SIZE,
			CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | SIGCHLD, argv);

	if (namespace_process.pid != -1) {
		if (chdir(dir))
			ERROR("failed to chdir() out of the jail\n");
		free(dir);
		uloop_process_add(&namespace_process);
		uloop_run();
		uloop_done();
		if (namespace_running) {
			kill(namespace_process.pid, SIGTERM);
			waitpid(namespace_process.pid, NULL, 0);
		}
	} else {
		ERROR("failed to spawn namespace: %s\n", strerror(errno));
	}
}

static void add_extra(char *name, int readonly)
{
	struct extra *f;

	if (*name != '/') {
		ERROR("%s is not an absolute path\n", name);
		return;
	}

	f = calloc(1, sizeof(struct extra));

	f->name = basename(name);
	f->path = dirname(strdup(name));
	f->readonly = readonly;

	list_add_tail(&f->list, &extras);
}

int main(int argc, char **argv)
{
	uid_t uid = getuid();
	const char *name = NULL;
	char *path = NULL;
	struct stat s;
	int ch, ret;
	char log[] = "/dev/log";
	char ubus[] = "/var/run/ubus.sock";

	if (uid) {
		ERROR("not root, aborting: %s\n", strerror(errno));
		return -1;
	}

	umask(022);

	while ((ch = getopt(argc, argv, OPT_ARGS)) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'P':
			path = optarg;
			break;
		case 'n':
			name = optarg;
			break;
		case 'S':
		case 'r':
			add_extra(optarg, 1);
			break;
		case 'w':
			add_extra(optarg, 0);
			break;
		case 'u':
			add_extra(ubus, 0);
			break;
		case 'l':
			add_extra(log, 0);
			break;
		}
	}

	if (argc - optind < 1)
		return usage();

	if (!path && asprintf(&path, "/tmp/%s", basename(argv[optind])) == -1) {
		ERROR("failed to set root path\n: %s", strerror(errno));
		return -1;
	}

	if (!stat(path, &s)) {
		ERROR("%s already exists: %s\n", path, strerror(errno));
		return -1;
	}

	if (name)
		prctl(PR_SET_NAME, name, NULL, NULL, NULL);

	avl_init(&libraries, avl_strcmp, false, NULL);
	alloc_library_path("/lib64");
	alloc_library_path("/lib");
	alloc_library_path("/usr/lib");
	load_ldso_conf("/etc/ld.so.conf");

	if (elf_load_deps(argv[optind])) {
		ERROR("failed to load dependencies\n");
		return -1;
	}

	if (elf_load_deps("libpreload-seccomp.so")) {
		ERROR("failed to load libpreload-seccomp.so\n");
		return -1;
	}

	ret = build_jail(path);

	if (!ret)
		spawn_namespace(path, argc, argv);
	else
		ERROR("failed to build jail\n");

	stop_jail(path);

	return ret;
}
