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
#include <libgen.h>
#include <sched.h>

#include "elf.h"
#include "capabilities.h"

#include <libubox/list.h>
#include <libubox/uloop.h>

#define STACK_SIZE	(1024 * 1024)
#define OPT_ARGS	"P:S:C:n:r:w:d:psulo"

static struct {
	char *path;
	char *name;
	char **jail_argv;
	char *seccomp;
	char *capabilities;
	int namespace;
	int procfs;
	int ronly;
	int sysfs;
} opts;

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

	if (readonly && mount(NULL, new, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL)) {
		ERROR("failed to remount ro %s: %s\n", new, strerror(errno));
		return -1;
	}

	DEBUG("mount -B %s %s\n", old, new);

	return 0;
}

static int build_jail_fs()
{
	struct library *l;
	struct extra *m;

	if (mount("tmpfs", opts.path, "tmpfs", MS_NOATIME, "mode=0755")) {
		ERROR("tmpfs mount failed %s\n", strerror(errno));
		return -1;
	}

	if (chdir(opts.path)) {
		ERROR("failed to chdir() in the jail root\n");
		return -1;
	}

	avl_init(&libraries, avl_strcmp, false, NULL);
	alloc_library_path("/lib64");
	alloc_library_path("/lib");
	alloc_library_path("/usr/lib");
	load_ldso_conf("/etc/ld.so.conf");

	if (elf_load_deps(*opts.jail_argv)) {
		ERROR("failed to load dependencies\n");
		return -1;
	}

	if (opts.seccomp && elf_load_deps("libpreload-seccomp.so")) {
		ERROR("failed to load libpreload-seccomp.so\n");
		return -1;
	}

	avl_for_each_element(&libraries, l, avl)
		if (mount_bind(opts.path, l->path, l->name, 1, -1))
			return -1;

	list_for_each_entry(m, &extras, list)
		if (mount_bind(opts.path, m->path, m->name, m->readonly, 0))
			return -1;

	char *mpoint;
	if (asprintf(&mpoint, "%s/old", opts.path) < 0) {
		ERROR("failed to alloc pivot path: %s\n", strerror(errno));
		return -1;
	}
	mkdir_p(mpoint, 0755);
	if (pivot_root(opts.path, mpoint) == -1) {
		ERROR("pivot_root failed:%s\n", strerror(errno));
		free(mpoint);
		return -1;
	}
	free(mpoint);
	umount2("/old", MNT_DETACH);
	rmdir("/old");
	if (opts.procfs) {
		mkdir("/proc", 0755);
		mount("proc", "/proc", "proc", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID, 0);
	}
	if (opts.sysfs) {
		mkdir("/sys", 0755);
		mount("sysfs", "/sys", "sysfs", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID, 0);
	}
	if (opts.ronly)
		mount(NULL, "/", NULL, MS_RDONLY | MS_REMOUNT, 0);

	return 0;
}

#define MAX_ENVP	8
static char** build_envp(const char *seccomp)
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
	if (debug > 1)
		envp[count++] = debug_var;

	return envp;
}

static void usage(void)
{
	fprintf(stderr, "ujail <options> -- <binary> <params ...>\n");
	fprintf(stderr, "  -d <num>\tshow debug log (increase num to increase verbosity)\n");
	fprintf(stderr, "  -S <file>\tseccomp filter config\n");
	fprintf(stderr, "  -C <file>\tcapabilities drop config\n");
	fprintf(stderr, "  -n <name>\tthe name of the jail\n");
	fprintf(stderr, "namespace jail options:\n");
	fprintf(stderr, "  -P <path>\tpath where the jail will be staged\n");
	fprintf(stderr, "  -r <file>\treadonly files that should be staged\n");
	fprintf(stderr, "  -w <file>\twriteable files that should be staged\n");
	fprintf(stderr, "  -p\t\tjail has /proc\n");
	fprintf(stderr, "  -s\t\tjail has /sys\n");
	fprintf(stderr, "  -l\t\tjail has /dev/log\n");
	fprintf(stderr, "  -u\t\tjail has a ubus socket\n");
	fprintf(stderr, "  -o\t\tremont jail root (/) read only\n");
	fprintf(stderr, "\nWarning: by default root inside the jail is the same\n\
and he has the same powers as root outside the jail,\n\
thus he can escape the jail and/or break stuff.\n\
Please use seccomp/capabilities (-S/-C) to restrict his powers\n\n\
If you use none of the namespace jail options,\n\
ujail will not use namespace/build a jail,\n\
and will only drop capabilities/apply seccomp filter.\n\n");
}

static int exec_jail()
{
	char **envp = build_envp(opts.seccomp);
	if (!envp)
		exit(EXIT_FAILURE);

	if (opts.capabilities && drop_capabilities(opts.capabilities))
		exit(EXIT_FAILURE);

	INFO("exec-ing %s\n", *opts.jail_argv);
	execve(*opts.jail_argv, opts.jail_argv, envp);
	//we get there only if execve fails
	ERROR("failed to execve %s: %s\n", *opts.jail_argv, strerror(errno));
	exit(EXIT_FAILURE);
}

static int spawn_jail(void *arg)
{
	if (opts.name && sethostname(opts.name, strlen(opts.name))) {
		ERROR("failed to sethostname: %s\n", strerror(errno));
	}

	if (build_jail_fs()) {
		ERROR("failed to build jail fs");
		exit(EXIT_FAILURE);
	}

	return exec_jail();
}

static int jail_running = 1;
static int jail_return_code = 0;

static void jail_process_handler(struct uloop_process *c, int ret)
{
	if (WIFEXITED(ret)) {
		jail_return_code = WEXITSTATUS(ret);
		INFO("jail (%d) exited with exit: %d\n", c->pid, jail_return_code);
	} else {
		jail_return_code = WTERMSIG(ret);
		INFO("jail (%d) exited with signal: %d\n", c->pid, jail_return_code);
	}
	jail_running = 0;
	uloop_end();
}

static struct uloop_process jail_process = {
	.cb = jail_process_handler,
};

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
	char log[] = "/dev/log";
	char ubus[] = "/var/run/ubus.sock";
	int ret = EXIT_SUCCESS;
	int ch;

	if (uid) {
		ERROR("not root, aborting: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	umask(022);

	while ((ch = getopt(argc, argv, OPT_ARGS)) != -1) {
		switch (ch) {
		case 'd':
			debug = atoi(optarg);
			break;
		case 'p':
			opts.namespace = 1;
			opts.procfs = 1;
			break;
		case 'o':
			opts.namespace = 1;
			opts.ronly = 1;
			break;
		case 's':
			opts.namespace = 1;
			opts.sysfs = 1;
			break;
		case 'S':
			opts.seccomp = optarg;
			add_extra(optarg, 1);
			break;
		case 'C':
			opts.capabilities = optarg;
			add_extra(optarg, 1);
			break;
		case 'P':
			opts.namespace = 1;
			opts.path = optarg;
			break;
		case 'n':
			opts.name = optarg;
			break;
		case 'r':
			opts.namespace = 1;
			add_extra(optarg, 1);
			break;
		case 'w':
			opts.namespace = 1;
			add_extra(optarg, 0);
			break;
		case 'u':
			opts.namespace = 1;
			add_extra(ubus, 0);
			break;
		case 'l':
			opts.namespace = 1;
			add_extra(log, 0);
			break;
		}
	}

	//no <binary> param found
	if (argc - optind < 1) {
		usage();
		return EXIT_FAILURE;
	}
	if (!(opts.namespace||opts.capabilities||opts.seccomp)) {
		ERROR("Not using namespaces, capabilities or seccomp !!!\n\n");
		usage();
		return EXIT_FAILURE;
	}
	DEBUG("Using namespaces(%d), capabilities(%d), seccomp(%d)\n",
		opts.namespace,
		opts.capabilities != 0,
		opts.seccomp != 0);

	opts.jail_argv = &argv[optind];

	if (opts.name)
		prctl(PR_SET_NAME, opts.name, NULL, NULL, NULL);

	if (opts.namespace && !opts.path && asprintf(&opts.path, "/tmp/%s", basename(*opts.jail_argv)) == -1) {
		ERROR("failed to asprintf root path: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	if (opts.namespace && mkdir(opts.path, 0755)) {
		ERROR("unable to create root path: %s (%s)\n", opts.path, strerror(errno));
		return EXIT_FAILURE;
	}

	uloop_init();
	if (opts.namespace) {
		jail_process.pid = clone(spawn_jail,
			child_stack + STACK_SIZE,
			CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | SIGCHLD, argv);
	} else {
		jail_process.pid = fork();
	}

	if (jail_process.pid > 0) {
		//parent process
		uloop_process_add(&jail_process);
		uloop_run();
		uloop_done();
		if (jail_running) {
			DEBUG("uloop interrupted, killing jail process\n");
			kill(jail_process.pid, SIGTERM);
			waitpid(jail_process.pid, NULL, 0);
		}
	} else if (jail_process.pid == 0) {
		//fork child process
		return exec_jail();
	} else {
		ERROR("failed to clone/fork: %s\n", strerror(errno));
		ret = EXIT_FAILURE;
	}

	if (opts.namespace && rmdir(opts.path)) {
		ERROR("Unable to remove root path: %s (%s)\n", opts.path, strerror(errno));
		ret = EXIT_FAILURE;
	}

	if (ret)
		return ret;

	return jail_return_code;
}
