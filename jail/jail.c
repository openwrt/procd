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
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <sched.h>
#include <linux/limits.h>
#include <signal.h>

#include "capabilities.h"
#include "elf.h"
#include "fs.h"
#include "jail.h"
#include "log.h"

#include <libubox/uloop.h>

#define STACK_SIZE	(1024 * 1024)
#define OPT_ARGS	"S:C:n:h:r:w:d:psuloc"

static struct {
	char *name;
	char *hostname;
	char **jail_argv;
	char *seccomp;
	char *capabilities;
	int no_new_privs;
	int namespace;
	int procfs;
	int ronly;
	int sysfs;
} opts;

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
		ERROR("mkdir(%s, %d) failed: %s\n", dir, mask, strerror(errno));

	return ret;
}

int mount_bind(const char *root, const char *path, int readonly, int error)
{
	struct stat s;
	char new[PATH_MAX];
	int fd;

	if (stat(path, &s)) {
		ERROR("stat(%s) failed: %s\n", path, strerror(errno));
		return error;
	}

	snprintf(new, sizeof(new), "%s%s", root, path);
	if (S_ISDIR(s.st_mode)) {
		mkdir_p(new, 0755);
	} else {
		mkdir_p(dirname(new), 0755);
		snprintf(new, sizeof(new), "%s%s", root, path);
		fd = creat(new, 0644);
		if (fd == -1) {
			ERROR("creat(%s) failed: %s\n", new, strerror(errno));
			return -1;
		}
		close(fd);
	}

	if (mount(path, new, NULL, MS_BIND, NULL)) {
		ERROR("failed to mount -B %s %s: %s\n", path, new, strerror(errno));
		return -1;
	}

	if (readonly && mount(NULL, new, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL)) {
		ERROR("failed to remount ro %s: %s\n", new, strerror(errno));
		return -1;
	}

	DEBUG("mount -B %s %s (%s)\n", path, new, readonly?"ro":"rw");

	return 0;
}

static int build_jail_fs(void)
{
	char jail_root[] = "/tmp/ujail-XXXXXX";
	if (mkdtemp(jail_root) == NULL) {
		ERROR("mkdtemp(%s) failed: %s\n", jail_root, strerror(errno));
		return -1;
	}

	/* oldroot can't be MS_SHARED else pivot_root() fails */
	if (mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL)) {
		ERROR("private mount failed %s\n", strerror(errno));
		return -1;
	}

	if (mount("tmpfs", jail_root, "tmpfs", MS_NOATIME, "mode=0755")) {
		ERROR("tmpfs mount failed %s\n", strerror(errno));
		return -1;
	}

	if (chdir(jail_root)) {
		ERROR("chdir(%s) (jail_root) failed: %s\n", jail_root, strerror(errno));
		return -1;
	}

	if (mount_all(jail_root)) {
		ERROR("mount_all() failed\n");
		return -1;
	}

	char dirbuf[sizeof(jail_root) + 4];
	snprintf(dirbuf, sizeof(dirbuf), "%s/old", jail_root);
	mkdir(dirbuf, 0755);

	if (pivot_root(jail_root, dirbuf) == -1) {
		ERROR("pivot_root(%s, %s) failed: %s\n", jail_root, dirbuf, strerror(errno));
		return -1;
	}
	if (chdir("/")) {
		ERROR("chdir(/) (after pivot_root) failed: %s\n", strerror(errno));
		return -1;
	}

	snprintf(dirbuf, sizeof(dirbuf), "/old%s", jail_root);
	rmdir(dirbuf);
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
	static char preload_var[PATH_MAX];
	static char seccomp_var[PATH_MAX];
	static char debug_var[] = "LD_DEBUG=all";
	const char *preload_lib = find_lib("libpreload-seccomp.so");
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
	fprintf(stderr, "  -c\t\tset PR_SET_NO_NEW_PRIVS\n");
	fprintf(stderr, "  -n <name>\tthe name of the jail\n");
	fprintf(stderr, "namespace jail options:\n");
	fprintf(stderr, "  -h <hostname>\tchange the hostname of the jail\n");
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

static int exec_jail(void *_notused)
{
	if (opts.capabilities && drop_capabilities(opts.capabilities))
		exit(EXIT_FAILURE);

	if (opts.no_new_privs && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
                ERROR("prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (opts.namespace && opts.hostname && strlen(opts.hostname) > 0
			&& sethostname(opts.hostname, strlen(opts.hostname))) {
		ERROR("sethostname(%s) failed: %s\n", opts.hostname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (opts.namespace && build_jail_fs()) {
		ERROR("failed to build jail fs\n");
		exit(EXIT_FAILURE);
	}

	char **envp = build_envp(opts.seccomp);
	if (!envp)
		exit(EXIT_FAILURE);

	INFO("exec-ing %s\n", *opts.jail_argv);
	execve(*opts.jail_argv, opts.jail_argv, envp);
	/* we get there only if execve fails */
	ERROR("failed to execve %s: %s\n", *opts.jail_argv, strerror(errno));
	exit(EXIT_FAILURE);
}

static int jail_running = 1;
static int jail_return_code = 0;

static void jail_process_timeout_cb(struct uloop_timeout *t);
static struct uloop_timeout jail_process_timeout = {
	.cb = jail_process_timeout_cb,
};

static void jail_process_handler(struct uloop_process *c, int ret)
{
	uloop_timeout_cancel(&jail_process_timeout);
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

static void jail_process_timeout_cb(struct uloop_timeout *t)
{
	DEBUG("jail process failed to stop, sending SIGKILL\n");
	kill(jail_process.pid, SIGKILL);
}

static void jail_handle_signal(int signo)
{
	DEBUG("forwarding signal %d to the jailed process\n", signo);
	kill(jail_process.pid, signo);
}

int main(int argc, char **argv)
{
	sigset_t sigmask;
	uid_t uid = getuid();
	char log[] = "/dev/log";
	char ubus[] = "/var/run/ubus.sock";
	int ch, i;

	if (uid) {
		ERROR("not root, aborting: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	umask(022);
	mount_list_init();
	init_library_search();

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
			add_mount(optarg, 1, -1);
			break;
		case 'C':
			opts.capabilities = optarg;
			break;
		case 'c':
			opts.no_new_privs = 1;
			break;
		case 'n':
			opts.name = optarg;
			break;
		case 'h':
			opts.hostname = optarg;
			break;
		case 'r':
			opts.namespace = 1;
			add_path_and_deps(optarg, 1, 0, 0);
			break;
		case 'w':
			opts.namespace = 1;
			add_path_and_deps(optarg, 0, 0, 0);
			break;
		case 'u':
			opts.namespace = 1;
			add_mount(ubus, 0, -1);
			break;
		case 'l':
			opts.namespace = 1;
			add_mount(log, 0, -1);
			break;
		}
	}

	/* no <binary> param found */
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

	if (opts.namespace && add_path_and_deps(*opts.jail_argv, 1, -1, 0)) {
		ERROR("failed to load dependencies\n");
		return -1;
	}

	if (opts.namespace && opts.seccomp && add_path_and_deps("libpreload-seccomp.so", 1, -1, 1)) {
		ERROR("failed to load libpreload-seccomp.so\n");
		return -1;
	}

	if (opts.name)
		prctl(PR_SET_NAME, opts.name, NULL, NULL, NULL);

	uloop_init();

	sigfillset(&sigmask);
	for (i = 0; i < _NSIG; i++) {
		struct sigaction s = { 0 };

		if (!sigismember(&sigmask, i))
			continue;
		if ((i == SIGCHLD) || (i == SIGPIPE))
			continue;

		s.sa_handler = jail_handle_signal;
		sigaction(i, &s, NULL);
	}

	if (opts.namespace) {
		add_mount("/dev/full", 0, -1);
		add_mount("/dev/null", 0, -1);
		add_mount("/dev/urandom", 0, -1);
		add_mount("/dev/zero", 0, -1);

		int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | SIGCHLD;
		if (opts.hostname)
			flags |= CLONE_NEWUTS;
		jail_process.pid = clone(exec_jail, child_stack + STACK_SIZE, flags, NULL);
	} else {
		jail_process.pid = fork();
	}

	if (jail_process.pid > 0) {
		/* parent process */
		uloop_process_add(&jail_process);
		uloop_run();
		if (jail_running) {
			DEBUG("uloop interrupted, killing jail process\n");
			kill(jail_process.pid, SIGTERM);
			uloop_timeout_set(&jail_process_timeout, 1000);
			uloop_run();
		}
		uloop_done();
		return jail_return_code;
	} else if (jail_process.pid == 0) {
		/* fork child process */
		return exec_jail(NULL);
	} else {
		ERROR("failed to clone/fork: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
}
