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
#include <sys/types.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
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
#include <libubus.h>

#define STACK_SIZE	(1024 * 1024)
#define OPT_ARGS	"S:C:n:h:r:w:d:psulocU:G:N"

#define NAMESPACE_MOUNT		(1U << 0)
#define NAMESPACE_IPC		(1U << 1)
#define NAMESPACE_NET		(1U << 2)
#define NAMESPACE_PID		(1U << 3)
#define NAMESPACE_USER		(1U << 4)
#define NAMESPACE_UTS		(1U << 5)
#define NAMESPACE_CGROUP	(1U << 6)

static struct {
	char *name;
	char *hostname;
	char **jail_argv;
	char *seccomp;
	char *capabilities;
	char *user;
	char *group;
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
		ERROR("mkdir(%s, %d) failed: %m\n", dir, mask);

	return ret;
}

static int _mount_bind(const char *root, const char *path, const char *target, int readonly, int strict, int error)
{
	struct stat s;
	char new[PATH_MAX];
	int fd;
	int remount_flags = MS_BIND | MS_REMOUNT;

	if (stat(path, &s)) {
		ERROR("stat(%s) failed: %m\n", path);
		return error;
	}

	snprintf(new, sizeof(new), "%s%s", root, target?target:path);

	if (S_ISDIR(s.st_mode)) {
		mkdir_p(new, 0755);
	} else {
		mkdir_p(dirname(new), 0755);
		snprintf(new, sizeof(new), "%s%s", root, target?target:path);
		fd = creat(new, 0644);
		if (fd == -1) {
			ERROR("creat(%s) failed: %m\n", new);
			return -1;
		}
		close(fd);
	}

	if (mount(path, new, NULL, MS_BIND, NULL)) {
		ERROR("failed to mount -B %s %s: %m\n", path, new);
		return -1;
	}

	if (readonly)
		remount_flags |= MS_RDONLY;

	if (strict)
		remount_flags |= MS_NOEXEC | MS_NOSUID | MS_NODEV;

	if ((strict || readonly) && mount(NULL, new, NULL, remount_flags, NULL)) {
		ERROR("failed to remount (%s%s%s) %s: %m\n", readonly?"ro":"rw",
		      (readonly && strict)?", ":"", strict?"strict":"", new);
		return -1;
	}

	DEBUG("mount -B %s %s (%s%s%s)\n", path, new,
	      readonly?"ro":"rw", (readonly && strict)?", ":"", strict?"strict":"");

	return 0;
}

int mount_bind(const char *root, const char *path, int readonly, int error) {
	return _mount_bind(root, path, NULL, readonly, 0, error);
}

static int build_jail_fs(void)
{
	char jail_root[] = "/tmp/ujail-XXXXXX";
	if (mkdtemp(jail_root) == NULL) {
		ERROR("mkdtemp(%s) failed: %m\n", jail_root);
		return -1;
	}

	/* oldroot can't be MS_SHARED else pivot_root() fails */
	if (mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL)) {
		ERROR("private mount failed %m\n");
		return -1;
	}

	if (mount("tmpfs", jail_root, "tmpfs", MS_NOATIME, "mode=0755")) {
		ERROR("tmpfs mount failed %m\n");
		return -1;
	}

	if (chdir(jail_root)) {
		ERROR("chdir(%s) (jail_root) failed: %m\n", jail_root);
		return -1;
	}

	if (mount_all(jail_root)) {
		ERROR("mount_all() failed\n");
		return -1;
	}

	if (opts.namespace & NAMESPACE_NET) {
		char hostdir[PATH_MAX], jailetc[PATH_MAX], jaillink[PATH_MAX];

		snprintf(hostdir, PATH_MAX, "/tmp/resolv.conf-%s.d", opts.name);
		mkdir_p(hostdir, 0755);
		_mount_bind(jail_root, hostdir, "/tmp/resolv.conf.d", 1, 1, -1);
		snprintf(jailetc, PATH_MAX, "%s/etc", jail_root);
		mkdir_p(jailetc, 0755);
		snprintf(jaillink, PATH_MAX, "%s/etc/resolv.conf", jail_root);
		symlink("../tmp/resolv.conf.d/resolv.conf.auto", jaillink);
	}

	char dirbuf[sizeof(jail_root) + 4];
	snprintf(dirbuf, sizeof(dirbuf), "%s/old", jail_root);
	mkdir(dirbuf, 0755);

	if (pivot_root(jail_root, dirbuf) == -1) {
		ERROR("pivot_root(%s, %s) failed: %m\n", jail_root, dirbuf);
		return -1;
	}
	if (chdir("/")) {
		ERROR("chdir(/) (after pivot_root) failed: %m\n");
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
	fprintf(stderr, "  -N\t\tjail has network namespace\n");
	fprintf(stderr, "  -r <file>\treadonly files that should be staged\n");
	fprintf(stderr, "  -w <file>\twriteable files that should be staged\n");
	fprintf(stderr, "  -p\t\tjail has /proc\n");
	fprintf(stderr, "  -s\t\tjail has /sys\n");
	fprintf(stderr, "  -l\t\tjail has /dev/log\n");
	fprintf(stderr, "  -u\t\tjail has a ubus socket\n");
	fprintf(stderr, "  -U <name>\tuser to run jailed process\n");
	fprintf(stderr, "  -G <name>\tgroup to run jailed process\n");
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
	struct passwd *p = NULL;
	struct group *g = NULL;

	if (opts.capabilities && drop_capabilities(opts.capabilities))
		exit(EXIT_FAILURE);

	if (opts.no_new_privs && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
                ERROR("prctl(PR_SET_NO_NEW_PRIVS) failed: %m\n");
		exit(EXIT_FAILURE);
	}

	if (opts.namespace && opts.hostname && strlen(opts.hostname) > 0
			&& sethostname(opts.hostname, strlen(opts.hostname))) {
		ERROR("sethostname(%s) failed: %m\n", opts.hostname);
		exit(EXIT_FAILURE);
	}

	if (opts.namespace && build_jail_fs()) {
		ERROR("failed to build jail fs\n");
		exit(EXIT_FAILURE);
	}

	if (opts.user) {
		p = getpwnam(opts.user);
		if (!p) {
			ERROR("failed to get uid/gid for user %s: %d (%s)\n",
			      opts.user, errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (opts.group) {
		g = getgrnam(opts.group);
		if (!g) {
			ERROR("failed to get gid for group %s: %m\n", opts.group);
			exit(EXIT_FAILURE);
		}
	}

	if (p && p->pw_gid && initgroups(opts.user, p->pw_gid)) {
		ERROR("failed to initgroups() for user %s: %m\n", opts.user);
		exit(EXIT_FAILURE);
	}

	if (g && g->gr_gid && setgid(g->gr_gid)) {
		ERROR("failed to set group id %d: %m\n", g?g->gr_gid:p->pw_gid);
		exit(EXIT_FAILURE);
	}

	if (p && p->pw_uid && setuid(p->pw_uid)) {
		ERROR("failed to set user id %d: %m\n", p->pw_uid);
		exit(EXIT_FAILURE);
	}


	char **envp = build_envp(opts.seccomp);
	if (!envp)
		exit(EXIT_FAILURE);

	INFO("exec-ing %s\n", *opts.jail_argv);
	execve(*opts.jail_argv, opts.jail_argv, envp);
	/* we get there only if execve fails */
	ERROR("failed to execve %s: %m\n", *opts.jail_argv);
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

static void netns_updown(bool start)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	static struct blob_buf req;
	uint32_t id;
	pid_t pid = getpid();

	if (!ctx)
		return;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "jail", opts.name);
	blobmsg_add_u32(&req, "pid", pid);
	blobmsg_add_u8(&req, "start", start);

	if (ubus_lookup_id(ctx, "network", &id) ||
	    ubus_invoke(ctx, id, "netns_updown", req.head, NULL, NULL, 3000))
		INFO("ubus request failed\n");

	blob_buf_free(&req);
	ubus_free(ctx);
}

int main(int argc, char **argv)
{
	sigset_t sigmask;
	uid_t uid = getuid();
	char log[] = "/dev/log";
	char ubus[] = "/var/run/ubus.sock";
	int ch, i;

	if (uid) {
		ERROR("not root, aborting: %m\n");
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
			opts.namespace |= NAMESPACE_MOUNT;
			opts.procfs = 1;
			break;
		case 'o':
			opts.namespace |= NAMESPACE_MOUNT;
			opts.ronly = 1;
			break;
		case 's':
			opts.namespace |= NAMESPACE_MOUNT;
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
		case 'N':
			opts.namespace |= NAMESPACE_NET;
			break;
		case 'h':
			opts.hostname = optarg;
			break;
		case 'r':
			opts.namespace |= NAMESPACE_MOUNT;
			add_path_and_deps(optarg, 1, 0, 0);
			break;
		case 'w':
			opts.namespace |= NAMESPACE_MOUNT;
			add_path_and_deps(optarg, 0, 0, 0);
			break;
		case 'u':
			opts.namespace |= NAMESPACE_MOUNT;
			add_mount(ubus, 0, -1);
			break;
		case 'l':
			opts.namespace |= NAMESPACE_MOUNT;
			add_mount(log, 0, -1);
			break;
		case 'U':
			opts.user = optarg;
			break;
		case 'G':
			opts.group = optarg;
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
		int flags = SIGCHLD | CLONE_NEWPID | CLONE_NEWIPC;

		if (opts.namespace & NAMESPACE_MOUNT) {
			flags |= CLONE_NEWNS;
			add_mount("/dev/full", 0, -1);
			add_mount("/dev/null", 0, -1);
			add_mount("/dev/urandom", 0, -1);
			add_mount("/dev/zero", 0, -1);

			if (opts.user || opts.group) {
				add_mount("/etc/passwd", 0, -1);
				add_mount("/etc/group", 0, -1);
			}
		}

		if (opts.hostname)
			flags |= CLONE_NEWUTS;

		if (opts.namespace & NAMESPACE_NET) {
			unshare(CLONE_NEWNET);
			netns_updown(true);
		};

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
		if (opts.namespace & NAMESPACE_NET)
			netns_updown(false);

		return jail_return_code;
	} else if (jail_process.pid == 0) {
		/* fork child process */
		return exec_jail(NULL);
	} else {
		ERROR("failed to clone/fork: %m\n");
		return EXIT_FAILURE;
	}
}
