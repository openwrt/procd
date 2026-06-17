/*
 * Copyright (C) 2015 John Crispin <blogic@openwrt.org>
 * Copyright (C) 2020 Daniel Golle <daniel@makrotopia.org>
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
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/ioctl.h>
#include <sys/personality.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <poll.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

/* musl only defined 15 limit types, make sure all 16 are supported */
#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#undef RLIMIT_NLIMITS
#define RLIMIT_NLIMITS 16
#undef RLIM_NLIMITS
#define RLIM_NLIMITS 16
#endif

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <fcntl.h>
#include <sched.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/nsfs.h>
#include <linux/securebits.h>
#include <signal.h>
#include <inttypes.h>

#include "capabilities.h"
#include "elf.h"
#include "fs.h"
#include "jail.h"
#include "log.h"
#include "seccomp-oci.h"
#include "cgroups.h"
#include "netifd.h"

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/list.h>
#include <libubox/vlist.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

#define STACK_SIZE	(1024 * 1024)
#define OPT_ARGS	"cC:d:De:EfFG:h:ij:J:ln:NoO:pP:r:R:sS:uU:w:t:T:y"

#define OCI_VERSION_STRING "1.0.2"

struct hook_execvpe {
	char *file;
	char **argv;
	char **envp;
	int timeout;
};

struct sysctl_val {
	char *entry;
	char *value;
};

struct mknod_args {
	char *path;
	mode_t mode;
	dev_t dev;
	uid_t uid;
	gid_t gid;
};

static struct {
	char *name;
	char *hostname;
	char *domainname;
	char **jail_argv;
	char *cwd;
	char *seccomp;
	struct sock_fprog *ociseccomp;
	char *capabilities;
	struct jail_capset capset;
	char *user;
	char *group;
	char *extroot;
	char *overlaydir;
	char *tmpoverlaysize;
	char **envp;
	char *uidmap;
	char *gidmap;
	char *pidfile;
	struct sysctl_val **sysctl;
	int no_new_privs;
	int namespace;
	struct {
		int pid;
		int net;
		int ns;
		int ipc;
		int uts;
		int user;
		int cgroup;
		int time;
	} setns;
	int procfs;
	int ronly;
	int sysfs;
	int console;
	int pw_uid;
	int pw_gid;
	int gr_gid;
	int root_map_uid;
	gid_t *additional_gids;
	size_t num_additional_gids;
	mode_t umask;
	bool set_umask;
	int require_jail;
	struct {
		struct hook_execvpe **prestart;
		struct hook_execvpe **createRuntime;
		struct hook_execvpe **createContainer;
		struct hook_execvpe **startContainer;
		struct hook_execvpe **poststart;
		struct hook_execvpe **poststop;
	} hooks;
	struct rlimit *rlimits[RLIM_NLIMITS];
	int oom_score_adj;
	bool set_oom_score_adj;
	struct mknod_args **devices;
	char *ocibundle;
	char **oci_deferred_masked;
	char **oci_deferred_readonly;
	bool immediately;
	struct blob_attr *annotations;
	struct blob_attr *netdevices;
	int term_timeout;
	struct {
		bool set;
		uint32_t policy;
		uint64_t flags;
		int32_t nice;
		uint32_t priority;
		uint64_t runtime;
		uint64_t deadline;
		uint64_t period;
	} scheduler;
	struct {
		bool set;
		int class;
		int priority;
	} ioprio;
} opts;

static struct blob_buf ocibuf;

extern int pivot_root(const char *new_root, const char *put_old);

int debug = 0;

static char child_stack[STACK_SIZE];

static struct ubus_context *parent_ctx;

int console_fd;


static inline bool has_namespaces(void)
{
return ((opts.setns.pid != -1) ||
	(opts.setns.net != -1) ||
	(opts.setns.ns != -1) ||
	(opts.setns.ipc != -1) ||
	(opts.setns.uts != -1) ||
	(opts.setns.user != -1) ||
	(opts.setns.cgroup != -1) ||
	(opts.setns.time != -1) ||
	opts.namespace);
}

static void free_oci_envp(char **p) {
	char **tmp;

	if (p) {
		tmp = p;
		while (*tmp)
			free(*(tmp++));

		free(p);
	}
}

static void free_hooklist(struct hook_execvpe **hooklist)
{
	struct hook_execvpe **cur;

	if (!hooklist)
		return;

	cur = hooklist;
	while (*cur) {
		free_oci_envp((*cur)->argv);
		free_oci_envp((*cur)->envp);
		free((*cur)->file);
		free(*(cur++));
	}
	free(hooklist);
}

static void free_sysctl(void) {
	struct sysctl_val **cur;

	if (!opts.sysctl)
		return;

	cur = opts.sysctl;

	while (*cur) {
		free((*cur)->entry);
		free((*cur)->value);
		free(*(cur++));
	}
	free(opts.sysctl);
}

static void free_devices(void) {
	struct mknod_args **cur;

	if (!opts.devices)
		return;

	cur = opts.devices;

	while (*cur) {
		free((*cur)->path);
		free(*(cur++));
	}
	free(opts.devices);
}

static void free_rlimits(void) {
	int type;

	for (type = 0; type < RLIM_NLIMITS; ++type)
		free(opts.rlimits[type]);
}

static void free_opts(bool parent) {

	free_library_search();
	mount_free();
	cgroups_free();

	/* we need to keep argv, envp and seccomp filter in child */
	if (parent) { /* parent-only */
		if (opts.ociseccomp) {
			free(opts.ociseccomp->filter);
			free(opts.ociseccomp);
		}

		free_oci_envp(opts.jail_argv);
		free_oci_envp(opts.envp);
	}

	free_rlimits();
	free_sysctl();
	free_devices();
	free(opts.hostname);
	free(opts.domainname);
	free(opts.cwd);
	free(opts.uidmap);
	free(opts.gidmap);
	free(opts.annotations);
	free(opts.netdevices);
	free(opts.extroot);
	free(opts.overlaydir);
	free_hooklist(opts.hooks.prestart);
	free_hooklist(opts.hooks.createRuntime);
	free_hooklist(opts.hooks.createContainer);
	free_hooklist(opts.hooks.startContainer);
	free_hooklist(opts.hooks.poststart);
	free_hooklist(opts.hooks.poststop);

	if (opts.oci_deferred_masked) {
		char **p;
		for (p = opts.oci_deferred_masked; *p; p++)
			free(*p);
		free(opts.oci_deferred_masked);
	}
	if (opts.oci_deferred_readonly) {
		char **p;
		for (p = opts.oci_deferred_readonly; *p; p++)
			free(*p);
		free(opts.oci_deferred_readonly);
	}
}

static int mount_overlay(char *jail_root, char *overlaydir) {
	char *upperdir, *workdir, *optsstr, *upperetc, *upperresolvconf;
	const char mountoptsformat[] = "lowerdir=%s,upperdir=%s,workdir=%s";
	const char mountoptsformat_userns[] = "lowerdir=%s,upperdir=%s,workdir=%s,userxattr";
	int ret = -1, fd;

	if (asprintf(&upperdir, "%s%s", overlaydir, "/upper") < 0)
		goto out;

	if (asprintf(&workdir, "%s%s", overlaydir, "/work") < 0)
		goto upper_printf;

	if (asprintf(&optsstr,
		     (opts.namespace & CLONE_NEWUSER) ? mountoptsformat_userns : mountoptsformat,
		     jail_root, upperdir, workdir) < 0)
		goto work_printf;

	if (mkdir_p(upperdir, 0755) || mkdir_p(workdir, 0755))
		goto opts_printf;

/*
 * make sure /etc/resolv.conf exists in overlay and is owned by jail userns root
 * this is to work-around a bug in overlayfs described in the overlayfs-userns
 * patch:
 * 3. modification of a file 'hithere' which is in l but not yet
 * in u, and which is not owned by T, is not allowed, even if
 * writes to u are allowed.  This may be a bug in overlayfs,
 * but it is safe behavior.
 */
	if (asprintf(&upperetc, "%s/etc", upperdir) < 0)
		goto opts_printf;

	if (mkdir_p(upperetc, 0755))
		goto upper_etc_printf;

	if (asprintf(&upperresolvconf, "%s/resolv.conf", upperetc) < 0)
		goto upper_etc_printf;

	fd = creat(upperresolvconf, 0644);
	if (fd < 0) {
		if (errno != EEXIST)
			ERROR("creat(%s) failed: %m\n", upperresolvconf);
	} else {
		close(fd);
	}
	DEBUG("mount -t overlay %s %s (%s)\n", jail_root, jail_root, optsstr);

	if (mount(jail_root, jail_root, "overlay", MS_NOATIME, optsstr))
		goto upper_resolvconf_printf;

	ret = 0;

upper_resolvconf_printf:
	free(upperresolvconf);
upper_etc_printf:
	free(upperetc);
opts_printf:
	free(optsstr);
work_printf:
	free(workdir);
upper_printf:
	free(upperdir);
out:
	return ret;
}

static void pass_console(int console_fd)
{
	struct ubus_context *child_ctx = ubus_connect(NULL);
	static struct blob_buf req;
	uint32_t id;

	if (!child_ctx)
		return;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", opts.name);

	if (ubus_lookup_id(child_ctx, "container", &id) ||
	    ubus_invoke_fd(child_ctx, id, "console_set", req.head, NULL, NULL, 3000, console_fd))
		INFO("ubus request failed\n");
	else
		close(console_fd);

	blob_buf_free(&req);
	ubus_free(child_ctx);
}

static int create_dev_console(const char *jail_root)
{
	char *console_fname;
	char dev_console_path[PATH_MAX];
	int slave_console_fd, dev_console_dummy;

	/* Open UNIX/98 virtual console */
	console_fd = posix_openpt(O_RDWR | O_NOCTTY);
	if (console_fd < 0)
		return -1;

	console_fname = ptsname(console_fd);
	DEBUG("got console fd %d and PTS client name %s\n", console_fd, console_fname);
	if (!console_fname)
		goto no_console;

	grantpt(console_fd);
	unlockpt(console_fd);

	/* pass PTY master to procd */
	pass_console(console_fd);

	/* mount-bind PTY slave to /dev/console in jail */
	snprintf(dev_console_path, sizeof(dev_console_path), "%s/dev/console", jail_root);
	dev_console_dummy = creat(dev_console_path, 0620);
	if (dev_console_dummy < 0)
		goto no_console;

	close(dev_console_dummy);

	if (mount(console_fname, dev_console_path, "bind", MS_BIND, NULL))
		goto no_console;

	/* use PTY slave for stdio */
	slave_console_fd = open(console_fname, O_RDWR); /* | O_NOCTTY */
	if (slave_console_fd < 0)
		goto no_console;

	dup2(slave_console_fd, 0);
	dup2(slave_console_fd, 1);
	dup2(slave_console_fd, 2);
	close(slave_console_fd);

	INFO("using guest console %s\n", console_fname);

	return 0;

no_console:
	close(console_fd);
	return 1;
}

static int hook_running = 0;
static int hook_return_code = 0;
static bool hook_chain_failed = false;
static struct hook_execvpe **current_hook = NULL;
typedef void (*hook_return_handler)(void);
static hook_return_handler hook_return_cb = NULL;

static void hook_process_timeout_cb(struct uloop_timeout *t);
static struct uloop_timeout hook_process_timeout = {
	.cb = hook_process_timeout_cb,
};

static void run_hooklist(void);
static void hook_process_handler(struct uloop_process *c, int ret)
{
	uloop_timeout_cancel(&hook_process_timeout);

	if (WIFEXITED(ret)) {
		hook_return_code = WEXITSTATUS(ret);
		if (hook_return_code)
			ERROR("hook (%d) exited with exit: %d\n", c->pid, hook_return_code);
		else
			DEBUG("hook (%d) exited with exit: %d\n", c->pid, hook_return_code);

	} else {
		hook_return_code = WTERMSIG(ret);
		ERROR("hook (%d) exited with signal: %d\n", c->pid, hook_return_code);
	}
	if (hook_return_code)
		hook_chain_failed = true;
	hook_running = 0;
	++current_hook;
	run_hooklist();
}

static struct uloop_process hook_process = {
	.cb = hook_process_handler,
};

static void hook_process_timeout_cb(struct uloop_timeout *t)
{
	DEBUG("hook process failed to stop, sending SIGKILL\n");
	kill(hook_process.pid, SIGKILL);
}

static void run_hooklist(void)
{
	struct hook_execvpe *hook = *current_hook;
	struct stat s;

	if (!hook)
		return hook_return_cb();

	DEBUG("executing hook %s\n", hook->file);

	if (stat(hook->file, &s))
		hook_process_handler(&hook_process, ENOENT);

	if (!((unsigned long)s.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
		hook_process_handler(&hook_process, EPERM);

	hook_running = 1;
	hook_process.pid = fork();
	if (hook_process.pid == 0) {
		/* child */
		execve(hook->file, hook->argv, hook->envp);
		ERROR("execve error %m\n");
		_exit(errno);
	} else if (hook_process.pid < 0) {
		/* fork error */
		ERROR("hook fork error\n");
		hook_running = 0;
		hook_process_handler(&hook_process, errno);
	}

	/* parent */
	uloop_process_add(&hook_process);

	if (hook->timeout > 0)
		uloop_timeout_set(&hook_process_timeout, 1000 * hook->timeout);

	uloop_run();
	if (hook_running) {
		DEBUG("uloop interrupted, killing jail process\n");
		kill(hook_process.pid, SIGTERM);
		uloop_timeout_set(&hook_process_timeout, 1000);
		uloop_run();
	}
}

static void run_hooks(struct hook_execvpe **hooklist, hook_return_handler return_cb)
{
	hook_chain_failed = false;

	if (!hooklist) {
		return_cb();
		return;
	}

	current_hook = hooklist;
	hook_return_cb = return_cb;

	run_hooklist();
}

static int apply_sysctl(const char *jail_root)
{
	struct sysctl_val **cur;
	char *procdir, *fname;
	int f;

	if (!opts.sysctl)
		return 0;

	if (asprintf(&procdir, "%s/proc", jail_root) < 0)
		return ENOMEM;

	if (mkdir(procdir, 0700))
		return errno;

	if (mount("proc", procdir, "proc", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID, 0))
		return EPERM;

	cur = opts.sysctl;

	while (*cur) {
		if (asprintf(&fname, "%s/sys/%s", procdir, (*cur)->entry) < 0)
			return ENOMEM;

		DEBUG("sysctl: writing '%s' to %s\n", (*cur)->value, fname);

		f = open(fname, O_WRONLY);
		if (f < 0) {
			ERROR("sysctl: can't open %s\n", fname);
			free(fname);
			return errno;
		}
		if (write(f, (*cur)->value, strlen((*cur)->value)) < 0) {
			ERROR("sysctl: write to %s\n", fname);
			free(fname);
			close(f);
			return errno;
		}

		free(fname);
		close(f);
		++cur;
	}
	umount(procdir);
	rmdir(procdir);
	free(procdir);

	return 0;
}

/* glibc defines makedev calling a function. make sure it's a pure macro */
#if defined(__GLIBC__)
#undef makedev
/* from musl's sys/sysmacros.h */
#define makedev(x,y) ( \
	(((x)&0xfffff000ULL) << 32) | \
	(((x)&0x00000fffULL) << 8) | \
	(((y)&0xffffff00ULL) << 12) | \
	(((y)&0x000000ffULL)) )
#endif

static struct mknod_args default_devices[] = {
	{ .path = "/dev/null", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(1, 3) },
	{ .path = "/dev/zero", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(1, 5) },
	{ .path = "/dev/full", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(1, 7) },
	{ .path = "/dev/random", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(1, 8) },
	{ .path = "/dev/urandom", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(1, 9) },
	{ .path = "/dev/tty", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(5, 0), .gid = 5 },
	{ 0 },
};

static int create_devices(void)
{
	struct mknod_args **cur, *curdef;
	char *path, *tmp;
	int ret;

	if (!opts.devices)
		goto only_default_devices;

	cur = opts.devices;

	while (*cur) {
		path = (*cur)->path;
		/* don't allow devices outside of /dev */
		if (strncmp(path, "/dev", 4))
			return EPERM;

		if (opts.setns.user != -1) {
			++cur;
			continue;
		}

		/* make sure parent folder exists */
		tmp = strrchr(path, '/');
		if (!tmp)
			return EINVAL;

		*tmp = '\0';
		if (strcmp(path, "/dev")) {
			DEBUG("creating directory %s\n", path);

			if (mkdir_p(path, 0755))
				return errno;
		}
		*tmp = '/';

		DEBUG("creating %s (mode=%08o)\n", path, (*cur)->mode);

		/* create device */
		if (mknod(path, (*cur)->mode, (*cur)->dev))
			return errno;

		/* change owner, if needed */
		if (((*cur)->uid || (*cur)->gid) &&
		    chown(path, (*cur)->uid, (*cur)->gid))
			return errno;

		++cur;
	}

only_default_devices:
	curdef = default_devices;
	while(curdef->path) {
		DEBUG("creating %s (mode=%08o)\n", curdef->path, curdef->mode);
		if (mknod(curdef->path, curdef->mode, curdef->dev)) {
			++curdef;
			continue; /* may already exist, eg. due to a bind-mount */
		}
		if ((curdef->uid || curdef->gid) &&
		    chown(curdef->path, curdef->uid, curdef->gid))
			return errno;

		++curdef;
	}

	/* Dev symbolic links as defined in OCI spec */
	ret = symlink("/dev/pts/ptmx", "/dev/ptmx");
	if (ret < 0)
		WARNING("symlink() failed to create link to /dev/pts/ptmx");

	ret = symlink("/proc/self/fd", "/dev/fd");
	if (ret < 0)
		WARNING("symlink() failed to create link to /proc/self/fd");

	ret = symlink("/proc/self/fd/0", "/dev/stdin");
	if (ret < 0)
		WARNING("symlink() failed to create link to /proc/self/fd/0");

	ret = symlink("/proc/self/fd/1", "/dev/stdout");
	if (ret < 0)
		WARNING("symlink() failed to create link to /proc/self/fd/1");

	ret = symlink("/proc/self/fd/2", "/dev/stderr");
	if (ret < 0)
		WARNING("symlink() failed to create link to /proc/self/fd/2");

	return 0;
}

static char jail_root[] = "/tmp/ujail-XXXXXX";
/* Handshake for the deferred CLONE_NEWUSER creation in enter_userns(). */
int userns_pipe[4];

/* single-byte read()/write(), retrying on EINTR */
static ssize_t xread_byte(int fd, char *buf)
{
	ssize_t n;

	do {
		n = read(fd, buf, 1);
	} while (n < 0 && errno == EINTR);

	return n;
}

static ssize_t xwrite_byte(int fd, char byte)
{
	ssize_t n;

	do {
		n = write(fd, &byte, 1);
	} while (n < 0 && errno == EINTR);

	return n;
}

static char tmpovdir[] = "/tmp/ujail-overlay-XXXXXX";
static mode_t old_umask;
static void enter_jail_fs(void);

static size_t path_depth(const char *path)
{
	size_t depth = 0;

	for (; *path; path++)
		if (*path == '/')
			depth++;

	return depth;
}

static void mountinfo_unescape(char *s)
{
	char *r = s, *w = s;

	while (*r) {
		if (r[0] == '\\' && r[1] >= '0' && r[1] <= '7' &&
		    r[2] >= '0' && r[2] <= '7' && r[3] >= '0' && r[3] <= '7') {
			*w++ = (char)(((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
			r += 4;
		} else {
			*w++ = *r++;
		}
	}
	*w = '\0';
}

static int mountinfo_detach_children(const char *prefix)
{
	size_t prefixlen = strlen(prefix);
	int pass;

	for (pass = 0; pass < 16; pass++) {
		FILE *f;
		char *line = NULL;
		size_t linecap = 0;
		char *paths[128];
		size_t n = 0, dropped = 0, i, j;
		bool progress = false;

		f = fopen("/proc/self/mountinfo", "re");
		if (!f) {
			ERROR("mountinfo_detach_children(%s): fopen(/proc/self/mountinfo) "
			      "failed: %m\n", prefix);
			return -1;
		}

		while (getline(&line, &linecap, f) >= 0) {
			char *mp, *save = NULL;

			strtok_r(line, " ", &save);
			strtok_r(NULL, " ", &save);
			strtok_r(NULL, " ", &save);
			strtok_r(NULL, " ", &save);
			mp = strtok_r(NULL, " ", &save);
			if (!mp)
				continue;
			mountinfo_unescape(mp);

			if (strncmp(mp, prefix, prefixlen) || mp[prefixlen] != '/')
				continue;

			if (n < ARRAY_SIZE(paths)) {
				char *dup = strdup(mp);

				if (dup)
					paths[n++] = dup;
				else
					dropped++;
			} else {
				dropped++;
			}
		}
		free(line);
		fclose(f);

		if (dropped)
			WARNING("mountinfo_detach_children(%s): %zu nested mount(s) "
				"exceeded the %zu-entry per-pass limit or could not "
				"be recorded (out of memory); retrying over further "
				"passes\n", prefix, dropped, ARRAY_SIZE(paths));

		if (n == 0 && dropped == 0)
			return 0;

		for (i = 0; i < n; i++) {
			size_t deepest = i;

			for (j = i + 1; j < n; j++)
				if (path_depth(paths[j]) > path_depth(paths[deepest]))
					deepest = j;
			if (deepest != i) {
				char *tmp = paths[i];
				paths[i] = paths[deepest];
				paths[deepest] = tmp;
			}
		}

		for (i = 0; i < n; i++) {
			if (!umount2(paths[i], MNT_DETACH))
				progress = true;
			free(paths[i]);
		}

		if (!progress && !dropped) {
			ERROR("mountinfo_detach_children(%s): %zu nested mount(s) could "
			      "not be detached; refusing to continue\n", prefix, n);
			return -1;
		}
	}

	ERROR("mountinfo_detach_children(%s): nested mounts remained attached "
	      "after %d passes; refusing to continue\n", prefix, pass);
	return -1;
}

/*
 * Make the mount namespace private and detach inherited /proc,/sys
 * children before build_jail_fs() mounts its own. Must run before
 * setns_open(CLONE_NEWUSER) joins an external userns and drops
 * privilege; see the call site in exec_jail().
 */
static int isolate_mountns_and_detach_inherited(void)
{
	if (mount("none", "/", "none", MS_REC|MS_PRIVATE, NULL)) {
		ERROR("private mount failed %m\n");
		return -1;
	}

	if ((opts.procfs || opts.ocibundle) && mountinfo_detach_children("/proc"))
		return -1;
	if ((opts.sysfs || opts.ocibundle) && mountinfo_detach_children("/sys"))
		return -1;

	return 0;
}

static int build_jail_fs(void)
{
	char *overlaydir = NULL;
	int ret;

	old_umask = umask(0);

	if (mkdtemp(jail_root) == NULL) {
		ERROR("mkdtemp(%s) failed: %m\n", jail_root);
		return -1;
	}

	if (apply_sysctl(jail_root)) {
		ERROR("failed to apply sysctl values\n");
		return -1;
	}

	if (opts.extroot) {
		if (mount(opts.extroot, jail_root, "bind", MS_BIND, NULL)) {
			ERROR("extroot mount failed %m\n");
			return -1;
		}
	} else {
		if (mount("tmpfs", jail_root, "tmpfs", MS_NOATIME, "mode=0755")) {
			ERROR("tmpfs mount failed %m\n");
			return -1;
		}
	}

	if (opts.tmpoverlaysize) {
		char mountoptsstr[] = "mode=0755,size=XXXXXXXX";

		snprintf(mountoptsstr, sizeof(mountoptsstr),
			 "mode=0755,size=%s", opts.tmpoverlaysize);
		if (mkdtemp(tmpovdir) == NULL) {
			ERROR("mkdtemp(%s) failed: %m\n", jail_root);
			return -1;
		}
		if (mount("tmpfs", tmpovdir, "tmpfs", MS_NOATIME,
			  mountoptsstr)) {
			ERROR("failed to mount tmpfs for overlay (size=%s)\n", opts.tmpoverlaysize);
			return -1;
		}
		overlaydir = tmpovdir;
	}

	if (opts.overlaydir)
		overlaydir = opts.overlaydir;

	if (overlaydir) {
		ret = mount_overlay(jail_root, overlaydir);
		if (ret)
			return ret;
	}

	if (chdir(jail_root)) {
		ERROR("chdir(%s) (jail_root) failed: %m\n", jail_root);
		return -1;
	}

	{
	/* fds stay open until mount_all() performs the /proc/self/fd/N
	 * binds below; closing early would drop or swap the source */
	int *held_fds = NULL;
	size_t n_devices = 0, n_custom = 0, i;
	int fail = 0;

	if (opts.setns.user != -1) {
		struct mknod_args *curdef;

		if (opts.devices) {
			struct mknod_args **cur;

			for (cur = opts.devices; *cur; cur++)
				n_custom++;
		}

		for (curdef = default_devices; curdef->path; curdef++)
			n_devices++;

		n_devices += n_custom;

		held_fds = malloc(n_devices * sizeof(int));
		if (!held_fds) {
			ERROR("out of memory validating devices\n");
			return -1;
		}
		for (i = 0; i < n_devices; i++)
			held_fds[i] = -1;

		if (opts.devices) {
			struct mknod_args **cur;

			for (i = 0, cur = opts.devices; *cur && !fail; cur++, i++) {
				struct stat st;

				if (strncmp((*cur)->path, "/dev", 4)) {
					ERROR("custom device %s is outside of /dev; "
					      "refusing to bind-mount it\n",
					      (*cur)->path);
					fail = 1;
					break;
				}

				held_fds[i] = open((*cur)->path, O_PATH | O_CLOEXEC);
				if (held_fds[i] < 0) {
					ERROR("custom device %s requested but not found "
					      "on the host; it cannot be created under "
					      "CLONE_NEWUSER (no privilege to mknod)\n",
					      (*cur)->path);
					fail = 1;
					break;
				}

				if (fstat(held_fds[i], &st)) {
					ERROR("custom device %s: fstat() failed: %m\n",
					      (*cur)->path);
					fail = 1;
					break;
				}

				if (((*cur)->mode & S_IFMT) &&
				    (st.st_mode & S_IFMT) != ((*cur)->mode & S_IFMT)) {
					ERROR("custom device %s exists on the host but "
					      "is not the requested node type; its "
					      "major:minor/mode/owner cannot be enforced "
					      "under CLONE_NEWUSER\n",
					      (*cur)->path);
					fail = 1;
					break;
				}

				if (((*cur)->mode & S_IFMT) == S_IFCHR ||
				    ((*cur)->mode & S_IFMT) == S_IFBLK) {
					if ((*cur)->dev && st.st_rdev != (*cur)->dev) {
						ERROR("custom device %s exists on the host "
						      "but its major:minor (%u:%u) does not "
						      "match the requested %u:%u; refusing "
						      "to bind-mount a different device than "
						      "configured\n", (*cur)->path,
						      major(st.st_rdev), minor(st.st_rdev),
						      major((*cur)->dev), minor((*cur)->dev));
						fail = 1;
						break;
					}
				}

				{
					int tree;
					struct ujail_mount_attr attr = { .attr_set = MOUNT_ATTR_RDONLY };

					tree = sys_open_tree(held_fds[i], "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH);
					if (tree < 0) {
						ERROR("open_tree() on custom device %s failed: %m\n", (*cur)->path);
						fail = 1;
						break;
					}
					close(held_fds[i]);
					held_fds[i] = tree;

					if (sys_mount_setattr(tree, "", AT_EMPTY_PATH, &attr, sizeof(attr))) {
						ERROR("mount_setattr() on custom device %s failed: %m\n", (*cur)->path);
						fail = 1;
						break;
					}
				}
				if (add_mount_fd(held_fds[i], (*cur)->path, -1)) {
					ERROR("could not queue bind-mount for mandatory "
					      "custom device %s; refusing to start with "
					      "a requested device missing\n",
					      (*cur)->path);
					fail = 1;
					break;
				}
			}
		}

		if (!fail) {
			size_t j = 0;

			for (curdef = default_devices; curdef->path; curdef++, j++) {
				int tree;
				struct ujail_mount_attr attr = { .attr_set = MOUNT_ATTR_RDONLY };

				held_fds[n_custom + j] = open(curdef->path, O_PATH | O_CLOEXEC);
				if (held_fds[n_custom + j] < 0) {
					WARNING("could not open default device %s; "
						"it will be unavailable in the jail\n",
						curdef->path);
					continue;
				}

				tree = sys_open_tree(held_fds[n_custom + j], "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH);
				if (tree < 0) {
					WARNING("open_tree() on default device %s failed; "
						"it will be unavailable in the jail\n", curdef->path);
					continue;
				}
				close(held_fds[n_custom + j]);
				held_fds[n_custom + j] = tree;

				if (sys_mount_setattr(tree, "", AT_EMPTY_PATH, &attr, sizeof(attr))) {
					WARNING("mount_setattr() on default device %s failed; "
						"it will be unavailable in the jail\n", curdef->path);
					continue;
				}

				if (add_mount_fd(held_fds[n_custom + j], curdef->path, 0))
					WARNING("could not queue bind-mount for default "
						"device %s; it will be unavailable in "
						"the jail\n", curdef->path);
			}
		}
	}

	if (!fail && mount_all(jail_root)) {
		ERROR("mount_all() failed\n");
		fail = 1;
	}

	for (i = 0; i < n_devices; i++)
		if (held_fds && held_fds[i] >= 0)
			close(held_fds[i]);
	free(held_fds);

	if (fail)
		return -1;
	}

	if (opts.console)
		create_dev_console(jail_root);

	/* make sure /etc/resolv.conf exists if in new network namespace */
	if (opts.namespace & CLONE_NEWNET) {
		char jailetc[PATH_MAX], jaillink[PATH_MAX];

		snprintf(jailetc, PATH_MAX, "%s/etc", jail_root);
		if (mkdir_p(jailetc, 0755)) {
			ERROR("mkdir(%s) failed: %m\n", jailetc);
			return -1;
		}
		snprintf(jaillink, PATH_MAX, "%s/etc/resolv.conf", jail_root);
		if (overlaydir)
			unlink(jaillink);

		ret = symlink("../dev/resolv.conf.d/resolv.conf.auto", jaillink);
		if (ret < 0)
			WARNING("symlink() failed to create link to ../dev/resolv.conf.d/resolv.conf.auto");
	}

	run_hooks(opts.hooks.createContainer, enter_jail_fs);

	return 0;
}

static bool exit_from_child;
static void free_and_exit(int ret)
{
	if (!exit_from_child && opts.ocibundle)
		cgroups_free();

	if (!exit_from_child && parent_ctx)
		ubus_free(parent_ctx);

	free_opts(!exit_from_child);

	exit(ret);
}

static void post_jail_fs(void);
static void enter_userns(void);
static void remask_after_unshare(void);
static void remount_proc_sys_after_unshare(void);
static void enter_jail_fs(void)
{
	char dirbuf[sizeof(jail_root) + 4];

	snprintf(dirbuf, sizeof(dirbuf), "%s/old", jail_root);
	if (mkdir(dirbuf, 0755)) {
		ERROR("mkdir(%s) failed: %m\n", dirbuf);
		free_and_exit(-1);
	}
	if (pivot_root(jail_root, dirbuf) == -1) {
		ERROR("pivot_root(%s, %s) failed: %m\n", jail_root, dirbuf);
		free_and_exit(-1);
	}
	if (chdir("/")) {
		ERROR("chdir(/) (after pivot_root) failed: %m\n");
		free_and_exit(-1);
	}

	snprintf(dirbuf, sizeof(dirbuf), "/old%s", jail_root);
	umount2(dirbuf, MNT_DETACH);
	rmdir(dirbuf);
	if (opts.tmpoverlaysize) {
		char tmpdirbuf[sizeof(tmpovdir) + 4];
		snprintf(tmpdirbuf, sizeof(tmpdirbuf), "/old%s", tmpovdir);
		umount2(tmpdirbuf, MNT_DETACH);
		rmdir(tmpdirbuf);
	}

	umount2("/old", MNT_DETACH);
	rmdir("/old");

	if (create_devices()) {
		ERROR("create_devices() failed\n");
		free_and_exit(-1);
	}
	if (opts.ronly)
		mount(NULL, "/", "bind", MS_REMOUNT | MS_BIND | MS_RDONLY, 0);

	umask(old_umask);
	enter_userns();
}

/*
 * Create our own CLONE_NEWUSER here, after /proc and /sys are already
 * mounted, so the PID namespace stays owned by the initial userns
 * throughout mount setup. See the comment in exec_jail() for why.
 */
static void enter_userns(void)
{
	char buf[1];

	if (!((opts.namespace & CLONE_NEWUSER) && opts.setns.user == -1)) {
		post_jail_fs();
		return;
	}

	if (unshare(CLONE_NEWUSER)) {
		ERROR("unshare(CLONE_NEWUSER) failed: %m\n");
		free_and_exit(-1);
	}

	buf[0] = 'i';
	if (xwrite_byte(userns_pipe[1], buf[0]) < 1) {
		ERROR("can't write to parent\n");
		free_and_exit(-1);
	}
	close(userns_pipe[1]);

	if (xread_byte(userns_pipe[2], buf) < 1) {
		ERROR("can't read from parent\n");
		free_and_exit(-1);
	}
	close(userns_pipe[2]);
	if (buf[0] != 'O') {
		ERROR("parent had an error, child exiting\n");
		free_and_exit(-1);
	}

	if ((opts.namespace & CLONE_NEWNS) && unshare(CLONE_NEWNS)) {
		ERROR("unshare(CLONE_NEWNS) failed: %m\n");
		free_and_exit(-1);
	}
	if (opts.namespace & CLONE_NEWNS) {
		remask_after_unshare();
		remount_proc_sys_after_unshare();
	}

	if (setregid(0, 0) < 0) {
		ERROR("setgid\n");
		free_and_exit(-1);
	}
	if (setreuid(0, 0) < 0) {
		ERROR("setuid\n");
		free_and_exit(-1);
	}
	if (setgroups(0, NULL) < 0) {
		ERROR("setgroups\n");
		free_and_exit(-1);
	}

	post_jail_fs();
}

static int write_uid_gid_map(pid_t child_pid, bool gidmap, char *mapstr)
{
	int map_file;
	char map_path[64];

	if (snprintf(map_path, sizeof(map_path), "/proc/%d/%s",
		child_pid, gidmap?"gid_map":"uid_map") < 0)
		return -1;

	if ((map_file = open(map_path, O_WRONLY | O_CLOEXEC)) < 0)
		return -1;

	if (dprintf(map_file, "%s", mapstr) < 0) {
		close(map_file);
		return -1;
	}

	close(map_file);
	return 0;
}

static int write_single_uid_gid_map(pid_t child_pid, bool gidmap, int id)
{
	int map_file;
	char map_path[64];
	const char *map_format = "%d %d %d\n";
	if (snprintf(map_path, sizeof(map_path), "/proc/%d/%s",
		child_pid, gidmap?"gid_map":"uid_map") < 0)
		return -1;

	if ((map_file = open(map_path, O_WRONLY | O_CLOEXEC)) < 0)
		return -1;

	if (dprintf(map_file, map_format, 0, id, 1) < 0) {
		close(map_file);
		return -1;
	}

	close(map_file);
	return 0;
}

static int write_setgroups(pid_t child_pid, bool allow)
{
	int setgroups_file;
	char setgroups_path[64];

	if (snprintf(setgroups_path, sizeof(setgroups_path), "/proc/%d/setgroups",
		child_pid) < 0) {
		return -1;
	}

	if ((setgroups_file = open(setgroups_path, O_WRONLY | O_CLOEXEC)) < 0) {
		return -1;
	}

	if (dprintf(setgroups_file, "%s", allow?"allow":"deny") == -1) {
		close(setgroups_file);
		return -1;
	}

	close(setgroups_file);
	return 0;
}

static void get_jail_user(int *user, int *user_gid, int *gr_gid)
{
	struct passwd pwd, *p = NULL;
	struct group grp, *g = NULL;
	char *buf = NULL;
	size_t bufsize;
	long sc;
	int ret = 0, attempt;

	if (opts.user) {
		sc = sysconf(_SC_GETPW_R_SIZE_MAX);
		bufsize = (sc > 0) ? (size_t)sc : 16384;

		for (attempt = 0; attempt < 8; attempt++) {
			buf = malloc(bufsize);
			if (!buf) {
				ERROR("out of memory resolving user %s\n", opts.user);
				free_and_exit(EXIT_FAILURE);
			}

			ret = getpwnam_r(opts.user, &pwd, buf, bufsize, &p);
			if (ret != ERANGE)
				break;

			free(buf);
			buf = NULL;
			bufsize *= 2;
		}

		if (ret || !p) {
			free(buf);
			if (!ret)
				ERROR("failed to get uid/gid for user %s: "
				      "no such user\n", opts.user);
			else
				ERROR("failed to get uid/gid for user %s: %d (%s)\n",
				      opts.user, ret, strerror(ret));
			free_and_exit(EXIT_FAILURE);
		}

		*user = p->pw_uid;
		*user_gid = p->pw_gid;
		free(buf);
	} else {
		*user = -1;
		*user_gid = -1;
	}

	if (opts.group) {
		sc = sysconf(_SC_GETGR_R_SIZE_MAX);
		bufsize = (sc > 0) ? (size_t)sc : 16384;

		for (attempt = 0; attempt < 8; attempt++) {
			buf = malloc(bufsize);
			if (!buf) {
				ERROR("out of memory resolving group %s\n", opts.group);
				free_and_exit(EXIT_FAILURE);
			}

			ret = getgrnam_r(opts.group, &grp, buf, bufsize, &g);
			if (ret != ERANGE)
				break;

			free(buf);
			buf = NULL;
			bufsize *= 2;
		}

		if (ret || !g) {
			free(buf);
			if (!ret)
				ERROR("failed to get gid for group %s: "
				      "no such group\n", opts.group);
			else
				ERROR("failed to get gid for group %s: %d (%s)\n",
				      opts.group, ret, strerror(ret));
			free_and_exit(EXIT_FAILURE);
		}

		*gr_gid = g->gr_gid;
		free(buf);
	} else {
		*gr_gid = -1;
	}
};

static void set_jail_user(int pw_uid, int user_gid, int gr_gid)
{
	if (opts.user && (user_gid != -1) && initgroups(opts.user, user_gid)) {
		ERROR("failed to initgroups() for user %s: %m\n", opts.user);
		free_and_exit(EXIT_FAILURE);
	}

	if ((gr_gid != -1) && setregid(gr_gid, gr_gid)) {
		ERROR("failed to set group id %d: %m\n", gr_gid);
		free_and_exit(EXIT_FAILURE);
	}

	if ((pw_uid != -1) && setreuid(pw_uid, pw_uid)) {
		ERROR("failed to set user id %d: %m\n", pw_uid);
		free_and_exit(EXIT_FAILURE);
	}
}

static const char *proc_mask_critical[] = {
	"/proc/kcore",
	"/proc/sysrq-trigger",
	NULL,
};

static const char *proc_mask_optional[] = {
	"/proc/latency_stats",
	"/proc/timer_list",
	"/proc/timer_stats",
	"/proc/sched_debug",
	"/proc/scsi",
	NULL,
};

static const char *sys_mask_critical[] = {
	"/sys/firmware",
	NULL,
};

static int mask_default_paths(const char **paths, bool critical)
{
	const char **p;

	for (p = paths; *p; p++) {
		if (add_mount((void *)(-1), *p, NULL, 0, 0, NULL, critical ? -1 : 0)) {
			if (critical) {
				ERROR("failed to mask sensitive path %s\n", *p);
				return -1;
			}
			WARNING("could not mask optional path %s; it may not "
				"exist on this kernel/config\n", *p);
		}
	}

	return 0;
}

/* deferred like mask_path_now(): locking a readonlyPath in phase 1
 * would stay locked past the jail's own unshare(CLONE_NEWNS). */
static int remount_readonly_now(const char *path)
{
	struct stat s;

	if (stat(path, &s))
		return 0; /* doesn't exist, nothing to restrict */

	if (mount(path, path, "bind", MS_BIND | MS_REC, NULL))
		return -1;
	if (mount(path, path, "bind", MS_REMOUNT | MS_BIND | MS_RDONLY | MS_REC, NULL))
		return -1;

	DEBUG("read-only path %s\n", path);
	return 0;
}

/* re-apply masks inside the container's own mntns: the first pass is
 * locked once copied in after unshare(CLONE_NEWNS); best-effort */
static void remask_after_unshare(void)
{
	const char **p;
	char **dp;

	if (!opts.ocibundle) {
		if (opts.procfs) {
			for (p = proc_mask_critical; *p; p++)
				mask_path_now(*p);
			for (p = proc_mask_optional; *p; p++)
				mask_path_now(*p);
		}

		if (opts.sysfs) {
			for (p = sys_mask_critical; *p; p++)
				mask_path_now(*p);
		}
	}

	/* same reason as the default masks above: locked in phase 1, an
	 * OCI bundle's own masks would outlive its unshare(CLONE_NEWNS). */
	if (opts.oci_deferred_masked)
		for (dp = opts.oci_deferred_masked; *dp; dp++)
			mask_path_now(*dp);

	if (opts.oci_deferred_readonly)
		for (dp = opts.oci_deferred_readonly; *dp; dp++)
			remount_readonly_now(*dp);
}

/* /proc/sys is locked read-only for every procfs jail via a self-bind,
 * separately from the mask_default_paths() lists above; a deferred-
 * userns jail skips it in phase 1 for the same reason it skips the
 * masks (see the call site in post_main()), so re-apply it here. */
static void remount_proc_sys_after_unshare(void)
{
	struct stat s;

	if (!(opts.procfs || opts.ocibundle))
		return;
	if (stat("/proc/sys", &s))
		return;

	/* the MS_MOVE below needs a mountpoint to move from, or it's a
	 * silent EINVAL. */
	if (opts.namespace & CLONE_NEWNET)
		mount("/proc/sys/net", "/proc/self/net", "bind", MS_BIND, NULL);

	if (mount("/proc/sys", "/proc/sys", "bind", MS_BIND, NULL))
		return;
	if (mount("/proc/sys", "/proc/sys", "bind", MS_REMOUNT | MS_BIND | MS_RDONLY, NULL))
		WARNING("could not remount /proc/sys read-only\n");

	if (opts.namespace & CLONE_NEWNET)
		mount("/proc/self/net", "/proc/sys/net", "bind", MS_MOVE, NULL);
}

static bool resolve_jail_user_gids(int primary_gid)
{
	gid_t *groups = NULL;
	int ngroups = 16;
	int ret = -1;
	int attempt, i, n;

	if (!opts.user || primary_gid == -1)
		return false;

	for (attempt = 0; attempt < 16; attempt++) {
		gid_t *tmp = realloc(groups, ngroups * sizeof(gid_t));
		if (!tmp) {
			free(groups);
			ERROR("out of memory resolving groups for %s\n", opts.user);
			return false;
		}
		groups = tmp;

		ret = getgrouplist(opts.user, primary_gid, groups, &ngroups);
		if (ret >= 0)
			break;
	}

	if (ret < 0) {
		free(groups);
		ERROR("could not resolve groups for %s\n", opts.user);
		return false;
	}

	for (n = 0, i = 0; i < ret; i++) {
		if ((int)groups[i] == primary_gid)
			continue;
		groups[n++] = groups[i];
	}

	opts.additional_gids = groups;
	opts.num_additional_gids = n;

	return true;
}

/* deterministic: parent and child (across fork) compute the same ids */
static int *compute_inner_gids(int primary_gid)
{
	size_t i;
	int *inner_id;
	int next_id = 1;

	inner_id = calloc(opts.num_additional_gids ?: 1, sizeof(int));
	if (!inner_id)
		return NULL;

	for (i = 0; i < opts.num_additional_gids; i++) {
		int gid = (int)opts.additional_gids[i];
		int candidate = gid;
		bool used;

		if (gid == 0) {
			do {
				used = (candidate == 0 || candidate == primary_gid);
				for (size_t j = 0; !used && j < opts.num_additional_gids; j++)
					if ((int)opts.additional_gids[j] == candidate)
						used = true;
				for (size_t j = 0; !used && j < i; j++)
					if (inner_id[j] == candidate)
						used = true;
				if (used)
					candidate = next_id++;
			} while (used);
		}

		inner_id[i] = candidate;
	}

	return inner_id;
}

static char *build_group_gidmap(int primary_gid)
{
	size_t i, len = 0, pos = 0;
	char *map;
	int *inner_id;

	inner_id = compute_inner_gids(primary_gid);
	if (!inner_id)
		return NULL;

	len += snprintf(NULL, 0, "%d %d %d\n", 0, primary_gid, 1);
	for (i = 0; i < opts.num_additional_gids; i++)
		len += snprintf(NULL, 0, "%d %d %d\n",
				inner_id[i], opts.additional_gids[i], 1);

	map = malloc(len + 1);
	if (!map) {
		free(inner_id);
		return NULL;
	}

	pos += snprintf(&map[pos], len + 1 - pos, "%d %d %d\n", 0, primary_gid, 1);
	for (i = 0; i < opts.num_additional_gids; i++)
		pos += snprintf(&map[pos], len + 1 - pos, "%d %d %d\n",
				inner_id[i], opts.additional_gids[i], 1);

	free(inner_id);
	return map;
}

static int apply_rlimits(void)
{
	int resource;

	for (resource = 0; resource < RLIM_NLIMITS; ++resource) {
		if (opts.rlimits[resource])
			DEBUG("applying limits to resource %u\n", resource);

		if (opts.rlimits[resource] &&
		    setrlimit(resource, opts.rlimits[resource]))
			return errno;
	}

	return 0;
}

#define MAX_ENVP	64
static char** build_envp(const char *seccomp, char **ocienvp)
{
	static char *envp[MAX_ENVP];
	static char preload_var[PATH_MAX];
	static char seccomp_var[PATH_MAX];
	static char seccomp_debug_var[20];
	static char debug_var[] = "LD_DEBUG=all";
	static char container_var[] = "container=ujail";
	const char *preload_lib = find_lib("libpreload-seccomp.so");
	char **addenv;

	int count = 0;

	if (seccomp && !preload_lib) {
		ERROR("failed to add preload-lib to env\n");
		return NULL;
	}
	if (seccomp) {
		snprintf(seccomp_var, sizeof(seccomp_var), "SECCOMP_FILE=%s", seccomp);
		envp[count++] = seccomp_var;
		snprintf(seccomp_debug_var, sizeof(seccomp_debug_var), "SECCOMP_DEBUG=%2d", debug);
		envp[count++] = seccomp_debug_var;
		snprintf(preload_var, sizeof(preload_var), "LD_PRELOAD=%s", preload_lib);
		envp[count++] = preload_var;
	}

	envp[count++] = container_var;

	if (debug > 1)
		envp[count++] = debug_var;

	addenv = ocienvp;
	while (addenv && *addenv) {
		envp[count++] = *(addenv++);
		if (count >= MAX_ENVP) {
			ERROR("environment limited to %d extra records, truncating\n", MAX_ENVP);
			break;
		}
	}
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
	fprintf(stderr, "  -e <var>\timport environment variable\n");
	fprintf(stderr, "namespace jail options:\n");
	fprintf(stderr, "  -h <hostname>\tchange the hostname of the jail\n");
	fprintf(stderr, "  -N\t\tjail has network namespace\n");
	fprintf(stderr, "  -f\t\tjail has user namespace\n");
	fprintf(stderr, "  -F\t\tjail has cgroups namespace\n");
	fprintf(stderr, "  -r <file>\treadonly files that should be staged\n");
	fprintf(stderr, "  -w <file>\twriteable files that should be staged\n");
	fprintf(stderr, "  -p\t\tjail has /proc\n");
	fprintf(stderr, "  -s\t\tjail has /sys\n");
	fprintf(stderr, "  -l\t\tjail has /dev/log\n");
	fprintf(stderr, "  -u\t\tjail has a ubus socket\n");
	fprintf(stderr, "  -D\t\tjail has a udebug socket\n");
	fprintf(stderr, "  -U <name>\tuser to run jailed process\n");
	fprintf(stderr, "  -G <name>\tgroup to run jailed process\n");
	fprintf(stderr, "  -o\t\tremont jail root (/) read only\n");
	fprintf(stderr, "  -R <dir>\texternal jail rootfs (system container)\n");
	fprintf(stderr, "  -O <dir>\tdirectory for r/w overlayfs\n");
	fprintf(stderr, "  -T <size>\tuse tmpfs r/w overlayfs with <size>\n");
	fprintf(stderr, "  -E\t\tfail if jail cannot be setup\n");
	fprintf(stderr, "  -y\t\tprovide jail console\n");
	fprintf(stderr, "  -J <dir>\tcreate container from OCI bundle\n");
	fprintf(stderr, "  -i\t\tstart container immediately\n");
	fprintf(stderr, "  -P <pidfile>\tcreate <pidfile>\n");
	fprintf(stderr, "\nWarning: by default root inside the jail is the same\n\
and he has the same powers as root outside the jail,\n\
thus he can escape the jail and/or break stuff.\n\
Please use seccomp/capabilities (-S/-C) to restrict his powers\n\n\
If you use none of the namespace jail options,\n\
ujail will not use namespace/build a jail,\n\
and will only drop capabilities/apply seccomp filter.\n\n");
}

static int* get_namespace_fd(const unsigned int nstype)
{
	switch (nstype) {
		case CLONE_NEWPID:
			return &opts.setns.pid;
		case CLONE_NEWNET:
			return &opts.setns.net;
		case CLONE_NEWNS:
			return &opts.setns.ns;
		case CLONE_NEWIPC:
			return &opts.setns.ipc;
		case CLONE_NEWUTS:
			return &opts.setns.uts;
		case CLONE_NEWUSER:
			return &opts.setns.user;
		case CLONE_NEWCGROUP:
			return &opts.setns.cgroup;
		case CLONE_NEWTIME:
			return &opts.setns.time;
		default:
			return NULL;
	}
}

static int setns_open(unsigned long nstype)
{
	int *fd = get_namespace_fd(nstype);

	assert(fd != NULL);

	if (*fd < 0)
		return 0;

	if (setns(*fd, nstype) == -1) {
		close(*fd);
		return errno;
	}

	close(*fd);
	return 0;
}

static int jail_running = 0;
static int jail_return_code = 0;

static void jail_process_timeout_cb(struct uloop_timeout *t);
static struct uloop_timeout jail_process_timeout = {
	.cb = jail_process_timeout_cb,
};
static void poststop(void);
static void jail_process_handler(struct uloop_process *c, int ret)
{
	uloop_timeout_cancel(&jail_process_timeout);
	if (WIFEXITED(ret)) {
		jail_return_code = WEXITSTATUS(ret);
		INFO("jail (%d) exited with exit: %d\n", c->pid, jail_return_code);
	} else {
		jail_return_code = 128 + WTERMSIG(ret);
		INFO("jail (%d) exited with signal: %d\n", c->pid, WTERMSIG(ret));
	}
	jail_running = 0;
	poststop();
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
	if (hook_running) {
		DEBUG("forwarding signal %d to the hook process\n", signo);
		kill(hook_process.pid, signo);
		/* set timeout to send SIGKILL hook process in case SIGTERM doesn't succeed */
		if (signo == SIGTERM)
			uloop_timeout_set(&hook_process_timeout, opts.term_timeout * 1000);
	}

	if (jail_running) {
		DEBUG("forwarding signal %d to the jailed process\n", signo);
		kill(jail_process.pid, signo);
		/* set timeout to send SIGKILL jail process in case SIGTERM doesn't succeed */
		if (signo == SIGTERM)
			uloop_timeout_set(&jail_process_timeout, opts.term_timeout * 1000);
	}
}

static void signals_init(void)
{
	int i;
	sigset_t sigmask;

	sigfillset(&sigmask);
	for (i = 0; i < _NSIG; i++) {
		struct sigaction s = { 0 };

		if (!sigismember(&sigmask, i))
			continue;
		switch (i) {
		case SIGCHLD:
		case SIGPIPE:
		case SIGKILL:
		case SIGSTOP:
		case SIGSEGV:
		case SIGBUS:
		case SIGFPE:
		case SIGILL:
		case SIGSYS:
		case SIGABRT:
		case SIGTRAP:
			continue;
		default:
			break;
		}

		s.sa_handler = jail_handle_signal;
		sigaction(i, &s, NULL);
	}
}

enum {
	OCI_PROCESS_SCHEDULER_POLICY,
	OCI_PROCESS_SCHEDULER_NICE,
	OCI_PROCESS_SCHEDULER_PRIORITY,
	OCI_PROCESS_SCHEDULER_FLAGS,
	OCI_PROCESS_SCHEDULER_RUNTIME,
	OCI_PROCESS_SCHEDULER_DEADLINE,
	OCI_PROCESS_SCHEDULER_PERIOD,
	__OCI_PROCESS_SCHEDULER_MAX,
};

static const struct blobmsg_policy oci_process_scheduler_policy[] = {
	[OCI_PROCESS_SCHEDULER_POLICY] = { "policy", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS_SCHEDULER_NICE] = { "nice", BLOBMSG_TYPE_INT32 },
	[OCI_PROCESS_SCHEDULER_PRIORITY] = { "priority", BLOBMSG_TYPE_INT32 },
	[OCI_PROCESS_SCHEDULER_FLAGS] = { "flags", BLOBMSG_TYPE_ARRAY },
	[OCI_PROCESS_SCHEDULER_RUNTIME] = { "runtime", BLOBMSG_CAST_INT64 },
	[OCI_PROCESS_SCHEDULER_DEADLINE] = { "deadline", BLOBMSG_CAST_INT64 },
	[OCI_PROCESS_SCHEDULER_PERIOD] = { "period", BLOBMSG_CAST_INT64 },
};

#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

#ifndef SCHED_FLAG_RESET_ON_FORK
#define SCHED_FLAG_RESET_ON_FORK 0x01
#endif

#ifndef SCHED_FLAG_RECLAIM
#define SCHED_FLAG_RECLAIM 0x02
#endif

#ifndef SCHED_FLAG_DL_OVERRUN
#define SCHED_FLAG_DL_OVERRUN 0x04
#endif

struct procd_sched_attr {
	uint32_t size;
	uint32_t sched_policy;
	uint64_t sched_flags;
	int32_t  sched_nice;
	uint32_t sched_priority;
	uint64_t sched_runtime;
	uint64_t sched_deadline;
	uint64_t sched_period;
};

static int parseOCIprocessscheduler(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_PROCESS_SCHEDULER_MAX];
	struct blob_attr *cur;
	const char *policy;
	int rem;

	blobmsg_parse(oci_process_scheduler_policy, __OCI_PROCESS_SCHEDULER_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_PROCESS_SCHEDULER_POLICY])
		return ENODATA;

	policy = blobmsg_get_string(tb[OCI_PROCESS_SCHEDULER_POLICY]);
	if (!strcmp(policy, "SCHED_OTHER"))
		opts.scheduler.policy = SCHED_OTHER;
	else if (!strcmp(policy, "SCHED_FIFO"))
		opts.scheduler.policy = SCHED_FIFO;
	else if (!strcmp(policy, "SCHED_RR"))
		opts.scheduler.policy = SCHED_RR;
	else if (!strcmp(policy, "SCHED_BATCH"))
		opts.scheduler.policy = SCHED_BATCH;
	else if (!strcmp(policy, "SCHED_IDLE"))
		opts.scheduler.policy = SCHED_IDLE;
	else if (!strcmp(policy, "SCHED_DEADLINE"))
		opts.scheduler.policy = SCHED_DEADLINE;
	else
		return EINVAL;

	if (tb[OCI_PROCESS_SCHEDULER_NICE])
		opts.scheduler.nice = blobmsg_get_u32(tb[OCI_PROCESS_SCHEDULER_NICE]);

	if (tb[OCI_PROCESS_SCHEDULER_PRIORITY]) {
		int32_t prio = (int32_t)blobmsg_get_u32(tb[OCI_PROCESS_SCHEDULER_PRIORITY]);

		if (prio < 0) {
			ERROR("scheduler: priority %d out of range\n", prio);
			return EINVAL;
		}
		if ((opts.scheduler.policy == SCHED_FIFO || opts.scheduler.policy == SCHED_RR) &&
		    (prio < 1 || prio > 99)) {
			ERROR("scheduler: priority %d outside 1..99 for FIFO/RR\n", prio);
			return EINVAL;
		}
		opts.scheduler.priority = prio;
	}

	if (tb[OCI_PROCESS_SCHEDULER_RUNTIME])
		opts.scheduler.runtime = blobmsg_cast_u64(tb[OCI_PROCESS_SCHEDULER_RUNTIME]);

	if (tb[OCI_PROCESS_SCHEDULER_DEADLINE])
		opts.scheduler.deadline = blobmsg_cast_u64(tb[OCI_PROCESS_SCHEDULER_DEADLINE]);

	if (tb[OCI_PROCESS_SCHEDULER_PERIOD])
		opts.scheduler.period = blobmsg_cast_u64(tb[OCI_PROCESS_SCHEDULER_PERIOD]);

	if (tb[OCI_PROCESS_SCHEDULER_FLAGS]) {
		if (blobmsg_check_array(tb[OCI_PROCESS_SCHEDULER_FLAGS], BLOBMSG_TYPE_STRING) < 0)
			return EINVAL;
		blobmsg_for_each_attr(cur, tb[OCI_PROCESS_SCHEDULER_FLAGS], rem) {
			const char *flag = blobmsg_get_string(cur);
			if (!strcmp(flag, "SCHED_FLAG_RESET_ON_FORK"))
				opts.scheduler.flags |= SCHED_FLAG_RESET_ON_FORK;
			else if (!strcmp(flag, "SCHED_FLAG_RECLAIM"))
				opts.scheduler.flags |= SCHED_FLAG_RECLAIM;
			else if (!strcmp(flag, "SCHED_FLAG_DL_OVERRUN"))
				opts.scheduler.flags |= SCHED_FLAG_DL_OVERRUN;
			else
				return EINVAL;
		}
	}

	opts.scheduler.set = true;
	return 0;
}

static int applyOCIprocessscheduler(void)
{
	struct procd_sched_attr attr = {
		.size = sizeof(attr),
		.sched_policy = opts.scheduler.policy,
		.sched_flags = opts.scheduler.flags,
		.sched_nice = opts.scheduler.nice,
		.sched_priority = opts.scheduler.priority,
		.sched_runtime = opts.scheduler.runtime,
		.sched_deadline = opts.scheduler.deadline,
		.sched_period = opts.scheduler.period,
	};

	if (syscall(SYS_sched_setattr, 0, &attr, 0)) {
		ERROR("sched_setattr: %m\n");
		return errno;
	}

	return 0;
}

enum {
	OCI_PROCESS_IOPRIORITY_CLASS,
	OCI_PROCESS_IOPRIORITY_PRIORITY,
	__OCI_PROCESS_IOPRIORITY_MAX,
};

static const struct blobmsg_policy oci_process_iopriority_policy[] = {
	[OCI_PROCESS_IOPRIORITY_CLASS] = { "class", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS_IOPRIORITY_PRIORITY] = { "priority", BLOBMSG_TYPE_INT32 },
};

#ifndef IOPRIO_WHO_PROCESS
#define IOPRIO_WHO_PROCESS 1
#endif

#ifndef IOPRIO_CLASS_RT
#define IOPRIO_CLASS_RT 1
#endif

#ifndef IOPRIO_CLASS_BE
#define IOPRIO_CLASS_BE 2
#endif

#ifndef IOPRIO_CLASS_SHIFT
#define IOPRIO_CLASS_SHIFT 13
#endif

#ifndef IOPRIO_CLASS_IDLE
#define IOPRIO_CLASS_IDLE 3
#endif

static int parseOCIprocessiopriority(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_PROCESS_IOPRIORITY_MAX];
	const char *class;
	int priority;

	blobmsg_parse(oci_process_iopriority_policy, __OCI_PROCESS_IOPRIORITY_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_PROCESS_IOPRIORITY_CLASS] || !tb[OCI_PROCESS_IOPRIORITY_PRIORITY])
		return ENODATA;

	class = blobmsg_get_string(tb[OCI_PROCESS_IOPRIORITY_CLASS]);
	if (!strcmp(class, "IOPRIO_CLASS_RT"))
		opts.ioprio.class = IOPRIO_CLASS_RT;
	else if (!strcmp(class, "IOPRIO_CLASS_BE"))
		opts.ioprio.class = IOPRIO_CLASS_BE;
	else if (!strcmp(class, "IOPRIO_CLASS_IDLE"))
		opts.ioprio.class = IOPRIO_CLASS_IDLE;
	else
		return EINVAL;

	priority = blobmsg_get_u32(tb[OCI_PROCESS_IOPRIORITY_PRIORITY]);
	if (priority < 0 || priority > 7)
		return EINVAL;

	opts.ioprio.priority = priority;
	opts.ioprio.set = true;
	return 0;
}

static int applyOCIprocessiopriority(void)
{
	int ioprio = (opts.ioprio.class << IOPRIO_CLASS_SHIFT) | opts.ioprio.priority;

	if (syscall(SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, ioprio)) {
		ERROR("ioprio_set: %m\n");
		return errno;
	}

	return 0;
}

static int move_netdev_to_ns(int netns_fd, const char *host_name, const char *new_name)
{
	struct {
		struct nlmsghdr hdr;
		struct ifinfomsg ifi;
		char attrbuf[256];
	} req = { 0 };
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct rtattr *rta;
	int sock, ifindex;
	char buf[4096];
	ssize_t n;

	int saved_err;

	ifindex = if_nametoindex(host_name);
	if (!ifindex) {
		ERROR("netDevices: interface %s not found\n", host_name);
		return ENODEV;
	}

	sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (sock < 0) {
		ERROR("netDevices: socket(AF_NETLINK): %m\n");
		return errno;
	}
	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		saved_err = errno;
		ERROR("netDevices: bind: %m\n");
		close(sock);
		errno = saved_err;
		return saved_err;
	}

	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifi));
	req.hdr.nlmsg_type = RTM_NEWLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.hdr.nlmsg_seq = 1;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = ifindex;

	rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.hdr.nlmsg_len));
	rta->rta_type = IFLA_NET_NS_FD;
	rta->rta_len = RTA_LENGTH(sizeof(int));
	memcpy(RTA_DATA(rta), &netns_fd, sizeof(int));
	req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_ALIGN(rta->rta_len);

	if (new_name) {
		size_t namelen = strlen(new_name) + 1;
		rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.hdr.nlmsg_len));
		rta->rta_type = IFLA_IFNAME;
		rta->rta_len = RTA_LENGTH(namelen);
		memcpy(RTA_DATA(rta), new_name, namelen);
		req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_ALIGN(rta->rta_len);
	}

	if (send(sock, &req, req.hdr.nlmsg_len, 0) < 0) {
		saved_err = errno;
		ERROR("netDevices: send: %m\n");
		close(sock);
		errno = saved_err;
		return saved_err;
	}

	n = recv(sock, buf, sizeof(buf), 0);
	saved_err = (n < 0) ? errno : 0;
	close(sock);
	if (n < 0) {
		errno = saved_err;
		ERROR("netDevices: recv: %m\n");
		return saved_err;
	}

	if (n < (ssize_t)NLMSG_HDRLEN ||
	    !NLMSG_OK((struct nlmsghdr *)buf, (size_t)n)) {
		ERROR("netDevices: short or malformed nlmsg (%zd bytes)\n", n);
		return EIO;
	}

	struct nlmsghdr *nh = (struct nlmsghdr *)buf;
	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nh);
		if (err->error) {
			ERROR("netDevices: kernel rejected move of %s: %s\n",
			      host_name, strerror(-err->error));
			return -err->error;
		}
	}

	return 0;
}

static int move_netdevs_into_jail(pid_t pid)
{
	enum {
		OCI_LINUX_NETDEVICES_NAME,
		__OCI_LINUX_NETDEVICES_MAX,
	};
	static const struct blobmsg_policy policy[] = {
		[OCI_LINUX_NETDEVICES_NAME] = { "name", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *cur, *tb[__OCI_LINUX_NETDEVICES_MAX];
	char path[64];
	int rem, netns_fd, ret = 0;

	if (!opts.netdevices)
		return 0;

	snprintf(path, sizeof(path), "/proc/%d/ns/net", pid);
	netns_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (netns_fd < 0) {
		ERROR("netDevices: open(%s): %m\n", path);
		return errno;
	}

	blobmsg_for_each_attr(cur, opts.netdevices, rem) {
		const char *host_name = blobmsg_name(cur);
		const char *new_name = NULL;

		blobmsg_parse(policy, __OCI_LINUX_NETDEVICES_MAX, tb,
			      blobmsg_data(cur), blobmsg_len(cur));
		if (tb[OCI_LINUX_NETDEVICES_NAME])
			new_name = blobmsg_get_string(tb[OCI_LINUX_NETDEVICES_NAME]);

		ret = move_netdev_to_ns(netns_fd, host_name, new_name);
		if (ret)
			break;
	}

	close(netns_fd);
	return ret;
}

enum {
	OCI_LINUX_TIMEOFFSETS_SECS,
	OCI_LINUX_TIMEOFFSETS_NANOSECS,
	__OCI_LINUX_TIMEOFFSETS_CLOCK_MAX,
};

static const struct blobmsg_policy oci_linux_timeoffsets_clock_policy[] = {
	[OCI_LINUX_TIMEOFFSETS_SECS] = { "secs", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_TIMEOFFSETS_NANOSECS] = { "nanosecs", BLOBMSG_TYPE_INT32 },
};

struct procd_timens_offset {
	bool set;
	int64_t secs;
	uint32_t nanosecs;
};

static struct {
	struct procd_timens_offset monotonic;
	struct procd_timens_offset boottime;
} timens_offsets;

enum {
	OCI_LINUX_TIMEOFFSETS_MONOTONIC,
	OCI_LINUX_TIMEOFFSETS_BOOTTIME,
	__OCI_LINUX_TIMEOFFSETS_MAX,
};

static const struct blobmsg_policy oci_linux_timeoffsets_policy[] = {
	[OCI_LINUX_TIMEOFFSETS_MONOTONIC] = { "monotonic", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_TIMEOFFSETS_BOOTTIME] = { "boottime", BLOBMSG_TYPE_TABLE },
};

static int parseOCItimensclock(struct blob_attr *msg, struct procd_timens_offset *off)
{
	struct blob_attr *tb[__OCI_LINUX_TIMEOFFSETS_CLOCK_MAX];

	blobmsg_parse(oci_linux_timeoffsets_clock_policy, __OCI_LINUX_TIMEOFFSETS_CLOCK_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_LINUX_TIMEOFFSETS_SECS])
		off->secs = blobmsg_cast_s64(tb[OCI_LINUX_TIMEOFFSETS_SECS]);

	if (tb[OCI_LINUX_TIMEOFFSETS_NANOSECS]) {
		uint32_t ns = blobmsg_get_u32(tb[OCI_LINUX_TIMEOFFSETS_NANOSECS]);

		if (ns > 999999999) {
			ERROR("timeOffsets: nanosecs %u out of range\n", ns);
			return EINVAL;
		}
		off->nanosecs = ns;
	}

	off->set = true;
	return 0;
}

static int parseOCIlinuxtimeoffsets(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_TIMEOFFSETS_MAX];
	int res;

	blobmsg_parse(oci_linux_timeoffsets_policy, __OCI_LINUX_TIMEOFFSETS_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_LINUX_TIMEOFFSETS_MONOTONIC]) {
		res = parseOCItimensclock(tb[OCI_LINUX_TIMEOFFSETS_MONOTONIC], &timens_offsets.monotonic);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_TIMEOFFSETS_BOOTTIME]) {
		res = parseOCItimensclock(tb[OCI_LINUX_TIMEOFFSETS_BOOTTIME], &timens_offsets.boottime);
		if (res)
			return res;
	}

	return 0;
}

static int applyOCIlinuxtimeoffsets(void)
{
	int fd = open("/proc/self/timens_offsets", O_WRONLY | O_CLOEXEC);
	int saved_errno;

	if (fd < 0) {
		ERROR("open(/proc/self/timens_offsets): %m\n");
		return errno;
	}

	if (timens_offsets.monotonic.set &&
	    dprintf(fd, "%d %" PRId64 " %" PRIu32 "\n", CLOCK_MONOTONIC,
		    timens_offsets.monotonic.secs, timens_offsets.monotonic.nanosecs) < 0) {
		saved_errno = errno;
		ERROR("timens_offsets monotonic: %m\n");
		close(fd);
		return saved_errno;
	}

	if (timens_offsets.boottime.set &&
	    dprintf(fd, "%d %" PRId64 " %" PRIu32 "\n", CLOCK_BOOTTIME,
		    timens_offsets.boottime.secs, timens_offsets.boottime.nanosecs) < 0) {
		saved_errno = errno;
		ERROR("timens_offsets boottime: %m\n");
		close(fd);
		return saved_errno;
	}

	close(fd);
	return 0;
}

static void pre_exec_jail(struct uloop_timeout *t);
static struct uloop_timeout pre_exec_timeout = {
	.cb = pre_exec_jail,
};

int pipes[4];
static int parent_pidfd = -1;
static int exec_jail(void *arg)
{
	char buf[1];
	ssize_t n;

	exit_from_child = true;
	prctl(PR_SET_SECUREBITS, 0);

	uloop_init();
	signals_init();

	close(pipes[0]);
	close(pipes[3]);

	if ((opts.namespace & CLONE_NEWUSER) && opts.setns.user == -1) {
		/* CLONE_NEWUSER is deferred to enter_userns(); keep our
		 * ends of the handshake open, close only the parent's. */
		close(userns_pipe[0]);
		close(userns_pipe[3]);
	} else {
		/* Not deferring anything: this handshake isn't used at all. */
		close(userns_pipe[0]);
		close(userns_pipe[1]);
		close(userns_pipe[2]);
		close(userns_pipe[3]);
	}

	setns_open(CLONE_NEWNET);
	setns_open(CLONE_NEWNS);
	setns_open(CLONE_NEWIPC);
	setns_open(CLONE_NEWUTS);

	/*
	 * Must run before setns_open(CLONE_NEWUSER) below: joining an
	 * external userns drops privilege immediately, and our own userns
	 * is deferred to enter_userns(), so this always runs privileged.
	 */
	if ((opts.namespace & CLONE_NEWNS) &&
	    ((opts.namespace & CLONE_NEWUSER) || opts.setns.user != -1) &&
	    isolate_mountns_and_detach_inherited()) {
		ERROR("failed to detach inherited mounts\n");
		return EXIT_FAILURE;
	}

	setns_open(CLONE_NEWUSER);

	buf[0] = 'i';
	if (write(pipes[1], buf, 1) < 1) {
		ERROR("can't write to parent\n");
		return EXIT_FAILURE;
	}
	close(pipes[1]);
	do {
		n = read(pipes[2], buf, 1);
	} while (n < 0 && errno == EINTR);
	if (n < 1) {
		ERROR("can't read from parent\n");
		return EXIT_FAILURE;
	}
	if (buf[0] != 'O') {
		ERROR("parent had an error, child exiting\n");
		return EXIT_FAILURE;
	}

	if (opts.setns.user != -1 && (opts.namespace & CLONE_NEWNS) &&
	    unshare(CLONE_NEWNS)) {
		ERROR("unshare(CLONE_NEWNS) failed: %m\n");
		return EXIT_FAILURE;
	}

	if (opts.namespace & CLONE_NEWCGROUP)
		unshare(CLONE_NEWCGROUP);

	setns_open(CLONE_NEWCGROUP);

	/*
	 * A join of an existing userns (opts.setns.user) can become root
	 * right away. Our own CLONE_NEWUSER is not created here: doing so
	 * before /proc,/sys are mounted ties the PID namespace to it,
	 * which fails mnt_already_visible() on hosts with locked /proc.
	 */
	if (opts.setns.user != -1) {
		if (setregid(0, 0) < 0) {
			ERROR("setgid\n");
			free_and_exit(EXIT_FAILURE);
		}
		if (setreuid(0, 0) < 0) {
			ERROR("setuid\n");
			free_and_exit(EXIT_FAILURE);
		}
		if (setgroups(0, NULL) < 0) {
			if (errno != EPERM) {
				ERROR("setgroups\n");
				free_and_exit(EXIT_FAILURE);
			}
			WARNING("setgroups(0, NULL) denied by the joined "
				"userns (setgroups=deny is permanent once a "
				"gid_map is written); continuing without "
				"dropping supplementary groups\n");
		}
	}

	if (((opts.namespace & CLONE_NEWUTS) || opts.setns.uts != -1)
			&& opts.hostname && strlen(opts.hostname) > 0
			&& sethostname(opts.hostname, strlen(opts.hostname))) {
		ERROR("sethostname(%s) failed: %m\n", opts.hostname);
		free_and_exit(EXIT_FAILURE);
	}

	if (((opts.namespace & CLONE_NEWUTS) || opts.setns.uts != -1)
			&& opts.domainname && strlen(opts.domainname) > 0
			&& setdomainname(opts.domainname, strlen(opts.domainname))) {
		ERROR("setdomainname(%s) failed: %m\n", opts.domainname);
		free_and_exit(EXIT_FAILURE);
	}

	uloop_timeout_add(&pre_exec_timeout);
	uloop_run();

	free_and_exit(-1);
	return -1;
}

static void pre_exec_jail(struct uloop_timeout *t)
{
	if ((opts.namespace & CLONE_NEWNS) && build_jail_fs()) {
		ERROR("failed to build jail fs\n");
		free_and_exit(EXIT_FAILURE);
	} else if (!(opts.namespace & CLONE_NEWNS)) {
		/*
		 * No mount namespace to build (plain "-f"): build_jail_fs()
		 * is skipped, so reach enter_userns() directly here instead.
		 */
		run_hooks(opts.hooks.createContainer, enter_userns);
	}
}

static void post_start_hook(void);
static void post_jail_fs(void)
{
	char buf[1];
	ssize_t n;

	do {
		n = read(pipes[2], buf, 1);
	} while (n < 0 && errno == EINTR);
	if (n < 1) {
		ERROR("can't read from parent\n");
		free_and_exit(EXIT_FAILURE);
	}
	if (buf[0] != '!') {
		ERROR("parent had an error, child exiting\n");
		free_and_exit(EXIT_FAILURE);
	}
	close(pipes[2]);

	run_hooks(opts.hooks.startContainer, post_start_hook);
}

static void post_start_hook(void)
{
	int pw_uid, pw_gid, gr_gid;

	if (opts.scheduler.set && applyOCIprocessscheduler())
		free_and_exit(EXIT_FAILURE);

	if (opts.ioprio.set && applyOCIprocessiopriority())
		free_and_exit(EXIT_FAILURE);

	/*
	 * make sure setuid/setgid won't drop capabilities in case capabilities
	 * have been specified explicitely.
	 */
	if (opts.capset.apply) {
		if (prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP)) {
			ERROR("prctl(PR_SET_SECUREBITS) failed: %m\n");
			free_and_exit(EXIT_FAILURE);
		}
	}

	/* drop capabilities, retain those still needed to further setup jail */
	if (applyOCIcapabilities(opts.capset, (1LLU << CAP_SETGID) | (1LLU << CAP_SETUID) | (1LLU << CAP_SETPCAP)))
		free_and_exit(EXIT_FAILURE);

	/* use either cmdline-supplied user/group or uid/gid from OCI spec */
	if (opts.ocibundle || opts.uidmap || !(opts.namespace & CLONE_NEWUSER)) {
		get_jail_user(&pw_uid, &pw_gid, &gr_gid);
		set_jail_user(opts.pw_uid?:pw_uid, opts.pw_gid?:pw_gid, opts.gr_gid?:gr_gid);
	} else if (opts.user || opts.group || opts.pw_uid != -1 || opts.pw_gid != -1 || opts.gr_gid != -1) {
		WARNING("user/group identity switch (-U/-G) is not re-applied under "
			"CLONE_NEWUSER without an OCI bundle or explicit uidmap; the "
			"process already has the correct identity via the uid_map\n");
	}

	if (opts.additional_gids) {
		bool default_own_userns_map = !opts.uidmap &&
			(opts.namespace & CLONE_NEWUSER) && opts.setns.user == -1;

		if (default_own_userns_map) {
			bool has_gr = (opts.gr_gid != -1);
			int primary_gid = has_gr ? opts.gr_gid :
				((opts.pw_uid != -1) ? opts.pw_gid : 65534);
			int *inner_id = compute_inner_gids(primary_gid);

			if (inner_id) {
				gid_t *mapped = calloc(opts.num_additional_gids ?: 1, sizeof(gid_t));
				size_t i;

				if (mapped) {
					for (i = 0; i < opts.num_additional_gids; i++)
						mapped[i] = (gid_t)inner_id[i];
					if (setgroups(opts.num_additional_gids, mapped) < 0) {
						ERROR("setgroups failed: %m\n");
						free(mapped);
						free(inner_id);
						free_and_exit(EXIT_FAILURE);
					}
					free(mapped);
				} else {
					ERROR("out of memory computing setgroups() list\n");
					free(inner_id);
					free_and_exit(EXIT_FAILURE);
				}
				free(inner_id);
			} else {
				ERROR("out of memory computing setgroups() list\n");
				free_and_exit(EXIT_FAILURE);
			}
		} else if (setgroups(opts.num_additional_gids, opts.additional_gids) < 0) {
			ERROR("setgroups failed: %m\n");
			free_and_exit(EXIT_FAILURE);
		}
	}

	if (opts.set_umask)
		umask(opts.umask);

	/* restore securebits back to normal (and lock them if not in userns) */
	if (opts.capset.apply) {
		if (prctl(PR_SET_SECUREBITS, (opts.namespace & CLONE_NEWUSER)?0:
		    SECBIT_KEEP_CAPS_LOCKED|SECBIT_NO_SETUID_FIXUP_LOCKED|SECBIT_NOROOT_LOCKED)) {
			ERROR("prctl(PR_SET_SECUREBITS) failed: %m\n");
			free_and_exit(EXIT_FAILURE);
		}
	}

	/* drop remaining capabilities to end up with specified sets */
	if (applyOCIcapabilities(opts.capset, 0))
		free_and_exit(EXIT_FAILURE);

	if (opts.no_new_privs && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		ERROR("prctl(PR_SET_NO_NEW_PRIVS) failed: %m\n");
		free_and_exit(EXIT_FAILURE);
	}

	/* the supervisor can SIGKILL ujail on its own death (netifd on exit,
	 * procd's instance_timeout() escalation); die with it, otherwise the
	 * jailed process keeps running and the supervisor's supervisor starts
	 * a second instance. Placed after set_jail_user() and the capability
	 * transitions, whose commit_creds() would zero pdeath_signal, but before
	 * the seccomp filter, which need not permit prctl() to reach execve(). */
	if (prctl(PR_SET_PDEATHSIG, SIGKILL)) {
		ERROR("prctl(PR_SET_PDEATHSIG) failed: %m\n");
		free_and_exit(EXIT_FAILURE);
	}

	/* the parent can die between the fork() and the prctl above; the death
	 * signal is then bound to the process we are reparented to and never
	 * delivered, so detect the exit on the inherited pidfd and die ourselves.
	 * getppid() == 1 cannot serve here: in a new PID namespace the parent is
	 * not visible and getppid() reads 0 either way. */
	if (parent_pidfd >= 0) {
		struct pollfd pfd = { .fd = parent_pidfd, .events = POLLIN };

		if (poll(&pfd, 1, 0) > 0) {
			ERROR("parent died before PR_SET_PDEATHSIG\n");
			free_and_exit(EXIT_FAILURE);
		}
		close(parent_pidfd);
	}

	char **envp = build_envp(opts.seccomp, opts.envp);
	if (!envp)
		free_and_exit(EXIT_FAILURE);

	if (opts.cwd && chdir(opts.cwd))
		free_and_exit(EXIT_FAILURE);

	if (opts.ociseccomp && applyOCIlinuxseccomp(opts.ociseccomp))
		free_and_exit(EXIT_FAILURE);

	uloop_end();
	free_opts(false);
	INFO("exec-ing %s\n", *opts.jail_argv);
	if (opts.envp) /* respect PATH if potentially set in ENV */
		execvpe(*opts.jail_argv, opts.jail_argv, envp);
	else
		execve(*opts.jail_argv, opts.jail_argv, envp);

	/* we get there only if execve fails */
	ERROR("failed to execve %s: %m\n", *opts.jail_argv);
	exit(EXIT_FAILURE);
}

int ns_open_pid(const char *nstype, const pid_t target_ns)
{
	char pid_pid_path[PATH_MAX];

	snprintf(pid_pid_path, sizeof(pid_pid_path), "/proc/%u/ns/%s", target_ns, nstype);

	return open(pid_pid_path, O_RDONLY);
}

static int parseOCIenvarray(struct blob_attr *msg, char ***envp)
{
	struct blob_attr *cur;
	int sz = 0, rem;

	blobmsg_for_each_attr(cur, msg, rem)
		++sz;

	if (sz > 0) {
		*envp = calloc(1 + sz, sizeof(char*));
		if (!(*envp))
			return ENOMEM;
	} else {
		*envp = NULL;
		return 0;
	}

	sz = 0;
	blobmsg_for_each_attr(cur, msg, rem)
		(*envp)[sz++] = strdup(blobmsg_get_string(cur));

	if (sz)
		(*envp)[sz] = NULL;

	return 0;
}

enum {
	OCI_ROOT_PATH,
	OCI_ROOT_READONLY,
	__OCI_ROOT_MAX,
};

static const struct blobmsg_policy oci_root_policy[] = {
	[OCI_ROOT_PATH] = { "path", BLOBMSG_TYPE_STRING },
	[OCI_ROOT_READONLY] = { "readonly", BLOBMSG_TYPE_BOOL },
};

static int parseOCIroot(const char *jsonfile, struct blob_attr *msg)
{
	char extroot[PATH_MAX] = { 0 };
	struct blob_attr *tb[__OCI_ROOT_MAX];
	char *cur;
	char *root_path;

	blobmsg_parse(oci_root_policy, __OCI_ROOT_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_ROOT_PATH])
		return ENODATA;

	root_path = blobmsg_get_string(tb[OCI_ROOT_PATH]);

	/* prepend bundle directory in case of relative paths */
	if (root_path[0] != '/') {
		strncpy(extroot, jsonfile, PATH_MAX - 1);

		cur = strrchr(extroot, '/');

		if (!cur)
			return ENOTDIR;

		*(++cur) = '\0';
	}

	strncat(extroot, root_path, PATH_MAX - (strlen(extroot) + 1));

	/* follow symbolic link(s) */
	opts.extroot = realpath(extroot, NULL);
	if (!opts.extroot)
		return errno;

	if (tb[OCI_ROOT_READONLY])
		opts.ronly = blobmsg_get_bool(tb[OCI_ROOT_READONLY]);

	return 0;
}


enum {
	OCI_HOOK_PATH,
	OCI_HOOK_ARGS,
	OCI_HOOK_ENV,
	OCI_HOOK_TIMEOUT,
	__OCI_HOOK_MAX,
};

static const struct blobmsg_policy oci_hook_policy[] = {
	[OCI_HOOK_PATH] = { "path", BLOBMSG_TYPE_STRING },
	[OCI_HOOK_ARGS] = { "args", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOK_ENV] = { "env", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOK_TIMEOUT] = { "timeout", BLOBMSG_TYPE_INT32 },
};


static int parseOCIhook(struct hook_execvpe ***hooklist, struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_HOOK_MAX];
	struct blob_attr *cur;
	int rem, ret = 0;
	int idx = 0;

	blobmsg_for_each_attr(cur, msg, rem)
		++idx;

	if (!idx)
		return 0;

	*hooklist = calloc(idx + 1, sizeof(struct hook_execvpe *));
	idx = 0;

	if (!(*hooklist))
		return ENOMEM;

	blobmsg_for_each_attr(cur, msg, rem) {
		blobmsg_parse(oci_hook_policy, __OCI_HOOK_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[OCI_HOOK_PATH]) {
			ret = EINVAL;
			goto errout;
		}

		(*hooklist)[idx] = calloc(1, sizeof(struct hook_execvpe));
		if (tb[OCI_HOOK_ARGS]) {
			ret = parseOCIenvarray(tb[OCI_HOOK_ARGS], &((*hooklist)[idx]->argv));
			if (ret)
				goto errout;
		} else {
			(*hooklist)[idx]->argv = calloc(2, sizeof(char *));
			((*hooklist)[idx]->argv)[0] = strdup(blobmsg_get_string(tb[OCI_HOOK_PATH]));
			((*hooklist)[idx]->argv)[1] = NULL;
		};


		if (tb[OCI_HOOK_ENV]) {
			ret = parseOCIenvarray(tb[OCI_HOOK_ENV], &((*hooklist)[idx]->envp));
			if (ret)
				goto errout;
		}

		if (tb[OCI_HOOK_TIMEOUT])
			(*hooklist)[idx]->timeout = blobmsg_get_u32(tb[OCI_HOOK_TIMEOUT]);

		(*hooklist)[idx]->file = strdup(blobmsg_get_string(tb[OCI_HOOK_PATH]));

		++idx;
	}

	(*hooklist)[idx] = NULL;

	DEBUG("added %d hooks\n", idx);

	return 0;

errout:
	free_hooklist(*hooklist);
	*hooklist = NULL;

	return ret;
};


enum {
	OCI_HOOKS_PRESTART,
	OCI_HOOKS_CREATERUNTIME,
	OCI_HOOKS_CREATECONTAINER,
	OCI_HOOKS_STARTCONTAINER,
	OCI_HOOKS_POSTSTART,
	OCI_HOOKS_POSTSTOP,
	__OCI_HOOKS_MAX,
};

static const struct blobmsg_policy oci_hooks_policy[] = {
	[OCI_HOOKS_PRESTART] = { "prestart", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS_CREATERUNTIME] = { "createRuntime", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS_CREATECONTAINER] = { "createContainer", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS_STARTCONTAINER] = { "startContainer", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS_POSTSTART] = { "poststart", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS_POSTSTOP] = { "poststop", BLOBMSG_TYPE_ARRAY },
};

static int parseOCIhooks(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_HOOKS_MAX];
	int ret;

	blobmsg_parse(oci_hooks_policy, __OCI_HOOKS_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_HOOKS_PRESTART]) {
		INFO("notice: deprecated prestart hook present; running it before createRuntime\n");
		ret = parseOCIhook(&opts.hooks.prestart, tb[OCI_HOOKS_PRESTART]);
		if (ret)
			return ret;
	}

	if (tb[OCI_HOOKS_CREATERUNTIME]) {
		ret = parseOCIhook(&opts.hooks.createRuntime, tb[OCI_HOOKS_CREATERUNTIME]);
		if (ret)
			goto out_prestart;
	}

	if (tb[OCI_HOOKS_CREATECONTAINER]) {
		ret = parseOCIhook(&opts.hooks.createContainer, tb[OCI_HOOKS_CREATECONTAINER]);
		if (ret)
			goto out_createruntime;
	}

	if (tb[OCI_HOOKS_STARTCONTAINER]) {
		ret = parseOCIhook(&opts.hooks.startContainer, tb[OCI_HOOKS_STARTCONTAINER]);
		if (ret)
			goto out_createcontainer;
	}

	if (tb[OCI_HOOKS_POSTSTART]) {
		ret = parseOCIhook(&opts.hooks.poststart, tb[OCI_HOOKS_POSTSTART]);
		if (ret)
			goto out_startcontainer;
	}

	if (tb[OCI_HOOKS_POSTSTOP]) {
		ret = parseOCIhook(&opts.hooks.poststop, tb[OCI_HOOKS_POSTSTOP]);
		if (ret)
			goto out_poststart;
	}

	return 0;

out_poststart:
	free_hooklist(opts.hooks.poststart);
out_startcontainer:
	free_hooklist(opts.hooks.startContainer);
out_createcontainer:
	free_hooklist(opts.hooks.createContainer);
out_createruntime:
	free_hooklist(opts.hooks.createRuntime);
out_prestart:
	free_hooklist(opts.hooks.prestart);

	return ret;
};


enum {
	OCI_PROCESS_USER_UID,
	OCI_PROCESS_USER_GID,
	OCI_PROCESS_USER_UMASK,
	OCI_PROCESS_USER_ADDITIONALGIDS,
	__OCI_PROCESS_USER_MAX,
};

static const struct blobmsg_policy oci_process_user_policy[] = {
	[OCI_PROCESS_USER_UID] = { "uid", BLOBMSG_TYPE_INT32 },
	[OCI_PROCESS_USER_GID] = { "gid", BLOBMSG_TYPE_INT32 },
	[OCI_PROCESS_USER_UMASK] = { "umask", BLOBMSG_TYPE_INT32 },
	[OCI_PROCESS_USER_ADDITIONALGIDS] = { "additionalGids", BLOBMSG_TYPE_ARRAY },
};

static int parseOCIprocessuser(struct blob_attr *msg) {
	struct blob_attr *tb[__OCI_PROCESS_USER_MAX];
	struct blob_attr *cur;
	int rem;
	int has_gid = 0;

	blobmsg_parse(oci_process_user_policy, __OCI_PROCESS_USER_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_PROCESS_USER_UID])
		opts.pw_uid = blobmsg_get_u32(tb[OCI_PROCESS_USER_UID]);

	if (tb[OCI_PROCESS_USER_GID]) {
		opts.pw_gid = blobmsg_get_u32(tb[OCI_PROCESS_USER_GID]);
		opts.gr_gid = blobmsg_get_u32(tb[OCI_PROCESS_USER_GID]);
		has_gid = 1;
	}

	if (tb[OCI_PROCESS_USER_ADDITIONALGIDS]) {
		size_t gidcnt = 0;

		blobmsg_for_each_attr(cur, tb[OCI_PROCESS_USER_ADDITIONALGIDS], rem) {
			++gidcnt;
			if (has_gid && (blobmsg_get_u32(cur) == opts.gr_gid))
				continue;
		}

		if (gidcnt) {
			opts.additional_gids = calloc(gidcnt + has_gid, sizeof(gid_t));
			gidcnt = 0;

			/* always add primary GID to set of GIDs if set */
			if (has_gid)
				opts.additional_gids[gidcnt++] = opts.gr_gid;

			blobmsg_for_each_attr(cur, tb[OCI_PROCESS_USER_ADDITIONALGIDS], rem) {
				if (has_gid && (blobmsg_get_u32(cur) == opts.gr_gid))
					continue;
				opts.additional_gids[gidcnt++] = blobmsg_get_u32(cur);
			}
			opts.num_additional_gids = gidcnt;
		}
		DEBUG("read %zu additional groups\n", gidcnt);
	}

	if (tb[OCI_PROCESS_USER_UMASK]) {
		opts.umask = blobmsg_get_u32(tb[OCI_PROCESS_USER_UMASK]);
		opts.set_umask = true;
	}

	return 0;
}

enum {
	OCI_PROCESS_RLIMIT_TYPE,
	OCI_PROCESS_RLIMIT_SOFT,
	OCI_PROCESS_RLIMIT_HARD,
	__OCI_PROCESS_RLIMIT_MAX,
};

static const struct blobmsg_policy oci_process_rlimit_policy[] = {
	[OCI_PROCESS_RLIMIT_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS_RLIMIT_SOFT] = { "soft", BLOBMSG_CAST_INT64 },
	[OCI_PROCESS_RLIMIT_HARD] = { "hard", BLOBMSG_CAST_INT64 },
};

/* from manpage GETRLIMIT(2) */
static const char* const rlimit_names[RLIM_NLIMITS] = {
	[RLIMIT_AS] = "AS",
	[RLIMIT_CORE] = "CORE",
	[RLIMIT_CPU] = "CPU",
	[RLIMIT_DATA] = "DATA",
	[RLIMIT_FSIZE] = "FSIZE",
	[RLIMIT_LOCKS] = "LOCKS",
	[RLIMIT_MEMLOCK] = "MEMLOCK",
	[RLIMIT_MSGQUEUE] = "MSGQUEUE",
	[RLIMIT_NICE] = "NICE",
	[RLIMIT_NOFILE] = "NOFILE",
	[RLIMIT_NPROC] = "NPROC",
	[RLIMIT_RSS] = "RSS",
	[RLIMIT_RTPRIO] = "RTPRIO",
	[RLIMIT_RTTIME] = "RTTIME",
	[RLIMIT_SIGPENDING] = "SIGPENDING",
	[RLIMIT_STACK] = "STACK",
};

static int resolve_rlimit(char *type) {
	unsigned int rltype;

	for (rltype = 0; rltype < RLIM_NLIMITS; ++rltype)
		if (rlimit_names[rltype] &&
		    !strncmp("RLIMIT_", type, 7) &&
		    !strcmp(rlimit_names[rltype], type + 7))
			return rltype;

	return -1;
}


static int parseOCIrlimit(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_PROCESS_RLIMIT_MAX];
	int limtype = -1;
	struct rlimit *curlim;

	blobmsg_parse(oci_process_rlimit_policy, __OCI_PROCESS_RLIMIT_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_PROCESS_RLIMIT_TYPE] ||
	    !tb[OCI_PROCESS_RLIMIT_SOFT] ||
	    !tb[OCI_PROCESS_RLIMIT_HARD])
		return ENODATA;

	limtype = resolve_rlimit(blobmsg_get_string(tb[OCI_PROCESS_RLIMIT_TYPE]));

	if (limtype < 0)
		return EINVAL;

	if (opts.rlimits[limtype])
		return ENOTUNIQ;

	curlim = malloc(sizeof(struct rlimit));
	curlim->rlim_cur = blobmsg_cast_u64(tb[OCI_PROCESS_RLIMIT_SOFT]);
	curlim->rlim_max = blobmsg_cast_u64(tb[OCI_PROCESS_RLIMIT_HARD]);

	opts.rlimits[limtype] = curlim;

	return 0;
};

enum {
	OCI_PROCESS_APPARMORPROFILE,
	OCI_PROCESS_ARGS,
	OCI_PROCESS_CAPABILITIES,
	OCI_PROCESS_CWD,
	OCI_PROCESS_ENV,
	OCI_PROCESS_EXECCPUAFFINITY,
	OCI_PROCESS_IOPRIORITY,
	OCI_PROCESS_OOMSCOREADJ,
	OCI_PROCESS_NONEWPRIVILEGES,
	OCI_PROCESS_RLIMITS,
	OCI_PROCESS_SCHEDULER,
	OCI_PROCESS_SELINUXLABEL,
	OCI_PROCESS_TERMINAL,
	OCI_PROCESS_USER,
	__OCI_PROCESS_MAX,
};

static const struct blobmsg_policy oci_process_policy[] = {
	[OCI_PROCESS_APPARMORPROFILE] = { "apparmorProfile", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS_ARGS] = { "args", BLOBMSG_TYPE_ARRAY },
	[OCI_PROCESS_CAPABILITIES] = { "capabilities", BLOBMSG_TYPE_TABLE },
	[OCI_PROCESS_CWD] = { "cwd", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS_ENV] = { "env", BLOBMSG_TYPE_ARRAY },
	[OCI_PROCESS_EXECCPUAFFINITY] = { "execCPUAffinity", BLOBMSG_TYPE_TABLE },
	[OCI_PROCESS_IOPRIORITY] = { "ioPriority", BLOBMSG_TYPE_TABLE },
	[OCI_PROCESS_OOMSCOREADJ] = { "oomScoreAdj", BLOBMSG_TYPE_INT32 },
	[OCI_PROCESS_NONEWPRIVILEGES] = { "noNewPrivileges", BLOBMSG_TYPE_BOOL },
	[OCI_PROCESS_RLIMITS] = { "rlimits", BLOBMSG_TYPE_ARRAY },
	[OCI_PROCESS_SCHEDULER] = { "scheduler", BLOBMSG_TYPE_TABLE },
	[OCI_PROCESS_SELINUXLABEL] = { "selinuxLabel", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS_TERMINAL] = { "terminal", BLOBMSG_TYPE_BOOL },
	[OCI_PROCESS_USER] = { "user", BLOBMSG_TYPE_TABLE },
};


static int parseOCIprocess(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_PROCESS_MAX], *cur;
	int rem, res;

	blobmsg_parse(oci_process_policy, __OCI_PROCESS_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_PROCESS_APPARMORPROFILE]) {
		ERROR("process.apparmorProfile is not supported\n");
		return ENOTSUP;
	}

	if (tb[OCI_PROCESS_SELINUXLABEL]) {
		ERROR("process.selinuxLabel is not supported\n");
		return ENOTSUP;
	}

	if (!tb[OCI_PROCESS_ARGS])
		return ENOENT;

	res = parseOCIenvarray(tb[OCI_PROCESS_ARGS], &opts.jail_argv);
	if (res)
		return res;

	if (tb[OCI_PROCESS_TERMINAL])
		opts.console = blobmsg_get_bool(tb[OCI_PROCESS_TERMINAL]);

	if (tb[OCI_PROCESS_SCHEDULER]) {
		res = parseOCIprocessscheduler(tb[OCI_PROCESS_SCHEDULER]);
		if (res)
			return res;
	}

	if (tb[OCI_PROCESS_IOPRIORITY]) {
		res = parseOCIprocessiopriority(tb[OCI_PROCESS_IOPRIORITY]);
		if (res)
			return res;
	}

	if (tb[OCI_PROCESS_NONEWPRIVILEGES])
		opts.no_new_privs = blobmsg_get_bool(tb[OCI_PROCESS_NONEWPRIVILEGES]);

	if (tb[OCI_PROCESS_CWD])
		opts.cwd = strdup(blobmsg_get_string(tb[OCI_PROCESS_CWD]));

	if (tb[OCI_PROCESS_ENV]) {
		res = parseOCIenvarray(tb[OCI_PROCESS_ENV], &opts.envp);
		if (res)
			return res;
	}

	if (tb[OCI_PROCESS_USER] && (res = parseOCIprocessuser(tb[OCI_PROCESS_USER])))
		return res;

	if (tb[OCI_PROCESS_CAPABILITIES] &&
	    (res = parseOCIcapabilities(&opts.capset, tb[OCI_PROCESS_CAPABILITIES])))
		return res;

	if (tb[OCI_PROCESS_RLIMITS]) {
		blobmsg_for_each_attr(cur, tb[OCI_PROCESS_RLIMITS], rem) {
			res = parseOCIrlimit(cur);
			if (res)
				return res;
		}
	}

	if (tb[OCI_PROCESS_OOMSCOREADJ]) {
		opts.oom_score_adj = blobmsg_get_u32(tb[OCI_PROCESS_OOMSCOREADJ]);
		opts.set_oom_score_adj = true;
	}

	return 0;
}

enum {
	OCI_LINUX_NAMESPACE_TYPE,
	OCI_LINUX_NAMESPACE_PATH,
	__OCI_LINUX_NAMESPACE_MAX,
};

static const struct blobmsg_policy oci_linux_namespace_policy[] = {
	[OCI_LINUX_NAMESPACE_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[OCI_LINUX_NAMESPACE_PATH] = { "path", BLOBMSG_TYPE_STRING },
};

static int resolve_nstype(char *type) {
	if (!strcmp("pid", type))
		return CLONE_NEWPID;
	else if (!strcmp("network", type))
		return CLONE_NEWNET;
	else if (!strcmp("net", type))
		return CLONE_NEWNET;
	else if (!strcmp("mount", type))
		return CLONE_NEWNS;
	else if (!strcmp("ipc", type))
		return CLONE_NEWIPC;
	else if (!strcmp("uts", type))
		return CLONE_NEWUTS;
	else if (!strcmp("user", type))
		return CLONE_NEWUSER;
	else if (!strcmp("cgroup", type))
		return CLONE_NEWCGROUP;
	else if (!strcmp("time", type))
		return CLONE_NEWTIME;
	else
		return 0;
}

static int parseOCIlinuxns(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_NAMESPACE_MAX];
	int nstype;
	int *setns;
	int fd;

	blobmsg_parse(oci_linux_namespace_policy, __OCI_LINUX_NAMESPACE_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_LINUX_NAMESPACE_TYPE])
		return EINVAL;

	nstype = resolve_nstype(blobmsg_get_string(tb[OCI_LINUX_NAMESPACE_TYPE]));
	if (!nstype)
		return EINVAL;

	if (opts.namespace & nstype)
		return ENOTUNIQ;

	setns = get_namespace_fd(nstype);

	if (!setns)
		return EFAULT;

	if (*setns != -1)
		return ENOTUNIQ;

	if (tb[OCI_LINUX_NAMESPACE_PATH]) {
		DEBUG("opening existing %s namespace from path %s\n",
			blobmsg_get_string(tb[OCI_LINUX_NAMESPACE_TYPE]),
			blobmsg_get_string(tb[OCI_LINUX_NAMESPACE_PATH]));

		fd = open(blobmsg_get_string(tb[OCI_LINUX_NAMESPACE_PATH]), O_RDONLY);
		if (fd < 0)
			return errno?:ESTALE;

		if (ioctl(fd, NS_GET_NSTYPE) != nstype) {
			close(fd);
			return EINVAL;
		}

		DEBUG("opened existing %s namespace got filehandler %u\n",
			blobmsg_get_string(tb[OCI_LINUX_NAMESPACE_TYPE]),
			fd);

		*setns = fd;
	} else {
		opts.namespace |= nstype;
	}

	return 0;
}

/*
 * join namespace of existing PID
 * The string argument is the reference PID followed by ':' and a
 * ',' separated list of namespaces to to join.
 */
static int jail_join_ns(char *arg)
{
	pid_t pid;
	int fd;
	int nstype;
	char *tmp, *etmp, *nspath;
	int *setns;

	tmp = strchr(arg, ':');
	if (!tmp)
		return EINVAL;

	*tmp = '\0';
	pid = atoi(arg);

	do {
		++tmp;
		etmp = strchr(tmp, ',');
		if (etmp)
			*etmp = '\0';

		nstype = resolve_nstype(tmp);
		if (!nstype)
			return EINVAL;

		if (opts.namespace & nstype)
			return ENOTUNIQ;

		setns = get_namespace_fd(nstype);

		if (!setns)
			return EFAULT;

		if (*setns != -1)
			return ENOTUNIQ;

		if (asprintf(&nspath, "/proc/%d/ns/%s", pid, tmp) < 0)
			return ENOMEM;

		fd = open(nspath, O_RDONLY);
		free(nspath);

		if (fd < 0)
			return errno?:ESTALE;

		*setns = fd;

		if (etmp)
			tmp = etmp;
		else
			tmp = NULL;
	} while (tmp);

	return 0;
}

static void get_jail_root_user(bool is_gidmap, uint32_t container_id, uint32_t host_id, uint32_t size)
{
	if (container_id == 0 && size >= 1)
		if (!is_gidmap)
			opts.root_map_uid = host_id;
}

enum {
	OCI_LINUX_UIDGIDMAP_CONTAINERID,
	OCI_LINUX_UIDGIDMAP_HOSTID,
	OCI_LINUX_UIDGIDMAP_SIZE,
	__OCI_LINUX_UIDGIDMAP_MAX,
};

static const struct blobmsg_policy oci_linux_uidgidmap_policy[] = {
	[OCI_LINUX_UIDGIDMAP_CONTAINERID] = { "containerID", BLOBMSG_TYPE_INT32 },
	[OCI_LINUX_UIDGIDMAP_HOSTID] = { "hostID", BLOBMSG_TYPE_INT32 },
	[OCI_LINUX_UIDGIDMAP_SIZE] = { "size", BLOBMSG_TYPE_INT32 },
};

static int parseOCIuidgidmappings(struct blob_attr *msg, bool is_gidmap)
{
	struct blob_attr *tb[__OCI_LINUX_UIDGIDMAP_MAX];
	struct blob_attr *cur;
	int rem;
	char *map;
	size_t len, pos, totallen = 0;

	blobmsg_for_each_attr(cur, msg, rem) {
		blobmsg_parse(oci_linux_uidgidmap_policy, __OCI_LINUX_UIDGIDMAP_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[OCI_LINUX_UIDGIDMAP_CONTAINERID] ||
		    !tb[OCI_LINUX_UIDGIDMAP_HOSTID] ||
		    !tb[OCI_LINUX_UIDGIDMAP_SIZE])
			return EINVAL;

		/* count length */
		totallen += snprintf(NULL, 0, "%d %d %d\n",
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_CONTAINERID]),
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_HOSTID]),
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_SIZE]));
	}

	/* allocate combined mapping string */
	map = malloc(totallen + 1);
	if (!map)
		return ENOMEM;

	pos = 0;
	blobmsg_for_each_attr(cur, msg, rem) {
		blobmsg_parse(oci_linux_uidgidmap_policy, __OCI_LINUX_UIDGIDMAP_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));

		get_jail_root_user(is_gidmap, blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_CONTAINERID]),
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_HOSTID]),
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_SIZE]));

		/* write mapping line into pre-allocated string */
		len = snprintf(&map[pos], totallen + 1, "%d %d %d\n",
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_CONTAINERID]),
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_HOSTID]),
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_SIZE]));
		pos += len;
		totallen -= len;
	}

	assert(totallen == 0);

	if (is_gidmap)
		opts.gidmap = map;
	else
		opts.uidmap = map;

	return 0;
}

enum {
	OCI_DEVICES_TYPE,
	OCI_DEVICES_PATH,
	OCI_DEVICES_MAJOR,
	OCI_DEVICES_MINOR,
	OCI_DEVICES_FILEMODE,
	OCI_DEVICES_UID,
	OCI_DEVICES_GID,
	__OCI_DEVICES_MAX,
};

static const struct blobmsg_policy oci_devices_policy[] = {
	[OCI_DEVICES_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[OCI_DEVICES_PATH] = { "path", BLOBMSG_TYPE_STRING },
	[OCI_DEVICES_MAJOR] = { "major", BLOBMSG_TYPE_INT32 },
	[OCI_DEVICES_MINOR] = { "minor", BLOBMSG_TYPE_INT32 },
	[OCI_DEVICES_FILEMODE] = { "fileMode", BLOBMSG_TYPE_INT32 },
	[OCI_DEVICES_UID] = { "uid", BLOBMSG_TYPE_INT32 },
	[OCI_DEVICES_GID] = { "gid", BLOBMSG_TYPE_INT32 },
};

static mode_t resolve_devtype(char *tstr)
{
	if (!strcmp("c", tstr) ||
	    !strcmp("u", tstr))
		return S_IFCHR;
	else if (!strcmp("b", tstr))
		return S_IFBLK;
	else if (!strcmp("p", tstr))
		return S_IFIFO;
	else
		return 0;
}

static int parseOCIdevices(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_DEVICES_MAX];
	struct blob_attr *cur;
	int rem;
	size_t cnt = 0;
	struct mknod_args *tmp;

	blobmsg_for_each_attr(cur, msg, rem)
		++cnt;

	opts.devices = calloc(cnt + 1, sizeof(struct mknod_args *));

	cnt = 0;
	blobmsg_for_each_attr(cur, msg, rem) {
		blobmsg_parse(oci_devices_policy, __OCI_DEVICES_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[OCI_DEVICES_TYPE] ||
		    !tb[OCI_DEVICES_PATH])
			return ENODATA;

		tmp = calloc(1, sizeof(struct mknod_args));
		if (!tmp)
			return ENOMEM;

		tmp->mode = resolve_devtype(blobmsg_get_string(tb[OCI_DEVICES_TYPE]));
		if (!tmp->mode) {
			free(tmp);
			return EINVAL;
		}

		if (tmp->mode != S_IFIFO) {
			if (!tb[OCI_DEVICES_MAJOR] || !tb[OCI_DEVICES_MINOR]) {
				free(tmp);
				return ENODATA;
			}

			tmp->dev = makedev(blobmsg_get_u32(tb[OCI_DEVICES_MAJOR]),
					   blobmsg_get_u32(tb[OCI_DEVICES_MINOR]));
		}

		if (tb[OCI_DEVICES_FILEMODE]) {
			if (~(S_IRWXU|S_IRWXG|S_IRWXO) & blobmsg_get_u32(tb[OCI_DEVICES_FILEMODE])) {
				free(tmp);
				return EINVAL;
			}

			tmp->mode |= blobmsg_get_u32(tb[OCI_DEVICES_FILEMODE]);
		} else {
			tmp->mode |= (S_IRUSR|S_IWUSR); /* 0600 */
		}

		tmp->path = strdup(blobmsg_get_string(tb[OCI_DEVICES_PATH]));

		if (tb[OCI_DEVICES_UID])
			tmp->uid = blobmsg_get_u32(tb[OCI_DEVICES_UID]);
		else
			tmp->uid = -1;

		if (tb[OCI_DEVICES_GID])
			tmp->gid = blobmsg_get_u32(tb[OCI_DEVICES_GID]);
		else
			tmp->gid = -1;

		DEBUG("read device %s (%s)\n", blobmsg_get_string(tb[OCI_DEVICES_PATH]), blobmsg_get_string(tb[OCI_DEVICES_TYPE]));
		opts.devices[cnt++] = tmp;
	}

	opts.devices[cnt] = NULL;

	return 0;
}

static int parseOCIsysctl(struct blob_attr *msg)
{
	struct blob_attr *cur;
	int rem;
	char *tmp, *tc;
	size_t cnt = 0;

	blobmsg_for_each_attr(cur, msg, rem) {
		if (!blobmsg_name(cur) || !blobmsg_get_string(cur))
			return EINVAL;

		++cnt;
	}

	if (!cnt)
		return 0;

	opts.sysctl = calloc(cnt + 1, sizeof(struct sysctl_val *));
	if (!opts.sysctl)
		return ENOMEM;

	cnt = 0;
	blobmsg_for_each_attr(cur, msg, rem) {
		opts.sysctl[cnt] = malloc(sizeof(struct sysctl_val));
		if (!opts.sysctl[cnt])
			return ENOMEM;

		/* replace '.' with '/' in entry name */
		tc = tmp = strdup(blobmsg_name(cur));
		while ((tc = strchr(tc, '.')))
			*tc = '/';

		opts.sysctl[cnt]->value = strdup(blobmsg_get_string(cur));
		opts.sysctl[cnt]->entry = tmp;

		++cnt;
	}

	opts.sysctl[cnt] = NULL;

	return 0;
}


enum {
	OCI_LINUX_CGROUPSPATH,
	OCI_LINUX_RESOURCES,
	OCI_LINUX_SECCOMP,
	OCI_LINUX_SYSCTL,
	OCI_LINUX_NAMESPACES,
	OCI_LINUX_DEVICES,
	OCI_LINUX_UIDMAPPINGS,
	OCI_LINUX_GIDMAPPINGS,
	OCI_LINUX_MASKEDPATHS,
	OCI_LINUX_READONLYPATHS,
	OCI_LINUX_ROOTFSPROPAGATION,
	OCI_LINUX_PERSONALITY,
	OCI_LINUX_TIMEOFFSETS,
	OCI_LINUX_NETDEVICES,
	OCI_LINUX_MEMORYPOLICY,
	OCI_LINUX_MOUNTLABEL,
	__OCI_LINUX_MAX,
};

static const struct blobmsg_policy oci_linux_policy[] = {
	[OCI_LINUX_CGROUPSPATH] = { "cgroupsPath", BLOBMSG_TYPE_STRING },
	[OCI_LINUX_RESOURCES] = { "resources", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_SECCOMP] = { "seccomp", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_SYSCTL] = { "sysctl", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_NAMESPACES] = { "namespaces", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_DEVICES] = { "devices", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_UIDMAPPINGS] = { "uidMappings", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_GIDMAPPINGS] = { "gidMappings", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_MASKEDPATHS] = { "maskedPaths", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_READONLYPATHS] = { "readonlyPaths", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_ROOTFSPROPAGATION] = { "rootfsPropagation", BLOBMSG_TYPE_STRING },
	[OCI_LINUX_PERSONALITY] = { "personality", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_TIMEOFFSETS] = { "timeOffsets", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_NETDEVICES] = { "netDevices", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_MEMORYPOLICY] = { "memoryPolicy", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_MOUNTLABEL] = { "mountLabel", BLOBMSG_TYPE_STRING },
};

static int append_deferred_path(char ***list, const char *path)
{
	size_t n = 0;
	char **newlist;

	if (*list)
		while ((*list)[n])
			n++;

	newlist = realloc(*list, (n + 2) * sizeof(char *));
	if (!newlist)
		return ENOMEM;

	newlist[n] = strdup(path);
	if (!newlist[n]) {
		*list = newlist;
		return ENOMEM;
	}
	newlist[n + 1] = NULL;
	*list = newlist;

	return 0;
}

enum {
	OCI_LINUX_PERSONALITY_DOMAIN,
	OCI_LINUX_PERSONALITY_FLAGS,
	__OCI_LINUX_PERSONALITY_MAX,
};

static const struct blobmsg_policy oci_linux_personality_policy[] = {
	[OCI_LINUX_PERSONALITY_DOMAIN] = { "domain", BLOBMSG_TYPE_STRING },
	[OCI_LINUX_PERSONALITY_FLAGS] = { "flags", BLOBMSG_TYPE_ARRAY },
};

static int parseOCIlinuxpersonality(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_PERSONALITY_MAX];
	const char *domain;
	unsigned long requested, current;

	blobmsg_parse(oci_linux_personality_policy, __OCI_LINUX_PERSONALITY_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_LINUX_PERSONALITY_FLAGS] &&
	    blobmsg_len(tb[OCI_LINUX_PERSONALITY_FLAGS])) {
		ERROR("linux.personality.flags is not supported\n");
		return ENOTSUP;
	}

	if (!tb[OCI_LINUX_PERSONALITY_DOMAIN])
		return ENODATA;

	domain = blobmsg_get_string(tb[OCI_LINUX_PERSONALITY_DOMAIN]);
	if (!strcmp(domain, "LINUX"))
		requested = PER_LINUX;
	else if (!strcmp(domain, "LINUX32"))
		requested = PER_LINUX32;
	else
		return EINVAL;

	current = personality(0xFFFFFFFF) & PER_MASK;
	if (requested != current) {
		ERROR("linux.personality '%s' differs from current; cross-personality execution is not supported\n",
		      domain);
		return ENOTSUP;
	}

	return 0;
}

static int parseOCIlinux(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_MAX];
	struct blob_attr *cur;
	int rem;
	int res = 0;
	char *cgpath;
	char cgfullpath[256] = "/sys/fs/cgroup";

	blobmsg_parse(oci_linux_policy, __OCI_LINUX_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_LINUX_PERSONALITY]) {
		res = parseOCIlinuxpersonality(tb[OCI_LINUX_PERSONALITY]);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_TIMEOFFSETS]) {
		res = parseOCIlinuxtimeoffsets(tb[OCI_LINUX_TIMEOFFSETS]);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_NETDEVICES])
		opts.netdevices = blob_memdup(tb[OCI_LINUX_NETDEVICES]);

	if (tb[OCI_LINUX_MEMORYPOLICY]) {
		ERROR("linux.memoryPolicy is not supported on OpenWrt\n");
		return ENOTSUP;
	}

	if (tb[OCI_LINUX_MOUNTLABEL]) {
		ERROR("linux.mountLabel is not supported\n");
		return ENOTSUP;
	}

	if (tb[OCI_LINUX_NAMESPACES]) {
		blobmsg_for_each_attr(cur, tb[OCI_LINUX_NAMESPACES], rem) {
			res = parseOCIlinuxns(cur);
			if (res)
				return res;
		}
	}

	if (tb[OCI_LINUX_UIDMAPPINGS]) {
		res = parseOCIuidgidmappings(tb[OCI_LINUX_UIDMAPPINGS], 0);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_GIDMAPPINGS]) {
		res = parseOCIuidgidmappings(tb[OCI_LINUX_GIDMAPPINGS], 1);
		if (res)
			return res;
	}

	{
		bool defer_userns = (opts.namespace & CLONE_NEWUSER) && opts.setns.user == -1;

		if (tb[OCI_LINUX_READONLYPATHS]) {
			blobmsg_for_each_attr(cur, tb[OCI_LINUX_READONLYPATHS], rem) {
				if (defer_userns) {
					res = append_deferred_path(&opts.oci_deferred_readonly, blobmsg_get_string(cur));
					if (res)
						return res;
					continue;
				}
				res = add_mount(NULL, blobmsg_get_string(cur), NULL, MS_BIND | MS_REC | MS_RDONLY, 0, NULL, 0);
				if (res)
					return res;
			}
		}

		if (tb[OCI_LINUX_MASKEDPATHS]) {
			blobmsg_for_each_attr(cur, tb[OCI_LINUX_MASKEDPATHS], rem) {
				if (defer_userns) {
					res = append_deferred_path(&opts.oci_deferred_masked, blobmsg_get_string(cur));
					if (res)
						return res;
					continue;
				}
				res = add_mount((void *)(-1), blobmsg_get_string(cur), NULL, 0, 0, NULL, 0);
				if (res)
					return res;
			}
		}
	}

	if (tb[OCI_LINUX_SYSCTL]) {
		res = parseOCIsysctl(tb[OCI_LINUX_SYSCTL]);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_SECCOMP]) {
		opts.ociseccomp = parseOCIlinuxseccomp(tb[OCI_LINUX_SECCOMP]);
		if (!opts.ociseccomp)
			return EINVAL;
	}

	if (tb[OCI_LINUX_DEVICES]) {
		res = parseOCIdevices(tb[OCI_LINUX_DEVICES]);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_CGROUPSPATH]) {
		cgpath = blobmsg_get_string(tb[OCI_LINUX_CGROUPSPATH]);
		if (cgpath[0] == '/') {
			if (strlen(cgpath) + 1 >= (sizeof(cgfullpath) - strlen(cgfullpath)))
				return E2BIG;

			strcat(cgfullpath, cgpath);
		} else {
			strcat(cgfullpath, "/containers/");
			if (strlen(opts.name) + strlen(cgpath) + 2 >= (sizeof(cgfullpath) - strlen(cgfullpath)))
				return E2BIG;

			strcat(cgfullpath, opts.name); /* should be container name rather than jail name */
			strcat(cgfullpath, "/");
			strcat(cgfullpath, cgpath);
		}
	} else {
		strcat(cgfullpath, "/containers/");
		if (2 * strlen(opts.name) + 2 >= (sizeof(cgfullpath) - strlen(cgfullpath)))
			return E2BIG;

		strcat(cgfullpath, opts.name); /* should be container name rather than jail name */
		strcat(cgfullpath, "/");
		strcat(cgfullpath, opts.name); /* should be container instance name rather than jail name */
	}

	cgroups_init(cgfullpath);

	if (tb[OCI_LINUX_RESOURCES]) {
		res = parseOCIlinuxcgroups(tb[OCI_LINUX_RESOURCES]);
		if (res)
			return res;
	}

	return 0;
}

enum {
	OCI_VERSION,
	OCI_HOSTNAME,
	OCI_DOMAINNAME,
	OCI_PROCESS,
	OCI_ROOT,
	OCI_MOUNTS,
	OCI_HOOKS,
	OCI_LINUX,
	OCI_ANNOTATIONS,
	__OCI_MAX,
};

static const struct blobmsg_policy oci_policy[] = {
	[OCI_VERSION] = { "ociVersion", BLOBMSG_TYPE_STRING },
	[OCI_HOSTNAME] = { "hostname", BLOBMSG_TYPE_STRING },
	[OCI_DOMAINNAME] = { "domainname", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS] = { "process", BLOBMSG_TYPE_TABLE },
	[OCI_ROOT] = { "root", BLOBMSG_TYPE_TABLE },
	[OCI_MOUNTS] = { "mounts", BLOBMSG_TYPE_ARRAY },
	[OCI_HOOKS] = { "hooks", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX] = { "linux", BLOBMSG_TYPE_TABLE },
	[OCI_ANNOTATIONS] = { "annotations", BLOBMSG_TYPE_TABLE },
};

static int parseOCI(const char *jsonfile)
{
	struct blob_attr *tb[__OCI_MAX];
	struct blob_attr *cur;
	int rem;
	int res;

	blob_buf_init(&ocibuf, 0);

	if (!blobmsg_add_json_from_file(&ocibuf, jsonfile)) {
		res=ENOENT;
		goto errout;
	}

	blobmsg_parse(oci_policy, __OCI_MAX, tb, blob_data(ocibuf.head), blob_len(ocibuf.head));

	if (!tb[OCI_VERSION]) {
		res=ENOMSG;
		goto errout;
	}

	if (strncmp("1.0", blobmsg_get_string(tb[OCI_VERSION]), 3)) {
		ERROR("unsupported ociVersion %s\n", blobmsg_get_string(tb[OCI_VERSION]));
		res=ENOTSUP;
		goto errout;
	}

	if (tb[OCI_HOSTNAME])
		opts.hostname = strdup(blobmsg_get_string(tb[OCI_HOSTNAME]));

	if (tb[OCI_DOMAINNAME])
		opts.domainname = strdup(blobmsg_get_string(tb[OCI_DOMAINNAME]));

	if (!tb[OCI_PROCESS]) {
		res=ENODATA;
		goto errout;
	}

	if ((res = parseOCIprocess(tb[OCI_PROCESS])))
		goto errout;

	if (!tb[OCI_ROOT]) {
		res=ENODATA;
		goto errout;
	}
	if ((res = parseOCIroot(jsonfile, tb[OCI_ROOT])))
		goto errout;

	if (!tb[OCI_MOUNTS]) {
		res=ENODATA;
		goto errout;
	}

	blobmsg_for_each_attr(cur, tb[OCI_MOUNTS], rem)
		if ((res = parseOCImount(cur)))
			goto errout;

	if (tb[OCI_LINUX] && (res = parseOCIlinux(tb[OCI_LINUX])))
		goto errout;

	if (tb[OCI_HOOKS] && (res = parseOCIhooks(tb[OCI_HOOKS])))
		goto errout;

	if (tb[OCI_ANNOTATIONS])
		opts.annotations = blob_memdup(tb[OCI_ANNOTATIONS]);

errout:
	blob_buf_free(&ocibuf);

	return res;
}

static int set_oom_score_adj(void)
{
	int f;
	char fname[32];

	if (!opts.set_oom_score_adj)
		return 0;

	snprintf(fname, sizeof(fname), "/proc/%u/oom_score_adj", jail_process.pid);
	f = open(fname, O_WRONLY | O_TRUNC);
	if (f < 0)
		return errno;

	dprintf(f, "%d", opts.oom_score_adj);
	close(f);

	return 0;
}


enum {
	OCI_STATE_CREATING,
	OCI_STATE_CREATED,
	OCI_STATE_RUNNING,
	OCI_STATE_STOPPED,
};

static int jail_oci_state = OCI_STATE_CREATED;
static void pipe_send_start_container(struct uloop_timeout *t);
static struct uloop_timeout start_container_timeout = {
	.cb = pipe_send_start_container,
};

static int handle_start(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	if (jail_oci_state != OCI_STATE_CREATED)
		return UBUS_STATUS_INVALID_ARGUMENT;

	uloop_timeout_add(&start_container_timeout);

	return UBUS_STATUS_OK;
}

static struct blob_buf bb;
static int handle_state(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	char *statusstr;

	switch (jail_oci_state) {
		case OCI_STATE_CREATING:
			statusstr = "creating";
			break;
		case OCI_STATE_CREATED:
			statusstr = "created";
			break;
		case OCI_STATE_RUNNING:
			statusstr = "running";
			break;
		case OCI_STATE_STOPPED:
			statusstr = "stopped";
			break;
		default:
			statusstr = "unknown";
	}

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "ociVersion", OCI_VERSION_STRING);
	blobmsg_add_string(&bb, "id", opts.name);
	blobmsg_add_string(&bb, "status", statusstr);
	if (jail_oci_state == OCI_STATE_CREATED ||
	    jail_oci_state == OCI_STATE_RUNNING)
		blobmsg_add_u32(&bb, "pid", jail_process.pid);

	blobmsg_add_string(&bb, "bundle", opts.ocibundle);

	if (opts.annotations)
		blobmsg_add_blob(&bb, opts.annotations);

	ubus_send_reply(ctx, req, bb.head);

	return UBUS_STATUS_OK;
}

enum {
	CONTAINER_KILL_ATTR_SIGNAL,
	__CONTAINER_KILL_ATTR_MAX,
};

static const struct blobmsg_policy container_kill_attrs[__CONTAINER_KILL_ATTR_MAX] = {
	[CONTAINER_KILL_ATTR_SIGNAL] = { "signal", BLOBMSG_TYPE_INT32 },
};

static int
container_handle_kill(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__CONTAINER_KILL_ATTR_MAX], *cur;
	int sig = SIGTERM;

	blobmsg_parse(container_kill_attrs, __CONTAINER_KILL_ATTR_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	cur = tb[CONTAINER_KILL_ATTR_SIGNAL];
	if (cur)
		sig = blobmsg_get_u32(cur);

	if (jail_oci_state == OCI_STATE_CREATING)
		return UBUS_STATUS_NOT_FOUND;

	if (kill(jail_process.pid, sig) == 0)
		return 0;

	switch (errno) {
	case EINVAL: return UBUS_STATUS_INVALID_ARGUMENT;
	case EPERM:  return UBUS_STATUS_PERMISSION_DENIED;
	case ESRCH:  return UBUS_STATUS_NOT_FOUND;
	}

	return UBUS_STATUS_UNKNOWN_ERROR;
}

static int
jail_writepid(pid_t pid)
{
	FILE *_pidfile;

	if (!opts.pidfile)
		return 0;

	_pidfile = fopen(opts.pidfile, "w");
	if (_pidfile == NULL)
		return errno;

	if (fprintf(_pidfile, "%d\n", pid) < 0) {
		fclose(_pidfile);
		return errno;
	}

	if (fclose(_pidfile))
		return errno;

	return 0;
}

static int checkpath(const char *path)
{
	int dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0) {
		ERROR("path %s open failed %m\n", path);
		return -1;
	}
	close(dirfd);

	return 0;
}

static struct ubus_method container_methods[] = {
	UBUS_METHOD_NOARG("start", handle_start),
	UBUS_METHOD_NOARG("state", handle_state),
	UBUS_METHOD("kill", container_handle_kill, container_kill_attrs),
};

static struct ubus_object_type container_object_type =
	UBUS_OBJECT_TYPE("container", container_methods);

static struct ubus_object container_object = {
	.type = &container_object_type,
	.methods = container_methods,
	.n_methods = ARRAY_SIZE(container_methods),
};

static void post_main(struct uloop_timeout *t);
static struct uloop_timeout post_main_timeout = {
	.cb = post_main,
};
static int netns_fd;
static int pidns_fd;
static int timens_fd;
static void post_create_runtime(void);

struct env_e {
	struct list_head list;
	char *envarg;
};

int main(int argc, char **argv)
{
	uid_t uid = getuid();
	const char log[] = "/dev/log";
	const char ubus[] = "/var/run/ubus/ubus.sock";
	const char udebug[] = "/var/run/udebug.sock";
	int ret = EXIT_FAILURE;
	int ch;
	char *tmp;
	struct list_head envl = LIST_HEAD_INIT(envl);
	struct env_e *enve, *tmpenve;
	unsigned short int envn = 0, envc = 0;

	if (uid) {
		ERROR("not root, aborting: %m\n");
		return EXIT_FAILURE;
	}

	/* those are filehandlers, so -1 indicates unused */
	opts.setns.pid = -1;
	opts.setns.net = -1;
	opts.setns.ns = -1;
	opts.setns.ipc = -1;
	opts.setns.uts = -1;
	opts.setns.user = -1;
	opts.setns.cgroup = -1;
	opts.setns.time = -1;

	/* default 5 seconds timeout after SIGTERM before SIGKILL is sent */
	opts.term_timeout = 5;

	umask(022);
	mount_list_init();
	init_library_search();
	cgroups_prepare();
	exit_from_child = false;

	while ((ch = getopt(argc, argv, OPT_ARGS)) != -1) {
		switch (ch) {
		case 'd':
			debug = atoi(optarg);
			break;
		case 'e':
			enve = calloc(1, sizeof(*enve));
			enve->envarg = optarg;
			list_add_tail(&enve->list, &envl);
			break;
		case 'p':
			opts.namespace |= CLONE_NEWNS;
			opts.procfs = 1;
			break;
		case 'o':
			opts.namespace |= CLONE_NEWNS;
			opts.ronly = 1;
			break;
		case 'f':
			opts.namespace |= CLONE_NEWUSER;
			break;
		case 'F':
			opts.namespace |= CLONE_NEWCGROUP;
			break;
		case 'R':
			opts.extroot = realpath(optarg, NULL);
			break;
		case 's':
			opts.namespace |= CLONE_NEWNS;
			opts.sysfs = 1;
			break;
		case 'S':
			opts.seccomp = optarg;
			add_mount_bind(optarg, 1, -1);
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
			opts.namespace |= CLONE_NEWNET;
			break;
		case 'h':
			opts.namespace |= CLONE_NEWUTS;
			opts.hostname = strdup(optarg);
			break;
		case 'j':
			jail_join_ns(optarg);
			break;
		case 'r':
			opts.namespace |= CLONE_NEWNS;
			tmp = strchr(optarg, ':');
			if (tmp) {
				*(tmp++) = '\0';
				add_2paths_and_deps(optarg, tmp, 1, 0, 0);
			} else {
				add_path_and_deps(optarg, 1, 0, 0);
			}
			break;
		case 'w':
			opts.namespace |= CLONE_NEWNS;
			tmp = strchr(optarg, ':');
			if (tmp) {
				*(tmp++) = '\0';
				add_2paths_and_deps(optarg, tmp, 0, 0, 0);
			} else {
				add_path_and_deps(optarg, 0, 0, 0);
			}
			break;
		case 'u':
			opts.namespace |= CLONE_NEWNS;
			add_mount_bind(ubus, 0, -1);
			break;
		case 'D':
			opts.namespace |= CLONE_NEWNS;
			add_mount_bind(udebug, 0, 0);
			break;
		case 'l':
			opts.namespace |= CLONE_NEWNS;
			add_mount_bind(log, 0, -1);
			break;
		case 'U':
			opts.user = optarg;
			break;
		case 'G':
			opts.group = optarg;
			break;
		case 'O':
			opts.overlaydir = realpath(optarg, NULL);
			break;
		case 't':
			opts.term_timeout = atoi(optarg);
			break;
		case 'T':
			opts.tmpoverlaysize = optarg;
			break;
		case 'E':
			opts.require_jail = 1;
			break;
		case 'y':
			opts.console = 1;
			break;
		case 'J':
			opts.ocibundle = optarg;
			break;
		case 'i':
			opts.immediately = true;
			break;
		case 'P':
			opts.pidfile = optarg;
			break;
		}
	}

	if (opts.namespace && !opts.ocibundle)
		opts.namespace |= CLONE_NEWIPC | CLONE_NEWPID;

	/*
	 * env import from cmdline is not available for OCI containers
	 */
	if (opts.ocibundle && !list_empty(&envl)) {
		ret=-ENOTSUP;
		goto errout;
	}

	/*
	 * prepare list of env variables to import for slim containers
	 */
	if (!list_empty(&envl)) {
		list_for_each_entry(enve, &envl, list)
			++envn;

		opts.envp = calloc(1 + envn, sizeof(char*));
		list_for_each_entry_safe(enve, tmpenve, &envl, list) {
			tmp = getenv(enve->envarg);
			if (tmp) {
				ret = asprintf(&opts.envp[envc++], "%s=%s", enve->envarg, tmp);
				if (ret < 0) {
					ERROR("filed to handle envargs %s\n", tmp);
					free(enve);
					goto errout;
				}
			}

			list_del(&enve->list);
			free(enve);
		}

		opts.envp[envc] = NULL;
	}

	/*
	 * uid in parent user namespace representing root user in new
	 * user namespace, defaults to nobody unless specified in uidMappings
	 */
	opts.root_map_uid = 65534;

	if (opts.capabilities && parseOCIcapabilities_from_file(&opts.capset, opts.capabilities)) {
		ERROR("failed to read capabilities from file %s\n", opts.capabilities);
		ret=-1;
		goto errout;
	}

	if (opts.ocibundle) {
		char *jsonfile;
		int ocires;

		if (!opts.name) {
			ERROR("OCI bundle needs a named jail\n");
			ret=-1;
			goto errout;
		}
		if (asprintf(&jsonfile, "%s/config.json", opts.ocibundle) < 0) {
			ret=-ENOMEM;
			goto errout;
		}
		ocires = parseOCI(jsonfile);
		free(jsonfile);
		if (ocires) {
			ERROR("parsing of OCI JSON spec has failed: %s (%d)\n", strerror(ocires), ocires);
			ret=ocires;
			goto errout;
		}
	}

	if (opts.namespace & CLONE_NEWNET) {
		if (!opts.name) {
			ERROR("netns needs a named jail\n");
			ret=-1;
			goto errout;
		}
	}


	if (!opts.extroot && (opts.user || opts.group)) {
		int precheck_uid, precheck_gid, precheck_grgid;

		get_jail_user(&precheck_uid, &precheck_gid, &precheck_grgid);
	}

	if (opts.tmpoverlaysize && strlen(opts.tmpoverlaysize) > 8) {
		ERROR("size parameter too long: \"%s\"\n", opts.tmpoverlaysize);
		ret=-1;
		goto errout;
	}

	if (opts.extroot && checkpath(opts.extroot)) {
		ERROR("invalid rootfs path '%s'", opts.extroot);
		ret=-1;
		goto errout;
	}

	if (opts.overlaydir && checkpath(opts.overlaydir)) {
		ERROR("invalid rootfs overlay path '%s'", opts.overlaydir);
		ret=-1;
		goto errout;
	}

	/* no <binary> param found */
	if (!opts.ocibundle && (argc - optind < 1)) {
		usage();
		ret=EXIT_FAILURE;
		goto errout;
	}
	if (!(opts.ocibundle||opts.namespace||opts.capabilities||opts.seccomp||
		(opts.setns.net != -1) ||
		(opts.setns.ns != -1) ||
		(opts.setns.ipc != -1) ||
		(opts.setns.uts != -1) ||
		(opts.setns.user != -1) ||
		(opts.setns.cgroup != -1))) {
		ERROR("Not using namespaces, capabilities or seccomp !!!\n\n");
		usage();
		ret=EXIT_FAILURE;
		goto errout;
	}
	DEBUG("Using namespaces(0x%08x), capabilities(%d), seccomp(%d)\n",
		opts.namespace,
		opts.capset.apply,
		opts.seccomp != 0 || opts.ociseccomp != 0);

	uloop_init();
	signals_init();

	parent_ctx = ubus_connect(NULL);
	if (!parent_ctx) {
		ERROR("Connection to ubus failed\n");
		ret = -ECONNREFUSED;
		goto errout;
	}

	ubus_add_uloop(parent_ctx);

	if (opts.ocibundle) {
		char *objname;
		if (asprintf(&objname, "container.%s", opts.name) < 0) {
			ret=-ENOMEM;
			goto errout;
		}

		container_object.name = objname;
		ret = ubus_add_object(parent_ctx, &container_object);
		if (ret) {
			ERROR("Failed to add object: %s\n", ubus_strerror(ret));
			ret=-1;
			goto errout;
		}
	}

	/* deliberately not using 'else' on unrelated conditional branches */
	if (!opts.ocibundle) {
		/* allocate NULL-terminated array for argv */
		opts.jail_argv = calloc(1 + argc - optind, sizeof(void *));
		if (!opts.jail_argv) {
			ret=EXIT_FAILURE;
			goto errout;
		}
		for (size_t s = optind; s < argc; s++)
			opts.jail_argv[s - optind] = strdup(argv[s]);

		if (opts.namespace & CLONE_NEWUSER) {
			get_jail_user(&opts.pw_uid, &opts.pw_gid, &opts.gr_gid);

			if (!opts.uidmap && opts.user) {
				int primary_gid = (opts.gr_gid != -1) ? opts.gr_gid : opts.pw_gid;

				if (!resolve_jail_user_gids(primary_gid))
					WARNING("could not resolve supplementary groups for "
						"user %s; jail will start with no supplementary "
						"groups\n", opts.user);
			}
		}
	}

	if (!opts.extroot) {
		if (opts.namespace && add_path_and_deps(*opts.jail_argv, 1, -1, 0)) {
			ERROR("failed to load dependencies\n");
			ret=-1;
			goto errout;
		}
	}

	if (opts.namespace && opts.seccomp && add_path_and_deps("libpreload-seccomp.so", 1, -1, 1)) {
		ERROR("failed to load libpreload-seccomp.so\n");
		opts.seccomp = 0;
		if (opts.require_jail) {
			ret=-1;
			goto errout;
		}
	}

	uloop_timeout_add(&post_main_timeout);
	uloop_run();

errout:
	if (opts.ocibundle)
		cgroups_free();

	free_opts(true);

	return ret;
}

static void post_prestart(void)
{
	if (hook_chain_failed) {
		ERROR("prestart hook failed; aborting container\n");
		free_and_exit(EXIT_FAILURE);
	}
	run_hooks(opts.hooks.createRuntime, post_create_runtime);
}

static void post_main(struct uloop_timeout *t)
{
	if (apply_rlimits()) {
		ERROR("error applying resource limits\n");
		free_and_exit(EXIT_FAILURE);
	}

	if (opts.name)
		prctl(PR_SET_NAME, opts.name, NULL, NULL, NULL);

	if (pipe(&pipes[0]) < 0 || pipe(&pipes[2]) < 0)
		free_and_exit(-1);

	if (pipe2(&userns_pipe[0], O_CLOEXEC) < 0 || pipe2(&userns_pipe[2], O_CLOEXEC) < 0)
		free_and_exit(-1);

	parent_pidfd = syscall(SYS_pidfd_open, getpid(), 0);

	if (has_namespaces()) {
		if (opts.namespace & CLONE_NEWNS) {
			if (!opts.extroot && (opts.user || opts.group)) {
				add_mount_bind("/etc/passwd", 1, -1);
				add_mount_bind("/etc/group", 1, -1);
			}

#if defined(__GLIBC__)
			if (!opts.extroot)
				add_mount_bind("/etc/nsswitch.conf", 1, -1);
#endif
			if (opts.setns.ns == -1) {
				if (!(opts.namespace & CLONE_NEWNET)) {
					add_mount_bind("/etc/resolv.conf", 1, 0);
				} else {
					/* new mount namespace to provide /dev/resolv.conf.d */
					char hostdir[PATH_MAX];

					snprintf(hostdir, PATH_MAX, "/tmp/resolv.conf-%s.d", opts.name);
					if (mkdir_p(hostdir, 0755)) {
						ERROR("mkdir(%s) failed: %m\n", hostdir);
						free_and_exit(-1);
					}
					add_mount(hostdir, "/dev/resolv.conf.d", NULL,
						MS_BIND | MS_NOEXEC | MS_NOATIME | MS_NOSUID | MS_NODEV | MS_RDONLY, 0, NULL, 0);
				}
			}
			/* default mounts */
			add_mount(NULL, "/dev", "tmpfs", MS_NOATIME | MS_NOEXEC | MS_NOSUID, 0, "size=1M", -1);
			add_mount("shm", "/dev/shm", "tmpfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, 0, "mode=1777", -1);
			{
				const char *ptsopts = (opts.namespace & CLONE_NEWUSER) ?
					"newinstance,ptmxmode=0666,mode=0620,gid=0" :
					"newinstance,ptmxmode=0666,mode=0620,gid=5";

				add_mount(NULL, "/dev/pts", "devpts", MS_NOATIME | MS_NOEXEC | MS_NOSUID, 0, ptsopts, 0);
			}

			bool defer_userns = (opts.namespace & CLONE_NEWUSER) && opts.setns.user == -1;

			if (defer_userns)
				add_mount(PROCD_NOAFILE, JAIL_NOAFILE, NULL,
					  MS_BIND | MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV, 0, NULL, -1);

			if (opts.procfs || opts.ocibundle) {
				add_mount("proc", "/proc", "proc",
					  detect_atime_flag("/proc") | MS_NODEV | MS_NOEXEC | MS_NOSUID, 0, NULL, -1);

				/*
				 * hack to make /proc/sys/net read-write while the rest of /proc/sys is read-only
				 * which cannot be expressed with OCI spec, but happends to be very useful.
				 * Only apply it if '/proc/sys' is not already listed as mount, maskedPath or
				 * readonlyPath.
				 * If not running in a new network namespace, only make /proc/sys read-only.
				 * If running in a new network namespace, temporarily stash (ie. mount-bind)
				 * /proc/sys/net into (totally unrelated, but surely existing) /proc/self/net.
				 * Then we mount-bind /proc/sys read-only and then mount-move /proc/self/net into
				 * /proc/sys/net.
				 * This works because mounts are executed in incrementing strcmp() order and
				 * /proc/self/net appears there before /proc/sys/net and hence the operation
				 * succeeds as the bind-mount of /proc/self/net is performed first and then
				 * move-mount of /proc/sys/net follows because 'e' preceeds 'y' in the ASCII
				 * table (and in the alphabet).
				 *
				 * A jail that defers its own CLONE_NEWUSER applies this (and all other
				 * default masking below) itself in phase 2, once it regains its own
				 * mount namespace: a mount locked here, while still privileged, can
				 * never be replaced by that same, now less-privileged phase, since a
				 * locked mount stays present underneath anything mounted over it and
				 * still counts against the kernel's mount-visibility check for any
				 * nested runtime's own /proc mount.
				 */
				if (!defer_userns &&
				    !add_mount(NULL, "/proc/sys", NULL, MS_BIND | MS_RDONLY, 0, NULL, -1))
					if (opts.namespace & CLONE_NEWNET)
						if (!add_mount_inner("/proc/self/net", "/proc/sys/net", NULL, MS_MOVE, 0, NULL, -1))
							add_mount_inner("/proc/sys/net", "/proc/self/net", NULL, MS_BIND, 0, NULL, -1);

			}
			if (opts.sysfs || opts.ocibundle)
				add_mount("sysfs", "/sys", "sysfs",
					  detect_atime_flag("/sys") | MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RDONLY, 0, NULL, -1);

			if (!opts.ocibundle && !defer_userns) {
				if (opts.procfs &&
				    (mask_default_paths(proc_mask_critical, true) ||
				     mask_default_paths(proc_mask_optional, false)))
					free_and_exit(-1);
				if (opts.sysfs && mask_default_paths(sys_mask_critical, true))
					free_and_exit(-1);
			}

		}

		if (opts.setns.pid != -1) {
			pidns_fd = ns_open_pid("pid", getpid());
			setns_open(CLONE_NEWPID);
		} else {
			pidns_fd = -1;
		}

		if ((opts.namespace & CLONE_NEWTIME) && opts.setns.time == -1 &&
		    access("/proc/self/ns/time", F_OK)) {
			ERROR("kernel lacks time namespace support\n");
			free_and_exit(EXIT_FAILURE);
		}

		if (opts.setns.time != -1) {
			timens_fd = ns_open_pid("time", getpid());
			setns_open(CLONE_NEWTIME);
		} else if (opts.namespace & CLONE_NEWTIME) {
			timens_fd = ns_open_pid("time", getpid());
			if (unshare(CLONE_NEWTIME)) {
				ERROR("unshare(CLONE_NEWTIME) failed: %m\n");
				free_and_exit(EXIT_FAILURE);
			}
			if ((timens_offsets.monotonic.set || timens_offsets.boottime.set) &&
			    applyOCIlinuxtimeoffsets())
				free_and_exit(EXIT_FAILURE);
		} else {
			timens_fd = -1;
		}

		if (opts.namespace & CLONE_NEWUSER) {
			if (opts.overlaydir) {
				if (chown(opts.overlaydir, opts.root_map_uid, opts.root_map_uid)) {
					ERROR("chown(%s, %d, %d) failed: %m\n",
					      opts.overlaydir, opts.root_map_uid, opts.root_map_uid);
					free_and_exit(EXIT_FAILURE);
				}
			}
			if (prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP)) {
				ERROR("prctl(PR_SET_SECUREBITS) failed: %m\n");
				free_and_exit(EXIT_FAILURE);
			}
			if (seteuid(opts.root_map_uid)) {
				ERROR("seteuid(%d) failed: %m\n", opts.root_map_uid);
				free_and_exit(EXIT_FAILURE);
			}
		}

		/*
		 * CLONE_NEWUSER is excluded here; the child creates its own
		 * later, in enter_userns(). See exec_jail() for why.
		 */
		jail_process.pid = clone(exec_jail, child_stack + STACK_SIZE, SIGCHLD | (opts.namespace & ~(CLONE_NEWCGROUP | CLONE_NEWUSER | CLONE_NEWTIME)), NULL);
	} else {
		jail_process.pid = fork();
	}

	if (jail_process.pid > 0) {
		/* parent process */
		char sig_buf[1];

		close(parent_pidfd);
		uloop_process_add(&jail_process);
		jail_running = 1;
		if (seteuid(0)) {
			ERROR("seteuid(%d) failed: %m\n", opts.root_map_uid);
			free_and_exit(EXIT_FAILURE);
		}

		prctl(PR_SET_SECUREBITS, 0);

		if (pidns_fd != -1) {
			setns(pidns_fd, CLONE_NEWPID);
			close(pidns_fd);
		}
		if (timens_fd != -1) {
			setns(timens_fd, CLONE_NEWTIME);
			close(timens_fd);
		}
		if (opts.setns.net != -1)
			close(opts.setns.net);
		if (opts.setns.ns != -1)
			close(opts.setns.ns);
		if (opts.setns.ipc != -1)
			close(opts.setns.ipc);
		if (opts.setns.uts != -1)
			close(opts.setns.uts);
		if (opts.setns.user != -1)
			close(opts.setns.user);
		if (opts.setns.cgroup != -1)
			close(opts.setns.cgroup);
		close(pipes[1]);
		close(pipes[2]);
		close(userns_pipe[1]);
		close(userns_pipe[2]);
		if (read(pipes[0], sig_buf, 1) < 1) {
			ERROR("can't read from child\n");
			free_and_exit(-1);
		}
		close(pipes[0]);
		set_oom_score_adj();

		if (opts.ocibundle)
			cgroups_apply(jail_process.pid);

		if (opts.namespace & CLONE_NEWNET)
			jail_network_start(parent_ctx, opts.name, jail_process.pid);

		if (opts.netdevices &&
		    ((opts.namespace & CLONE_NEWNET) || opts.setns.net != -1) &&
		    move_netdevs_into_jail(jail_process.pid))
			free_and_exit(-1);

		if (jail_writepid(jail_process.pid)) {
			ERROR("failed to write pidfile: %m\n");
			free_and_exit(-1);
		}
	} else if (jail_process.pid == 0) {
		/* fork child process */
		free_and_exit(exec_jail(NULL));
	} else {
		ERROR("failed to clone/fork: %m\n");
		free_and_exit(EXIT_FAILURE);
	}
	run_hooks(opts.hooks.prestart, post_prestart);
}

static void post_poststart(void);
static void post_create_runtime(void)
{
	char sig_buf[1];

	if (hook_chain_failed) {
		ERROR("createRuntime hook failed; aborting container\n");
		free_and_exit(EXIT_FAILURE);
	}

	sig_buf[0] = 'O';
	if (write(pipes[3], sig_buf, 1) < 0) {
		ERROR("can't write to child\n");
		free_and_exit(-1);
	}

	/*
	 * Wait for the child to reach enter_userns() and create its own
	 * userns before writing its uid/gid maps; see that function.
	 */
	if ((opts.namespace & CLONE_NEWUSER) && opts.setns.user == -1) {
		char ubuf[1];

		if (xread_byte(userns_pipe[0], ubuf) < 1) {
			ERROR("can't read from child\n");
			free_and_exit(-1);
		}
		close(userns_pipe[0]);

		if (write_setgroups(jail_process.pid, true)) {
			ERROR("can't write setgroups\n");
			free_and_exit(-1);
		}
		if (!opts.uidmap) {
			bool has_gr = (opts.gr_gid != -1);
			int primary_gid = has_gr ? opts.gr_gid :
				((opts.pw_uid != -1) ? opts.pw_gid : 65534);
			int target_uid = (opts.pw_uid != -1) ? opts.pw_uid : 65534;

			if (write_single_uid_gid_map(jail_process.pid, 0, target_uid)) {
				ERROR("failed to map uid %d into the jail's user "
				      "namespace (mapping a uid other than your own "
				      "requires CAP_SETUID, typically real root; use "
				      "-U with your own account, run as a privileged "
				      "user, or supply an explicit --uidmap)\n",
				      target_uid);
				free_and_exit(-1);
			}

			if (opts.additional_gids && opts.num_additional_gids) {
				char *gidmap = build_group_gidmap(primary_gid);

				if (gidmap) {
					if (write_uid_gid_map(jail_process.pid, 1, gidmap)) {
						ERROR("failed to map supplementary groups for "
						      "%s into the jail's user namespace "
						      "(mapping a gid other than your own "
						      "requires CAP_SETGID, typically real "
						      "root)\n", opts.user);
						free(gidmap);
						free_and_exit(-1);
					}
					free(gidmap);
				} else {
					WARNING("failed to build supplementary group map for "
						"%s; falling back to primary gid only\n", opts.user);
					if (write_single_uid_gid_map(jail_process.pid, 1, primary_gid)) {
						ERROR("failed to map gid %d into the jail's "
						      "user namespace (mapping a gid other "
						      "than your own requires CAP_SETGID, "
						      "typically real root)\n", primary_gid);
						free_and_exit(-1);
					}
				}
			} else {
				if (write_single_uid_gid_map(jail_process.pid, 1, primary_gid)) {
					ERROR("failed to map gid %d into the jail's user "
					      "namespace (mapping a gid other than your "
					      "own requires CAP_SETGID, typically real "
					      "root)\n", primary_gid);
					free_and_exit(-1);
				}
			}
		} else {
			if (write_uid_gid_map(jail_process.pid, 0, opts.uidmap)) {
				ERROR("failed to write uidmap (check --uidmap values "
				      "and privileges)\n");
				free_and_exit(-1);
			}
			if (opts.gidmap && write_uid_gid_map(jail_process.pid, 1, opts.gidmap)) {
				ERROR("failed to write gidmap (check --gidmap values "
				      "and privileges)\n");
				free_and_exit(-1);
			}
		}

		ubuf[0] = 'O';
		if (xwrite_byte(userns_pipe[3], ubuf[0]) < 0) {
			ERROR("can't write to child\n");
			free_and_exit(-1);
		}
		close(userns_pipe[3]);
	} else {
		close(userns_pipe[0]);
		close(userns_pipe[3]);
	}

	jail_oci_state = OCI_STATE_CREATED;
	if (opts.ocibundle && !opts.immediately)
		uloop_run(); /* wait for 'start' command via ubus */
	else
		pipe_send_start_container(NULL);
}

static void pipe_send_start_container(struct uloop_timeout *t)
{
	char sig_buf[1];

	jail_oci_state = OCI_STATE_RUNNING;
	sig_buf[0] = '!';
	if (write(pipes[3], sig_buf, 1) < 0) {
		ERROR("can't write to child\n");
		free_and_exit(-1);
	}
	close(pipes[3]);

	run_hooks(opts.hooks.poststart, post_poststart);
}

static void post_poststart(void)
{
	if (hook_chain_failed)
		ERROR("poststart hook failed; stopping container\n");
	else
		uloop_run(); /* idle here while jail is running */

	if (jail_running) {
		DEBUG("killing jail process\n");
		kill(jail_process.pid, SIGTERM);
		uloop_timeout_set(&jail_process_timeout, 1000);
		uloop_run();
	}
	uloop_done();
	poststop();
}

static void post_poststop(void);
static void poststop(void) {
	if (opts.namespace & CLONE_NEWNET) {
		setns(netns_fd, CLONE_NEWNET);
		jail_network_stop();
		close(netns_fd);
	}
	run_hooks(opts.hooks.poststop, post_poststop);
}

static void post_poststop(void)
{
	free_opts(true);
	if (parent_ctx)
		ubus_free(parent_ctx);

	exit(jail_return_code);
}
