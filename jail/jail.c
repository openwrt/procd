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
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
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
#include <limits.h>
#include <linux/close_range.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/limits.h>
#include <linux/nsfs.h>
#include <linux/sched.h>
#include <linux/securebits.h>
#include <signal.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/ptrace.h>

#include "capabilities.h"
#include "elf.h"
#include "fs.h"
#include "jail.h"
#include "landlock.h"
#include "log.h"
#include "seccomp-oci.h"
#include "seccomp-inject.h"
#include "seccomp-trace.h"
#include "cgroups.h"
#include "netifd.h"
#include "../stdio-fds.h"

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

#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#endif
#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#define PR_MDWE_REFUSE_EXEC_GAIN (1UL << 0)
#endif
#ifndef PR_MDWE_NO_INHERIT
#define PR_MDWE_NO_INHERIT (1UL << 1)
#endif

#define OPT_ARGS	"a:b:cC:d:De:EfFG:h:iI:j:J:k:lm:M:n:NoO:pP:r:R:sS:uU:V:w:x:t:T:yY:Z"

#define JAIL_MAX_CREDENTIALS	16
static const char *cred_targets[JAIL_MAX_CREDENTIALS];
static int n_cred_targets;

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
	struct sock_fprog *ociseccomp_linker;
	struct sock_fprog *ociseccomp_init;
	struct sock_fprog *ociseccomp_delta_entry;
	struct sock_fprog *ociseccomp_delta_main;
	enum seccomp_mode seccomp_mode;
	char *seccomp_log;
	char *capabilities;
	struct jail_capset capset;
	char *user;
	char *group;
	char *extroot;
	char *overlaydir;
	char *tmpoverlaysize;
	char **envp;
	char *envfile;
	char *uidmap;
	char *gidmap;
	struct blob_attr *uidmappings;
	struct blob_attr *gidmappings;
	unsigned int idmap_offset;
	char *pidfile;
	int notify_fd;
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
	char *console_socket;
	bool systemd_cgroup;
	unsigned short console_height;
	unsigned short console_width;
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
	unsigned long mdwe_flags;
	struct landlock_config landlock;
	bool private_ubus;
	bool private_netifd;
	bool jail_network_started;
} opts;

static struct blob_buf ocibuf;
static struct blob_buf notify_buf;

static char **volume_sources;
static int num_volume_sources;
static int exec_ack[2] = { -1, -1 };
static void exec_ack_cb(struct uloop_fd *fd, unsigned int events);
static struct uloop_fd exec_ack_uloop = {
	.cb = exec_ack_cb,
};

extern int pivot_root(const char *new_root, const char *put_old);

int debug = 0;

static long jail_clone3(struct clone_args *args)
{
	return syscall(SYS_clone3, args, sizeof(*args));
}

static int jail_process_pidfd = -1;

static struct ubus_context *parent_ctx;

int console_fd;
static int console_slave_fd = -1;
static char console_slave_name[64];


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

		if (opts.ociseccomp_linker) {
			free(opts.ociseccomp_linker->filter);
			free(opts.ociseccomp_linker);
		}

		if (opts.ociseccomp_init) {
			free(opts.ociseccomp_init->filter);
			free(opts.ociseccomp_init);
		}

		if (opts.ociseccomp_delta_entry) {
			free(opts.ociseccomp_delta_entry->filter);
			free(opts.ociseccomp_delta_entry);
		}

		if (opts.ociseccomp_delta_main) {
			free(opts.ociseccomp_delta_main->filter);
			free(opts.ociseccomp_delta_main);
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
	free(opts.uidmappings);
	free(opts.gidmappings);
	free(opts.annotations);
	landlock_config_free(&opts.landlock);
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

static int parse_inherited_console_fd(const char *spec)
{
	char *endptr;
	long fd;

	if (!spec || !*spec)
		return -1;

	errno = 0;
	fd = strtol(spec, &endptr, 10);
	if (errno || *endptr || endptr == spec || fd < 0 || fd > INT_MAX)
		return -1;

	if (fcntl((int)fd, F_GETFD) == -1)
		return -1;

	return (int)fd;
}

static int open_console_sock(const char *spec, bool *owned, bool path_only)
{
	int sock;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };

	*owned = false;
	if (!path_only) {
		sock = parse_inherited_console_fd(spec);
		if (sock >= 0) {
			int dom = 0, typ = 0;
			socklen_t slen = sizeof(dom);

			if (getsockopt(sock, SOL_SOCKET, SO_DOMAIN, &dom, &slen) < 0 ||
			    dom != AF_UNIX) {
				ERROR("console-socket: inherited fd %d is not AF_UNIX\n", sock);
				return -1;
			}
			slen = sizeof(typ);
			if (getsockopt(sock, SOL_SOCKET, SO_TYPE, &typ, &slen) < 0 ||
			    typ != SOCK_STREAM) {
				ERROR("console-socket: inherited fd %d is not SOCK_STREAM\n", sock);
				return -1;
			}
			return sock;
		}
	}

	if (strlen(spec) >= sizeof(addr.sun_path)) {
		ERROR("console-socket path too long: %s\n", spec);
		return -1;
	}
	memcpy(addr.sun_path, spec, strlen(spec) + 1);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		ERROR("console-socket: socket(): %m\n");
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		ERROR("console-socket: connect(%s): %m\n", spec);
		close(sock);
		return -1;
	}
	*owned = true;
	return sock;
}

static int sendmsg_console_fd(int sock, int console_fd, const char *slave_name)
{
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	char cbuf[CMSG_SPACE(sizeof(int))] = { 0 };

	iov.iov_base = (void *)slave_name;
	iov.iov_len = strlen(slave_name);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &console_fd, sizeof(int));

	if (sendmsg(sock, &msg, 0) < 0) {
		ERROR("console-socket: sendmsg: %m\n");
		return -1;
	}
	return 0;
}

static int send_console_fd(const char *spec, int console_fd, const char *slave_name)
{
	bool owned;
	int sock, ret;

	sock = open_console_sock(spec, &owned, false);
	if (sock < 0)
		return -1;
	ret = sendmsg_console_fd(sock, console_fd, slave_name);
	if (owned)
		close(sock);
	return ret;
}

static int create_dev_console(const char *jail_root)
{
	char dev_console_path[PATH_MAX];
	char fdpath[64];
	int dev_console_dummy;

	if (console_slave_fd < 0)
		return 1;

	snprintf(dev_console_path, sizeof(dev_console_path), "%s/dev/console", jail_root);
	dev_console_dummy = creat(dev_console_path, 0620);
	if (dev_console_dummy >= 0)
		close(dev_console_dummy);

	snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", console_slave_fd);
	if (mount(fdpath, dev_console_path, "bind", MS_BIND, NULL))
		return 1;

	setsid();
	if (ioctl(console_slave_fd, TIOCSCTTY, 0) < 0)
		WARNING("TIOCSCTTY on guest console failed: %m\n");

	dup2(console_slave_fd, 0);
	dup2(console_slave_fd, 1);
	dup2(console_slave_fd, 2);
	if (console_slave_fd > 2)
		close(console_slave_fd);

	return 0;
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
static void oci_state_fill(struct blob_buf *b);
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

static int hook_state_pipe(void)
{
	static struct blob_buf sb;
	int state_pipe[2];
	char *state;
	size_t len;

	blob_buf_init(&sb, 0);
	oci_state_fill(&sb);
	state = blobmsg_format_json(sb.head, true);
	if (!state)
		return -1;

	if (pipe(state_pipe)) {
		free(state);
		return -1;
	}

	len = strlen(state);
	if (write(state_pipe[1], state, len) != (ssize_t)len)
		WARNING("cannot pass the container state to the hook: %m\n");

	free(state);
	close(state_pipe[1]);

	return state_pipe[0];
}

static void run_hooklist(void)
{
	struct hook_execvpe *hook = *current_hook;
	int state_fd;
	struct stat s;

	if (!hook)
		return hook_return_cb();

	DEBUG("executing hook %s\n", hook->file);

	if (stat(hook->file, &s))
		hook_process_handler(&hook_process, ENOENT);

	if (!((unsigned long)s.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
		hook_process_handler(&hook_process, EPERM);

	state_fd = hook_state_pipe();

	hook_running = 1;
	hook_process.pid = fork();
	if (hook_process.pid == 0) {
		/* child */
		if (state_fd > -1) {
			dup2(state_fd, STDIN_FILENO);
			close(state_fd);
		}
		execve(hook->file, hook->argv, hook->envp);
		ERROR("execve error %m\n");
		_exit(errno);
	} else if (hook_process.pid < 0) {
		/* fork error */
		ERROR("hook fork error\n");
		hook_running = 0;
		if (state_fd > -1)
			close(state_fd);
		hook_process_handler(&hook_process, errno);
	}

	/* parent */
	if (state_fd > -1)
		close(state_fd);

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

static char jail_dev[] = "/tmp/ujail-dev-XXXXXX";
static bool jail_dev_staged;

static struct mknod_args default_devices[] = {
	{ .path = "/dev/null", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(1, 3) },
	{ .path = "/dev/zero", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(1, 5) },
	{ .path = "/dev/full", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(1, 7) },
	{ .path = "/dev/random", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(1, 8) },
	{ .path = "/dev/urandom", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(1, 9) },
	{ .path = "/dev/tty", .mode = (S_IFCHR|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH), .dev = makedev(5, 0), .gid = 5 },
	{ 0 },
};

static int prepare_jail_dev(void)
{
	struct mknod_args **cur, *curdef;
	uid_t base = (opts.namespace & CLONE_NEWUSER) ? opts.root_map_uid : 0;
	mode_t oldmask = umask(0);
	char path[PATH_MAX], *tmp;
	int consfd;

	if (mkdtemp(jail_dev) == NULL) {
		ERROR("mkdtemp(%s) failed: %m\n", jail_dev);
		return errno;
	}
	jail_dev_staged = true;

	if (mount("tmpfs", jail_dev, "tmpfs", MS_NOSUID | MS_NOATIME, "mode=0755")) {
		ERROR("tmpfs mount for /dev failed: %m\n");
		return errno;
	}

	if (mount(NULL, jail_dev, NULL, MS_PRIVATE, NULL)) {
		ERROR("making /dev tmpfs private failed: %m\n");
		return errno;
	}

	for (cur = opts.devices; cur && *cur; ++cur) {
		/* don't allow devices outside of /dev */
		if (strncmp((*cur)->path, "/dev", 4))
			return EPERM;

		snprintf(path, sizeof(path), "%s%s", jail_dev, (*cur)->path + 4);

		/* make sure parent folder exists */
		tmp = strrchr(path, '/');
		if (!tmp)
			return EINVAL;
		*tmp = '\0';
		if (strcmp(path, jail_dev) && mkdir_p(path, 0755))
			return errno;
		*tmp = '/';

		if (mknod(path, (*cur)->mode, (*cur)->dev))
			return errno;
		if (chown(path, base + (*cur)->uid, base + (*cur)->gid))
			return errno;
	}

	for (curdef = default_devices; curdef->path; ++curdef) {
		snprintf(path, sizeof(path), "%s%s", jail_dev, curdef->path + 4);
		if (mknod(path, curdef->mode, curdef->dev))
			return errno;
		if (chown(path, base + curdef->uid, base + curdef->gid))
			return errno;
	}

	/* Dev symbolic links as defined in OCI spec */
	snprintf(path, sizeof(path), "%s/ptmx", jail_dev);
	if (symlink("/dev/pts/ptmx", path))
		WARNING("symlink() failed to create link to /dev/pts/ptmx");

	snprintf(path, sizeof(path), "%s/fd", jail_dev);
	if (symlink("/proc/self/fd", path))
		WARNING("symlink() failed to create link to /proc/self/fd");

	snprintf(path, sizeof(path), "%s/stdin", jail_dev);
	if (symlink("/proc/self/fd/0", path))
		WARNING("symlink() failed to create link to /proc/self/fd/0");

	snprintf(path, sizeof(path), "%s/stdout", jail_dev);
	if (symlink("/proc/self/fd/1", path))
		WARNING("symlink() failed to create link to /proc/self/fd/1");

	snprintf(path, sizeof(path), "%s/stderr", jail_dev);
	if (symlink("/proc/self/fd/2", path))
		WARNING("symlink() failed to create link to /proc/self/fd/2");

	snprintf(path, sizeof(path), "%s/pts", jail_dev);
	mkdir(path, 0755);
	snprintf(path, sizeof(path), "%s/shm", jail_dev);
	mkdir(path, 0755);
	snprintf(path, sizeof(path), "%s/mqueue", jail_dev);
	mkdir(path, 0755);

	if ((opts.namespace & CLONE_NEWNET) && opts.private_netifd) {
		snprintf(path, sizeof(path), "%s/resolv.conf.d", jail_dev);
		mkdir(path, 0755);
		snprintf(path, sizeof(path), "%s/resolv.conf", jail_dev);
		if (symlink("/dev/resolv.conf.d/resolv.conf.auto", path))
			WARNING("symlink() failed to create /dev/resolv.conf: %m\n");
	}

	if (opts.console) {
		snprintf(path, sizeof(path), "%s/console", jail_dev);
		consfd = creat(path, 0620);
		if (consfd < 0)
			WARNING("creat() failed to stage /dev/console: %m\n");
		else
			close(consfd);
	}

	mount_stage_dev(jail_dev);

	if (mount(NULL, jail_dev, NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NOATIME, NULL)) {
		ERROR("read-only remount of /dev staging failed: %m\n");
		return errno;
	}

	umask(oldmask);
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
#define JAIL_IDMAP_MAX_FDS 64

static int idmap_fds[JAIL_IDMAP_MAX_FDS];
static int num_idmap_fds;
static int extroot_idmap_fd = -1;
static int overlay_idmap_fd = -1;

static bool jail_idmap_active(void)
{
	return (opts.namespace & CLONE_NEWUSER) && opts.uidmap;
}

static int sock_send_fds(int sock, char tag, const int *fds, int nfds)
{
	struct msghdr msg = { 0 };
	struct iovec iov;
	char cmsgbuf[CMSG_SPACE(JAIL_IDMAP_MAX_FDS * sizeof(int))];
	struct cmsghdr *cmsg;
	char data[1];
	ssize_t n;

	data[0] = tag;
	iov.iov_base = data;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (nfds > 0) {
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = CMSG_SPACE(nfds * sizeof(int));
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(nfds * sizeof(int));
		memcpy(CMSG_DATA(cmsg), fds, nfds * sizeof(int));
	}

	do {
		n = sendmsg(sock, &msg, MSG_NOSIGNAL);
	} while (n < 0 && errno == EINTR);

	return (n == 1) ? 0 : -1;
}

static int sock_recv_fds(int sock, char *tag, int *fds, int maxfds)
{
	struct msghdr msg = { 0 };
	struct iovec iov;
	char cmsgbuf[CMSG_SPACE(JAIL_IDMAP_MAX_FDS * sizeof(int))];
	struct cmsghdr *cmsg;
	char data[1];
	ssize_t n;
	int nfds = 0;

	iov.iov_base = data;
	iov.iov_len = 1;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	do {
		n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
	} while (n < 0 && errno == EINTR);

	if (n < 1)
		return -1;

	*tag = data[0];

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
			continue;
		nfds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		if (nfds > maxfds)
			nfds = maxfds;
		memcpy(fds, CMSG_DATA(cmsg), nfds * sizeof(int));
		break;
	}

	return nfds;
}

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

	if (opts.console && console_slave_name[0]) {
		console_slave_fd = open(console_slave_name, O_RDWR);
		if (console_slave_fd < 0)
			WARNING("open guest console slave %s: %m\n", console_slave_name);
	}

	if (mkdtemp(jail_root) == NULL) {
		ERROR("mkdtemp(%s) failed: %m\n", jail_root);
		return -1;
	}

	if (apply_sysctl(jail_root)) {
		ERROR("failed to apply sysctl values\n");
		return -1;
	}

	if (opts.extroot) {
		if (extroot_idmap_fd >= 0) {
			if (sys_move_mount(extroot_idmap_fd, "", AT_FDCWD, jail_root, MOVE_MOUNT_F_EMPTY_PATH)) {
				ERROR("move_mount(idmapped extroot) failed: %m\n");
				return -1;
			}
			close(extroot_idmap_fd);
			extroot_idmap_fd = -1;
		} else if (mount(opts.extroot, jail_root, "bind", MS_BIND, NULL)) {
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
		if (mount("tmpfs", tmpovdir, "tmpfs", MS_NOATIME | MS_NOEXEC | MS_NOSUID | MS_NODEV,
			  mountoptsstr)) {
			ERROR("failed to mount tmpfs for overlay (size=%s)\n", opts.tmpoverlaysize);
			return -1;
		}
		overlaydir = tmpovdir;
	}

	if (opts.overlaydir)
		overlaydir = opts.overlaydir;

	if (overlaydir) {
		if (overlay_idmap_fd >= 0) {
			if (sys_move_mount(overlay_idmap_fd, "", AT_FDCWD, overlaydir, MOVE_MOUNT_F_EMPTY_PATH)) {
				ERROR("move_mount(idmapped overlay upper) failed: %m\n");
				return -1;
			}
			close(overlay_idmap_fd);
			overlay_idmap_fd = -1;
		} else if (mount(NULL, overlaydir, NULL,
			  MS_BIND | MS_REMOUNT | MS_NOEXEC | MS_NOSUID | MS_NODEV, NULL)) {
			WARNING("failed to harden overlay upper %s: %m\n", overlaydir);
		}

		ret = mount_overlay(jail_root, overlaydir);
		if (ret)
			return ret;
	}

	if (chdir(jail_root)) {
		ERROR("chdir(%s) (jail_root) failed: %m\n", jail_root);
		return -1;
	}

	jail_fs_set_userns((opts.namespace & CLONE_NEWUSER) || (opts.setns.user != -1));

	if (mount_all(jail_root, jail_dev)) {
		ERROR("mount_all() failed\n");
		return -1;
	}

	if (opts.console)
		create_dev_console(jail_root);

	if ((opts.namespace & CLONE_NEWNET) && opts.private_netifd) {
		char jailetc[PATH_MAX], devresolv[PATH_MAX], etcresolv[PATH_MAX];
		struct stat rcst;
		int treefd;

		snprintf(devresolv, PATH_MAX, "%s/dev/resolv.conf", jail_root);
		snprintf(etcresolv, PATH_MAX, "%s/etc/resolv.conf", jail_root);
		if (stat(etcresolv, &rcst) && (overlaydir || !opts.ronly)) {
			snprintf(jailetc, PATH_MAX, "%s/etc", jail_root);
			mkdir_p(jailetc, 0755);
			close(creat(etcresolv, 0644));
		}
		if (!stat(etcresolv, &rcst)) {
			treefd = sys_open_tree(AT_FDCWD, devresolv,
					       OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_SYMLINK_NOFOLLOW);
			if (treefd < 0) {
				WARNING("open_tree(/dev/resolv.conf) failed: %m\n");
			} else {
				if (sys_move_mount(treefd, "", AT_FDCWD, etcresolv, MOVE_MOUNT_F_EMPTY_PATH))
					WARNING("move_mount onto /etc/resolv.conf failed: %m\n");
				close(treefd);
			}
		}
	}

	run_hooks(opts.hooks.createContainer, enter_jail_fs);

	return 0;
}

static bool exit_from_child;
static void emit_instance_event(const char *event);
static bool pidfile_sibling(const char *pidfile, const char *name, char *path, size_t len)
{
	char *slash;

	if (!pidfile)
		return false;

	if (snprintf(path, len, "%s", pidfile) >= (int)len)
		return false;

	slash = strrchr(path, '/');
	if (!slash)
		return false;

	if ((size_t)(slash - path) + strlen(name) + 1 >= len)
		return false;

	strcpy(slash, name);

	return true;
}

static void jail_write_exit_status(const char *pidfile, int status)
{
	char path[PATH_MAX], tmp[PATH_MAX];
	char buf[12];
	int fd, len;

	if (!pidfile_sibling(pidfile, "/exit_status", path, sizeof(path)))
		return;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return;

	len = snprintf(buf, sizeof(buf), "%d", status);
	if (len < 0 || len >= (int)sizeof(buf))
		return;

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return;

	if (write(fd, buf, len) != len) {
		close(fd);
		unlink(tmp);
		return;
	}

	if (close(fd)) {
		unlink(tmp);
		return;
	}

	if (rename(tmp, path))
		unlink(tmp);
}

static void jail_clear_exit_status(const char *pidfile)
{
	char path[PATH_MAX];

	if (pidfile_sibling(pidfile, "/exit_status", path, sizeof(path)))
		unlink(path);
}

static void notify_signal(int fd)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	if (fd < 0)
		return;

	if (poll(&pfd, 1, 0) > 0)
		return;

	syscall(SYS_pidfd_send_signal, fd, SIGCHLD, NULL, 0);
}

static bool jail_ptrace_seccomp(void);

static void free_and_exit(int ret)
{
	if (!exit_from_child)
		notify_signal(opts.notify_fd);

	if (!exit_from_child && opts.jail_network_started) {
		jail_network_teardown();
		opts.jail_network_started = false;
	}

	if (!exit_from_child && opts.ocibundle) {
		cgroups_destroy();
		cgroups_free();
	}

	if (!exit_from_child && jail_dev_staged) {
		umount2(jail_dev, MNT_DETACH);
		rmdir(jail_dev);
		jail_dev_staged = false;
	}

	if (!exit_from_child && opts.ocibundle && parent_ctx && opts.name)
		emit_instance_event("instance.stopped");

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
	if (chdir(jail_root)) {
		ERROR("chdir(%s) (jail_root) failed: %m\n", jail_root);
		free_and_exit(-1);
	}
	if (pivot_root(".", ".") == -1) {
		ERROR("pivot_root(%s) failed: %m\n", jail_root);
		free_and_exit(-1);
	}
	if (umount2(".", MNT_DETACH)) {
		ERROR("umount2() of the old root failed: %m\n");
		free_and_exit(-1);
	}
	if (chdir("/")) {
		ERROR("chdir(/) (after pivot_root) failed: %m\n");
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
static char** build_envp(char **ocienvp)
{
	static char *envp[MAX_ENVP];
	static char debug_var[] = "LD_DEBUG=all";
	static char container_var[] = "container=ujail";
	char **addenv;

	int count = 0;

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

static int build_oci_seccomp(struct blob_attr *msg)
{
	opts.ociseccomp = parseOCIlinuxseccomp(msg, NULL);
	if (!opts.ociseccomp)
		return -1;

	if (!seccomp_profile_covers(opts.ociseccomp, seccomp_init_base)) {
		opts.ociseccomp_init = parseOCIlinuxseccomp(msg, seccomp_init_base);
		if (!opts.ociseccomp_init)
			return -1;
	}

	if (!seccomp_profile_covers(opts.ociseccomp, seccomp_linker_base)) {
		opts.ociseccomp_linker = parseOCIlinuxseccomp(msg, seccomp_linker_base);
		if (!opts.ociseccomp_linker)
			return -1;

		opts.ociseccomp_delta_entry = seccomp_deny_delta(seccomp_loader_files,
				opts.ociseccomp);
		opts.ociseccomp_delta_main = seccomp_deny_delta(seccomp_init_base,
				opts.ociseccomp);
	}

	return 0;
}

static int seccomp_compile_file(const char *json_path)
{
	struct blob_buf b = { 0 };
	int rc;

	blob_buf_init(&b, 0);
	if (!blobmsg_add_json_from_file(&b, json_path)) {
		ERROR("seccomp: failed to load %s\n", json_path);
		blob_buf_free(&b);
		return -1;
	}

	rc = build_oci_seccomp(b.head);
	blob_buf_free(&b);
	if (rc) {
		ERROR("seccomp: failed to parse %s\n", json_path);
		return -1;
	}

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "ujail <options> -- <binary> <params ...>\n");
	fprintf(stderr, "  -d <num>\tshow debug log (increase num to increase verbosity)\n");
	fprintf(stderr, "  -S <file>\tseccomp filter config\n");
	fprintf(stderr, "  -m <mode>\tseccomp mode: enforce (default), trace, audit or complain\n");
	fprintf(stderr, "  -M <file>\tseccomp trace log (NDJSON) output path\n");
	fprintf(stderr, "  -C <file>\tcapabilities drop config\n");
	fprintf(stderr, "  -c\t\tset PR_SET_NO_NEW_PRIVS\n");
	fprintf(stderr, "  -n <name>\tthe name of the jail\n");
	fprintf(stderr, "  -e <var>\timport environment variable\n");
	fprintf(stderr, "  -x <file>\tappend KEY=VALUE lines from <file> to the container env\n");
	fprintf(stderr, "namespace jail options:\n");
	fprintf(stderr, "  -h <hostname>\tchange the hostname of the jail\n");
	fprintf(stderr, "  -N\t\tjail has network namespace\n");
	fprintf(stderr, "  -f\t\tjail has user namespace\n");
	fprintf(stderr, "  -F\t\tjail has cgroups namespace\n");
	fprintf(stderr, "  -r <file>\treadonly files that should be staged\n");
	fprintf(stderr, "  -w <file>\twriteable files that should be staged\n");
	fprintf(stderr, "  -V <src:dest>\tbind <src> at <dest> as a noexec,nosuid,nodev volume\n");
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
	fprintf(stderr, "  -Y <spec>\tsend PTY master fd via inherited fd or AF_UNIX path\n");
	fprintf(stderr, "  -J <dir>\tcreate container from OCI bundle\n");
	fprintf(stderr, "  -i\t\tstart container immediately\n");
	fprintf(stderr, "  -P <pidfile>\tcreate <pidfile>\n");
	fprintf(stderr, "  -a <fd>\tsend SIGCHLD through inherited pidfd <fd> once the container is gone\n");
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
	jail_write_exit_status(opts.pidfile, jail_return_code);
	jail_running = 0;
	poststop();
}

static struct uloop_process jail_process = {
	.cb = jail_process_handler,
};

static int jail_pidfd_send_signal(int sig)
{
	if (jail_process_pidfd < 0)
		return kill(jail_process.pid, sig);
	return syscall(SYS_pidfd_send_signal, jail_process_pidfd, sig, NULL, 0);
}

static void jail_process_timeout_cb(struct uloop_timeout *t)
{
	DEBUG("jail process failed to stop, sending SIGKILL\n");
	jail_pidfd_send_signal(SIGKILL);
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
		jail_pidfd_send_signal(signo);
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
	char tag;
	int recv_fds[JAIL_IDMAP_MAX_FDS];
	int nrecv;
	int ret;

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

	ret = setns_open(CLONE_NEWNET);
	if (!ret)
		ret = setns_open(CLONE_NEWNS);
	if (!ret)
		ret = setns_open(CLONE_NEWIPC);
	if (!ret)
		ret = setns_open(CLONE_NEWUTS);
	if (ret) {
		ERROR("failed to join namespace: %s\n", strerror(ret));
		return EXIT_FAILURE;
	}

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

	ret = setns_open(CLONE_NEWUSER);
	if (ret) {
		ERROR("failed to join user namespace: %s\n", strerror(ret));
		return EXIT_FAILURE;
	}

	buf[0] = 'i';
	if (write(pipes[1], buf, 1) < 1) {
		ERROR("can't write to parent\n");
		return EXIT_FAILURE;
	}
	close(pipes[1]);

	nrecv = sock_recv_fds(pipes[2], &tag, recv_fds, JAIL_IDMAP_MAX_FDS);
	if (nrecv < 0) {
		ERROR("can't read from parent\n");
		return EXIT_FAILURE;
	}
	if (tag != 'O') {
		ERROR("parent had an error, child exiting\n");
		return EXIT_FAILURE;
	}
	if (nrecv > 0)
		jail_idmap_assign(jail_idmap_active() && opts.extroot,
				  false,
				  recv_fds, nrecv, &extroot_idmap_fd, &overlay_idmap_fd);

	if (opts.setns.user != -1 && (opts.namespace & CLONE_NEWNS) &&
	    unshare(CLONE_NEWNS)) {
		ERROR("unshare(CLONE_NEWNS) failed: %m\n");
		return EXIT_FAILURE;
	}

	if (opts.namespace & CLONE_NEWCGROUP)
		unshare(CLONE_NEWCGROUP);

	ret = setns_open(CLONE_NEWCGROUP);
	if (ret) {
		ERROR("failed to join cgroup namespace: %s\n", strerror(ret));
		free_and_exit(EXIT_FAILURE);
	}

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

	if (opts.mdwe_flags && prctl(PR_SET_MDWE, opts.mdwe_flags, 0, 0, 0)) {
		ERROR("prctl(PR_SET_MDWE, 0x%lx) failed: %m\n", opts.mdwe_flags);
		free_and_exit(EXIT_FAILURE);
	}

	char **envp = build_envp(opts.envp);
	if (!envp)
		free_and_exit(EXIT_FAILURE);

	if (opts.cwd && chdir(opts.cwd)) {
		ERROR("chdir(cwd=%s) failed: %m\n", opts.cwd);
		free_and_exit(EXIT_FAILURE);
	}

	if (opts.landlock.n > 0 && landlock_apply(&opts.landlock)) {
		ERROR("landlock_apply failed\n");
		free_and_exit(EXIT_FAILURE);
	}

	if (opts.ociseccomp && seccomp_oci_needs_inproc() &&
	    applyOCIlinuxseccomp(opts.ociseccomp_linker ?: opts.ociseccomp, opts.name, opts.ocibundle))
		free_and_exit(EXIT_FAILURE);

	uloop_end();
	free_opts(false);
	syscall(SYS_close_range, 3, ~0U, CLOSE_RANGE_CLOEXEC);
	if (jail_ptrace_seccomp() && ptrace(PTRACE_TRACEME, 0, 0, 0)) {
		ERROR("PTRACE_TRACEME failed: %m\n");
		exit(EXIT_FAILURE);
	}
	DEBUG("exec-ing %s\n", *opts.jail_argv);
	if (opts.envp) { /* respect PATH if potentially set in ENV */
		environ = envp;
		execvpe(*opts.jail_argv, opts.jail_argv, envp);
	} else {
		execve(*opts.jail_argv, opts.jail_argv, envp);
	}

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

static int append_envfile(char ***envp, const char *path)
{
	char line[4096];
	char **arr = *envp;
	char *nl;
	int n = 0;
	FILE *f;

	f = fopen(path, "r");
	if (!f)
		return 0;

	while (arr && arr[n])
		++n;

	while (fgets(line, sizeof(line), f)) {
		nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';

		if (line[0] == '\0' || line[0] == '#' || !strchr(line, '='))
			continue;

		arr = realloc(arr, (n + 2) * sizeof(char *));
		if (!arr) {
			fclose(f);
			return ENOMEM;
		}

		arr[n++] = strdup(line);
		arr[n] = NULL;
	}

	fclose(f);
	*envp = arr;
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
	OCI_PROCESS_CONSOLESIZE,
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
	[OCI_PROCESS_CONSOLESIZE] = { "consoleSize", BLOBMSG_TYPE_TABLE },
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

enum {
	OCI_PROCESS_CONSOLESIZE_HEIGHT,
	OCI_PROCESS_CONSOLESIZE_WIDTH,
	__OCI_PROCESS_CONSOLESIZE_MAX,
};

static const struct blobmsg_policy oci_process_consolesize_policy[] = {
	[OCI_PROCESS_CONSOLESIZE_HEIGHT] = { "height", BLOBMSG_TYPE_INT32 },
	[OCI_PROCESS_CONSOLESIZE_WIDTH] = { "width", BLOBMSG_TYPE_INT32 },
};

static int parseOCIprocessconsolesize(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_PROCESS_CONSOLESIZE_MAX];
	uint32_t height, width;

	blobmsg_parse(oci_process_consolesize_policy, __OCI_PROCESS_CONSOLESIZE_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_PROCESS_CONSOLESIZE_HEIGHT] || !tb[OCI_PROCESS_CONSOLESIZE_WIDTH])
		return ENODATA;

	height = blobmsg_get_u32(tb[OCI_PROCESS_CONSOLESIZE_HEIGHT]);
	width = blobmsg_get_u32(tb[OCI_PROCESS_CONSOLESIZE_WIDTH]);
	if (!height || !width || height > USHRT_MAX || width > USHRT_MAX) {
		ERROR("consoleSize: %u x %u out of range\n", height, width);
		return EINVAL;
	}

	opts.console_height = height;
	opts.console_width = width;

	return 0;
}


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

	if (opts.console && tb[OCI_PROCESS_CONSOLESIZE]) {
		res = parseOCIprocessconsolesize(tb[OCI_PROCESS_CONSOLESIZE]);
		if (res)
			return res;
	}

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

	if (opts.envfile && (res = append_envfile(&opts.envp, opts.envfile)))
		return res;

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
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_HOSTID]) + opts.idmap_offset,
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
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_HOSTID]) + opts.idmap_offset,
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_SIZE]));

		/* write mapping line into pre-allocated string */
		len = snprintf(&map[pos], totallen + 1, "%d %d %d\n",
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_CONTAINERID]),
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_HOSTID]) + opts.idmap_offset,
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_SIZE]));
		pos += len;
		totallen -= len;
	}

	assert(totallen == 0);

	if (is_gidmap) {
		opts.gidmap = map;
		free(opts.gidmappings);
		opts.gidmappings = blob_memdup(msg);
		if (!opts.gidmappings)
			return ENOMEM;
	} else {
		opts.uidmap = map;
		free(opts.uidmappings);
		opts.uidmappings = blob_memdup(msg);
		if (!opts.uidmappings)
			return ENOMEM;
	}

	return 0;
}

static unsigned int host_id_for(struct blob_attr *mappings, unsigned int cid)
{
	struct blob_attr *tb[__OCI_LINUX_UIDGIDMAP_MAX];
	struct blob_attr *cur;
	unsigned int base, host, size;
	int rem;

	if (!mappings)
		return (unsigned int)-1;

	blobmsg_for_each_attr(cur, mappings, rem) {
		blobmsg_parse(oci_linux_uidgidmap_policy, __OCI_LINUX_UIDGIDMAP_MAX, tb,
			      blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[OCI_LINUX_UIDGIDMAP_CONTAINERID] ||
		    !tb[OCI_LINUX_UIDGIDMAP_HOSTID] ||
		    !tb[OCI_LINUX_UIDGIDMAP_SIZE])
			continue;
		base = blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_CONTAINERID]);
		host = blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_HOSTID]);
		size = blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_SIZE]);
		if (cid >= base && cid < base + size)
			return host + (cid - base) + opts.idmap_offset;
	}

	return (unsigned int)-1;
}

static void jail_chown_writable_surfaces(void)
{
	unsigned int vuid, vgid, ouid, ogid;

	vuid = host_id_for(opts.uidmappings, opts.pw_uid);
	vgid = host_id_for(opts.gidmappings, opts.pw_gid);
	if (vuid != (unsigned int)-1 && vgid != (unsigned int)-1)
		jail_chown_fresh_volumes(vuid, vgid);

	if (!opts.overlaydir)
		return;

	ouid = host_id_for(opts.uidmappings, 0);
	ogid = host_id_for(opts.gidmappings, 0);
	if (ouid != (unsigned int)-1 && ogid != (unsigned int)-1 &&
	    jail_dir_is_fresh(opts.overlaydir) &&
	    chown(opts.overlaydir, ouid, ogid))
		ERROR("chown(fresh overlay %s -> %u:%u): %m\n", opts.overlaydir, ouid, ogid);
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
	char cgleaf[200];
	char *cgsep;

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
		if (build_oci_seccomp(tb[OCI_LINUX_SECCOMP]))
			return EINVAL;
	}

	if (tb[OCI_LINUX_DEVICES]) {
		res = parseOCIdevices(tb[OCI_LINUX_DEVICES]);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_CGROUPSPATH]) {
		cgpath = blobmsg_get_string(tb[OCI_LINUX_CGROUPSPATH]);
		if (opts.systemd_cgroup) {
			char *orig = strdupa(cgpath);
			char *slice = cgpath;
			char *prefix = strchr(slice, ':');
			char *id;

			if (!prefix || prefix == slice) {
				ERROR("--systemd-cgroup: cgroupsPath %s is not slice:prefix:name\n", orig);
				return EINVAL;
			}
			*prefix++ = '\0';
			id = strchr(prefix, ':');
			if (!id || id == prefix || !id[1]) {
				ERROR("--systemd-cgroup: cgroupsPath %s is not slice:prefix:name\n", orig);
				return EINVAL;
			}
			*id++ = '\0';

			if (strlen(slice) + strlen(prefix) + strlen(id) + 9
			    >= (sizeof(cgfullpath) - strlen(cgfullpath)))
				return E2BIG;

			strcat(cgfullpath, "/");
			strcat(cgfullpath, slice);
			strcat(cgfullpath, "/");
			strcat(cgfullpath, prefix);
			strcat(cgfullpath, "-");
			strcat(cgfullpath, id);
			strcat(cgfullpath, ".scope");
		} else if (cgpath[0] == '/') {
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
		cgsep = strchr(opts.name, '.');
		if (cgsep)
			snprintf(cgleaf, sizeof(cgleaf), "/containers/%.*s/%s.%d",
				 (int)(cgsep - opts.name), opts.name, cgsep + 1, (int)getpid());
		else
			snprintf(cgleaf, sizeof(cgleaf), "/containers/%s/%s.%d",
				 opts.name, opts.name, (int)getpid());

		if (strlen(cgleaf) >= sizeof(cgfullpath) - strlen(cgfullpath))
			return E2BIG;

		strcat(cgfullpath, cgleaf);
	}

	cgroups_init(cgfullpath);

	if (tb[OCI_LINUX_RESOURCES]) {
		res = parseOCIlinuxcgroups(tb[OCI_LINUX_RESOURCES], false);
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

static int64_t read_memtotal_bytes(void)
{
	char buf[512];
	char *p;
	char *end;
	int64_t kb;
	int fd;
	ssize_t n;

	fd = open("/proc/meminfo", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	do {
		n = read(fd, buf, sizeof(buf) - 1);
	} while (n < 0 && errno == EINTR);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	p = strstr(buf, "MemTotal:");
	if (!p)
		return -1;
	p += strlen("MemTotal:");
	while (*p == ' ' || *p == '\t')
		p++;
	kb = strtoll(p, &end, 10);
	if (end == p || kb <= 0)
		return -1;
	return kb * 1024;
}

static int parseOCI(const char *jsonfile)
{
	struct blob_attr *tb[__OCI_MAX];
	struct blob_attr *cur;
	int rem;
	int arem;
	struct blob_attr *acur;
	int res;
	long pct;
	char *pct_end;
	int64_t memtotal;

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

	const char *ociver = blobmsg_get_string(tb[OCI_VERSION]);
	if (strncmp("1.", ociver, 2) || ociver[2] < '1' || ociver[2] > '3') {
		ERROR("unsupported ociVersion %s\n", ociver);
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

	if (tb[OCI_ANNOTATIONS]) {
		opts.annotations = blob_memdup(tb[OCI_ANNOTATIONS]);

		blobmsg_for_each_attr(acur, tb[OCI_ANNOTATIONS], arem) {
			const char *name = blobmsg_name(acur);
			const char *val;

			if (!name || blobmsg_type(acur) != BLOBMSG_TYPE_STRING)
				continue;

			val = blobmsg_get_string(acur);

			if (!strcmp(name, "org.openwrt.ujail.mdwe")) {
				while (val && *val) {
					size_t tlen;
					const char *comma = strchr(val, ',');

					tlen = comma ? (size_t)(comma - val) : strlen(val);
					if (tlen == strlen("refuse_exec_gain") &&
					    !strncmp(val, "refuse_exec_gain", tlen))
						opts.mdwe_flags |= PR_MDWE_REFUSE_EXEC_GAIN;
					else if (tlen == strlen("no_inherit") &&
						 !strncmp(val, "no_inherit", tlen))
						opts.mdwe_flags |= PR_MDWE_NO_INHERIT;
					val = comma ? comma + 1 : NULL;
				}
			} else if (!strcmp(name, "org.openwrt.ujail.landlock.ro")) {
				res = landlock_config_add_paths(&opts.landlock, val,
					LANDLOCK_ACCESS_FS_READ_FILE |
					LANDLOCK_ACCESS_FS_READ_DIR);
				if (res)
					goto errout;
			} else if (!strcmp(name, "org.openwrt.ujail.landlock.rx")) {
				res = landlock_config_add_paths(&opts.landlock, val,
					LANDLOCK_ACCESS_FS_READ_FILE |
					LANDLOCK_ACCESS_FS_READ_DIR |
					LANDLOCK_ACCESS_FS_EXECUTE);
				if (res)
					goto errout;
			} else if (!strcmp(name, "org.openwrt.ujail.landlock.rw")) {
				res = landlock_config_add_paths(&opts.landlock, val,
					LANDLOCK_ACCESS_FS_READ_FILE |
					LANDLOCK_ACCESS_FS_READ_DIR |
					LANDLOCK_ACCESS_FS_WRITE_FILE |
					LANDLOCK_ACCESS_FS_TRUNCATE |
					LANDLOCK_ACCESS_FS_MAKE_REG |
					LANDLOCK_ACCESS_FS_MAKE_DIR |
					LANDLOCK_ACCESS_FS_REMOVE_FILE |
					LANDLOCK_ACCESS_FS_REMOVE_DIR);
				if (res)
					goto errout;
			} else if (!strcmp(name, "org.openwrt.procd.ubus")) {
				opts.private_ubus = !strcmp(val, "true") || !strcmp(val, "1");
			} else if (!strcmp(name, "org.openwrt.procd.netifd")) {
				opts.private_netifd = !strcmp(val, "true") || !strcmp(val, "1");
				if (opts.private_netifd)
					opts.private_ubus = true;
			} else if (!strcmp(name, "org.openwrt.cgroup.memory.pct")) {
				pct = strtol(val, &pct_end, 10);
				if (pct_end == val || pct < 1 || pct > 100) {
					ERROR("cgroup.memory.pct: invalid value '%s'\n", val);
					res = EINVAL;
					goto errout;
				}
				memtotal = read_memtotal_bytes();
				if (memtotal < 0) {
					ERROR("cgroup.memory.pct: cannot read MemTotal\n");
					res = EIO;
					goto errout;
				}
				cgroups_set_memory_limit(memtotal * pct / 100);
			}

			if ((opts.mdwe_flags & PR_MDWE_NO_INHERIT) &&
			    !(opts.mdwe_flags & PR_MDWE_REFUSE_EXEC_GAIN)) {
				ERROR("mdwe: no_inherit requires refuse_exec_gain\n");
				res = ENOTSUP;
				goto errout;
			}
		}

		if (opts.landlock.n > 0)
			opts.no_new_privs = 1;
	}

	if (opts.private_netifd && mount_is_defined("/etc/resolv.conf")) {
		ERROR("bundle bind-mounts /etc/resolv.conf but the container has its own netifd\n");
		res = EINVAL;
		goto errout;
	}

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
	OCI_STATE_PAUSED,
	OCI_STATE_STOPPED,
};

static int jail_oci_state = OCI_STATE_CREATING;
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
static void oci_state_fill(struct blob_buf *b)
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
		case OCI_STATE_PAUSED:
			statusstr = "paused";
			break;
		case OCI_STATE_STOPPED:
			statusstr = "stopped";
			break;
		default:
			statusstr = "unknown";
	}

	blobmsg_add_string(b, "ociVersion", OCI_VERSION_STRING);
	blobmsg_add_string(b, "id", opts.name);
	blobmsg_add_string(b, "status", statusstr);
	if (jail_oci_state == OCI_STATE_CREATED ||
	    jail_oci_state == OCI_STATE_RUNNING ||
	    jail_oci_state == OCI_STATE_PAUSED) {
		int64_t v;

		blobmsg_add_u32(b, "pid", jail_process.pid);

		v = cgroups_read_int64("memory.peak");
		if (v >= 0)
			blobmsg_add_u64(b, "memoryPeak", (uint64_t)v);
		v = cgroups_read_int64("memory.swap.peak");
		if (v >= 0)
			blobmsg_add_u64(b, "memorySwapPeak", (uint64_t)v);
		v = cgroups_read_int64("pids.peak");
		if (v >= 0)
			blobmsg_add_u64(b, "pidsPeak", (uint64_t)v);

		int events_fd = cgroups_open_attr("memory.events.local");
		if (events_fd >= 0) {
			char ebuf[1024], *line, *next;
			ssize_t en = read(events_fd, ebuf, sizeof(ebuf) - 1);

			close(events_fd);
			if (en > 0) {
				void *sub = blobmsg_open_table(b, "memoryEventsLocal");

				ebuf[en] = '\0';
				next = ebuf;
				while ((line = strsep(&next, "\n"))) {
					char *space = strchr(line, ' ');

					if (!space)
						continue;
					*space = '\0';
					blobmsg_add_u64(b, line,
							strtoull(space + 1, NULL, 10));
				}
				blobmsg_close_table(b, sub);
			}
		}
	}

	blobmsg_add_string(b, "bundle", opts.ocibundle);

	if (opts.annotations)
		blobmsg_add_blob(b, opts.annotations);
}

static int handle_state(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	blob_buf_init(&bb, 0);
	oci_state_fill(&bb);
	ubus_send_reply(ctx, req, bb.head);

	return UBUS_STATUS_OK;
}

#define UXC_STOP_TIMEOUT 120

enum {
	CONTAINER_KILL_ATTR_SIGNAL,
	CONTAINER_KILL_ATTR_ALL,
	__CONTAINER_KILL_ATTR_MAX,
};

static const struct blobmsg_policy container_kill_attrs[__CONTAINER_KILL_ATTR_MAX] = {
	[CONTAINER_KILL_ATTR_SIGNAL] = { "signal", BLOBMSG_TYPE_INT32 },
	[CONTAINER_KILL_ATTR_ALL]    = { "all",    BLOBMSG_TYPE_BOOL  },
};

static int
container_handle_kill(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__CONTAINER_KILL_ATTR_MAX], *cur;
	int sig = SIGTERM;
	bool all = false;
	bool escalate = false;

	blobmsg_parse(container_kill_attrs, __CONTAINER_KILL_ATTR_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	cur = tb[CONTAINER_KILL_ATTR_SIGNAL];
	if (cur) {
		sig = (int32_t)blobmsg_get_u32(cur);
		if (sig < 0) {
			sig = SIGTERM;
			escalate = true;
		}
	}

	cur = tb[CONTAINER_KILL_ATTR_ALL];
	if (cur)
		all = blobmsg_get_bool(cur);

	if (jail_oci_state == OCI_STATE_CREATING)
		return UBUS_STATUS_NOT_FOUND;
	if (jail_oci_state == OCI_STATE_PAUSED && sig != SIGKILL && sig != 0)
		return UBUS_STATUS_PERMISSION_DENIED;

	if (all && sig == SIGKILL) {
		int rc = cgroups_kill_all();
		if (rc == 0)
			return 0;
		DEBUG("cgroup.kill unavailable (%d), falling back to per-pid kill\n", rc);
	}

	if (jail_pidfd_send_signal(sig) == 0) {
		if (escalate)
			uloop_timeout_set(&jail_process_timeout, UXC_STOP_TIMEOUT * 1000);
		return 0;
	}

	switch (errno) {
	case EINVAL: return UBUS_STATUS_INVALID_ARGUMENT;
	case EPERM:  return UBUS_STATUS_PERMISSION_DENIED;
	case ESRCH:  return UBUS_STATUS_NOT_FOUND;
	case EBADF:  return UBUS_STATUS_UNKNOWN_ERROR;
	}

	return UBUS_STATUS_UNKNOWN_ERROR;
}

static int
container_handle_pause(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	int rc;

	if (jail_oci_state != OCI_STATE_CREATED &&
	    jail_oci_state != OCI_STATE_RUNNING)
		return UBUS_STATUS_INVALID_ARGUMENT;

	rc = cgroups_set_frozen(true);
	if (rc < 0) {
		switch (rc) {
		case -ENODEV:
		case -ENOENT:
			return UBUS_STATUS_NOT_SUPPORTED;
		case -EINVAL:
			return UBUS_STATUS_INVALID_ARGUMENT;
		default:
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
	}

	jail_oci_state = OCI_STATE_PAUSED;
	return UBUS_STATUS_OK;
}

static int
container_handle_resume(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	int rc;

	if (jail_oci_state != OCI_STATE_PAUSED)
		return UBUS_STATUS_INVALID_ARGUMENT;

	rc = cgroups_set_frozen(false);
	if (rc < 0) {
		switch (rc) {
		case -ENODEV:
		case -ENOENT:
			return UBUS_STATUS_NOT_SUPPORTED;
		case -EINVAL:
			return UBUS_STATUS_INVALID_ARGUMENT;
		default:
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
	}

	jail_oci_state = OCI_STATE_RUNNING;
	return UBUS_STATUS_OK;
}

enum {
	CONTAINER_RECLAIM_ATTR_BYTES,
	CONTAINER_RECLAIM_ATTR_SWAPPINESS,
	__CONTAINER_RECLAIM_ATTR_MAX,
};

static const struct blobmsg_policy container_reclaim_attrs[__CONTAINER_RECLAIM_ATTR_MAX] = {
	[CONTAINER_RECLAIM_ATTR_BYTES]      = { "bytes",      BLOBMSG_CAST_INT64 },
	[CONTAINER_RECLAIM_ATTR_SWAPPINESS] = { "swappiness", BLOBMSG_TYPE_INT32 },
};

static int
container_handle_reclaim(struct ubus_context *ctx, struct ubus_object *obj,
			 struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg)
{
	struct blob_attr *tb[__CONTAINER_RECLAIM_ATTR_MAX];
	int64_t bytes;
	int32_t swappiness = -1;
	int rc;

	if (jail_oci_state != OCI_STATE_CREATED &&
	    jail_oci_state != OCI_STATE_RUNNING)
		return UBUS_STATUS_INVALID_ARGUMENT;
	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_parse(container_reclaim_attrs, __CONTAINER_RECLAIM_ATTR_MAX, tb,
		      blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[CONTAINER_RECLAIM_ATTR_BYTES])
		return UBUS_STATUS_INVALID_ARGUMENT;

	bytes = blobmsg_cast_s64(tb[CONTAINER_RECLAIM_ATTR_BYTES]);
	if (tb[CONTAINER_RECLAIM_ATTR_SWAPPINESS]) {
		uint32_t s = blobmsg_get_u32(tb[CONTAINER_RECLAIM_ATTR_SWAPPINESS]);
		if (s > 200)
			return UBUS_STATUS_INVALID_ARGUMENT;
		swappiness = (int32_t)s;
	}

	rc = cgroups_reclaim(bytes, swappiness);
	if (rc == 0)
		return UBUS_STATUS_OK;
	if (rc == -EAGAIN)
		return UBUS_STATUS_TIMEOUT;
	if (rc == -EINVAL)
		return UBUS_STATUS_INVALID_ARGUMENT;
	if (rc == -ENODEV)
		return UBUS_STATUS_NOT_SUPPORTED;
	return UBUS_STATUS_UNKNOWN_ERROR;
}

static int
container_handle_update(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	int rc;

	if (jail_oci_state != OCI_STATE_CREATED &&
	    jail_oci_state != OCI_STATE_RUNNING)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	rc = parseOCIlinuxcgroups(msg, true);
	if (rc) {
		switch (rc) {
		case ENOTSUP:
			return UBUS_STATUS_NOT_SUPPORTED;
		case EBUSY:
		case EINVAL:
		case ENODATA:
		case ERANGE:
			return UBUS_STATUS_INVALID_ARGUMENT;
		case EIO:
			return UBUS_STATUS_UNKNOWN_ERROR;
		default:
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
	}

	cgroups_apply(jail_process.pid);
	return UBUS_STATUS_OK;
}

enum {
	CONTAINER_EXEC_ATTR_ARGS,
	CONTAINER_EXEC_ATTR_ENV,
	CONTAINER_EXEC_ATTR_CWD,
	CONTAINER_EXEC_ATTR_USER,
	CONTAINER_EXEC_ATTR_CAPABILITIES,
	CONTAINER_EXEC_ATTR_RLIMITS,
	CONTAINER_EXEC_ATTR_NO_NEW_PRIVS,
	CONTAINER_EXEC_ATTR_TERMINAL,
	CONTAINER_EXEC_ATTR_CONSOLE_SOCKET,
	CONTAINER_EXEC_ATTR_PIDFILE,
	CONTAINER_EXEC_ATTR_DETACH,
	__CONTAINER_EXEC_ATTR_MAX,
};

static const struct blobmsg_policy container_exec_attrs[__CONTAINER_EXEC_ATTR_MAX] = {
	[CONTAINER_EXEC_ATTR_ARGS]           = { "args",            BLOBMSG_TYPE_ARRAY  },
	[CONTAINER_EXEC_ATTR_ENV]            = { "env",             BLOBMSG_TYPE_ARRAY  },
	[CONTAINER_EXEC_ATTR_CWD]            = { "cwd",             BLOBMSG_TYPE_STRING },
	[CONTAINER_EXEC_ATTR_USER]           = { "user",            BLOBMSG_TYPE_TABLE  },
	[CONTAINER_EXEC_ATTR_CAPABILITIES]   = { "capabilities",    BLOBMSG_TYPE_TABLE  },
	[CONTAINER_EXEC_ATTR_RLIMITS]        = { "rlimits",         BLOBMSG_TYPE_ARRAY  },
	[CONTAINER_EXEC_ATTR_NO_NEW_PRIVS]   = { "noNewPrivileges", BLOBMSG_TYPE_BOOL   },
	[CONTAINER_EXEC_ATTR_TERMINAL]       = { "terminal",        BLOBMSG_TYPE_BOOL   },
	[CONTAINER_EXEC_ATTR_CONSOLE_SOCKET] = { "consolesocket",   BLOBMSG_TYPE_STRING },
	[CONTAINER_EXEC_ATTR_PIDFILE]        = { "pidfile",         BLOBMSG_TYPE_STRING },
	[CONTAINER_EXEC_ATTR_DETACH]         = { "detach",          BLOBMSG_TYPE_BOOL   },
};

enum {
	CONTAINER_EXEC_USER_UID,
	CONTAINER_EXEC_USER_GID,
	CONTAINER_EXEC_USER_ADDITIONAL_GIDS,
	CONTAINER_EXEC_USER_UMASK,
	__CONTAINER_EXEC_USER_MAX,
};

static const struct blobmsg_policy container_exec_user_attrs[__CONTAINER_EXEC_USER_MAX] = {
	[CONTAINER_EXEC_USER_UID]             = { "uid",            BLOBMSG_TYPE_INT32 },
	[CONTAINER_EXEC_USER_GID]             = { "gid",            BLOBMSG_TYPE_INT32 },
	[CONTAINER_EXEC_USER_ADDITIONAL_GIDS] = { "additionalGids", BLOBMSG_TYPE_ARRAY },
	[CONTAINER_EXEC_USER_UMASK]           = { "umask",          BLOBMSG_TYPE_INT32 },
};

struct container_exec {
	struct ubus_context *ctx;
	struct ubus_request_data req;
	struct uloop_process exec_proc;
	char *pidfile;
	int notify_fd;
	int stdio_fds[STDIO_FDS_NUM];
};

static struct container_exec *current_exec;

static char **container_exec_strarray(struct blob_attr *arr)
{
	struct blob_attr *cur;
	char **out;
	int rem, n = 0;

	blobmsg_for_each_attr(cur, arr, rem)
		++n;

	out = calloc(n + 1, sizeof(char *));
	if (!out)
		return NULL;

	n = 0;
	blobmsg_for_each_attr(cur, arr, rem)
		out[n++] = strdup(blobmsg_get_string(cur));
	out[n] = NULL;
	return out;
}

static void container_exec_free_strarray(char **a)
{
	int i;

	if (!a)
		return;
	for (i = 0; a[i]; i++)
		free(a[i]);
	free(a);
}

static int wait_status_decode(int wstatus)
{
	if (WIFEXITED(wstatus))
		return WEXITSTATUS(wstatus);

	if (WIFSIGNALED(wstatus))
		return 128 + WTERMSIG(wstatus);

	return 255;
}

static void container_exec_done_reply(struct uloop_process *p, int wstatus)
{
	struct container_exec *e = container_of(p, struct container_exec, exec_proc);
	static struct blob_buf bb;
	int status = wait_status_decode(wstatus);

	jail_write_exit_status(e->pidfile, status);
	stdio_fds_close(e->stdio_fds);
	notify_signal(e->notify_fd);
	if (e->notify_fd >= 0)
		close(e->notify_fd);

	blob_buf_init(&bb, 0);
	blobmsg_add_u32(&bb, "status", status);
	ubus_send_reply(e->ctx, &e->req, bb.head);
	ubus_complete_deferred_request(e->ctx, &e->req, 0);
	if (current_exec == e)
		current_exec = NULL;
	free(e->pidfile);
	free(e);
}

static void container_exec_done_reap(struct uloop_process *p, int wstatus)
{
	struct container_exec *e = container_of(p, struct container_exec, exec_proc);

	jail_write_exit_status(e->pidfile, wait_status_decode(wstatus));
	stdio_fds_close(e->stdio_fds);
	notify_signal(e->notify_fd);
	if (e->notify_fd >= 0)
		close(e->notify_fd);

	if (current_exec == e)
		current_exec = NULL;
	free(e->pidfile);
	free(e);
}

static int
container_handle_exec(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[__CONTAINER_EXEC_ATTR_MAX];
	struct blob_attr *tu[__CONTAINER_EXEC_USER_MAX] = { 0 };
	static const char * const ns_names[] = { "user", "ipc", "uts", "net", "cgroup", "pid", "mnt" };
	static const int ns_flags[] = {
		CLONE_NEWUSER, CLONE_NEWIPC, CLONE_NEWUTS, CLONE_NEWNET,
		CLONE_NEWCGROUP, CLONE_NEWPID, CLONE_NEWNS,
	};
	int ns_fds[7] = { -1, -1, -1, -1, -1, -1, -1 };
	char **args = NULL, **env = NULL;
	const char *cwd = "/", *pidfile = NULL;
	const char *console_socket = NULL;
	uint32_t uid, gid;
	bool detach = false;
	bool terminal = false;
	bool exec_nnp = opts.no_new_privs;
	struct jail_capset exec_capset = opts.capset;
	struct rlimit exec_rlimits[RLIM_NLIMITS];
	bool exec_rlimits_set[RLIM_NLIMITS] = { 0 };
	gid_t *exec_additional_gids = NULL;
	size_t exec_num_additional_gids = 0;
	size_t exec_max_additional_gids;
	mode_t exec_umask = opts.umask;
	bool exec_set_umask = opts.set_umask;
	int console_sock_fd = -1;
	bool console_sock_owned = false;
	int cgroup_fd = -1;
	int pipe_fds[2] = { -1, -1 };
	int stdio_fds[STDIO_FDS_NUM] = { -1, -1, -1 };
	int stdio_sock;
	int notify_fd = -1;
	pid_t exec_pid, grandchild = -1;
	struct container_exec *e = NULL;
	char nspath[64];
	int i, rc = UBUS_STATUS_UNKNOWN_ERROR;

	if (jail_oci_state != OCI_STATE_CREATED &&
	    jail_oci_state != OCI_STATE_RUNNING)
		return UBUS_STATUS_INVALID_ARGUMENT;
	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;
	if (current_exec) {
		ERROR("exec: another exec is already in progress\n");
		return UBUS_STATUS_PERMISSION_DENIED;
	}

	uid = (opts.pw_uid > 0) ? (uint32_t)opts.pw_uid : 0;
	gid = (opts.pw_gid > 0) ? (uint32_t)opts.pw_gid : 0;

	for (i = 0; i < RLIM_NLIMITS; i++) {
		if (opts.rlimits[i]) {
			exec_rlimits[i] = *opts.rlimits[i];
			exec_rlimits_set[i] = true;
		}
	}
	{
		long n_max = sysconf(_SC_NGROUPS_MAX);
		if (n_max <= 0)
			n_max = NGROUPS_MAX;
		exec_max_additional_gids = (size_t)n_max;
	}
	if (opts.additional_gids && opts.num_additional_gids <= exec_max_additional_gids) {
		exec_additional_gids = calloc(opts.num_additional_gids, sizeof(gid_t));
		if (!exec_additional_gids) {
			rc = UBUS_STATUS_UNKNOWN_ERROR;
			goto out;
		}
		memcpy(exec_additional_gids, opts.additional_gids,
		       opts.num_additional_gids * sizeof(gid_t));
		exec_num_additional_gids = opts.num_additional_gids;
	}

	stdio_sock = ubus_request_get_caller_fd(req);
	if (stdio_sock > -1) {
		if (stdio_notify_fds_recv(stdio_sock, stdio_fds, &notify_fd))
			ERROR("exec: cannot receive caller descriptors: %m\n");

		close(stdio_sock);
	}

	blobmsg_parse(container_exec_attrs, __CONTAINER_EXEC_ATTR_MAX, tb,
		      blobmsg_data(msg), blobmsg_data_len(msg));

	if (!tb[CONTAINER_EXEC_ATTR_ARGS]) {
		rc = UBUS_STATUS_INVALID_ARGUMENT;
		goto out;
	}

	args = container_exec_strarray(tb[CONTAINER_EXEC_ATTR_ARGS]);
	if (!args || !args[0]) {
		rc = UBUS_STATUS_INVALID_ARGUMENT;
		goto out;
	}

	if (tb[CONTAINER_EXEC_ATTR_ENV])
		env = container_exec_strarray(tb[CONTAINER_EXEC_ATTR_ENV]);
	if (tb[CONTAINER_EXEC_ATTR_CWD])
		cwd = blobmsg_get_string(tb[CONTAINER_EXEC_ATTR_CWD]);
	if (tb[CONTAINER_EXEC_ATTR_PIDFILE])
		pidfile = blobmsg_get_string(tb[CONTAINER_EXEC_ATTR_PIDFILE]);
	if (tb[CONTAINER_EXEC_ATTR_DETACH])
		detach = blobmsg_get_bool(tb[CONTAINER_EXEC_ATTR_DETACH]);
	if (tb[CONTAINER_EXEC_ATTR_TERMINAL])
		terminal = blobmsg_get_bool(tb[CONTAINER_EXEC_ATTR_TERMINAL]);
	if (tb[CONTAINER_EXEC_ATTR_CONSOLE_SOCKET])
		console_socket = blobmsg_get_string(tb[CONTAINER_EXEC_ATTR_CONSOLE_SOCKET]);
	if (tb[CONTAINER_EXEC_ATTR_NO_NEW_PRIVS])
		exec_nnp = blobmsg_get_bool(tb[CONTAINER_EXEC_ATTR_NO_NEW_PRIVS]);
	if (tb[CONTAINER_EXEC_ATTR_CAPABILITIES]) {
		memset(&exec_capset, 0, sizeof(exec_capset));
		if (parseOCIcapabilities(&exec_capset,
					 tb[CONTAINER_EXEC_ATTR_CAPABILITIES])) {
			rc = UBUS_STATUS_INVALID_ARGUMENT;
			goto out;
		}
	}
	if (tb[CONTAINER_EXEC_ATTR_RLIMITS]) {
		struct blob_attr *cur;
		int rem;

		blobmsg_for_each_attr(cur, tb[CONTAINER_EXEC_ATTR_RLIMITS], rem) {
			struct blob_attr *rl[__OCI_PROCESS_RLIMIT_MAX];
			int rlt;

			blobmsg_parse(oci_process_rlimit_policy, __OCI_PROCESS_RLIMIT_MAX,
				      rl, blobmsg_data(cur), blobmsg_len(cur));
			if (!rl[OCI_PROCESS_RLIMIT_TYPE] ||
			    !rl[OCI_PROCESS_RLIMIT_SOFT] ||
			    !rl[OCI_PROCESS_RLIMIT_HARD])
				continue;
			rlt = resolve_rlimit(blobmsg_get_string(rl[OCI_PROCESS_RLIMIT_TYPE]));
			if (rlt < 0)
				continue;
			exec_rlimits[rlt].rlim_cur = blobmsg_cast_u64(rl[OCI_PROCESS_RLIMIT_SOFT]);
			exec_rlimits[rlt].rlim_max = blobmsg_cast_u64(rl[OCI_PROCESS_RLIMIT_HARD]);
			exec_rlimits_set[rlt] = true;
		}
	}
	if (tb[CONTAINER_EXEC_ATTR_USER]) {
		blobmsg_parse(container_exec_user_attrs, __CONTAINER_EXEC_USER_MAX, tu,
			      blobmsg_data(tb[CONTAINER_EXEC_ATTR_USER]),
			      blobmsg_len(tb[CONTAINER_EXEC_ATTR_USER]));
		if (tu[CONTAINER_EXEC_USER_UID])
			uid = blobmsg_get_u32(tu[CONTAINER_EXEC_USER_UID]);
		if (tu[CONTAINER_EXEC_USER_GID])
			gid = blobmsg_get_u32(tu[CONTAINER_EXEC_USER_GID]);
		if (tu[CONTAINER_EXEC_USER_UMASK]) {
			exec_umask = blobmsg_get_u32(tu[CONTAINER_EXEC_USER_UMASK]);
			exec_set_umask = true;
		}
		if (tu[CONTAINER_EXEC_USER_ADDITIONAL_GIDS]) {
			struct blob_attr *cur;
			int rem;
			size_t count = 0;

			blobmsg_for_each_attr(cur, tu[CONTAINER_EXEC_USER_ADDITIONAL_GIDS], rem)
				count++;

			if (count > exec_max_additional_gids)
				count = exec_max_additional_gids;

			free(exec_additional_gids);
			exec_additional_gids = count ? calloc(count, sizeof(gid_t)) : NULL;
			if (count && !exec_additional_gids) {
				rc = UBUS_STATUS_UNKNOWN_ERROR;
				goto out;
			}

			exec_num_additional_gids = 0;
			blobmsg_for_each_attr(cur, tu[CONTAINER_EXEC_USER_ADDITIONAL_GIDS], rem) {
				if (exec_num_additional_gids >= count)
					break;
				exec_additional_gids[exec_num_additional_gids++] =
					blobmsg_get_u32(cur);
			}
		}
	}

	for (i = 0; i < (int)ARRAY_SIZE(ns_names); i++) {
		struct stat nsst, ownst;

		snprintf(nspath, sizeof(nspath), "/proc/%d/ns/%s",
			 jail_process.pid, ns_names[i]);
		ns_fds[i] = open(nspath, O_RDONLY | O_CLOEXEC);
		if (ns_fds[i] < 0) {
			if (ns_flags[i] == CLONE_NEWCGROUP ||
			    ns_flags[i] == CLONE_NEWUSER)
				continue;

			ERROR("exec: open %s: %m\n", nspath);
			goto out;
		}

		snprintf(nspath, sizeof(nspath), "/proc/self/ns/%s", ns_names[i]);
		if (fstat(ns_fds[i], &nsst) || stat(nspath, &ownst))
			continue;

		/* joining a namespace we are already in fails for CLONE_NEWUSER */
		if (nsst.st_dev != ownst.st_dev || nsst.st_ino != ownst.st_ino)
			continue;

		close(ns_fds[i]);
		ns_fds[i] = -1;
	}

	if (terminal != !!console_socket) {
		ERROR("exec: terminal and consolesocket must be set together\n");
		rc = UBUS_STATUS_INVALID_ARGUMENT;
		goto out;
	}

	if (terminal && console_socket) {
		console_sock_fd = open_console_sock(console_socket, &console_sock_owned, true);
		if (console_sock_fd < 0)
			goto out;
	}

	cgroup_fd = cgroups_open_dir();
	if (cgroup_fd < 0)
		DEBUG("exec: cgroups_open_dir unavailable, will fall back to cgroups_attach_pid\n");

	if (pipe(pipe_fds) < 0) {
		ERROR("exec: pipe: %m\n");
		goto out;
	}

	exec_pid = fork();
	if (exec_pid < 0) {
		ERROR("exec: fork: %m\n");
		goto out;
	}

	if (exec_pid == 0) {
		int wstatus;
		int slave_fd = -1;

		close(pipe_fds[0]);
		for (i = 0; i < (int)ARRAY_SIZE(ns_names); i++) {
			if (ns_fds[i] < 0)
				continue;
			/*
			 * the cgroup namespace hides our own cgroup, which the
			 * kernel needs to see to honour CLONE_INTO_CGROUP, so
			 * the grandchild joins it once it has been placed
			 */
			if (ns_flags[i] == CLONE_NEWCGROUP)
				continue;

			if (setns(ns_fds[i], ns_flags[i]) < 0) {
				ERROR("exec: setns(%s): %m\n", ns_names[i]);
				_exit(126);
			}
		}

		if (terminal && console_sock_fd >= 0) {
			int master_fd;
			char *slave_name;

			master_fd = posix_openpt(O_RDWR | O_NOCTTY);
			if (master_fd < 0)
				_exit(126);
			if (grantpt(master_fd) || unlockpt(master_fd))
				_exit(126);
			slave_name = ptsname(master_fd);
			if (!slave_name)
				_exit(126);
			slave_fd = open(slave_name, O_RDWR | O_NOCTTY);
			if (slave_fd < 0)
				_exit(126);
			if (sendmsg_console_fd(console_sock_fd, master_fd, slave_name) < 0)
				_exit(126);
			close(console_sock_fd);
			close(master_fd);
		}

		{
			struct clone_args gargs = {
				.exit_signal = SIGCHLD,
			};
			if (cgroup_fd >= 0) {
				gargs.flags = CLONE_INTO_CGROUP;
				gargs.cgroup = (__u64)cgroup_fd;
			}
			grandchild = jail_clone3(&gargs);
		}
		if (grandchild < 0) {
			ERROR("exec: clone3: %m\n");
			_exit(126);
		}

		if (grandchild == 0) {
			int j;

			for (j = 0; j < (int)ARRAY_SIZE(ns_names); j++) {
				if (ns_flags[j] != CLONE_NEWCGROUP || ns_fds[j] < 0)
					continue;
				if (setns(ns_fds[j], CLONE_NEWCGROUP) < 0)
					_exit(127);
			}

			for (j = 0; j < RLIM_NLIMITS; j++)
				if (exec_rlimits_set[j] &&
				    setrlimit(j, &exec_rlimits[j]) < 0) {
					ERROR("exec: setrlimit(%d): %m\n", j);
					_exit(127);
				}
			if (slave_fd >= 0) {
				if (setsid() < 0)
					_exit(127);
				if (ioctl(slave_fd, TIOCSCTTY, 0) < 0)
					_exit(127);
				dup2(slave_fd, STDIN_FILENO);
				dup2(slave_fd, STDOUT_FILENO);
				dup2(slave_fd, STDERR_FILENO);
				if (slave_fd > STDERR_FILENO)
					close(slave_fd);
			} else if (stdio_fds[1] > -1) {
				for (j = 0; j < STDIO_FDS_NUM; j++) {
					if (dup2(stdio_fds[j], j) < 0)
						_exit(127);
					if (stdio_fds[j] > STDERR_FILENO)
						close(stdio_fds[j]);
				}
			}
			if (exec_set_umask)
				umask(exec_umask);

			if ((uid || gid || exec_num_additional_gids) &&
			    exec_capset.apply) {
				if (prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP)) {
					ERROR("exec: prctl(PR_SET_SECUREBITS): %m\n");
					_exit(127);
				}
				if (applyOCIcapabilities(exec_capset,
							 (1LLU << CAP_SETGID) |
							 (1LLU << CAP_SETUID) |
							 (1LLU << CAP_SETPCAP))) {
					ERROR("exec: applyOCIcapabilities(pre): failed\n");
					_exit(127);
				}
			}

			if (setgroups(exec_num_additional_gids,
				      exec_num_additional_gids ? exec_additional_gids : NULL) < 0) {
				ERROR("exec: setgroups: %m\n");
				_exit(127);
			}
			if (gid && setresgid(gid, gid, gid) < 0) {
				ERROR("exec: setresgid(%u): %m\n", gid);
				_exit(127);
			}
			if (uid && setresuid(uid, uid, uid) < 0) {
				ERROR("exec: setresuid(%u): %m\n", uid);
				_exit(127);
			}

			if (exec_capset.apply &&
			    applyOCIcapabilities(exec_capset, 0)) {
				ERROR("exec: applyOCIcapabilities: failed\n");
				_exit(127);
			}
			if (exec_nnp && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
				ERROR("exec: prctl(PR_SET_NO_NEW_PRIVS): %m\n");
				_exit(127);
			}
			if (opts.mdwe_flags &&
			    prctl(PR_SET_MDWE, opts.mdwe_flags, 0, 0, 0)) {
				ERROR("exec: prctl(PR_SET_MDWE): %m\n");
				_exit(127);
			}
			if (chdir(cwd) < 0) {
				ERROR("exec: chdir(%s): %m\n", cwd);
				_exit(127);
			}
			syscall(SYS_close_range, 3, ~0U, CLOSE_RANGE_CLOEXEC);
			if (env)
				execvpe(args[0], args, env);
			else
				execvp(args[0], args);
			ERROR("exec: execvpe(%s): %m\n", args[0]);
			_exit(127);
		}

		if (slave_fd >= 0)
			close(slave_fd);

		(void)!write(pipe_fds[1], &grandchild, sizeof(grandchild));
		close(pipe_fds[1]);

		if (waitpid(grandchild, &wstatus, 0) < 0) {
			ERROR("exec: waitpid(%d): %m\n", grandchild);
			_exit(126);
		}

		if (WIFEXITED(wstatus))
			_exit(WEXITSTATUS(wstatus));
		_exit(128 + WTERMSIG(wstatus));
	}

	close(pipe_fds[1]);
	pipe_fds[1] = -1;
	{
		char gcbuf[sizeof(pid_t)];
		size_t off = 0;
		ssize_t n;

		while (off < sizeof(gcbuf)) {
			n = read(pipe_fds[0], gcbuf + off, sizeof(gcbuf) - off);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				grandchild = -1;
				break;
			}
			if (n == 0) {
				grandchild = -1;
				break;
			}
			off += (size_t)n;
		}
		if (off == sizeof(gcbuf))
			memcpy(&grandchild, gcbuf, sizeof(grandchild));
		else
			grandchild = -1;
	}
	close(pipe_fds[0]);
	pipe_fds[0] = -1;

	for (i = 0; i < (int)ARRAY_SIZE(ns_names); i++)
		if (ns_fds[i] >= 0) {
			close(ns_fds[i]);
			ns_fds[i] = -1;
		}

	if (console_sock_owned && console_sock_fd >= 0) {
		close(console_sock_fd);
		console_sock_fd = -1;
	}

	if (cgroup_fd >= 0) {
		close(cgroup_fd);
		cgroup_fd = -1;
	} else if (grandchild > 0) {
		cgroups_attach_pid(grandchild);
	}

	container_exec_free_strarray(args);
	container_exec_free_strarray(env);
	args = env = NULL;
	free(exec_additional_gids);
	exec_additional_gids = NULL;

	jail_clear_exit_status(pidfile);

	if (pidfile && grandchild > 0) {
		FILE *pf = fopen(pidfile, "w");
		if (pf) {
			fprintf(pf, "%d", grandchild);
			fclose(pf);
		}
	}

	e = calloc(1, sizeof(*e));
	if (!e) {
		stdio_fds_close(stdio_fds);
		if (notify_fd >= 0)
			close(notify_fd);
		kill(exec_pid, SIGKILL);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	for (i = 0; i < STDIO_FDS_NUM; i++) {
		e->stdio_fds[i] = stdio_fds[i];
		stdio_fds[i] = -1;
	}
	e->ctx = ctx;
	e->exec_proc.pid = exec_pid;
	e->notify_fd = notify_fd;
	notify_fd = -1;
	if (pidfile)
		e->pidfile = strdup(pidfile);
	current_exec = e;

	if (detach) {
		static struct blob_buf bb;

		blob_buf_init(&bb, 0);
		if (grandchild > 0)
			blobmsg_add_u32(&bb, "pid", grandchild);
		ubus_send_reply(ctx, req, bb.head);

		e->exec_proc.cb = container_exec_done_reap;
		uloop_process_add(&e->exec_proc);
		return UBUS_STATUS_OK;
	}

	e->exec_proc.cb = container_exec_done_reply;
	uloop_process_add(&e->exec_proc);
	ubus_defer_request(ctx, req, &e->req);
	return UBUS_STATUS_OK;

out:
	stdio_fds_close(stdio_fds);
	if (notify_fd >= 0)
		close(notify_fd);
	for (i = 0; i < (int)ARRAY_SIZE(ns_names); i++)
		if (ns_fds[i] >= 0)
			close(ns_fds[i]);
	if (pipe_fds[0] >= 0)
		close(pipe_fds[0]);
	if (pipe_fds[1] >= 0)
		close(pipe_fds[1]);
	if (console_sock_owned && console_sock_fd >= 0)
		close(console_sock_fd);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	container_exec_free_strarray(args);
	container_exec_free_strarray(env);
	free(exec_additional_gids);
	return rc;
}

static int
jail_writepid(pid_t pid)
{
	FILE *_pidfile;

	if (!opts.pidfile)
		return 0;

	jail_clear_exit_status(opts.pidfile);

	_pidfile = fopen(opts.pidfile, "w");
	if (_pidfile == NULL)
		return errno;

	if (fprintf(_pidfile, "%d", pid) < 0) {
		fclose(_pidfile);
		return errno;
	}

	if (fclose(_pidfile))
		return errno;

	return 0;
}

static int checkpath(const char *path)
{
	struct open_how how = {
		.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
		.resolve = RESOLVE_NO_MAGICLINKS,
	};
	int dirfd = sys_openat2(AT_FDCWD, path, &how, sizeof(how));
	if (dirfd < 0) {
		ERROR("path %s open failed %m\n", path);
		return -1;
	}
	close(dirfd);

	return 0;
}

static void prime_jail_mount(const char *path)
{
	int fd;

	if (!path)
		return;

	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd >= 0)
		close(fd);
}

static int add_volume_source(const char *source)
{
	char **tmp;

	tmp = realloc(volume_sources, (num_volume_sources + 1) * sizeof(*volume_sources));
	if (!tmp)
		return -ENOMEM;

	volume_sources = tmp;
	volume_sources[num_volume_sources] = strdup(source);
	if (!volume_sources[num_volume_sources])
		return -ENOMEM;

	++num_volume_sources;
	return 0;
}

static void add_volume(const char *source, const char *dest)
{
	char *real;

	real = resolve_mount_source(source);
	add_volume_source(real ? real : source);
	add_mount_volume(real ? real : source, dest, 0);
	free(real);
}

static struct ubus_method container_methods[] = {
	UBUS_METHOD_NOARG("start", handle_start),
	UBUS_METHOD_NOARG("state", handle_state),
	UBUS_METHOD("kill", container_handle_kill, container_kill_attrs),
	UBUS_METHOD_NOARG("pause", container_handle_pause),
	UBUS_METHOD_NOARG("resume", container_handle_resume),
	UBUS_METHOD("reclaim", container_handle_reclaim, container_reclaim_attrs),
	UBUS_METHOD_NOARG("update", container_handle_update),
	UBUS_METHOD("exec", container_handle_exec, container_exec_attrs),
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
	int credidx;
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
	opts.notify_fd = -1;

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
		case 'x':
			opts.envfile = optarg;
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
		case 'b':
			if (!opts.ocibundle)
				opts.namespace |= CLONE_NEWNS;
			tmp = strchr(optarg, ':');
			if (tmp) {
				*(tmp++) = '\0';
				add_2paths_nodeps(optarg, tmp, 1, 0);
			} else {
				add_2paths_nodeps(optarg, optarg, 1, 0);
			}
			break;
		case 'r':
			if (!opts.ocibundle)
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
			if (!opts.ocibundle)
				opts.namespace |= CLONE_NEWNS;
			tmp = strchr(optarg, ':');
			if (tmp) {
				*(tmp++) = '\0';
				add_2paths_and_deps(optarg, tmp, 0, 0, 0);
			} else {
				add_path_and_deps(optarg, 0, 0, 0);
			}
			break;
		case 'k':
			if (!opts.ocibundle)
				opts.namespace |= CLONE_NEWNS;
			tmp = strchr(optarg, ':');
			if (!tmp) {
				ERROR("credential needs a src:dest pair: %s\n", optarg);
				return -1;
			}
			*(tmp++) = '\0';
			if (add_2paths_and_deps(optarg, tmp, 1, 0, 0))
				return -1;
			if (n_cred_targets < JAIL_MAX_CREDENTIALS)
				cred_targets[n_cred_targets++] = strdup(tmp);
			break;
		case 'V':
			tmp = strchr(optarg, ':');
			if (!tmp) {
				ERROR("volume needs a src:dest pair: %s\n", optarg);
				return -1;
			}
			*(tmp++) = '\0';
			add_volume(optarg, tmp);
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
		case 'I':
			opts.idmap_offset = strtoul(optarg, NULL, 10);
			jail_set_idmap_offset(opts.idmap_offset);
			break;
		case 'P':
			opts.pidfile = optarg;
			break;
		case 'a':
			opts.notify_fd = atoi(optarg);
			if (opts.notify_fd <= STDERR_FILENO ||
			    fcntl(opts.notify_fd, F_SETFD, FD_CLOEXEC) ||
			    syscall(SYS_pidfd_send_signal, opts.notify_fd, 0, NULL, 0))
				opts.notify_fd = -1;
			break;
		case 'Y':
			opts.console_socket = optarg;
			break;
		case 'Z':
			opts.systemd_cgroup = true;
			break;
		case 'm':
			if (!strcmp(optarg, "trace"))
				opts.seccomp_mode = SECCOMP_MODE_TRACE;
			else if (!strcmp(optarg, "audit"))
				opts.seccomp_mode = SECCOMP_MODE_AUDIT;
			else if (!strcmp(optarg, "complain"))
				opts.seccomp_mode = SECCOMP_MODE_COMPLAIN;
			else
				opts.seccomp_mode = SECCOMP_MODE_ENFORCE;
			break;
		case 'M':
			opts.seccomp_log = optarg;
			break;
		}
	}

	if (opts.console_socket && parse_inherited_console_fd(opts.console_socket) < 0) {
		static char fdspec[16];
		bool owned;
		int csfd;

		csfd = open_console_sock(opts.console_socket, &owned, false);
		if (csfd >= 0) {
			fcntl(csfd, F_SETFD, 0);
			snprintf(fdspec, sizeof(fdspec), "%d", csfd);
			opts.console_socket = fdspec;
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

		/* stdout and stderr belong to the container, not to us */
		ulog_open(ULOG_SYSLOG, LOG_DAEMON, "jail");

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

	for (credidx = 0; credidx < n_cred_targets; credidx++) {
		ret = fs_mount_enable_idmap(cred_targets[credidx],
					    opts.pw_uid > 0 ? (uint32_t)opts.pw_uid : 0,
					    opts.pw_gid > 0 ? (uint32_t)opts.pw_gid : 0);
		if (ret) {
			ERROR("failed to idmap credential %s: %s\n",
			      cred_targets[credidx], strerror(ret));
			ret = -1;
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
		(opts.seccomp_mode != SECCOMP_MODE_ENFORCE) ||
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

	if (opts.seccomp && !opts.ociseccomp &&
	    seccomp_compile_file(opts.seccomp)) {
		ERROR("failed to compile seccomp filter %s\n", opts.seccomp);
		opts.seccomp = 0;
		if (opts.require_jail) {
			ret=-1;
			goto errout;
		}
	}

	uloop_timeout_add(&post_main_timeout);
	uloop_run();

errout:
	free_and_exit(ret);
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

static int run_uxc_net(const char *action)
{
	char *argv[] = { "/sbin/uxc-net", opts.name, (char *)action, opts.ocibundle, NULL };
	pid_t pid;
	int status;

	if (!opts.ocibundle || !opts.name)
		return 0;

	pid = fork();
	if (pid == 0) {
		execv(argv[0], argv);
		ERROR("failed to execv uxc-net: %m\n");
		_exit(127);
	} else if (pid < 0) {
		ERROR("uxc-net fork error: %m\n");
		return -1;
	}

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR);

	return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

static void post_main(struct uloop_timeout *t)
{
	int child_status;

	if (apply_rlimits()) {
		ERROR("error applying resource limits\n");
		free_and_exit(EXIT_FAILURE);
	}

	if (opts.name)
		prctl(PR_SET_NAME, opts.name, NULL, NULL, NULL);

	if (pipe(&pipes[0]) < 0)
		free_and_exit(-1);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, &pipes[2]) < 0)
		free_and_exit(-1);

	if (pipe2(&userns_pipe[0], O_CLOEXEC) < 0 || pipe2(&userns_pipe[2], O_CLOEXEC) < 0)
		free_and_exit(-1);

	parent_pidfd = syscall(SYS_pidfd_open, getpid(), 0);

	if (pipe2(exec_ack, O_CLOEXEC) < 0)
		free_and_exit(-1);

	if (opts.ocibundle)
		cgroups_create();

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
				} else if (opts.private_netifd) {
					char hostdir[PATH_MAX], hostresolv[PATH_MAX];
					int hostresolvfd;

					snprintf(hostdir, PATH_MAX, "/tmp/resolv.conf-%s.d", opts.name);
					if (mkdir_p(hostdir, 0755)) {
						ERROR("mkdir(%s) failed: %m\n", hostdir);
						free_and_exit(-1);
					}
					snprintf(hostresolv, PATH_MAX, "%s/resolv.conf.auto", hostdir);
					hostresolvfd = open(hostresolv, O_WRONLY | O_CREAT, 0644);
					if (hostresolvfd >= 0)
						close(hostresolvfd);
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
				 * Mounts are established in the order they are added, so the three
				 * steps are registered in exactly the order they have to happen in.
				 *
				 * A jail that defers its own CLONE_NEWUSER applies this (and all other
				 * default masking below) itself in phase 2, once it regains its own
				 * mount namespace: a mount locked here, while still privileged, can
				 * never be replaced by that same, now less-privileged phase, since a
				 * locked mount stays present underneath anything mounted over it and
				 * still counts against the kernel's mount-visibility check for any
				 * nested runtime's own /proc mount.
				 */
				if (!defer_userns && !mount_is_defined("/proc/sys")) {
					if (opts.namespace & CLONE_NEWNET)
						add_mount_inner("/proc/sys/net", "/proc/self/net", NULL, MS_BIND, 0, NULL, -1);

					if (!add_mount(NULL, "/proc/sys", NULL, MS_BIND | MS_RDONLY, 0, NULL, -1) &&
					    (opts.namespace & CLONE_NEWNET))
						add_mount_inner("/proc/self/net", "/proc/sys/net", NULL, MS_MOVE, 0, NULL, -1);
				}

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

		if ((opts.namespace & CLONE_NEWNS) && prepare_jail_dev()) {
			ERROR("prepare_jail_dev() failed\n");
			free_and_exit(EXIT_FAILURE);
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

		if (opts.console) {
			char *slave_name;
			int parent_master;

			parent_master = posix_openpt(O_RDWR | O_NOCTTY);
			if (parent_master < 0) {
				ERROR("posix_openpt: %m\n");
				free_and_exit(-1);
			}
			if (grantpt(parent_master) || unlockpt(parent_master) ||
			    !(slave_name = ptsname(parent_master))) {
				ERROR("grantpt/unlockpt/ptsname failed\n");
				close(parent_master);
				free_and_exit(-1);
			}
			if (opts.console_height && opts.console_width) {
				struct winsize ws = {
					.ws_row = opts.console_height,
					.ws_col = opts.console_width,
				};
				ioctl(parent_master, TIOCSWINSZ, &ws);
			}
			strncpy(console_slave_name, slave_name, sizeof(console_slave_name) - 1);
			console_slave_name[sizeof(console_slave_name) - 1] = '\0';
			if (opts.console_socket) {
				if (send_console_fd(opts.console_socket, parent_master, slave_name)) {
					ERROR("send_console_fd failed\n");
					close(parent_master);
					free_and_exit(-1);
				}
				close(parent_master);
			} else {
				console_fd = parent_master;
				if ((opts.namespace & CLONE_NEWUSER) && seteuid(0)) {
					ERROR("seteuid(0) failed: %m\n");
					free_and_exit(EXIT_FAILURE);
				}
				pass_console(console_fd);
				if ((opts.namespace & CLONE_NEWUSER) && seteuid(opts.root_map_uid)) {
					ERROR("seteuid(%d) failed: %m\n", opts.root_map_uid);
					free_and_exit(EXIT_FAILURE);
				}
			}
		}

		/*
		 * CLONE_NEWUSER is excluded here; the child creates its own
		 * later, in enter_userns(). See exec_jail() for why.
		 */
		int init_cgroup_fd = -1;
		struct clone_args cargs = {
			.flags = (opts.namespace & ~(CLONE_NEWCGROUP | CLONE_NEWUSER | CLONE_NEWTIME)) | CLONE_PIDFD,
			.pidfd = (__u64)(uintptr_t)&jail_process_pidfd,
			.exit_signal = SIGCHLD,
		};

		if (opts.ocibundle) {
			init_cgroup_fd = cgroups_open_dir();
			if (init_cgroup_fd >= 0) {
				cargs.flags |= CLONE_INTO_CGROUP;
				cargs.cgroup = (__u64)init_cgroup_fd;
			}
		}

		prime_jail_mount(opts.extroot);
		prime_jail_mount(opts.overlaydir);
		for (size_t i = 0; i < (size_t)num_volume_sources; i++)
			prime_jail_mount(volume_sources[i]);

		jail_process.pid = jail_clone3(&cargs);
		if (init_cgroup_fd >= 0)
			close(init_cgroup_fd);
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
		if (exec_ack[1] >= 0) {
			close(exec_ack[1]);
			exec_ack[1] = -1;
		}
		if (exec_ack[0] >= 0) {
			exec_ack_uloop.fd = exec_ack[0];
			uloop_fd_add(&exec_ack_uloop, ULOOP_READ);
		}
		if (read(pipes[0], sig_buf, 1) < 1) {
			child_status = 0;
			if (waitpid(jail_process.pid, &child_status, 0) == jail_process.pid &&
			    WIFSIGNALED(child_status))
				ERROR("can't read from child: killed by signal %d\n", WTERMSIG(child_status));
			else if (WIFEXITED(child_status))
				ERROR("can't read from child: exited %d\n", WEXITSTATUS(child_status));
			else
				ERROR("can't read from child\n");
			free_and_exit(-1);
		}
		close(pipes[0]);
		set_oom_score_adj();

		if (opts.ocibundle) {
			cgroups_configure();
			cgroups_attach_pid(jail_process.pid);
		}

		if (jail_idmap_active()) {
			num_idmap_fds = jail_idmap_build(opts.extroot,
							 opts.uidmappings, opts.gidmappings,
							 idmap_fds, JAIL_IDMAP_MAX_FDS);
			if (num_idmap_fds < 0) {
				ERROR("failed to build idmapped jail mounts\n");
				free_and_exit(-1);
			}

			jail_chown_writable_surfaces();
		}

		if ((opts.namespace & CLONE_NEWNET) && opts.name && opts.ocibundle)
			run_uxc_net("up");

		if ((opts.namespace & CLONE_NEWNET) && opts.name)
			jail_network_attach(parent_ctx, opts.name, jail_process.pid);

		if ((opts.namespace & CLONE_NEWNET) && opts.private_ubus) {
			if (!jail_network_start(parent_ctx, opts.name, jail_process.pid,
						opts.private_netifd))
				opts.jail_network_started = true;
		}

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

static void emit_instance_event(const char *event)
{
	if (!opts.ocibundle || !opts.name || !parent_ctx)
		return;
	blob_buf_init(&notify_buf, 0);
	blobmsg_add_string(&notify_buf, "service", opts.name);
	blobmsg_add_string(&notify_buf, "instance", opts.name);
	ubus_send_event(parent_ctx, event, notify_buf.head);
}

static void exec_ack_cb(struct uloop_fd *fd, unsigned int events)
{
	char buf[8];
	ssize_t n;

	n = read(fd->fd, buf, sizeof(buf));
	if (n < 0 && errno == EINTR)
		return;

	uloop_fd_delete(fd);
	close(fd->fd);
	exec_ack[0] = -1;

	if (n != 0) {
		ERROR("container.start: exec_ack read=%zd errno=%m\n", n);
		return;
	}

	if (jail_dev_staged) {
		umount2(jail_dev, MNT_DETACH);
		rmdir(jail_dev);
		jail_dev_staged = false;
	}

	emit_instance_event("instance.running");
}

static void post_poststart(void);
static void post_create_runtime(void)
{
	if (hook_chain_failed) {
		ERROR("createRuntime hook failed; aborting container\n");
		free_and_exit(EXIT_FAILURE);
	}

	if (sock_send_fds(pipes[3], 'O', idmap_fds, num_idmap_fds) < 0) {
		ERROR("can't write to child\n");
		free_and_exit(-1);
	}

	while (num_idmap_fds > 0)
		close(idmap_fds[--num_idmap_fds]);

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
	emit_instance_event("instance.ready");

	if (opts.ocibundle && !opts.immediately)
		uloop_run(); /* wait for 'start' command via ubus */
	else
		pipe_send_start_container(NULL);
}

static bool jail_ptrace_seccomp(void)
{
	if (opts.seccomp_mode == SECCOMP_MODE_TRACE)
		return true;

	return opts.ociseccomp && !seccomp_oci_needs_inproc();
}

static void jail_seccomp_run(void)
{
	struct seccomp_trace_opts t = {
		.mode = opts.seccomp_mode,
		.name = opts.name ? opts.name : "trace",
		.log_fd = -1,
		.main_boundary = (opts.seccomp_mode == SECCOMP_MODE_TRACE),
		.dedup = 0,
	};
	int fd = -1;

	if (opts.seccomp_log) {
		fd = open(opts.seccomp_log, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0)
			ERROR("seccomp-trace: cannot open log %s: %m\n", opts.seccomp_log);
		t.log_fd = fd;
	}

	seccomp_trace_run(jail_process.pid, &t);

	if (fd >= 0)
		close(fd);

	free_and_exit(0);
}

static bool seccomp_target_is_static(pid_t pid)
{
	unsigned long pair[2];
	bool dynamic = false;
	char path[32];
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/auxv", (int)pid);
	f = fopen(path, "rb");
	if (!f)
		return false;

	while (fread(pair, sizeof(pair), 1, f) == 1) {
		if (pair[0] == 0)
			break;
		if (pair[0] == 7 && pair[1])
			dynamic = true;
	}
	fclose(f);
	return !dynamic;
}

static bool seccomp_main_trackable(pid_t pid)
{
	unsigned long at_entry, lsm;
	int main_argidx;

	if (seccomp_marker_addrs(pid, &at_entry, &lsm, &main_argidx))
		return false;

	return lsm != 0;
}

static int jail_seccomp_handshake(void)
{
	struct sock_fprog *aprog;
	int status, rc, mrc;

	if (!jail_ptrace_seccomp())
		return 0;

	while (waitpid(jail_process.pid, &status, 0) < 0) {
		if (errno == EINTR)
			continue;
		ERROR("seccomp-inject: waitpid: %m\n");
		return -1;
	}

	if (!WIFSTOPPED(status)) {
		if (WIFEXITED(status))
			ERROR("seccomp-inject: jail exited (code %d) before entrypoint exec\n", WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			ERROR("seccomp-inject: jail killed by signal %d before entrypoint exec\n", WTERMSIG(status));
		else
			ERROR("seccomp-inject: jail exited before entrypoint exec\n");
		uloop_process_delete(&jail_process);
		jail_process_handler(&jail_process, status);
		return -1;
	}

	if (opts.seccomp_mode == SECCOMP_MODE_TRACE)
		jail_seccomp_run();

	if (opts.seccomp_mode == SECCOMP_MODE_ENFORCE &&
	    seccomp_target_is_static(jail_process.pid)) {
		if (opts.ociseccomp_init &&
		    seccomp_main_trackable(jail_process.pid)) {
			if (seccomp_inject(jail_process.pid, opts.ociseccomp_init)) {
				ERROR("seccomp-inject: failed to arm init filter\n");
				ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
				return -1;
			}
			if (seccomp_run_to_main(jail_process.pid)) {
				ERROR("seccomp-inject: failed to reach main\n");
				ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
				return -1;
			}
			if (opts.ociseccomp_delta_main &&
			    seccomp_inject(jail_process.pid, opts.ociseccomp_delta_main)) {
				ERROR("seccomp-inject: failed to arm main delta\n");
				ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
				return -1;
			}
		} else if (seccomp_inject(jail_process.pid, opts.ociseccomp)) {
			ERROR("seccomp-inject: failed to arm filter\n");
			ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
			return -1;
		}
		if (ptrace(PTRACE_DETACH, jail_process.pid, 0, 0)) {
			ERROR("seccomp-inject: PTRACE_DETACH: %m\n");
			return -1;
		}
		return 0;
	}

	if (opts.seccomp_mode == SECCOMP_MODE_ENFORCE && !opts.ociseccomp_linker) {
		if (seccomp_inject(jail_process.pid, opts.ociseccomp)) {
			ERROR("seccomp-inject: failed to arm filter\n");
			ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
			return -1;
		}
		if (ptrace(PTRACE_DETACH, jail_process.pid, 0, 0)) {
			ERROR("seccomp-inject: PTRACE_DETACH: %m\n");
			return -1;
		}
		return 0;
	}

	if (opts.seccomp_mode == SECCOMP_MODE_ENFORCE && opts.ociseccomp_linker &&
	    seccomp_inject(jail_process.pid, opts.ociseccomp_linker)) {
		ERROR("seccomp-inject: failed to arm linker filter\n");
		ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
		return -1;
	}

	if (seccomp_run_to_entry(jail_process.pid)) {
		ERROR("seccomp-inject: failed to reach entry point\n");
		ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
		return -1;
	}

	if (opts.seccomp_mode == SECCOMP_MODE_AUDIT ||
	    opts.seccomp_mode == SECCOMP_MODE_COMPLAIN) {
		aprog = seccomp_oci_audit_filter(opts.ociseccomp);
		if (!aprog) {
			ERROR("seccomp-trace: failed to build audit filter\n");
			ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
			return -1;
		}
		rc = seccomp_inject(jail_process.pid, aprog);
		free(aprog->filter);
		free(aprog);
		if (rc) {
			ERROR("seccomp-trace: failed to arm audit filter\n");
			ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
			return -1;
		}
		jail_seccomp_run();
	}

	if (opts.seccomp_mode == SECCOMP_MODE_ENFORCE) {
		if (opts.ociseccomp_delta_entry &&
		    seccomp_inject(jail_process.pid, opts.ociseccomp_delta_entry)) {
			ERROR("seccomp-inject: failed to arm entry delta\n");
			ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
			return -1;
		}
	} else if (opts.ociseccomp_init &&
		   seccomp_inject(jail_process.pid, opts.ociseccomp_init)) {
		ERROR("seccomp-inject: failed to arm init filter\n");
		ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
		return -1;
	}

	mrc = seccomp_run_to_main_from_entry(jail_process.pid);
	if (mrc < 0) {
		ERROR("seccomp-inject: failed to reach main\n");
		ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
		return -1;
	}

	if (opts.seccomp_mode == SECCOMP_MODE_ENFORCE) {
		if (opts.ociseccomp_delta_main &&
		    seccomp_inject(jail_process.pid, opts.ociseccomp_delta_main)) {
			ERROR("seccomp-inject: failed to arm main delta\n");
			ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
			return -1;
		}
	} else if (seccomp_inject(jail_process.pid, opts.ociseccomp)) {
		ERROR("seccomp-inject: failed to arm filter\n");
		ptrace(PTRACE_KILL, jail_process.pid, 0, 0);
		return -1;
	}

	if (ptrace(PTRACE_DETACH, jail_process.pid, 0, 0)) {
		ERROR("seccomp-inject: PTRACE_DETACH: %m\n");
		return -1;
	}

	return 0;
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

	if (jail_seccomp_handshake())
		free_and_exit(-1);

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
		jail_pidfd_send_signal(SIGTERM);
		uloop_timeout_set(&jail_process_timeout, 1000);
		uloop_run();
	}
	uloop_done();
	poststop();
}

static void post_poststop(void);
static void poststop(void) {
	if (opts.jail_network_started) {
		jail_network_teardown();
		opts.jail_network_started = false;
	}
	if ((opts.namespace & CLONE_NEWNET) && opts.name && opts.ocibundle)
		run_uxc_net("down");
	run_hooks(opts.hooks.poststop, post_poststop);
}

static void post_poststop(void)
{
	if (jail_process_pidfd >= 0) {
		close(jail_process_pidfd);
		jail_process_pidfd = -1;
	}
	free_and_exit(jail_return_code);
}
