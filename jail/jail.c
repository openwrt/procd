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
#include <linux/filter.h>
#include <signal.h>

#include "capabilities.h"
#include "elf.h"
#include "fs.h"
#include "jail.h"
#include "log.h"
#include "seccomp-oci.h"

#include <libubox/utils.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/list.h>
#include <libubox/vlist.h>
#include <libubox/uloop.h>
#include <libubus.h>

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

#define STACK_SIZE	(1024 * 1024)
#define OPT_ARGS	"S:C:n:h:r:w:d:psulocU:G:NR:fFO:T:EyJ:"

static struct {
	char *name;
	char *hostname;
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
	int no_new_privs;
	int namespace;
	int procfs;
	int ronly;
	int sysfs;
	int console;
	int pw_uid;
	int pw_gid;
	int gr_gid;
	int require_jail;
} opts;

static struct blob_buf ocibuf;

extern int pivot_root(const char *new_root, const char *put_old);

int debug = 0;

static char child_stack[STACK_SIZE];

int console_fd;

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

static int mount_overlay(char *jail_root, char *overlaydir) {
	char *upperdir, *workdir, *optsstr, *upperetc, *upperresolvconf;
	const char mountoptsformat[] = "lowerdir=%s,upperdir=%s,workdir=%s";
	int ret = -1, fd;

	if (asprintf(&upperdir, "%s%s", overlaydir, "/upper") < 0)
		goto out;

	if (asprintf(&workdir, "%s%s", overlaydir, "/work") < 0)
		goto upper_printf;

	if (asprintf(&optsstr, mountoptsformat, jail_root, upperdir, workdir) < 0)
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
	if (fd == -1) {
		ERROR("creat(%s) failed: %m\n", upperresolvconf);
		goto upper_resolvconf_printf;
	}
	close(fd);

	DEBUG("mount -t overlay %s %s (%s)\n", jail_root, jail_root, optsstr);

	if (mount(jail_root, jail_root, "overlay", MS_NOATIME, optsstr))
		goto opts_printf;

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
	struct ubus_context *ctx = ubus_connect(NULL);
	static struct blob_buf req;
	uint32_t id;

	if (!ctx)
		return;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", opts.name);

	if (ubus_lookup_id(ctx, "container", &id) ||
	    ubus_invoke_fd(ctx, id, "console_set", req.head, NULL, NULL, 3000, console_fd))
		INFO("ubus request failed\n");
	else
		close(console_fd);

	blob_buf_free(&req);
	ubus_free(ctx);
}

static int create_dev_console(const char *jail_root)
{
	char *console_fname;
	char dev_console_path[PATH_MAX];
	int slave_console_fd;

	/* Open UNIX/98 virtual console */
	console_fd = posix_openpt(O_RDWR | O_NOCTTY);
	if (console_fd == -1)
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
	close(creat(dev_console_path, 0620));

	if (mount(console_fname, dev_console_path, NULL, MS_BIND, NULL))
		goto no_console;

	/* use PTY slave for stdio */
	slave_console_fd = open(console_fname, O_RDWR); /* | O_NOCTTY */
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

static int build_jail_fs(void)
{
	char jail_root[] = "/tmp/ujail-XXXXXX";
	char tmpovdir[] = "/tmp/ujail-overlay-XXXXXX";
	char tmpdevdir[] = "/tmp/ujail-XXXXXX/dev";
	char tmpdevptsdir[] = "/tmp/ujail-XXXXXX/dev/pts";
	char *overlaydir = NULL;

	if (mkdtemp(jail_root) == NULL) {
		ERROR("mkdtemp(%s) failed: %m\n", jail_root);
		return -1;
	}

	/* oldroot can't be MS_SHARED else pivot_root() fails */
	if (mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL)) {
		ERROR("private mount failed %m\n");
		return -1;
	}

	if (opts.extroot) {
		if (mount(opts.extroot, jail_root, NULL, MS_BIND, NULL)) {
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

	if (overlaydir)
		mount_overlay(jail_root, overlaydir);

	if (chdir(jail_root)) {
		ERROR("chdir(%s) (jail_root) failed: %m\n", jail_root);
		return -1;
	}

	snprintf(tmpdevdir, sizeof(tmpdevdir), "%s/dev", jail_root);
	mkdir_p(tmpdevdir, 0755);
	if (mount(NULL, tmpdevdir, "tmpfs", MS_NOATIME | MS_NOEXEC | MS_NOSUID, "size=1M"))
		return -1;

	snprintf(tmpdevptsdir, sizeof(tmpdevptsdir), "%s/dev/pts", jail_root);
	mkdir_p(tmpdevptsdir, 0755);
	if (mount(NULL, tmpdevptsdir, "devpts", MS_NOATIME | MS_NOEXEC | MS_NOSUID, NULL))
		return -1;

	if (opts.console)
		create_dev_console(jail_root);

	if (mount_all(jail_root)) {
		ERROR("mount_all() failed\n");
		return -1;
	}

	if (opts.namespace & CLONE_NEWNET) {
		char hostdir[PATH_MAX], jailetc[PATH_MAX], jaillink[PATH_MAX];

		snprintf(hostdir, PATH_MAX, "/tmp/resolv.conf-%s.d", opts.name);
		mkdir_p(hostdir, 0755);
		_mount_bind(jail_root, hostdir, "/tmp/resolv.conf.d", 1, 1, -1);
		snprintf(jailetc, PATH_MAX, "%s/etc", jail_root);
		mkdir_p(jailetc, 0755);
		snprintf(jaillink, PATH_MAX, "%s/etc/resolv.conf", jail_root);
		if (overlaydir)
			unlink(jaillink);
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

	if (opts.procfs) {
		mkdir("/proc", 0755);
		mount("proc", "/proc", "proc", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID, 0);
		/*
		 * make /proc/sys read-only while keeping read-write to
		 * /proc/sys/net if CLONE_NEWNET is set.
		 */
		if (opts.namespace & CLONE_NEWNET)
			mount("/proc/sys/net", "/proc/self/net", NULL, MS_BIND, 0);

		mount("/proc/sys", "/proc/sys", NULL, MS_BIND, 0);
		mount(NULL, "/proc/sys", NULL, MS_REMOUNT | MS_RDONLY, 0);
		mount(NULL, "/proc", NULL, MS_REMOUNT, 0);

		if (opts.namespace & CLONE_NEWNET)
			mount("/proc/self/net", "/proc/sys/net", NULL, MS_MOVE, 0);
	}
	if (opts.sysfs) {
		mkdir("/sys", 0755);
		mount("sysfs", "/sys", "sysfs", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RDONLY, 0);
	}
	if (opts.ronly)
		mount(NULL, "/", NULL, MS_RDONLY | MS_REMOUNT, 0);

	return 0;
}

static int write_uid_gid_map(pid_t child_pid, bool gidmap, char *mapstr)
{
	int map_file;
	char map_path[64];

	if (snprintf(map_path, sizeof(map_path), "/proc/%d/%s",
		child_pid, gidmap?"gid_map":"uid_map") < 0)
		return -1;

	if ((map_file = open(map_path, O_WRONLY)) == -1)
		return -1;

	if (dprintf(map_file, "%s", mapstr)) {
		close(map_file);
		return -1;
	}

	close(map_file);
	free(mapstr);
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

	if ((map_file = open(map_path, O_WRONLY)) == -1)
		return -1;

	if (dprintf(map_file, map_format, 0, id, 1) == -1) {
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

	if ((setgroups_file = open(setgroups_path, O_WRONLY)) == -1) {
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
	struct passwd *p = NULL;
	struct group *g = NULL;

	if (opts.user) {
		p = getpwnam(opts.user);
		if (!p) {
			ERROR("failed to get uid/gid for user %s: %d (%s)\n",
			      opts.user, errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		*user = p->pw_uid;
		*user_gid = p->pw_gid;
	} else {
		*user = -1;
		*user_gid = -1;
	}

	if (opts.group) {
		g = getgrnam(opts.group);
		if (!g) {
			ERROR("failed to get gid for group %s: %m\n", opts.group);
			exit(EXIT_FAILURE);
		}
		*gr_gid = g->gr_gid;
	} else {
		*gr_gid = -1;
	}
};

static void set_jail_user(int pw_uid, int user_gid, int gr_gid)
{
	if (opts.user && (user_gid != -1) && initgroups(opts.user, user_gid)) {
		ERROR("failed to initgroups() for user %s: %m\n", opts.user);
		exit(EXIT_FAILURE);
	}

	if ((gr_gid != -1) && setregid(gr_gid, gr_gid)) {
		ERROR("failed to set group id %d: %m\n", gr_gid);
		exit(EXIT_FAILURE);
	}

	if ((pw_uid != -1) && setreuid(pw_uid, pw_uid)) {
		ERROR("failed to set user id %d: %m\n", pw_uid);
		exit(EXIT_FAILURE);
	}
}

#define MAX_ENVP	8
static char** build_envp(const char *seccomp, char **ocienvp)
{
	static char *envp[MAX_ENVP];
	static char preload_var[PATH_MAX];
	static char seccomp_var[PATH_MAX];
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
	fprintf(stderr, "  -U <name>\tuser to run jailed process\n");
	fprintf(stderr, "  -G <name>\tgroup to run jailed process\n");
	fprintf(stderr, "  -o\t\tremont jail root (/) read only\n");
	fprintf(stderr, "  -R <dir>\texternal jail rootfs (system container)\n");
	fprintf(stderr, "  -O <dir>\tdirectory for r/w overlayfs\n");
	fprintf(stderr, "  -T <size>\tuse tmpfs r/w overlayfs with <size>\n");
	fprintf(stderr, "  -E\t\tfail if jail cannot be setup\n");
	fprintf(stderr, "  -y\t\tprovide jail console\n");
	fprintf(stderr, "  -J <dir>\tstart OCI bundle\n");
	fprintf(stderr, "\nWarning: by default root inside the jail is the same\n\
and he has the same powers as root outside the jail,\n\
thus he can escape the jail and/or break stuff.\n\
Please use seccomp/capabilities (-S/-C) to restrict his powers\n\n\
If you use none of the namespace jail options,\n\
ujail will not use namespace/build a jail,\n\
and will only drop capabilities/apply seccomp filter.\n\n");
}

static int exec_jail(void *pipes_ptr)
{
	int *pipes = (int*)pipes_ptr;
	char buf[1];
	int pw_uid, pw_gid, gr_gid;

	close(pipes[0]);
	close(pipes[3]);

	buf[0] = 'i';
	if (write(pipes[1], buf, 1) < 1) {
		ERROR("can't write to parent\n");
		exit(EXIT_FAILURE);
	}
	if (read(pipes[2], buf, 1) < 1) {
		ERROR("can't read from parent\n");
		exit(EXIT_FAILURE);
	}
	if (buf[0] != 'O') {
		ERROR("parent had an error, child exiting\n");
		exit(EXIT_FAILURE);
	}

	close(pipes[1]);
	close(pipes[2]);

	if (opts.namespace & CLONE_NEWUSER) {
		if (setregid(0, 0) < 0) {
			ERROR("setgid\n");
			exit(EXIT_FAILURE);
		}
		if (setreuid(0, 0) < 0) {
			ERROR("setuid\n");
			exit(EXIT_FAILURE);
		}
		if (setgroups(0, NULL) < 0) {
			ERROR("setgroups\n");
			exit(EXIT_FAILURE);
		}
	}

	if (opts.namespace && opts.hostname && strlen(opts.hostname) > 0
			&& sethostname(opts.hostname, strlen(opts.hostname))) {
		ERROR("sethostname(%s) failed: %m\n", opts.hostname);
		exit(EXIT_FAILURE);
	}

	if ((opts.namespace & CLONE_NEWNS) && build_jail_fs()) {
		ERROR("failed to build jail fs\n");
		exit(EXIT_FAILURE);
	}

	if (applyOCIcapabilities(opts.capset))
		exit(EXIT_FAILURE);

	if (opts.capabilities && drop_capabilities(opts.capabilities))
		exit(EXIT_FAILURE);

	if (opts.no_new_privs && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
                ERROR("prctl(PR_SET_NO_NEW_PRIVS) failed: %m\n");
		exit(EXIT_FAILURE);
	}

	if (!(opts.namespace & CLONE_NEWUSER)) {
		get_jail_user(&pw_uid, &pw_gid, &gr_gid);

		set_jail_user(opts.pw_uid?:pw_uid, opts.pw_gid?:pw_gid, opts.gr_gid?:gr_gid);
	}

	char **envp = build_envp(opts.seccomp, opts.envp);
	if (!envp)
		exit(EXIT_FAILURE);

	if (opts.ociseccomp && applyOCIlinuxseccomp(opts.ociseccomp))
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

static int netns_open_pid(const pid_t target_ns)
{
	char pid_net_path[PATH_MAX];

	snprintf(pid_net_path, sizeof(pid_net_path), "/proc/%u/ns/net", target_ns);

	return open(pid_net_path, O_RDONLY);
}

static void netns_updown(pid_t pid, bool start)
{
	struct ubus_context *ctx = ubus_connect(NULL);
	static struct blob_buf req;
	uint32_t id;

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
	static char rootpath[PATH_MAX] = { 0 };
	struct blob_attr *tb[__OCI_ROOT_MAX];
	char *cur;

	blobmsg_parse(oci_root_policy, __OCI_ROOT_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_ROOT_PATH])
		return ENODATA;

	strncpy(rootpath, jsonfile, PATH_MAX);
	cur = strrchr(rootpath, '/');

	if (!cur)
		return ENOTDIR;

	*(++cur) = '\0';
	strncat(rootpath, blobmsg_get_string(tb[OCI_ROOT_PATH]), PATH_MAX - (strlen(rootpath) + 1));

	opts.extroot = rootpath;

	opts.ronly = blobmsg_get_bool(tb[OCI_ROOT_READONLY]);

	return 0;
}


enum {
	OCI_MOUNT_SOURCE,
	OCI_MOUNT_DESTINATION,
	OCI_MOUNT_TYPE,
	OCI_MOUNT_OPTIONS,
	__OCI_MOUNT_MAX,
};

static const struct blobmsg_policy oci_mount_policy[] = {
	[OCI_MOUNT_SOURCE] = { "source", BLOBMSG_TYPE_STRING },
	[OCI_MOUNT_DESTINATION] = { "destination", BLOBMSG_TYPE_STRING },
	[OCI_MOUNT_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[OCI_MOUNT_OPTIONS] = { "options", BLOBMSG_TYPE_ARRAY },
};

static int parseOCImount(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_MOUNT_MAX];

	blobmsg_parse(oci_mount_policy, __OCI_MOUNT_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_MOUNT_DESTINATION])
		return EINVAL;

	if (!strcmp("proc", blobmsg_get_string(tb[OCI_MOUNT_TYPE])) &&
	    !strcmp("/proc", blobmsg_get_string(tb[OCI_MOUNT_DESTINATION]))) {
		opts.procfs = true;
		return 0;
	}

	if (!strcmp("sysfs", blobmsg_get_string(tb[OCI_MOUNT_TYPE])) &&
	    !strcmp("/sys", blobmsg_get_string(tb[OCI_MOUNT_DESTINATION]))) {
		opts.sysfs = true;
		return 0;
	}

	if (!strcmp("tmpfs", blobmsg_get_string(tb[OCI_MOUNT_TYPE])) &&
	    !strcmp("/dev", blobmsg_get_string(tb[OCI_MOUNT_DESTINATION]))) {
		/* we always mount a small tmpfs on /dev */
		return 0;
	}

	INFO("ignoring unsupported mount %s %s -t %s -o %s\n",
		blobmsg_get_string(tb[OCI_MOUNT_SOURCE]),
		blobmsg_get_string(tb[OCI_MOUNT_DESTINATION]),
		blobmsg_get_string(tb[OCI_MOUNT_TYPE]),
		blobmsg_format_json(tb[OCI_MOUNT_OPTIONS], true));

	return 0;
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

	blobmsg_parse(oci_process_user_policy, __OCI_PROCESS_USER_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_PROCESS_USER_UID])
		opts.pw_uid = blobmsg_get_u32(tb[OCI_PROCESS_USER_UID]);

	if (tb[OCI_PROCESS_USER_GID]) {
		opts.pw_gid = blobmsg_get_u32(tb[OCI_PROCESS_USER_GID]);
		opts.gr_gid = blobmsg_get_u32(tb[OCI_PROCESS_USER_GID]);
	}

	/* ToDo: umask, additional GIDs */

	return 0;
}

enum {
	OCI_PROCESS_ARGS,
	OCI_PROCESS_CAPABILITIES,
	OCI_PROCESS_CWD,
	OCI_PROCESS_ENV,
	OCI_PROCESS_NONEWPRIVILEGES,
	OCI_PROCESS_RLIMITS,
	OCI_PROCESS_TERMINAL,
	OCI_PROCESS_USER,
	__OCI_PROCESS_MAX,
};

static const struct blobmsg_policy oci_process_policy[] = {
	[OCI_PROCESS_ARGS] = { "args", BLOBMSG_TYPE_ARRAY },
	[OCI_PROCESS_CAPABILITIES] = { "capabilities", BLOBMSG_TYPE_TABLE },
	[OCI_PROCESS_CWD] = { "cwd", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS_ENV] = { "env", BLOBMSG_TYPE_ARRAY },
	[OCI_PROCESS_NONEWPRIVILEGES] = { "noNewPrivileges", BLOBMSG_TYPE_BOOL },
	[OCI_PROCESS_RLIMITS] = { "rlimits", BLOBMSG_TYPE_ARRAY },
	[OCI_PROCESS_TERMINAL] = { "terminal", BLOBMSG_TYPE_BOOL },
	[OCI_PROCESS_USER] = { "user", BLOBMSG_TYPE_TABLE },
};

static int parseOCIprocess(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_PROCESS_MAX];
	struct blob_attr *cur;
	unsigned int sz = 0;
	int rem;
	int res;

	blobmsg_parse(oci_process_policy, __OCI_PROCESS_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_PROCESS_ARGS])
		return ENOENT;

	blobmsg_for_each_attr(cur, tb[OCI_PROCESS_ARGS], rem)
		++sz;

	if (!sz)
		return ENODATA;

	opts.jail_argv = calloc(1 + sz, sizeof(char*));
	if (!opts.jail_argv)
		return ENOMEM;

	sz = 0;
	blobmsg_for_each_attr(cur, tb[OCI_PROCESS_ARGS], rem)
		opts.jail_argv[sz++] = blobmsg_get_string(cur);

	opts.console = blobmsg_get_bool(tb[OCI_PROCESS_TERMINAL]);
	opts.no_new_privs = blobmsg_get_bool(tb[OCI_PROCESS_NONEWPRIVILEGES]);

	if (tb[OCI_PROCESS_CWD])
		opts.cwd = blobmsg_get_string(tb[OCI_PROCESS_CWD]);

	sz = 0;
	blobmsg_for_each_attr(cur, tb[OCI_PROCESS_ENV], rem)
		++sz;

	if (sz > 0) {
		opts.envp = calloc(1 + sz, sizeof(char*));
		if (!opts.envp)
			return ENOMEM;
	}

	sz = 0;
	blobmsg_for_each_attr(cur, tb[OCI_PROCESS_ENV], rem)
		opts.envp[sz++] = strdup(blobmsg_get_string(cur));

	if (tb[OCI_PROCESS_USER] && (res = parseOCIprocessuser(tb[OCI_PROCESS_USER])))
		return res;

	if (tb[OCI_PROCESS_CAPABILITIES] &&
	    (res = parseOCIcapabilities(&opts.capset, tb[OCI_PROCESS_CAPABILITIES])))
		return res;

	/* ToDo: rlimits, capabilities */

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

static unsigned int resolve_nstype(char *type) {
	if (!strcmp("pid", type))
		return CLONE_NEWPID;
	else if (!strcmp("network", type))
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
	else
		return 0;
}

static int parseOCIlinuxns(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_NAMESPACE_MAX];


	blobmsg_parse(oci_linux_namespace_policy, __OCI_LINUX_NAMESPACE_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_LINUX_NAMESPACE_TYPE])
		return EINVAL;

	if (tb[OCI_LINUX_NAMESPACE_PATH])
		return ENOTSUP; /* ToDo */

	opts.namespace |= resolve_nstype(blobmsg_get_string(tb[OCI_LINUX_NAMESPACE_TYPE]));

	return 0;
};


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
	const char *map_format = "%d %d %d\n";
	struct blob_attr *tb[__OCI_LINUX_UIDGIDMAP_MAX];
	struct blob_attr *cur;
	int rem, len;
	char **mappings;
	char *map, *curstr;
	unsigned int cnt = 0;
	size_t totallen = 0;

	/* count number of mappings */
	blobmsg_for_each_attr(cur, msg, rem)
		cnt++;

	if (!cnt)
		return 0;

	/* allocate array for mappings */
	mappings = calloc(1 + cnt, sizeof(char*));
	if (!mappings)
		return ENOMEM;

	mappings[cnt] = NULL;

	cnt = 0;
	blobmsg_for_each_attr(cur, msg, rem) {
		blobmsg_parse(oci_linux_uidgidmap_policy, __OCI_LINUX_UIDGIDMAP_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[OCI_LINUX_UIDGIDMAP_CONTAINERID] ||
		    !tb[OCI_LINUX_UIDGIDMAP_HOSTID] ||
		    !tb[OCI_LINUX_UIDGIDMAP_SIZE])
			return EINVAL;

		/* write mapping line into allocated string */
		len = asprintf(&mappings[cnt++], map_format,
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_CONTAINERID]),
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_HOSTID]),
			 blobmsg_get_u32(tb[OCI_LINUX_UIDGIDMAP_SIZE]));

		if (len < 0)
			return ENOMEM;

		totallen += len;
	}

	/* allocate combined mapping string */
	map = calloc(1 + len, sizeof(char));
	if (!map)
		return ENOMEM;

	map[0] = '\0';

	/* concatenate mapping strings into combined string */
	curstr = mappings[0];
	while (curstr) {
		strcat(map, curstr);
		free(curstr++);
	}
	free(mappings);

	if (is_gidmap)
		opts.gidmap = map;
	else
		opts.uidmap = map;

	return 0;
}

enum {
	OCI_LINUX_RESOURCES,
	OCI_LINUX_SECCOMP,
	OCI_LINUX_SYSCTL,
	OCI_LINUX_NAMESPACES,
	OCI_LINUX_UIDMAPPINGS,
	OCI_LINUX_GIDMAPPINGS,
	OCI_LINUX_MASKEDPATHS,
	OCI_LINUX_READONLYPATHS,
	OCI_LINUX_ROOTFSPROPAGATION,
	__OCI_LINUX_MAX,
};

static const struct blobmsg_policy oci_linux_policy[] = {
	[OCI_LINUX_RESOURCES] = { "resources", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_SECCOMP] = { "seccomp", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_SYSCTL] = { "sysctl", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_NAMESPACES] = { "namespaces", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_UIDMAPPINGS] = { "uidMappings", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_GIDMAPPINGS] = { "gidMappings", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_MASKEDPATHS] = { "maskedPaths", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_READONLYPATHS] = { "readonlyPaths", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_ROOTFSPROPAGATION] = { "rootfsPropagation", BLOBMSG_TYPE_STRING },
};

static int parseOCIlinux(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_MAX];
	struct blob_attr *cur;
	int rem;
	int res = 0;

	blobmsg_parse(oci_linux_policy, __OCI_LINUX_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_LINUX_NAMESPACES]) {
		blobmsg_for_each_attr(cur, tb[OCI_LINUX_NAMESPACES], rem) {
			res = parseOCIlinuxns(cur);
			if (res)
				return res;
		}
	}

	if (tb[OCI_LINUX_UIDMAPPINGS]) {
		res = parseOCIuidgidmappings(tb[OCI_LINUX_GIDMAPPINGS], 0);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_GIDMAPPINGS]) {
		res = parseOCIuidgidmappings(tb[OCI_LINUX_GIDMAPPINGS], 1);
		if (res)
			return res;
	}

	if (tb[OCI_LINUX_SECCOMP]) {
		opts.ociseccomp = parseOCIlinuxseccomp(tb[OCI_LINUX_SECCOMP]);
		if (!opts.ociseccomp)
			return EINVAL;
	}

	return 0;
}

enum {
	OCI_VERSION,
	OCI_HOSTNAME,
	OCI_PROCESS,
	OCI_ROOT,
	OCI_MOUNTS,
	OCI_LINUX,
	__OCI_MAX,
};

static const struct blobmsg_policy oci_policy[] = {
	[OCI_VERSION] = { "ociVersion", BLOBMSG_TYPE_STRING },
	[OCI_HOSTNAME] = { "hostname", BLOBMSG_TYPE_STRING },
	[OCI_PROCESS] = { "process", BLOBMSG_TYPE_TABLE },
	[OCI_ROOT] = { "root", BLOBMSG_TYPE_TABLE },
	[OCI_MOUNTS] = { "mounts", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX] = { "linux", BLOBMSG_TYPE_TABLE },
};

static int parseOCI(const char *jsonfile)
{
	struct blob_attr *tb[__OCI_MAX];
	struct blob_attr *cur;
	int rem;
	int res;

	blob_buf_init(&ocibuf, 0);
	if (!blobmsg_add_json_from_file(&ocibuf, jsonfile))
		return ENOENT;

	blobmsg_parse(oci_policy, __OCI_MAX, tb, blob_data(ocibuf.head), blob_len(ocibuf.head));

	if (!tb[OCI_VERSION])
		return ENOMSG;

	if (strncmp("1.0", blobmsg_get_string(tb[OCI_VERSION]), 3)) {
		ERROR("unsupported ociVersion %s\n", blobmsg_get_string(tb[OCI_VERSION]));
		return ENOTSUP;
	}

	if (tb[OCI_HOSTNAME])
		opts.hostname = blobmsg_get_string(tb[OCI_HOSTNAME]);

	if (!tb[OCI_PROCESS])
		return ENODATA;

	if ((res = parseOCIprocess(tb[OCI_PROCESS])))
		return res;

	if (!tb[OCI_ROOT])
		return ENODATA;

	if ((res = parseOCIroot(jsonfile, tb[OCI_ROOT])))
		return res;

	if (!tb[OCI_MOUNTS])
		return ENODATA;

	blobmsg_for_each_attr(cur, tb[OCI_MOUNTS], rem)
		if ((res = parseOCImount(cur)))
			return res;

	if (tb[OCI_LINUX] && (res = parseOCIlinux(tb[OCI_LINUX])))
		return res;

	return 0;
}

int main(int argc, char **argv)
{
	sigset_t sigmask;
	uid_t uid = getuid();
	const char log[] = "/dev/log";
	const char ubus[] = "/var/run/ubus.sock";
	char *jsonfile = NULL;
	int ch, i;
	int pipes[4];
	char sig_buf[1];
	int netns_fd;

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
			opts.extroot = optarg;
			break;
		case 's':
			opts.namespace |= CLONE_NEWNS;
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
			opts.namespace |= CLONE_NEWNET;
			break;
		case 'h':
			opts.namespace |= CLONE_NEWUTS;
			opts.hostname = optarg;
			break;
		case 'r':
			opts.namespace |= CLONE_NEWNS;
			add_path_and_deps(optarg, 1, 0, 0);
			break;
		case 'w':
			opts.namespace |= CLONE_NEWNS;
			add_path_and_deps(optarg, 0, 0, 0);
			break;
		case 'u':
			opts.namespace |= CLONE_NEWNS;
			add_mount(ubus, 0, -1);
			break;
		case 'l':
			opts.namespace |= CLONE_NEWNS;
			add_mount(log, 0, -1);
			break;
		case 'U':
			opts.user = optarg;
			break;
		case 'G':
			opts.group = optarg;
			break;
		case 'O':
			opts.overlaydir = optarg;
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
			asprintf(&jsonfile, "%s/config.json", optarg);
			break;
		}
	}

	if (opts.namespace)
		opts.namespace |= CLONE_NEWIPC | CLONE_NEWPID;

	if (jsonfile) {
		int ocires;
		ocires = parseOCI(jsonfile);
		free(jsonfile);
		if (ocires) {
			ERROR("parsing of OCI JSON spec has failed: %s (%d)\n", strerror(ocires), ocires);
			return ocires;
		}
	}

	if (opts.tmpoverlaysize && strlen(opts.tmpoverlaysize) > 8) {
		ERROR("size parameter too long: \"%s\"\n", opts.tmpoverlaysize);
		return -1;
	}

	/* no <binary> param found */
	if (!jsonfile && (argc - optind < 1)) {
		usage();
		return EXIT_FAILURE;
	}
	if (!(opts.namespace||opts.capabilities||opts.seccomp)) {
		ERROR("Not using namespaces, capabilities or seccomp !!!\n\n");
		usage();
		return EXIT_FAILURE;
	}
	DEBUG("Using namespaces(0x%08x), capabilities(%d), seccomp(%d)\n",
		opts.namespace,
		opts.capabilities != 0 || opts.capset.apply,
		opts.seccomp != 0 || opts.ociseccomp != 0);

	if (!jsonfile) {
		opts.jail_argv = &argv[optind];
		if (opts.namespace & CLONE_NEWUSER)
			get_jail_user(&opts.pw_uid, &opts.pw_gid, &opts.gr_gid);
	}

	if (!opts.extroot) {
		if (opts.namespace && add_path_and_deps(*opts.jail_argv, 1, -1, 0)) {
			ERROR("failed to load dependencies\n");
			return -1;
		}
	}

	if (opts.namespace && opts.seccomp && add_path_and_deps("libpreload-seccomp.so", 1, -1, 1)) {
		ERROR("failed to load libpreload-seccomp.so\n");
		opts.seccomp = 0;
		if (opts.require_jail)
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
		if ((i == SIGCHLD) || (i == SIGPIPE) || (i == SIGSEGV))
			continue;

		s.sa_handler = jail_handle_signal;
		sigaction(i, &s, NULL);
	}

	if (opts.namespace) {
		if (opts.namespace & CLONE_NEWNS) {
			add_mount("/dev/full", 0, -1);
			add_mount("/dev/null", 0, -1);
			add_mount("/dev/random", 0, -1);
			add_mount("/dev/urandom", 0, -1);
			add_mount("/dev/zero", 0, -1);
			add_mount("/dev/ptmx", 0, -1);
			add_mount("/dev/tty", 0, -1);

			if (!opts.extroot && (opts.user || opts.group)) {
				add_mount("/etc/passwd", 0, -1);
				add_mount("/etc/group", 0, -1);
			}

#if defined(__GLIBC__)
			if (!opts.extroot)
				add_mount("/etc/nsswitch.conf", 0, -1);
#endif

			if (!(opts.namespace & CLONE_NEWNET)) {
				add_mount("/etc/resolv.conf", 0, -1);
			}
		}

		if (pipe(&pipes[0]) < 0 || pipe(&pipes[2]) < 0)
			return -1;

		jail_process.pid = clone(exec_jail, child_stack + STACK_SIZE, SIGCHLD | opts.namespace, &pipes);
	} else {
		jail_process.pid = fork();
	}

	if (jail_process.pid > 0) {
		seteuid(0);
		/* parent process */
		close(pipes[1]);
		close(pipes[2]);
		if (read(pipes[0], sig_buf, 1) < 1) {
			ERROR("can't read from child\n");
			return -1;
		}
		close(pipes[0]);
		if (opts.namespace & CLONE_NEWUSER) {
			if (write_setgroups(jail_process.pid, true)) {
				ERROR("can't write setgroups\n");
				return -1;
			}
			if (!opts.uidmap) {
				bool has_gr = (opts.gr_gid != -1);
				if (opts.pw_uid != -1) {
					write_single_uid_gid_map(jail_process.pid, 0, opts.pw_uid);
					write_single_uid_gid_map(jail_process.pid, 1, has_gr?opts.gr_gid:opts.pw_gid);
				} else {
					write_single_uid_gid_map(jail_process.pid, 0, 65534);
					write_single_uid_gid_map(jail_process.pid, 1, has_gr?opts.gr_gid:65534);
				}
			} else {
				write_uid_gid_map(jail_process.pid, 0, opts.uidmap);
				if (opts.gidmap)
					write_uid_gid_map(jail_process.pid, 1, opts.gidmap);
			}
		}

		if (opts.namespace & CLONE_NEWNET) {
			if (!opts.name) {
				ERROR("netns needs a named jail\n");
				return -1;
			}
			netns_fd = netns_open_pid(jail_process.pid);
			netns_updown(jail_process.pid, true);
		}

		sig_buf[0] = 'O';
		if (write(pipes[3], sig_buf, 1) < 0) {
			ERROR("can't write to child\n");
			return -1;
		}
		close(pipes[3]);
		uloop_process_add(&jail_process);
		uloop_run();
		if (jail_running) {
			DEBUG("uloop interrupted, killing jail process\n");
			kill(jail_process.pid, SIGTERM);
			uloop_timeout_set(&jail_process_timeout, 1000);
			uloop_run();
		}
		uloop_done();
		if (opts.namespace & CLONE_NEWNET) {
			setns(netns_fd, CLONE_NEWNET);
			netns_updown(getpid(), false);
			close(netns_fd);
		}
		return jail_return_code;
	} else if (jail_process.pid == 0) {
		/* fork child process */
		return exec_jail(NULL);
	} else {
		ERROR("failed to clone/fork: %m\n");
		return EXIT_FAILURE;
	}
}
