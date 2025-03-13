/*
 * Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2013 John Crispin <blogic@openwrt.org>
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
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <grp.h>
#include <net/if.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <pwd.h>
#include <libgen.h>
#include <unistd.h>
#define SYSLOG_NAMES
#include <syslog.h>

#include <libubox/md5.h>

#include "../procd.h"
#include "../rcS.h"

#include "service.h"
#include "instance.h"

#define UJAIL_BIN_PATH "/sbin/ujail"
#define CGROUP_BASEDIR "/sys/fs/cgroup/services"

enum {
	INSTANCE_ATTR_COMMAND,
	INSTANCE_ATTR_ENV,
	INSTANCE_ATTR_DATA,
	INSTANCE_ATTR_NETDEV,
	INSTANCE_ATTR_FILE,
	INSTANCE_ATTR_TRIGGER,
	INSTANCE_ATTR_RESPAWN,
	INSTANCE_ATTR_NICE,
	INSTANCE_ATTR_LIMITS,
	INSTANCE_ATTR_WATCH,
	INSTANCE_ATTR_ERROR,
	INSTANCE_ATTR_USER,
	INSTANCE_ATTR_GROUP,
	INSTANCE_ATTR_STDOUT,
	INSTANCE_ATTR_STDERR,
	INSTANCE_ATTR_NO_NEW_PRIVS,
	INSTANCE_ATTR_JAIL,
	INSTANCE_ATTR_TRACE,
	INSTANCE_ATTR_SECCOMP,
	INSTANCE_ATTR_CAPABILITIES,
	INSTANCE_ATTR_PIDFILE,
	INSTANCE_ATTR_RELOADSIG,
	INSTANCE_ATTR_TERMTIMEOUT,
	INSTANCE_ATTR_FACILITY,
	INSTANCE_ATTR_EXTROOT,
	INSTANCE_ATTR_OVERLAYDIR,
	INSTANCE_ATTR_TMPOVERLAYSIZE,
	INSTANCE_ATTR_BUNDLE,
	INSTANCE_ATTR_WATCHDOG,
	__INSTANCE_ATTR_MAX
};

static const struct blobmsg_policy instance_attr[__INSTANCE_ATTR_MAX] = {
	[INSTANCE_ATTR_COMMAND] = { "command", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_ENV] = { "env", BLOBMSG_TYPE_TABLE },
	[INSTANCE_ATTR_DATA] = { "data", BLOBMSG_TYPE_TABLE },
	[INSTANCE_ATTR_NETDEV] = { "netdev", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_FILE] = { "file", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_TRIGGER] = { "triggers", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_RESPAWN] = { "respawn", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_NICE] = { "nice", BLOBMSG_TYPE_INT32 },
	[INSTANCE_ATTR_LIMITS] = { "limits", BLOBMSG_TYPE_TABLE },
	[INSTANCE_ATTR_WATCH] = { "watch", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_ERROR] = { "error", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_USER] = { "user", BLOBMSG_TYPE_STRING },
	[INSTANCE_ATTR_GROUP] = { "group", BLOBMSG_TYPE_STRING },
	[INSTANCE_ATTR_STDOUT] = { "stdout", BLOBMSG_TYPE_BOOL },
	[INSTANCE_ATTR_STDERR] = { "stderr", BLOBMSG_TYPE_BOOL },
	[INSTANCE_ATTR_NO_NEW_PRIVS] = { "no_new_privs", BLOBMSG_TYPE_BOOL },
	[INSTANCE_ATTR_JAIL] = { "jail", BLOBMSG_TYPE_TABLE },
	[INSTANCE_ATTR_TRACE] = { "trace", BLOBMSG_TYPE_BOOL },
	[INSTANCE_ATTR_SECCOMP] = { "seccomp", BLOBMSG_TYPE_STRING },
	[INSTANCE_ATTR_CAPABILITIES] = { "capabilities", BLOBMSG_TYPE_STRING },
	[INSTANCE_ATTR_PIDFILE] = { "pidfile", BLOBMSG_TYPE_STRING },
	[INSTANCE_ATTR_RELOADSIG] = { "reload_signal", BLOBMSG_TYPE_INT32 },
	[INSTANCE_ATTR_TERMTIMEOUT] = { "term_timeout", BLOBMSG_TYPE_INT32 },
	[INSTANCE_ATTR_FACILITY] = { "facility", BLOBMSG_TYPE_STRING },
	[INSTANCE_ATTR_EXTROOT] = { "extroot", BLOBMSG_TYPE_STRING },
	[INSTANCE_ATTR_OVERLAYDIR] = { "overlaydir", BLOBMSG_TYPE_STRING },
	[INSTANCE_ATTR_TMPOVERLAYSIZE] = { "tmpoverlaysize", BLOBMSG_TYPE_STRING },
	[INSTANCE_ATTR_BUNDLE] = { "bundle", BLOBMSG_TYPE_STRING },
	[INSTANCE_ATTR_WATCHDOG] = { "watchdog", BLOBMSG_TYPE_ARRAY },
};

enum {
	JAIL_ATTR_NAME,
	JAIL_ATTR_HOSTNAME,
	JAIL_ATTR_PROCFS,
	JAIL_ATTR_SYSFS,
	JAIL_ATTR_UBUS,
	JAIL_ATTR_LOG,
	JAIL_ATTR_RONLY,
	JAIL_ATTR_MOUNT,
	JAIL_ATTR_NETNS,
	JAIL_ATTR_USERNS,
	JAIL_ATTR_CGROUPSNS,
	JAIL_ATTR_CONSOLE,
	JAIL_ATTR_REQUIREJAIL,
	JAIL_ATTR_IMMEDIATELY,
	JAIL_ATTR_PIDFILE,
	JAIL_ATTR_SETNS,
	__JAIL_ATTR_MAX,
};

static const struct blobmsg_policy jail_attr[__JAIL_ATTR_MAX] = {
	[JAIL_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[JAIL_ATTR_HOSTNAME] = { "hostname", BLOBMSG_TYPE_STRING },
	[JAIL_ATTR_PROCFS] = { "procfs", BLOBMSG_TYPE_BOOL },
	[JAIL_ATTR_SYSFS] = { "sysfs", BLOBMSG_TYPE_BOOL },
	[JAIL_ATTR_UBUS] = { "ubus", BLOBMSG_TYPE_BOOL },
	[JAIL_ATTR_LOG] = { "log", BLOBMSG_TYPE_BOOL },
	[JAIL_ATTR_RONLY] = { "ronly", BLOBMSG_TYPE_BOOL },
	[JAIL_ATTR_MOUNT] = { "mount", BLOBMSG_TYPE_TABLE },
	[JAIL_ATTR_NETNS] = { "netns", BLOBMSG_TYPE_BOOL },
	[JAIL_ATTR_USERNS] = { "userns", BLOBMSG_TYPE_BOOL },
	[JAIL_ATTR_CGROUPSNS] = { "cgroupsns", BLOBMSG_TYPE_BOOL },
	[JAIL_ATTR_CONSOLE] = { "console", BLOBMSG_TYPE_BOOL },
	[JAIL_ATTR_REQUIREJAIL] = { "requirejail", BLOBMSG_TYPE_BOOL },
	[JAIL_ATTR_IMMEDIATELY] = { "immediately", BLOBMSG_TYPE_BOOL },
	[JAIL_ATTR_PIDFILE] = { "pidfile", BLOBMSG_TYPE_STRING },
	[JAIL_ATTR_SETNS] = { "setns", BLOBMSG_TYPE_ARRAY },
};

enum {
	JAIL_SETNS_ATTR_PID,
	JAIL_SETNS_ATTR_NS,
	__JAIL_SETNS_ATTR_MAX,
};

static const struct blobmsg_policy jail_setns_attr[__JAIL_SETNS_ATTR_MAX] = {
	[JAIL_SETNS_ATTR_PID] = { "pid", BLOBMSG_TYPE_INT32 },
	[JAIL_SETNS_ATTR_NS] = { "namespaces", BLOBMSG_TYPE_ARRAY },
};

struct instance_netdev {
	struct blobmsg_list_node node;
	int ifindex;
};

struct instance_file {
	struct blobmsg_list_node node;
	uint32_t md5[4];
};

struct rlimit_name {
	const char *name;
	int resource;
};

static const struct rlimit_name rlimit_names[] = {
	{ "as", RLIMIT_AS },
	{ "core", RLIMIT_CORE },
	{ "cpu", RLIMIT_CPU },
	{ "data", RLIMIT_DATA },
	{ "fsize", RLIMIT_FSIZE },
	{ "memlock", RLIMIT_MEMLOCK },
	{ "nofile", RLIMIT_NOFILE },
	{ "nproc", RLIMIT_NPROC },
	{ "rss", RLIMIT_RSS },
	{ "stack", RLIMIT_STACK },
#ifdef linux
	{ "nice", RLIMIT_NICE },
	{ "rtprio", RLIMIT_RTPRIO },
	{ "msgqueue", RLIMIT_MSGQUEUE },
	{ "sigpending", RLIMIT_SIGPENDING },
#endif
	{ NULL, 0 }
};

static void closefd(int fd)
{
	if (fd > STDERR_FILENO)
		close(fd);
}

/* convert a string into numeric syslog facility or return -1 if no match found */
static int
syslog_facility_str_to_int(const char *facility)
{
	CODE *p = facilitynames;

	while (p->c_name && strcasecmp(p->c_name, facility))
		p++;

	return p->c_val;
}

static void
instance_limits(const char *limit, const char *value)
{
	int i;
	struct rlimit rlim;
	unsigned long cur, max;

	for (i = 0; rlimit_names[i].name != NULL; i++) {
		if (strcmp(rlimit_names[i].name, limit))
			continue;
		if (!strcmp(value, "unlimited")) {
			rlim.rlim_cur = RLIM_INFINITY;
			rlim.rlim_max = RLIM_INFINITY;
		} else {
			if (getrlimit(rlimit_names[i].resource, &rlim))
				return;

			cur = rlim.rlim_cur;
			max = rlim.rlim_max;

			if (sscanf(value, "%lu %lu", &cur, &max) < 1)
				return;

			rlim.rlim_cur = cur;
			rlim.rlim_max = max;
		}

		setrlimit(rlimit_names[i].resource, &rlim);
		return;
	}
}

static char *
instance_gen_setns_argstr(struct blob_attr *attr)
{
	struct blob_attr *tb[__JAIL_SETNS_ATTR_MAX];
	struct blob_attr *cur;
	int rem, len, total;
	char *ret;

	blobmsg_parse(jail_setns_attr, __JAIL_SETNS_ATTR_MAX, tb,
		blobmsg_data(attr), blobmsg_data_len(attr));

	if (!tb[JAIL_SETNS_ATTR_PID] || !tb[JAIL_SETNS_ATTR_NS])
		return NULL;

	len = snprintf(NULL, 0, "%d:", blobmsg_get_u32(tb[JAIL_SETNS_ATTR_PID]));

	blobmsg_for_each_attr(cur, tb[JAIL_SETNS_ATTR_NS], rem) {
		char *tmp;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			return NULL;

		tmp = blobmsg_get_string(cur);
		if (!tmp)
			return NULL;

		len += strlen(tmp) + 1;
	}

	total = len;
	ret = malloc(total);
	if (!ret)
		return NULL;

	len = snprintf(ret, total, "%d:", blobmsg_get_u32(tb[JAIL_SETNS_ATTR_PID]));

	blobmsg_for_each_attr(cur, tb[JAIL_SETNS_ATTR_NS], rem) {
		strncpy(&ret[len], blobmsg_get_string(cur), total - len);
		len += strlen(blobmsg_get_string(cur));
		ret[len++] = ',';
	}
	ret[total - 1] = '\0';

	return ret;
}

static inline int
jail_run(struct service_instance *in, char **argv)
{
	char *term_timeout_str;
	struct blobmsg_list_node *var;
	struct jail *jail = &in->jail;
	int argc = 0;

	argv[argc++] = UJAIL_BIN_PATH;

	if (asprintf(&term_timeout_str, "%d", in->term_timeout) == -1)
		exit(ENOMEM);

	argv[argc++] = "-t";
	argv[argc++] = term_timeout_str;

	if (jail->name) {
		argv[argc++] = "-n";
		argv[argc++] = jail->name;
	}

	if (jail->hostname) {
		argv[argc++] = "-h";
		argv[argc++] = jail->hostname;
	}

	if (in->seccomp) {
		argv[argc++] = "-S";
		argv[argc++] = in->seccomp;
	}

	if (in->user) {
		argv[argc++] = "-U";
		argv[argc++] = in->user;
	}

	if (in->group) {
		argv[argc++] = "-G";
		argv[argc++] = in->group;
	}

	if (in->capabilities) {
		argv[argc++] = "-C";
		argv[argc++] = in->capabilities;
	}

	if (in->no_new_privs)
		argv[argc++] = "-c";

	if (jail->procfs)
		argv[argc++] = "-p";

	if (jail->sysfs)
		argv[argc++] = "-s";

	if (jail->ubus)
		argv[argc++] = "-u";

	if (jail->log)
		argv[argc++] = "-l";

	if (jail->ronly)
		argv[argc++] = "-o";

	if (jail->netns)
		argv[argc++] = "-N";

	if (jail->userns)
		argv[argc++] = "-f";

	if (jail->cgroupsns)
		argv[argc++] = "-F";

	if (jail->console)
		argv[argc++] = "-y";

	if (in->extroot) {
		argv[argc++] = "-R";
		argv[argc++] = in->extroot;
	}

	if (in->overlaydir) {
		argv[argc++] = "-O";
		argv[argc++] = in->overlaydir;
	}

	if (in->tmpoverlaysize) {
		argv[argc++] = "-T";
		argv[argc++] = in->tmpoverlaysize;
	}

	if (in->immediately)
		argv[argc++] = "-i";

	if (jail->pidfile) {
		argv[argc++] = "-P";
		argv[argc++] = jail->pidfile;
	}

	if (in->bundle) {
		argv[argc++] = "-J";
		argv[argc++] = in->bundle;
	}

	if (in->require_jail)
		argv[argc++] = "-E";

	blobmsg_list_for_each(&in->env, var) {
		argv[argc++] = "-e";
		argv[argc++] = (char *) blobmsg_name(var->data);
	}

	blobmsg_list_for_each(&jail->mount, var) {
		const char *type = blobmsg_data(var->data);

		if (*type == '1')
			argv[argc++] = "-w";
		else
			argv[argc++] = "-r";
		argv[argc++] = (char *) blobmsg_name(var->data);
	}

	blobmsg_list_for_each(&jail->setns, var) {
		char *setns_arg = instance_gen_setns_argstr(var->data);

		if (setns_arg) {
			argv[argc++] = "-j";
			argv[argc++] = setns_arg;
		}
	}

	argv[argc++] = "--";

	return argc;
}

static int
instance_removepid(struct service_instance *in) {
	if (!in->pidfile)
		return 0;
	if (unlink(in->pidfile)) {
		ERROR("Failed to remove pidfile: %s: %m\n", in->pidfile);
		return 1;
	}
	return 0;
}

static int
instance_writepid(struct service_instance *in)
{
	FILE *_pidfile;

	if (!in->pidfile) {
		return 0;
	}
	_pidfile = fopen(in->pidfile, "w");
	if (_pidfile == NULL) {
		ERROR("failed to open pidfile for writing: %s: %m", in->pidfile);
		return 1;
	}
	if (fprintf(_pidfile, "%d\n", in->proc.pid) < 0) {
		ERROR("failed to write pidfile: %s: %m", in->pidfile);
		fclose(_pidfile);
		return 2;
	}
	if (fclose(_pidfile)) {
		ERROR("failed to close pidfile: %s: %m", in->pidfile);
		return 3;
	}

	return 0;
}

static void
instance_run(struct service_instance *in, int _stdout, int _stderr)
{
	struct blobmsg_list_node *var;
	struct blob_attr *cur;
	char **argv;
	int argc = 1; /* NULL terminated */
	int rem, _stdin;
	bool seccomp = !in->trace && !in->has_jail && in->seccomp;
	bool setlbf = _stdout >= 0;

	if (in->nice)
		setpriority(PRIO_PROCESS, 0, in->nice);

	blobmsg_for_each_attr(cur, in->command, rem)
		argc++;

	blobmsg_list_for_each(&in->env, var)
		setenv(blobmsg_name(var->data), blobmsg_data(var->data), 1);

	if (seccomp)
		setenv("SECCOMP_FILE", in->seccomp, 1);

	if (setlbf)
		setenv("LD_PRELOAD", "/lib/libsetlbf.so", 1);

	blobmsg_list_for_each(&in->limits, var)
		instance_limits(blobmsg_name(var->data), blobmsg_data(var->data));

	if (in->trace || seccomp)
		argc += 1;

	argv = alloca(sizeof(char *) * (argc + in->jail.argc));
	argc = 0;

#ifdef SECCOMP_SUPPORT
	if (in->trace)
		argv[argc++] = "/sbin/utrace";
	else if (seccomp)
		argv[argc++] = "/sbin/seccomp-trace";
#else
	if (in->trace || seccomp)
		ULOG_WARN("Seccomp support for %s::%s not available\n", in->srv->name, in->name);
#endif

	if (in->has_jail) {
		argc = jail_run(in, argv);
		if (argc != in->jail.argc)
			ULOG_WARN("expected %i jail params, used %i for %s::%s\n",
				in->jail.argc, argc, in->srv->name, in->name);
	}

	blobmsg_for_each_attr(cur, in->command, rem)
		argv[argc++] = blobmsg_data(cur);

	argv[argc] = NULL;

	_stdin = open("/dev/null", O_RDONLY);

	if (_stdout == -1)
		_stdout = open("/dev/null", O_WRONLY);

	if (_stderr == -1)
		_stderr = open("/dev/null", O_WRONLY);

	if (_stdin > -1) {
		dup2(_stdin, STDIN_FILENO);
		closefd(_stdin);
	}
	if (_stdout > -1) {
		dup2(_stdout, STDOUT_FILENO);
		closefd(_stdout);
	}
	if (_stderr > -1) {
		dup2(_stderr, STDERR_FILENO);
		closefd(_stderr);
	}

	if (!in->has_jail && in->user && in->pw_gid && initgroups(in->user, in->pw_gid)) {
		ERROR("failed to initgroups() for user %s: %m\n", in->user);
		exit(127);
	}
	if (!in->has_jail && in->gr_gid && setgid(in->gr_gid)) {
		ERROR("failed to set group id %d: %m\n", in->gr_gid);
		exit(127);
	}
	if (!in->has_jail && in->uid && setuid(in->uid)) {
		ERROR("failed to set user id %d: %m\n", in->uid);
		exit(127);
	}

	execvp(argv[0], argv);
	exit(127);
}

static void
instance_add_cgroup(const char *service, const char *instance)
{
	struct stat sb;
	char cgnamebuf[256];
	int fd;

	if (stat("/sys/fs/cgroup/cgroup.subtree_control", &sb))
		return;

	mkdir(CGROUP_BASEDIR, 0700);

	snprintf(cgnamebuf, sizeof(cgnamebuf), "%s/%s", CGROUP_BASEDIR, service);
	mkdir(cgnamebuf, 0700);
	snprintf(cgnamebuf, sizeof(cgnamebuf), "%s/%s/%s", CGROUP_BASEDIR, service, instance);
	mkdir(cgnamebuf, 0700);
	strcat(cgnamebuf, "/cgroup.procs");

	fd = open(cgnamebuf, O_WRONLY);
	if (fd == -1)
		return;

	dprintf(fd, "%d", getpid());
	close(fd);
}

static void
instance_free_stdio(struct service_instance *in)
{
	if (in->_stdout.fd.fd > -1) {
		ustream_free(&in->_stdout.stream);
		close(in->_stdout.fd.fd);
		in->_stdout.fd.fd = -1;
	}

	if (in->_stderr.fd.fd > -1) {
		ustream_free(&in->_stderr.stream);
		close(in->_stderr.fd.fd);
		in->_stderr.fd.fd = -1;
	}

	if (in->console.fd.fd > -1) {
		ustream_free(&in->console.stream);
		close(in->console.fd.fd);
		in->console.fd.fd = -1;
	}

	if (in->console_client.fd.fd > -1) {
		ustream_free(&in->console_client.stream);
		close(in->console_client.fd.fd);
		in->console_client.fd.fd = -1;
	}
}

void
instance_start(struct service_instance *in)
{
	int pid;
	int opipe[2] = { -1, -1 };
	int epipe[2] = { -1, -1 };

	if (!avl_is_empty(&in->errors.avl)) {
		LOG("Not starting instance %s::%s, an error was indicated\n", in->srv->name, in->name);
		return;
	}

	if (!in->bundle && !in->command) {
		LOG("Not starting instance %s::%s, command not set\n", in->srv->name, in->name);
		return;
	}

	if (in->proc.pending) {
		if (in->halt)
			in->restart = true;
		return;
	}

	instance_free_stdio(in);
	if (in->_stdout.fd.fd > -2) {
		if (pipe(opipe)) {
			ULOG_WARN("pipe() failed: %m\n");
			opipe[0] = opipe[1] = -1;
		}
	}

	if (in->_stderr.fd.fd > -2) {
		if (pipe(epipe)) {
			ULOG_WARN("pipe() failed: %m\n");
			epipe[0] = epipe[1] = -1;
		}
	}

	in->restart = false;
	in->halt = false;

	if (!in->valid)
		return;

	pid = fork();
	if (pid < 0)
		return;

	if (!pid) {
		uloop_done();
		closefd(opipe[0]);
		closefd(epipe[0]);
		instance_add_cgroup(in->srv->name, in->name);
		instance_run(in, opipe[1], epipe[1]);
		return;
	}

	P_DEBUG(2, "Started instance %s::%s[%d]\n", in->srv->name, in->name, pid);
	in->proc.pid = pid;
	instance_writepid(in);
	clock_gettime(CLOCK_MONOTONIC, &in->start);
	uloop_process_add(&in->proc);

	if (opipe[0] > -1) {
		ustream_fd_init(&in->_stdout, opipe[0]);
		closefd(opipe[1]);
		fcntl(opipe[0], F_SETFD, FD_CLOEXEC);
	}

	if (epipe[0] > -1) {
		ustream_fd_init(&in->_stderr, epipe[0]);
		closefd(epipe[1]);
		fcntl(epipe[0], F_SETFD, FD_CLOEXEC);
	}

	if (in->watchdog.mode != INSTANCE_WATCHDOG_MODE_DISABLED) {
		uloop_timeout_set(&in->watchdog.timeout, in->watchdog.freq * 1000);
		P_DEBUG(2, "Started instance %s::%s watchdog timer : timeout = %d\n", in->srv->name, in->name, in->watchdog.freq);
	}

	service_event("instance.start", in->srv->name, in->name);
}

static void
instance_stdio(struct ustream *s, int prio, struct service_instance *in)
{
	char *newline, *str, *arg0, ident[32];
	int len;

	arg0 = basename(blobmsg_data(blobmsg_data(in->command)));
	snprintf(ident, sizeof(ident), "%s[%d]", arg0, in->proc.pid);
	ulog_open(ULOG_SYSLOG, in->syslog_facility, ident);

	do {
		str = ustream_get_read_buf(s, &len);
		if (!str)
			break;

		newline = memchr(str, '\n', len);
		if (!newline && (s->r.buffer_len != len))
			break;

		if (newline) {
			*newline = 0;
			len = newline + 1 - str;
		}
		ulog(prio, "%s\n", str);

		ustream_consume(s, len);
	} while (1);

	ulog_open(ULOG_SYSLOG, LOG_DAEMON, "procd");
}

static void
instance_stdout(struct ustream *s, int bytes)
{
	instance_stdio(s, LOG_INFO,
	               container_of(s, struct service_instance, _stdout.stream));
}

static void
instance_console(struct ustream *s, int bytes)
{
	struct service_instance *in = container_of(s, struct service_instance, console.stream);
	char *buf;
	int len;

	do {
		buf = ustream_get_read_buf(s, &len);
		if (!buf)
			break;

		ulog(LOG_INFO, "out: %s\n", buf);

		/* test if console client is attached */
		if (in->console_client.fd.fd > -1)
			ustream_write(&in->console_client.stream, buf, len, false);

		ustream_consume(s, len);
	} while (1);
}

static void
instance_console_client(struct ustream *s, int bytes)
{
	struct service_instance *in = container_of(s, struct service_instance, console_client.stream);
	char *buf;
	int len;

	do {
		buf = ustream_get_read_buf(s, &len);
		if (!buf)
			break;

		ulog(LOG_INFO, "in: %s\n", buf);
		ustream_write(&in->console.stream, buf, len, false);
		ustream_consume(s, len);
	} while (1);
}

static void
instance_stderr(struct ustream *s, int bytes)
{
	instance_stdio(s, LOG_ERR,
	               container_of(s, struct service_instance, _stderr.stream));
}

static void
instance_timeout(struct uloop_timeout *t)
{
	struct service_instance *in;

	in = container_of(t, struct service_instance, timeout);

	if (in->halt) {
		LOG("Instance %s::%s pid %d not stopped on SIGTERM, sending SIGKILL instead\n",
				in->srv->name, in->name, in->proc.pid);
		kill(in->proc.pid, SIGKILL);
	} else if (in->restart || in->respawn) {
		instance_start(in);
		rc(in->srv->name, "running");
	}
}

static void
instance_delete(struct service_instance *in)
{
	struct service *s = in->srv;

	avl_delete(&s->instances.avl, &in->node.avl);
	instance_free(in);
	service_stopped(s);
}

static int
instance_exit_code(int ret)
{
	if (WIFEXITED(ret)) {
		return WEXITSTATUS(ret);
	}

	if (WIFSIGNALED(ret)) {
		return SIGNALLED_OFFSET + WTERMSIG(ret);
	}

	if (WIFSTOPPED(ret)) {
		return WSTOPSIG(ret);
	}

	return 1;
}

static void
instance_exit(struct uloop_process *p, int ret)
{
	struct service_instance *in;
	bool restart = false;
	struct timespec tp;
	long runtime;

	in = container_of(p, struct service_instance, proc);

	clock_gettime(CLOCK_MONOTONIC, &tp);
	runtime = tp.tv_sec - in->start.tv_sec;

	P_DEBUG(2, "Instance %s::%s exit with error code %d after %ld seconds\n", in->srv->name, in->name, ret, runtime);

	in->exit_code = instance_exit_code(ret);
	uloop_timeout_cancel(&in->timeout);
	uloop_timeout_cancel(&in->watchdog.timeout);
	service_event("instance.stop", in->srv->name, in->name);

	if (in->halt) {
		instance_removepid(in);
		if (in->restart)
			restart = true;
		else
			instance_delete(in);
	} else if (in->restart) {
		restart = true;
	} else if (in->respawn) {
		if (runtime < in->respawn_threshold)
			in->respawn_count++;
		else
			in->respawn_count = 0;
		if (in->respawn_count > in->respawn_retry && in->respawn_retry > 0 ) {
			LOG("Instance %s::%s s in a crash loop %d crashes, %ld seconds since last crash\n",
								in->srv->name, in->name, in->respawn_count, runtime);
			in->restart = in->respawn = 0;
			in->halt = 1;
			service_event("instance.fail", in->srv->name, in->name);
		} else {
			service_event("instance.respawn", in->srv->name, in->name);
			uloop_timeout_set(&in->timeout, in->respawn_timeout * 1000);
		}
	}

	if (restart) {
		instance_start(in);
		rc(in->srv->name, "running");
	}
}

void
instance_stop(struct service_instance *in, bool halt)
{
	if (!in->proc.pending) {
		if (halt)
			instance_delete(in);
		return;
	}
	in->halt = halt;
	in->restart = in->respawn = false;
	kill(in->proc.pid, SIGTERM);
	if (!in->has_jail)
		uloop_timeout_set(&in->timeout, in->term_timeout * 1000);
}

static void
instance_restart(struct service_instance *in)
{
	if (!in->proc.pending)
		return;

	if (in->reload_signal) {
		kill(in->proc.pid, in->reload_signal);
		return;
	}

	in->halt = true;
	in->restart = true;
	kill(in->proc.pid, SIGTERM);
	if (!in->has_jail)
		uloop_timeout_set(&in->timeout, in->term_timeout * 1000);
}

static void
instance_watchdog(struct uloop_timeout *t)
{
	struct service_instance *in = container_of(t, struct service_instance, watchdog.timeout);

	P_DEBUG(3, "instance %s::%s watchdog timer expired\n", in->srv->name, in->name);

	if (in->respawn)
		instance_restart(in);
	else
		instance_stop(in, true);
}

static bool string_changed(const char *a, const char *b)
{
	return !((!a && !b) || (a && b && !strcmp(a, b)));
}

static bool
instance_config_changed(struct service_instance *in, struct service_instance *in_new)
{
	if (!in->valid)
		return true;

	if (!blob_attr_equal(in->command, in_new->command))
		return true;

	if (string_changed(in->bundle, in_new->bundle))
		return true;

	if (string_changed(in->extroot, in_new->extroot))
		return true;

	if (string_changed(in->overlaydir, in_new->overlaydir))
		return true;

	if (string_changed(in->tmpoverlaysize, in_new->tmpoverlaysize))
		return true;

	if (!blobmsg_list_equal(&in->env, &in_new->env))
		return true;

	if (!blobmsg_list_equal(&in->netdev, &in_new->netdev))
		return true;

	if (!blobmsg_list_equal(&in->file, &in_new->file))
		return true;

	if (in->nice != in_new->nice)
		return true;

	if (in->syslog_facility != in_new->syslog_facility)
		return true;

	if (string_changed(in->user, in_new->user))
		return true;

	if (string_changed(in->group, in_new->group))
		return true;

	if (in->uid != in_new->uid)
		return true;

	if (in->pw_gid != in_new->pw_gid)
		return true;

	if (in->gr_gid != in_new->gr_gid)
		return true;

	if (string_changed(in->pidfile, in_new->pidfile))
		return true;

	if (in->respawn_retry != in_new->respawn_retry)
		return true;
	if (in->respawn_threshold != in_new->respawn_threshold)
		return true;
	if (in->respawn_timeout != in_new->respawn_timeout)
		return true;

	if (in->reload_signal != in_new->reload_signal)
		return true;

	if (in->term_timeout != in_new->term_timeout)
		return true;

	if (string_changed(in->seccomp, in_new->seccomp))
		return true;

	if (string_changed(in->capabilities, in_new->capabilities))
		return true;

	if (!blobmsg_list_equal(&in->limits, &in_new->limits))
		return true;

	if (!blobmsg_list_equal(&in->jail.mount, &in_new->jail.mount))
		return true;

	if (!blobmsg_list_equal(&in->jail.setns, &in_new->jail.setns))
		return true;

	if (!blobmsg_list_equal(&in->errors, &in_new->errors))
		return true;

	if (in->has_jail != in_new->has_jail)
		return true;

	if (in->trace != in_new->trace)
		return true;

	if (in->require_jail != in_new->require_jail)
		return true;

	if (in->immediately != in_new->immediately)
		return true;

	if (in->no_new_privs != in_new->no_new_privs)
		return true;

	if (string_changed(in->jail.name, in_new->jail.name))
		return true;

	if (string_changed(in->jail.hostname, in_new->jail.hostname))
		return true;

	if (string_changed(in->jail.pidfile, in_new->jail.pidfile))
		return true;

	if (in->jail.procfs != in_new->jail.procfs)
		return true;

	if (in->jail.sysfs != in_new->jail.sysfs)
		return true;

	if (in->jail.ubus != in_new->jail.ubus)
		return true;

	if (in->jail.log != in_new->jail.log)
		return true;

	if (in->jail.ronly != in_new->jail.ronly)
		return true;

	if (in->jail.netns != in_new->jail.netns)
		return true;

	if (in->jail.userns != in_new->jail.userns)
		return true;

	if (in->jail.cgroupsns != in_new->jail.cgroupsns)
		return true;

	if (in->jail.console != in_new->jail.console)
		return true;

	if (in->watchdog.mode != in_new->watchdog.mode)
		return true;

	if (in->watchdog.freq != in_new->watchdog.freq)
		return true;

	return false;
}

static bool
instance_netdev_cmp(struct blobmsg_list_node *l1, struct blobmsg_list_node *l2)
{
	struct instance_netdev *n1 = container_of(l1, struct instance_netdev, node);
	struct instance_netdev *n2 = container_of(l2, struct instance_netdev, node);

	return n1->ifindex == n2->ifindex;
}

static void
instance_netdev_update(struct blobmsg_list_node *l)
{
	struct instance_netdev *n = container_of(l, struct instance_netdev, node);

	n->ifindex = if_nametoindex(n->node.avl.key);
}

static bool
instance_file_cmp(struct blobmsg_list_node *l1, struct blobmsg_list_node *l2)
{
	struct instance_file *f1 = container_of(l1, struct instance_file, node);
	struct instance_file *f2 = container_of(l2, struct instance_file, node);

	return !memcmp(f1->md5, f2->md5, sizeof(f1->md5));
}

static void
instance_file_update(struct blobmsg_list_node *l)
{
	struct instance_file *f = container_of(l, struct instance_file, node);
	md5_ctx_t md5;
	char buf[256];
	int len, fd;

	memset(f->md5, 0, sizeof(f->md5));

	fd = open(l->avl.key, O_RDONLY);
	if (fd < 0)
		return;

	md5_begin(&md5);
	do {
		len = read(fd, buf, sizeof(buf));
		if (len < 0) {
			if (errno == EINTR)
				continue;

			break;
		}
		if (!len)
			break;

		md5_hash(buf, len, &md5);
	} while(1);

	md5_end(f->md5, &md5);
	close(fd);
}

static void
instance_fill_any(struct blobmsg_list *l, struct blob_attr *cur)
{
	if (!cur)
		return;

	blobmsg_list_fill(l, blobmsg_data(cur), blobmsg_data_len(cur), false);
}

static bool
instance_fill_array(struct blobmsg_list *l, struct blob_attr *cur, blobmsg_update_cb cb, bool array)
{
	struct blobmsg_list_node *node;

	if (!cur)
		return true;

	if (!blobmsg_check_attr_list(cur, BLOBMSG_TYPE_STRING))
		return false;

	blobmsg_list_fill(l, blobmsg_data(cur), blobmsg_data_len(cur), array);
	if (cb) {
		blobmsg_list_for_each(l, node)
			cb(node);
	}
	return true;
}

static int
instance_jail_parse(struct service_instance *in, struct blob_attr *attr)
{
	struct blob_attr *tb[__JAIL_ATTR_MAX];
	struct jail *jail = &in->jail;
	struct blobmsg_list_node *var;

	blobmsg_parse(jail_attr, __JAIL_ATTR_MAX, tb,
		blobmsg_data(attr), blobmsg_data_len(attr));

	jail->argc = 4;

	if (tb[JAIL_ATTR_REQUIREJAIL] && blobmsg_get_bool(tb[JAIL_ATTR_REQUIREJAIL])) {
		in->require_jail = true;
		jail->argc++;
	}
	if (tb[JAIL_ATTR_IMMEDIATELY] && blobmsg_get_bool(tb[JAIL_ATTR_IMMEDIATELY])) {
		in->immediately = true;
		jail->argc++;
	}
	if (tb[JAIL_ATTR_NAME]) {
		jail->name = strdup(blobmsg_get_string(tb[JAIL_ATTR_NAME]));
		jail->argc += 2;
	}
	if (tb[JAIL_ATTR_HOSTNAME]) {
		jail->hostname = strdup(blobmsg_get_string(tb[JAIL_ATTR_HOSTNAME]));
		jail->argc += 2;
	}
	if (tb[JAIL_ATTR_PROCFS] && blobmsg_get_bool(tb[JAIL_ATTR_PROCFS])) {
		jail->procfs = true;
		jail->argc++;
	}
	if (tb[JAIL_ATTR_SYSFS] && blobmsg_get_bool(tb[JAIL_ATTR_SYSFS])) {
		jail->sysfs = true;
		jail->argc++;
	}
	if (tb[JAIL_ATTR_UBUS] && blobmsg_get_bool(tb[JAIL_ATTR_UBUS])) {
		jail->ubus = true;
		jail->argc++;
	}
	if (tb[JAIL_ATTR_LOG] && blobmsg_get_bool(tb[JAIL_ATTR_LOG])) {
		jail->log = true;
		jail->argc++;
	}
	if (tb[JAIL_ATTR_RONLY] && blobmsg_get_bool(tb[JAIL_ATTR_RONLY])) {
		jail->ronly = true;
		jail->argc++;
	}
	if (tb[JAIL_ATTR_NETNS] && blobmsg_get_bool(tb[JAIL_ATTR_NETNS])) {
		jail->netns = true;
		jail->argc++;
	}
	if (tb[JAIL_ATTR_USERNS] && blobmsg_get_bool(tb[JAIL_ATTR_USERNS])) {
		jail->userns = true;
		jail->argc++;
	}
	if (tb[JAIL_ATTR_CGROUPSNS] && blobmsg_get_bool(tb[JAIL_ATTR_CGROUPSNS])) {
		jail->cgroupsns = true;
		jail->argc++;
	}
	if (tb[JAIL_ATTR_CONSOLE] && blobmsg_get_bool(tb[JAIL_ATTR_CONSOLE])) {
		jail->console = true;
		jail->argc++;
	}
	if (tb[JAIL_ATTR_PIDFILE]) {
		jail->pidfile = strdup(blobmsg_get_string(tb[JAIL_ATTR_PIDFILE]));
		jail->argc += 2;
	}

	if (tb[JAIL_ATTR_SETNS]) {
		struct blob_attr *cur;
		int rem;

		blobmsg_for_each_attr(cur, tb[JAIL_ATTR_SETNS], rem)
			jail->argc += 2;
		blobmsg_list_fill(&jail->setns, blobmsg_data(tb[JAIL_ATTR_SETNS]),
				  blobmsg_data_len(tb[JAIL_ATTR_SETNS]), true);
	}

	if (tb[JAIL_ATTR_MOUNT]) {
		struct blob_attr *cur;
		int rem;

		blobmsg_for_each_attr(cur, tb[JAIL_ATTR_MOUNT], rem)
			jail->argc += 2;
		instance_fill_array(&jail->mount, tb[JAIL_ATTR_MOUNT], NULL, false);
	}

	blobmsg_list_for_each(&in->env, var)
		jail->argc += 2;

	if (in->seccomp)
		jail->argc += 2;

	if (in->capabilities)
		jail->argc += 2;

	if (in->user)
		jail->argc += 2;

	if (in->group)
		jail->argc += 2;

	if (in->extroot)
		jail->argc += 2;

	if (in->overlaydir)
		jail->argc += 2;

	if (in->tmpoverlaysize)
		jail->argc += 2;

	if (in->no_new_privs)
		jail->argc++;

	if (in->bundle)
		jail->argc += 2;

	return true;
}

static bool
instance_config_parse_command(struct service_instance *in, struct blob_attr **tb)
{
	struct blob_attr *cur, *cur2;
	bool ret = false;
	int rem;

	cur = tb[INSTANCE_ATTR_COMMAND];
	if (!cur) {
		in->command = NULL;
		return true;
	}

	if (!blobmsg_check_attr_list(cur, BLOBMSG_TYPE_STRING))
		return false;

	blobmsg_for_each_attr(cur2, cur, rem) {
		ret = true;
		break;
	}

	in->command = cur;
	return ret;
}

static bool
instance_config_parse(struct service_instance *in)
{
	struct blob_attr *tb[__INSTANCE_ATTR_MAX];
	struct blob_attr *cur, *cur2;
	struct stat s;
	int rem, r;

	blobmsg_parse(instance_attr, __INSTANCE_ATTR_MAX, tb,
		blobmsg_data(in->config), blobmsg_data_len(in->config));

	if (!tb[INSTANCE_ATTR_BUNDLE] && !instance_config_parse_command(in, tb))
			return false;

	if (tb[INSTANCE_ATTR_TERMTIMEOUT])
		in->term_timeout = blobmsg_get_u32(tb[INSTANCE_ATTR_TERMTIMEOUT]);
	if (tb[INSTANCE_ATTR_RESPAWN]) {
		int i = 0;
		uint32_t vals[3] = { 3600, 5, 5};

		blobmsg_for_each_attr(cur2, tb[INSTANCE_ATTR_RESPAWN], rem) {
			if ((i >= 3) && (blobmsg_type(cur2) == BLOBMSG_TYPE_STRING))
				continue;
			vals[i] = atoi(blobmsg_get_string(cur2));
			i++;
		}
		in->respawn = true;
		in->respawn_count = 0;
		in->respawn_threshold = vals[0];
		in->respawn_timeout = vals[1];
		in->respawn_retry = vals[2];
	}
	if (tb[INSTANCE_ATTR_TRIGGER]) {
		in->trigger = tb[INSTANCE_ATTR_TRIGGER];
		trigger_add(in->trigger, in);
	}

	if (tb[INSTANCE_ATTR_WATCH]) {
		blobmsg_for_each_attr(cur2, tb[INSTANCE_ATTR_WATCH], rem) {
			if (blobmsg_type(cur2) != BLOBMSG_TYPE_STRING)
				continue;
			P_DEBUG(3, "watch for %s\n", blobmsg_get_string(cur2));
			watch_add(blobmsg_get_string(cur2), in);
		}
	}

	if ((cur = tb[INSTANCE_ATTR_NICE])) {
		in->nice = (int8_t) blobmsg_get_u32(cur);
		if (in->nice < -20 || in->nice > 20)
			return false;
	}

	if (tb[INSTANCE_ATTR_USER]) {
		const char *user = blobmsg_get_string(tb[INSTANCE_ATTR_USER]);
		struct passwd *p = getpwnam(user);
		if (p) {
			in->user = strdup(user);
			in->uid = p->pw_uid;
			in->gr_gid = in->pw_gid = p->pw_gid;
		}
	}

	if (tb[INSTANCE_ATTR_GROUP]) {
		const char *group = blobmsg_get_string(tb[INSTANCE_ATTR_GROUP]);
		struct group *p = getgrnam(group);
		if (p) {
			in->group = strdup(group);
			in->gr_gid = p->gr_gid;
		}
	}

	if (tb[INSTANCE_ATTR_TRACE])
		in->trace = blobmsg_get_bool(tb[INSTANCE_ATTR_TRACE]);

	if (tb[INSTANCE_ATTR_NO_NEW_PRIVS])
		in->no_new_privs = blobmsg_get_bool(tb[INSTANCE_ATTR_NO_NEW_PRIVS]);

	if (!in->trace && tb[INSTANCE_ATTR_SECCOMP])
		in->seccomp = strdup(blobmsg_get_string(tb[INSTANCE_ATTR_SECCOMP]));

	if (tb[INSTANCE_ATTR_CAPABILITIES])
		in->capabilities = strdup(blobmsg_get_string(tb[INSTANCE_ATTR_CAPABILITIES]));

	if (tb[INSTANCE_ATTR_EXTROOT])
		in->extroot = strdup(blobmsg_get_string(tb[INSTANCE_ATTR_EXTROOT]));

	if (tb[INSTANCE_ATTR_OVERLAYDIR])
		in->overlaydir = strdup(blobmsg_get_string(tb[INSTANCE_ATTR_OVERLAYDIR]));

	if (tb[INSTANCE_ATTR_TMPOVERLAYSIZE])
		in->tmpoverlaysize = strdup(blobmsg_get_string(tb[INSTANCE_ATTR_TMPOVERLAYSIZE]));

	if (tb[INSTANCE_ATTR_BUNDLE])
		in->bundle = strdup(blobmsg_get_string(tb[INSTANCE_ATTR_BUNDLE]));

	if (tb[INSTANCE_ATTR_PIDFILE]) {
		char *pidfile = blobmsg_get_string(tb[INSTANCE_ATTR_PIDFILE]);
		if (pidfile)
			in->pidfile = strdup(pidfile);
	}

	if (tb[INSTANCE_ATTR_RELOADSIG])
		in->reload_signal = blobmsg_get_u32(tb[INSTANCE_ATTR_RELOADSIG]);

	if (tb[INSTANCE_ATTR_STDOUT] && blobmsg_get_bool(tb[INSTANCE_ATTR_STDOUT]))
		in->_stdout.fd.fd = -1;

	if (tb[INSTANCE_ATTR_STDERR] && blobmsg_get_bool(tb[INSTANCE_ATTR_STDERR]))
		in->_stderr.fd.fd = -1;

	instance_fill_any(&in->data, tb[INSTANCE_ATTR_DATA]);

	if (!instance_fill_array(&in->env, tb[INSTANCE_ATTR_ENV], NULL, false))
		return false;

	if (!instance_fill_array(&in->netdev, tb[INSTANCE_ATTR_NETDEV], instance_netdev_update, true))
		return false;

	if (!instance_fill_array(&in->file, tb[INSTANCE_ATTR_FILE], instance_file_update, true))
		return false;

	if (!instance_fill_array(&in->limits, tb[INSTANCE_ATTR_LIMITS], NULL, false))
		return false;

	if (!instance_fill_array(&in->errors, tb[INSTANCE_ATTR_ERROR], NULL, true))
		return false;

	if (tb[INSTANCE_ATTR_FACILITY]) {
		int facility = syslog_facility_str_to_int(blobmsg_get_string(tb[INSTANCE_ATTR_FACILITY]));
		if (facility != -1) {
			in->syslog_facility = facility;
			P_DEBUG(3, "setting facility '%s'\n", blobmsg_get_string(tb[INSTANCE_ATTR_FACILITY]));
		} else
			P_DEBUG(3, "unknown syslog facility '%s' given, using default (LOG_DAEMON)\n", blobmsg_get_string(tb[INSTANCE_ATTR_FACILITY]));
	}

	if (tb[INSTANCE_ATTR_WATCHDOG]) {
		int i = 0;
		uint32_t vals[2] = { 0, 30 };

		blobmsg_for_each_attr(cur2, tb[INSTANCE_ATTR_WATCHDOG], rem) {
			if (i >= 2)
				break;

			vals[i] = atoi(blobmsg_get_string(cur2));
			i++;
		}

		if (vals[0] >= 0 && vals[0] < __INSTANCE_WATCHDOG_MODE_MAX) {
			in->watchdog.mode = vals[0];
			P_DEBUG(3, "setting watchdog mode (%d)\n", vals[0]);
		} else {
			in->watchdog.mode = 0;
			P_DEBUG(3, "unknown watchdog mode (%d) given, using default (0)\n", vals[0]);
		}

		if (vals[1] > 0) {
			in->watchdog.freq = vals[1];
			P_DEBUG(3, "setting watchdog timeout (%d)\n", vals[0]);
		} else {
			in->watchdog.freq = 30;
			P_DEBUG(3, "invalid watchdog timeout (%d) given, using default (30)\n", vals[1]);
		}
	}

	if (!in->trace && tb[INSTANCE_ATTR_JAIL])
		in->has_jail = instance_jail_parse(in, tb[INSTANCE_ATTR_JAIL]);

	if (in->has_jail) {
		r = stat(UJAIL_BIN_PATH, &s);
		if (r < 0) {
			if (in->require_jail) {
				ERROR("Cannot jail service %s::%s. %s: %m (%d)\n",
						in->srv->name, in->name, UJAIL_BIN_PATH, r);
				return false;
			}
			P_DEBUG(2, "unable to find %s: %m (%d)\n", UJAIL_BIN_PATH, r);
			in->has_jail = false;
		}
	}

	return true;
}

static void
instance_config_cleanup(struct service_instance *in)
{
	blobmsg_list_free(&in->env);
	blobmsg_list_free(&in->data);
	blobmsg_list_free(&in->netdev);
	blobmsg_list_free(&in->file);
	blobmsg_list_free(&in->limits);
	blobmsg_list_free(&in->errors);
	blobmsg_list_free(&in->jail.mount);
	blobmsg_list_free(&in->jail.setns);
}

static void
instance_config_move_strdup(char **dst, char *src)
{
	if (*dst) {
		free(*dst);
		*dst = NULL;
	}

	if (!src)
		return;

	*dst = strdup(src);
}

static void
instance_config_move(struct service_instance *in, struct service_instance *in_src)
{
	instance_config_cleanup(in);
	blobmsg_list_move(&in->env, &in_src->env);
	blobmsg_list_move(&in->data, &in_src->data);
	blobmsg_list_move(&in->netdev, &in_src->netdev);
	blobmsg_list_move(&in->file, &in_src->file);
	blobmsg_list_move(&in->limits, &in_src->limits);
	blobmsg_list_move(&in->errors, &in_src->errors);
	blobmsg_list_move(&in->jail.mount, &in_src->jail.mount);
	blobmsg_list_move(&in->jail.setns, &in_src->jail.setns);
	in->trigger = in_src->trigger;
	in->command = in_src->command;
	in->respawn = in_src->respawn;
	in->respawn_retry = in_src->respawn_retry;
	in->respawn_threshold = in_src->respawn_threshold;
	in->respawn_timeout = in_src->respawn_timeout;
	in->reload_signal = in_src->reload_signal;
	in->term_timeout = in_src->term_timeout;
	in->watchdog.mode = in_src->watchdog.mode;
	in->watchdog.freq = in_src->watchdog.freq;
	in->watchdog.timeout = in_src->watchdog.timeout;
	in->name = in_src->name;
	in->nice = in_src->nice;
	in->trace = in_src->trace;
	in->node.avl.key = in_src->node.avl.key;
	in->syslog_facility = in_src->syslog_facility;
	in->require_jail = in_src->require_jail;
	in->no_new_privs = in_src->no_new_privs;
	in->immediately = in_src->immediately;
	in->uid = in_src->uid;
	in->pw_gid = in_src->pw_gid;
	in->gr_gid = in_src->gr_gid;

	in->has_jail = in_src->has_jail;
	in->jail.procfs = in_src->jail.procfs;
	in->jail.sysfs = in_src->jail.sysfs;
	in->jail.ubus = in_src->jail.ubus;
	in->jail.log = in_src->jail.log;
	in->jail.ronly = in_src->jail.ronly;
	in->jail.netns = in_src->jail.netns;
	in->jail.cgroupsns = in_src->jail.cgroupsns;
	in->jail.console = in_src->jail.console;
	in->jail.argc = in_src->jail.argc;

	instance_config_move_strdup(&in->pidfile, in_src->pidfile);
	instance_config_move_strdup(&in->seccomp, in_src->seccomp);
	instance_config_move_strdup(&in->capabilities, in_src->capabilities);
	instance_config_move_strdup(&in->bundle, in_src->bundle);
	instance_config_move_strdup(&in->extroot, in_src->extroot);
	instance_config_move_strdup(&in->overlaydir, in_src->overlaydir);
	instance_config_move_strdup(&in->tmpoverlaysize, in_src->tmpoverlaysize);
	instance_config_move_strdup(&in->user, in_src->user);
	instance_config_move_strdup(&in->group, in_src->group);
	instance_config_move_strdup(&in->jail.name, in_src->jail.name);
	instance_config_move_strdup(&in->jail.hostname, in_src->jail.hostname);
	instance_config_move_strdup(&in->jail.pidfile, in_src->jail.pidfile);

	free(in->config);
	in->config = in_src->config;
	in_src->config = NULL;
}

void
instance_update(struct service_instance *in, struct service_instance *in_new)
{
	bool changed = instance_config_changed(in, in_new);
	bool running = in->proc.pending;
	bool stopping = in->halt;

	if (!running || stopping) {
		instance_config_move(in, in_new);
		instance_start(in);
	} else {
		if (changed)
			instance_restart(in);
		else if (!blobmsg_list_equal(&in->data, &in_new->data)) {
			service_data_trigger(&in->data);
			service_data_trigger(&in_new->data);
		}
		instance_config_move(in, in_new);
		/* restart happens in the child callback handler */
	}
}

void
instance_free(struct service_instance *in)
{
	service_data_trigger(&in->data);
	instance_free_stdio(in);
	uloop_process_delete(&in->proc);
	uloop_timeout_cancel(&in->timeout);
	uloop_timeout_cancel(&in->watchdog.timeout);
	trigger_del(in);
	watch_del(in);
	instance_config_cleanup(in);
	free(in->config);
	free(in->user);
	free(in->group);
	free(in->extroot);
	free(in->overlaydir);
	free(in->tmpoverlaysize);
	free(in->bundle);
	free(in->jail.name);
	free(in->jail.hostname);
	free(in->jail.pidfile);
	free(in->seccomp);
	free(in->capabilities);
	free(in->pidfile);
	free(in);
}

void
instance_init(struct service_instance *in, struct service *s, struct blob_attr *config)
{
	config = blob_memdup(config);
	in->srv = s;
	in->name = blobmsg_name(config);
	in->config = config;
	in->timeout.cb = instance_timeout;
	in->proc.cb = instance_exit;
	in->term_timeout = 5;
	in->syslog_facility = LOG_DAEMON;
	in->exit_code = 0;
	in->require_jail = false;
	in->immediately = false;

	in->_stdout.fd.fd = -2;
	in->_stdout.stream.string_data = true;
	in->_stdout.stream.notify_read = instance_stdout;

	in->_stderr.fd.fd = -2;
	in->_stderr.stream.string_data = true;
	in->_stderr.stream.notify_read = instance_stderr;

	in->console.fd.fd = -2;
	in->console.stream.string_data = true;
	in->console.stream.notify_read = instance_console;

	in->console_client.fd.fd = -2;
	in->console_client.stream.string_data = true;
	in->console_client.stream.notify_read = instance_console_client;

	blobmsg_list_init(&in->netdev, struct instance_netdev, node, instance_netdev_cmp);
	blobmsg_list_init(&in->file, struct instance_file, node, instance_file_cmp);
	blobmsg_list_simple_init(&in->env);
	blobmsg_list_simple_init(&in->data);
	blobmsg_list_simple_init(&in->limits);
	blobmsg_list_simple_init(&in->errors);
	blobmsg_list_simple_init(&in->jail.mount);
	blobmsg_list_simple_init(&in->jail.setns);

	in->watchdog.timeout.cb = instance_watchdog;

	in->valid = instance_config_parse(in);
	service_data_trigger(&in->data);
}

void instance_dump(struct blob_buf *b, struct service_instance *in, int verbose)
{
	void *i;

	if (!in->valid)
		return;

	i = blobmsg_open_table(b, in->name);
	blobmsg_add_u8(b, "running", in->proc.pending);
	if (in->proc.pending)
		blobmsg_add_u32(b, "pid", in->proc.pid);
	if (in->command)
		blobmsg_add_blob(b, in->command);
	if (in->bundle)
		blobmsg_add_string(b, "bundle", in->bundle);
	blobmsg_add_u32(b, "term_timeout", in->term_timeout);
	if (!in->proc.pending)
		blobmsg_add_u32(b, "exit_code", in->exit_code);

	if (!avl_is_empty(&in->errors.avl)) {
		struct blobmsg_list_node *var;
		void *e = blobmsg_open_array(b, "errors");
		blobmsg_list_for_each(&in->errors, var)
			blobmsg_add_string(b, NULL, blobmsg_data(var->data));
		blobmsg_close_table(b, e);
	}

	if (!avl_is_empty(&in->env.avl)) {
		struct blobmsg_list_node *var;
		void *e = blobmsg_open_table(b, "env");
		blobmsg_list_for_each(&in->env, var)
			blobmsg_add_string(b, blobmsg_name(var->data), blobmsg_data(var->data));
		blobmsg_close_table(b, e);
	}

	if (!avl_is_empty(&in->data.avl)) {
		struct blobmsg_list_node *var;
		void *e = blobmsg_open_table(b, "data");
		blobmsg_list_for_each(&in->data, var)
			blobmsg_add_blob(b, var->data);
		blobmsg_close_table(b, e);
	}

	if (!avl_is_empty(&in->limits.avl)) {
		struct blobmsg_list_node *var;
		void *e = blobmsg_open_table(b, "limits");
		blobmsg_list_for_each(&in->limits, var)
			blobmsg_add_string(b, blobmsg_name(var->data), blobmsg_data(var->data));
		blobmsg_close_table(b, e);
	}

	if (!avl_is_empty(&in->netdev.avl)) {
		struct blobmsg_list_node *var;
		void *n = blobmsg_open_array(b, "netdev");

		blobmsg_list_for_each(&in->netdev, var)
			blobmsg_add_string(b, NULL, blobmsg_data(var->data));
		blobmsg_close_array(b, n);
	}

	if (in->reload_signal)
		blobmsg_add_u32(b, "reload_signal", in->reload_signal);

	if (in->respawn) {
		void *r = blobmsg_open_table(b, "respawn");
		blobmsg_add_u32(b, "threshold", in->respawn_threshold);
		blobmsg_add_u32(b, "timeout", in->respawn_timeout);
		blobmsg_add_u32(b, "retry", in->respawn_retry);
		blobmsg_close_table(b, r);
	}

	if (in->trace)
		blobmsg_add_u8(b, "trace", true);

	if (in->no_new_privs)
		blobmsg_add_u8(b, "no_new_privs", true);

	if (in->seccomp)
		blobmsg_add_string(b, "seccomp", in->seccomp);

	if (in->capabilities)
		blobmsg_add_string(b, "capabilities", in->capabilities);

	if (in->pidfile)
		blobmsg_add_string(b, "pidfile", in->pidfile);

	if (in->user)
		blobmsg_add_string(b, "user", in->user);

	if (in->group)
		blobmsg_add_string(b, "group", in->group);

	if (in->has_jail) {
		void *r = blobmsg_open_table(b, "jail");
		if (in->jail.name)
			blobmsg_add_string(b, "name", in->jail.name);
		if (!in->bundle) {
			if (in->jail.hostname)
				blobmsg_add_string(b, "hostname", in->jail.hostname);

			blobmsg_add_u8(b, "procfs", in->jail.procfs);
			blobmsg_add_u8(b, "sysfs", in->jail.sysfs);
			blobmsg_add_u8(b, "ubus", in->jail.ubus);
			blobmsg_add_u8(b, "log", in->jail.log);
			blobmsg_add_u8(b, "ronly", in->jail.ronly);
			blobmsg_add_u8(b, "netns", in->jail.netns);
			blobmsg_add_u8(b, "userns", in->jail.userns);
			blobmsg_add_u8(b, "cgroupsns", in->jail.cgroupsns);
		} else {
			if (in->jail.pidfile)
				blobmsg_add_string(b, "pidfile", in->jail.pidfile);

			blobmsg_add_u8(b, "immediately", in->immediately);
		}
		blobmsg_add_u8(b, "console", (in->console.fd.fd > -1));
		blobmsg_close_table(b, r);
		if (!avl_is_empty(&in->jail.mount.avl)) {
			struct blobmsg_list_node *var;
			void *e = blobmsg_open_table(b, "mount");
			blobmsg_list_for_each(&in->jail.mount, var)
				blobmsg_add_string(b, blobmsg_name(var->data), blobmsg_data(var->data));
			blobmsg_close_table(b, e);
		}

		if (!avl_is_empty(&in->jail.setns.avl)) {
			struct blobmsg_list_node *var;
			void *s = blobmsg_open_array(b, "setns");
			blobmsg_list_for_each(&in->jail.setns, var)
				blobmsg_add_blob(b, var->data);
			blobmsg_close_array(b, s);
		}
	}

	if (in->extroot)
		blobmsg_add_string(b, "extroot", in->extroot);
	if (in->overlaydir)
		blobmsg_add_string(b, "overlaydir", in->overlaydir);
	if (in->tmpoverlaysize)
		blobmsg_add_string(b, "tmpoverlaysize", in->tmpoverlaysize);

	if (verbose && in->trigger)
		blobmsg_add_blob(b, in->trigger);

	if (in->watchdog.mode != INSTANCE_WATCHDOG_MODE_DISABLED) {
		void *r = blobmsg_open_table(b, "watchdog");
		blobmsg_add_u32(b, "mode", in->watchdog.mode);
		blobmsg_add_u32(b, "timeout", in->watchdog.freq);
		blobmsg_close_table(b, r);
	}

	blobmsg_close_table(b, i);
}
