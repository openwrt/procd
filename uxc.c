/*
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <sys/file.h>
#include <glob.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <libubus.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/ustream.h>

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#include "container.h"
#include "log.h"
#include "state-file.h"
#include "stdio-fds.h"

#define UXC_VERSION "0.3"
#define UXC_ETC_CONFDIR "/etc/uxc"
#define UXC_VOL_CONFDIR "/tmp/run/uvol/.meta/uxc"
#define UXC_VOL_SECRETDIR "/tmp/run/uvol/.meta/secrets"
#define UXC_RUN_DIR "/tmp/run/uxc"

static bool verbose = false;
static bool json_output = false;
static bool quiet_output = false;
static int stdio_fds[STDIO_FDS_NUM] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };
static const char *confdir = UXC_ETC_CONFDIR;
static struct ustream_fd cufd;
static struct ustream_fd lufd;


struct runtime_state {
	struct avl_node avl;
	char *container_name;
	char *instance_name;
	char *jail_name;
	bool running;
	int runtime_pid;
	int exitcode;
	uint64_t incarnation;
	uint32_t stop_timeout;
	struct blob_attr *ocistate;
};

enum {
	OPT_CONSOLE_SOCKET	= 0x100,
	OPT_NO_PIVOT,
	OPT_NO_NEW_KEYRING,
	OPT_PRESERVE_FDS,
	OPT_PROCESS,
	OPT_RESOURCES,
	OPT_AUTOSTART,
	OPT_PID_FILE,
	OPT_TEMP_OVERLAY_SIZE,
	OPT_WRITE_OVERLAY_PATH,
	OPT_MOUNTS,
	OPT_MODULE_VERSION,
	OPT_DATA_VOLUME,
	OPT_ENV,
	OPT_RESPAWN,
	OPT_STOP_TIMEOUT,
	OPT_UNSET,
};

static const struct option create_opts[] = {
	{"autostart",		no_argument,		0,	'a'			},
	{"bundle",		required_argument,	0,	'b'			},
	{"console-socket",	required_argument,	0,	OPT_CONSOLE_SOCKET	},
	{"mounts",		required_argument,	0,	'm'			},
	{"no-new-keyring",	no_argument,		0,	OPT_NO_NEW_KEYRING	},
	{"no-pivot",		no_argument,		0,	OPT_NO_PIVOT		},
	{"pid-file",		required_argument,	0,	'p'			},
	{"preserve-fds",	required_argument,	0,	OPT_PRESERVE_FDS	},
	{"temp-overlay-size",	required_argument,	0,	't'			},
	{"write-overlay-path",	required_argument,	0,	'w'			},
	{0,			0,			0,	0			}
};

static const struct option start_opts[] = {
	{"console",		no_argument,		0,	'c'	},
	{0,			0,			0,	0	}
};

static const struct option kill_opts[] = {
	{"signal",		required_argument,	0,	's'	},
	{"all",			no_argument,		0,	'a'	},
	{0,			0,			0,	0	}
};

static const struct option delete_opts[] = {
	{"force",		no_argument,		0,	'f'	},
	{"volumes",		no_argument,		0,	'V'	},
	{0,			0,			0,	0	}
};

static const struct option list_opts[] = {
	{"format",		required_argument,	0,	'f'	},
	{"json",		no_argument,		0,	'j'	},
	{"quiet",		no_argument,		0,	'q'	},
	{0,			0,			0,	0	}
};

static const struct option exec_opts[] = {
	{"console-socket",	required_argument,	0,	OPT_CONSOLE_SOCKET	},
	{"detach",		no_argument,		0,	'd'			},
	{"pid-file",		required_argument,	0,	'p'			},
	{"preserve-fds",	required_argument,	0,	OPT_PRESERVE_FDS	},
	{"process",		required_argument,	0,	OPT_PROCESS		},
	{"tty",			no_argument,		0,	't'			},
	{0,			0,			0,	0			}
};

static const struct option update_opts[] = {
	{"resources",		required_argument,	0,	OPT_RESOURCES		},
	{0,			0,			0,	0			}
};

static const struct option set_opts[] = {
	{"autostart",		required_argument,	0,	OPT_AUTOSTART		},
	{"data-volume",		required_argument,	0,	OPT_DATA_VOLUME		},
	{"env",			required_argument,	0,	OPT_ENV			},
	{"module-version",	required_argument,	0,	OPT_MODULE_VERSION	},
	{"mounts",		required_argument,	0,	OPT_MOUNTS		},
	{"pid-file",		required_argument,	0,	OPT_PID_FILE		},
	{"resources",		required_argument,	0,	OPT_RESOURCES		},
	{"respawn",		required_argument,	0,	OPT_RESPAWN		},
	{"stop-timeout",	required_argument,	0,	OPT_STOP_TIMEOUT	},
	{"temp-overlay-size",	required_argument,	0,	OPT_TEMP_OVERLAY_SIZE	},
	{"unset",		required_argument,	0,	OPT_UNSET		},
	{"write-overlay-path",	required_argument,	0,	OPT_WRITE_OVERLAY_PATH	},
	{0,			0,			0,	0			}
};

struct signame {
	int	signal;
	char	name[7];
};

static const struct signame signames[] = {
#ifdef SIGABRT
	{ .signal =   SIGABRT, .name = "ABRT" },
#endif
#ifdef SIGALRM
	{ .signal =   SIGALRM, .name = "ALRM" },
#endif
#ifdef SIGBUS
	{ .signal =    SIGBUS, .name = "BUS" },
#endif
#ifdef SIGCHLD
	{ .signal =   SIGCHLD, .name = "CHLD" },
#endif
#ifdef SIGCLD
	{ .signal =    SIGCLD, .name = "CLD" },
#endif
#ifdef SIGCONT
	{ .signal =   SIGCONT, .name = "CONT" },
#endif
#ifdef SIGEMT
	{ .signal =    SIGEMT, .name = "EMT" },
#endif
#ifdef SIGFPE
	{ .signal =    SIGFPE, .name = "FPE" },
#endif
#ifdef SIGHUP
	{ .signal =    SIGHUP, .name = "HUP" },
#endif
#ifdef SIGILL
	{ .signal =    SIGILL, .name = "ILL" },
#endif
#ifdef SIGINFO
	{ .signal =   SIGINFO, .name = "INFO" },
#endif
#ifdef SIGINT
	{ .signal =    SIGINT, .name = "INT" },
#endif
#ifdef SIGIO
	{ .signal =     SIGIO, .name = "IO" },
#endif
#ifdef SIGIOT
	{ .signal =    SIGIOT, .name = "IOT" },
#endif
#ifdef SIGKILL
	{ .signal =   SIGKILL, .name = "KILL" },
#endif
#ifdef SIGLOST
	{ .signal =   SIGLOST, .name = "LOST" },
#endif
#ifdef SIGPIPE
	{ .signal =   SIGPIPE, .name = "PIPE" },
#endif
#ifdef SIGPOLL
	{ .signal =   SIGPOLL, .name = "POLL" },
#endif
#ifdef SIGPROF
	{ .signal =   SIGPROF, .name = "PROF" },
#endif
#ifdef SIGPWR
	{ .signal =    SIGPWR, .name = "PWR" },
#endif
#ifdef SIGQUIT
	{ .signal =   SIGQUIT, .name = "QUIT" },
#endif
#ifdef SIGSEGV
	{ .signal =   SIGSEGV, .name = "SEGV" },
#endif
#ifdef SIGSTKFLT
	{ .signal = SIGSTKFLT, .name = "STKFLT" },
#endif
#ifdef SIGSTOP
	{ .signal =   SIGSTOP, .name = "STOP" },
#endif
#ifdef SIGSYS
	{ .signal =    SIGSYS, .name = "SYS" },
#endif
#ifdef SIGTERM
	{ .signal =   SIGTERM, .name = "TERM" },
#endif
#ifdef SIGTRAP
	{ .signal =   SIGTRAP, .name = "TRAP" },
#endif
#ifdef SIGTSTP
	{ .signal =   SIGTSTP, .name = "TSTP" },
#endif
#ifdef SIGTTIN
	{ .signal =   SIGTTIN, .name = "TTIN" },
#endif
#ifdef SIGTTOU
	{ .signal =   SIGTTOU, .name = "TTOU" },
#endif
#ifdef SIGUNUSED
	{ .signal = SIGUNUSED, .name = "UNUSED" },
#endif
#ifdef SIGURG
	{ .signal =    SIGURG, .name = "URG" },
#endif
#ifdef SIGUSR1
	{ .signal =   SIGUSR1, .name = "USR1" },
#endif
#ifdef SIGUSR2
	{ .signal =   SIGUSR2, .name = "USR2" },
#endif
#ifdef SIGVTALRM
	{ .signal = SIGVTALRM, .name = "VTALRM" },
#endif
#ifdef SIGWINCH
	{ .signal =  SIGWINCH, .name = "WINCH" },
#endif
#ifdef SIGXCPU
	{ .signal =   SIGXCPU, .name = "XCPU" },
#endif
#ifdef SIGXFSZ
	{ .signal =   SIGXFSZ, .name = "XFSZ" },
#endif
};

AVL_TREE(runtime, avl_strcmp, false, NULL);
AVL_TREE(settings, avl_strcmp, false, NULL);
static struct blob_buf conf;
static struct blob_buf settingsbuf;
static struct blob_attr *blockinfo;
static struct blob_attr *fstabinfo;
static struct ubus_context *ctx;

#define UXC_WAIT_UNSET		0
#define UXC_WAIT_OK		1
#define UXC_WAIT_STOPPED	2
#define UXC_WAIT_FAILED		3
#define UXC_WAIT_GONE		4

struct uxc_wait_state {
	const char *service;
	const char *instance;
	const char *success_event;
	const char *fail_event;
	const char *object;
	char reason[96];
	uint64_t since_incarnation;
	int result;
	int err;
};

static struct uxc_wait_state *active_wait;

enum {
	UXC_WAIT_SERVICE,
	UXC_WAIT_INSTANCE,
	UXC_WAIT_REASON,
	UXC_WAIT_ERRNO,
	UXC_WAIT_INCARNATION,
	__UXC_WAIT_INST_MAX,
};

static const struct blobmsg_policy uxc_wait_inst_policy[__UXC_WAIT_INST_MAX] = {
	[UXC_WAIT_SERVICE]     = { "service",     BLOBMSG_TYPE_STRING },
	[UXC_WAIT_INSTANCE]    = { "instance",    BLOBMSG_TYPE_STRING },
	[UXC_WAIT_REASON]      = { "reason",      BLOBMSG_TYPE_STRING },
	[UXC_WAIT_ERRNO]       = { "errno",       BLOBMSG_TYPE_INT32 },
	[UXC_WAIT_INCARNATION] = { "incarnation", BLOBMSG_TYPE_INT64 },
};

static void uxc_wait_timeout_cb(struct uloop_timeout *t)
{
	uloop_end();
}

static void uxc_wait_event_cb(struct ubus_context *uctx,
			      struct ubus_event_handler *ev,
			      const char *type, struct blob_attr *msg)
{
	struct blob_attr *tb[__UXC_WAIT_INST_MAX];
	struct uxc_wait_state *w = active_wait;
	int result;

	if (!w)
		return;
	blobmsg_parse(uxc_wait_inst_policy, __UXC_WAIT_INST_MAX, tb,
		      blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[UXC_WAIT_SERVICE] || !tb[UXC_WAIT_INSTANCE])
		return;
	if (w->service && strcmp(blobmsg_get_string(tb[UXC_WAIT_SERVICE]), w->service))
		return;
	if (w->instance && strcmp(blobmsg_get_string(tb[UXC_WAIT_INSTANCE]), w->instance))
		return;
	if (w->since_incarnation && tb[UXC_WAIT_INCARNATION] &&
	    blobmsg_get_u64(tb[UXC_WAIT_INCARNATION]) < w->since_incarnation)
		return;

	if (w->success_event && !strcmp(type, w->success_event))
		result = UXC_WAIT_OK;
	else if (w->fail_event && !strcmp(type, w->fail_event))
		result = UXC_WAIT_FAILED;
	else if (!strcmp(type, "instance.stopped"))
		result = UXC_WAIT_STOPPED;
	else
		return;

	if (tb[UXC_WAIT_REASON])
		snprintf(w->reason, sizeof(w->reason), "%s",
			 blobmsg_get_string(tb[UXC_WAIT_REASON]));

	if (tb[UXC_WAIT_ERRNO])
		w->err = blobmsg_get_u32(tb[UXC_WAIT_ERRNO]);

	w->result = result;
	uloop_end();
}

static const char *uxc_object_remove_path(struct blob_attr *msg)
{
	static const struct blobmsg_policy pol = {
		.name = "path", .type = BLOBMSG_TYPE_STRING
	};
	struct blob_attr *tb;

	if (!msg)
		return NULL;

	blobmsg_parse(&pol, 1, &tb, blob_data(msg), blob_len(msg));
	if (!tb)
		return NULL;

	return blobmsg_get_string(tb);
}

static void uxc_wait_gone_cb(struct ubus_context *uctx,
			     struct ubus_event_handler *ev,
			     const char *type, struct blob_attr *msg)
{
	struct uxc_wait_state *w = active_wait;
	const char *path;

	if (!w || !w->object)
		return;

	path = uxc_object_remove_path(msg);
	if (!path || strcmp(path, w->object))
		return;

	w->result = UXC_WAIT_GONE;
	uloop_end();
}

static const char *uxc_wait_why(struct uxc_wait_state *w)
{
	static char buf[160];

	if (!w->reason[0])
		return NULL;

	if (w->err)
		snprintf(buf, sizeof(buf), "%s: %s", w->reason,
			 strerror(w->err));
	else
		snprintf(buf, sizeof(buf), "%s", w->reason);

	return buf;
}

static struct ubus_event_handler uxc_wait_ev;
static struct ubus_event_handler uxc_wait_gone_ev;
static bool uxc_wait_armed;
static bool uxc_uloop_ready;

static void uxc_uloop_init(void)
{
	if (uxc_uloop_ready)
		return;

	uloop_init();
	ubus_add_uloop(ctx);
	uxc_uloop_ready = true;
}

static int uxc_wait_arm(struct uxc_wait_state *w)
{
	uxc_uloop_init();

	if (!uxc_wait_armed) {
		uxc_wait_ev.cb = uxc_wait_event_cb;
		if (ubus_register_event_handler(ctx, &uxc_wait_ev, "instance.*"))
			return -EIO;
		uxc_wait_gone_ev.cb = uxc_wait_gone_cb;
		if (ubus_register_event_handler(ctx, &uxc_wait_gone_ev,
						"ubus.object.remove")) {
			ubus_unregister_event_handler(ctx, &uxc_wait_ev);
			return -EIO;
		}
		uxc_wait_armed = true;
	}
	active_wait = w;
	return 0;
}

static int uxc_wait_run(struct uxc_wait_state *w, unsigned int timeout_ms)
{
	struct uloop_timeout t = { .cb = uxc_wait_timeout_cb };

	if (timeout_ms)
		uloop_timeout_set(&t, timeout_ms);
	if (w->result == UXC_WAIT_UNSET)
		uloop_run();
	if (timeout_ms)
		uloop_timeout_cancel(&t);
	if (w->result == UXC_WAIT_UNSET)
		return timeout_ms ? -ETIMEDOUT : -EINTR;
	return 0;
}

static void uxc_wait_disarm(void)
{
	active_wait = NULL;
}

static void usage(void) {
	printf("syntax: uxc [global options] <command> [parameters ...]\n");
	printf("global options:\n");
	printf("\t[--debug|-v] [--log <path>] [--log-format <text|json>]\n");
	printf("\t[--root <dir>] [--rootless[=auto|true|false]]\n");
	printf("\t[--systemd-cgroup] [--criu <path>]\n");
	printf("commands:\n");
	printf("\tlist [--json|--format json] [--quiet]\tlist all configured containers (runc-compatible)\n");
	printf("\tattach <conf>\t\t\t\tattach to container console\n");
	printf("\tcreate <conf>\t\t\t\t(re-)create <conf>\n");
	printf("\t\t[--bundle <path>]\t\t\tOCI bundle at <path>\n");
	printf("\t\t[--pid-file <path>]\t\t\twrite container PID to <path>\n");
	printf("\t\t[--console-socket <path>]\t\tAF_UNIX socket to receive the PTY master fd\n");
	printf("\t\t[--no-pivot|--no-new-keyring|--preserve-fds <N>] runc-compat, currently ignored\n");
	printf("\t\t[--autostart]\t\t\t\tstart on boot\n");
	printf("\t\t[--temp-overlay-size <size>]\t\tuse tmpfs overlay with {size}\n");
	printf("\t\t[--write-overlay-path <path>]\t\tuse overlay on {path}\n");
	printf("\t\t[--mounts <v1>,<v2>,...,<vN>]\t\trequire filesystems to be available\n");
	printf("\tstart [--console] <conf>\t\tstart container <conf>\n");
	printf("\ttrace <conf>\t\t\t\trun <conf> logging every syscall (seccomp trace)\n");
	printf("\taudit <conf>\t\t\t\trun <conf> enforcing its seccomp filter and logging denials\n");
	printf("\tcomplain <conf>\t\t\t\trun <conf> permitting but logging seccomp denials\n");
	printf("\tstate <conf>\t\t\t\tget state of container <conf>\n");
	printf("\tkill [--signal <sig>] [--all] <conf> [<sig>]\tsignal <conf> (no signal: graceful stop); --all+KILL: whole cgroup\n");
	printf("\trestart <conf>\t\t\t\tstop <conf> if running, then re-create and start it\n");
	printf("\tenable <conf>\t\t\t\tstart container <conf> on boot\n");
	printf("\tdisable <conf>\t\t\t\tdon't start container <conf> on boot\n");
	printf("\tset <conf> [--autostart 0|1] [--pid-file <path>]\n");
	printf("\t\t[--temp-overlay-size <size>] [--write-overlay-path <path>]\n");
	printf("\t\t[--mounts <v1>,<v2>,...,<vN>] [--module-version <string>]\n");
	printf("\t\t[--data-volume <vol>:<mnt>[:<size>]]... [--env <KEY>=<value>]...\n");
	printf("\t\t[--respawn enable=0|1[,min=N,max=N,multiplier=N,"
	       "max-retries=N,reset-period=N]]\n");
	printf("\t\t[--stop-timeout <seconds>] [--resources <file>]\n");
	printf("\t\t[--unset <key>]...\t\t\tedit the settings of <conf> in one rewrite\n");
	printf("\t\t\t\t\t\t--unset keys: autostart pidfile temp-overlay-size\n");
	printf("\t\t\t\t\t\twrite-overlay-path volumes module-version\n");
	printf("\t\t\t\t\t\tdata-volumes data-volume=<vol> env env=<KEY> respawn\n");
	printf("\t\t\t\t\t\tstop-timeout resources\n");
	printf("\tdelete <conf> [--force] [--volumes]\tdelete <conf>; --volumes also reaps its rw state and per-container volumes\n");
	printf("\treconcile\t\t\t\treap orphaned state of containers whose package was removed (data volumes kept)\n");
	printf("\tpause <conf>\t\t\t\tfreeze every process in container <conf>'s cgroup\n");
	printf("\tresume <conf>\t\t\t\tthaw a previously paused container <conf>\n");
	printf("\texec <conf> [--process <file>] [-d] [-p <pid-file>] [-- cmd args]\n");
	printf("\t\t\t\t\t\trun a command inside running container <conf>\n");
	printf("\tupdate <conf> --resources <file>\tapply linux.resources from <file> to running container <conf>\n");
}

enum {
	CONF_NAME,
	CONF_PATH,
	CONF_JAIL,
	CONF_AUTOSTART,
	CONF_PIDFILE,
	CONF_TEMP_OVERLAY_SIZE,
	CONF_WRITE_OVERLAY_PATH,
	CONF_VOLUMES,
	CONF_IDMAP_OFFSET,
	CONF_DATA_VOLUMES,
	CONF_OVERLAY_SIZE,
	CONF_INITENV,
	CONF_HOSTS_FILE,
	CONF_PROVISION,
	CONF_ORIGIN,
	CONF_MODULE_VERSION,
	CONF_ENV,
	CONF_RESPAWN,
	CONF_STOP_TIMEOUT,
	CONF_RESOURCES,
	__CONF_MAX,
};

static const struct blobmsg_policy conf_policy[__CONF_MAX] = {
	[CONF_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[CONF_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
	[CONF_JAIL] = { .name = "jail", .type = BLOBMSG_TYPE_STRING },
	[CONF_AUTOSTART] = { .name = "autostart", .type = BLOBMSG_TYPE_BOOL },
	[CONF_PIDFILE] = { .name = "pidfile", .type = BLOBMSG_TYPE_STRING },
	[CONF_TEMP_OVERLAY_SIZE] = { .name = "temp-overlay-size", .type = BLOBMSG_TYPE_STRING },
	[CONF_WRITE_OVERLAY_PATH] = { .name = "write-overlay-path", .type = BLOBMSG_TYPE_STRING },
	[CONF_VOLUMES] = { .name = "volumes", .type = BLOBMSG_TYPE_ARRAY },
	[CONF_IDMAP_OFFSET] = { .name = "idmap-offset", .type = BLOBMSG_TYPE_STRING },
	[CONF_DATA_VOLUMES] = { .name = "data-volumes", .type = BLOBMSG_TYPE_ARRAY },
	[CONF_OVERLAY_SIZE] = { .name = "overlay-size", .type = BLOBMSG_TYPE_STRING },
	[CONF_INITENV] = { .name = "initenv", .type = BLOBMSG_TYPE_TABLE },
	[CONF_HOSTS_FILE] = { .name = "hosts-file", .type = BLOBMSG_TYPE_STRING },
	[CONF_PROVISION] = { .name = "provision", .type = BLOBMSG_TYPE_ARRAY },
	[CONF_ORIGIN] = { .name = "origin", .type = BLOBMSG_TYPE_STRING },
	[CONF_MODULE_VERSION] = { .name = "module-version", .type = BLOBMSG_TYPE_STRING },
	[CONF_ENV] = { .name = "env", .type = BLOBMSG_TYPE_TABLE },
	[CONF_RESPAWN] = { .name = "respawn", .type = BLOBMSG_TYPE_TABLE },
	[CONF_STOP_TIMEOUT] = { .name = "stop-timeout", .type = BLOBMSG_TYPE_INT32 },
	[CONF_RESOURCES] = { .name = "resources", .type = BLOBMSG_TYPE_TABLE },
};

struct settings {
	struct avl_node avl;
	char *container_name;
	const char *fname;
	char *tmprwsize;
	char *writepath;
	signed char autostart;
	struct blob_attr *volumes;
	struct blob_attr *file;
	struct blob_attr *tb[__CONF_MAX];
};

enum {
	PROV_SOURCE,
	PROV_DESTINATION,
	PROV_SECRET,
	__PROV_MAX,
};

static const struct blobmsg_policy prov_policy[__PROV_MAX] = {
	[PROV_SOURCE] = { .name = "source", .type = BLOBMSG_TYPE_STRING },
	[PROV_DESTINATION] = { .name = "destination", .type = BLOBMSG_TYPE_STRING },
	[PROV_SECRET] = { .name = "secret", .type = BLOBMSG_TYPE_BOOL },
};

static int conf_load(bool load_settings)
{
	int gl_flags = GLOB_NOESCAPE | GLOB_MARK;
	int j, res;
	glob_t gl;
	char *globstr;
	void *c, *o;
	struct stat sb;
	struct blob_buf *target;

	if (asprintf(&globstr, "%s/%s*.json", confdir, load_settings?"settings/":"") == -1)
		return -ENOMEM;

	res = glob(globstr, gl_flags, NULL, &gl);
	if (res == 0)
		gl_flags |= GLOB_APPEND;

	free(globstr);

	if (!stat(UXC_VOL_CONFDIR, &sb)) {
		if (sb.st_mode & S_IFDIR) {
			if (asprintf(&globstr, "%s/%s*.json",  UXC_VOL_CONFDIR, load_settings?"settings/":"") == -1)
				return -ENOMEM;

			res = glob(globstr, gl_flags, NULL, &gl);
			free(globstr);
		}
	}

	target = load_settings ? &settingsbuf : &conf;
	blob_buf_init(target, 0);
	c = blobmsg_open_table(target, NULL);

	for (j = 0; j < gl.gl_pathc; j++) {
		o = blobmsg_open_table(target, gl.gl_pathv[j]);
		if (!blobmsg_add_json_from_file(target, gl.gl_pathv[j])) {
			ERROR("uxc: failed to load %s\n", gl.gl_pathv[j]);
			blobmsg_close_table(target, o);
			continue;
		}
		blobmsg_close_table(target, o);
	}
	blobmsg_close_table(target, c);
	globfree(&gl);

	return 0;
}

static struct settings *
settings_alloc(const char *container_name)
{
	struct settings *s;
	char *new_name;
	s = calloc_a(sizeof(*s), &new_name, strlen(container_name) + 1);
	strcpy(new_name, container_name);
	s->container_name = new_name;
	s->avl.key = s->container_name;
	s->autostart = -1;
	s->tmprwsize = NULL;
	s->writepath = NULL;
	s->volumes = NULL;
	s->file = NULL;
	return s;
}

static int settings_add(void)
{
	struct blob_attr *cur, *tb[__CONF_MAX];
	struct settings *s;
	int rem, err;

	avl_init(&settings, avl_strcmp, false, NULL);

	blobmsg_for_each_attr(cur, blob_data(settingsbuf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME])
			continue;

		if (tb[CONF_TEMP_OVERLAY_SIZE] && tb[CONF_WRITE_OVERLAY_PATH])
			return -EINVAL;

		s = settings_alloc(blobmsg_get_string(tb[CONF_NAME]));

		if (tb[CONF_AUTOSTART])
			s->autostart = blobmsg_get_bool(tb[CONF_AUTOSTART]);

		if (tb[CONF_TEMP_OVERLAY_SIZE])
			s->tmprwsize = blobmsg_get_string(tb[CONF_TEMP_OVERLAY_SIZE]);

		if (tb[CONF_WRITE_OVERLAY_PATH])
			s->writepath = blobmsg_get_string(tb[CONF_WRITE_OVERLAY_PATH]);

		s->volumes = tb[CONF_VOLUMES];
		s->fname = blobmsg_name(cur);
		s->file = cur;
		memcpy(s->tb, tb, sizeof(s->tb));

		err = avl_insert(&settings, &s->avl);
		if (err) {
			fprintf(stderr, "error adding settings for %s\n", blobmsg_get_string(tb[CONF_NAME]));
			free(s);
		}
	}

	return 0;
}

static void settings_free(void)
{
	struct settings *item, *tmp;

	avl_for_each_element_safe(&settings, item, avl, tmp) {
		avl_delete(&settings, &item->avl);
		free(item);
	}

	return;
}

static int registration_dir(const char *cfname, char *out, size_t len)
{
	const char *slash;
	int ret;

	slash = strrchr(cfname, '/');
	if (!slash)
		return -EINVAL;

	ret = snprintf(out, len, "%.*s", (int)(slash - cfname), cfname);
	if (ret < 0 || (size_t)ret >= len)
		return -ENAMETOOLONG;

	return 0;
}

static int settings_path_new(const char *cfname, const char *name, char *out, size_t len)
{
	char conf_dir[PATH_MAX];
	char dir[PATH_MAX];
	int ret;

	ret = registration_dir(cfname, conf_dir, sizeof(conf_dir));
	if (ret)
		return ret;

	ret = snprintf(dir, sizeof(dir), "%s/settings", conf_dir);
	if (ret < 0 || (size_t)ret >= sizeof(dir))
		return -ENAMETOOLONG;

	if (mkdir(dir, 0755) && errno != EEXIST)
		return -errno;

	ret = snprintf(out, len, "%s/%s.json", dir, name);
	if (ret < 0 || (size_t)ret >= len)
		return -ENAMETOOLONG;

	return 0;
}

static struct blob_attr *registration_find(const char *name, struct blob_attr **tb)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		if (!strcmp(name, blobmsg_get_string(tb[CONF_NAME])))
			return cur;
	}

	return NULL;
}

static struct blob_attr *blob_key_find(struct blob_attr *root, const char *name)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, root, rem)
		if (!strcmp(blobmsg_name(cur), name))
			return cur;

	return NULL;
}

static bool blob_has_key(struct blob_attr *root, const char *name)
{
	return !!blob_key_find(root, name);
}

static void blob_table_overlay(struct blob_buf *out, struct blob_attr *base,
			       struct blob_attr *over)
{
	struct blob_attr *cur;
	void *t;
	int rem;

	t = blobmsg_open_table(out, NULL);
	blobmsg_for_each_attr(cur, base, rem)
		if (!blob_has_key(over, blobmsg_name(cur)))
			blobmsg_add_blob(out, cur);

	blobmsg_for_each_attr(cur, over, rem)
		blobmsg_add_blob(out, cur);

	blobmsg_close_table(out, t);
}

static void *blob_container_open(struct blob_buf *out, const char *name, int type)
{
	if (type == BLOBMSG_TYPE_TABLE)
		return blobmsg_open_table(out, name);

	return blobmsg_open_array(out, name);
}

enum {
	STORE_STATE,
	STORE_SECRETS,
	__STORE_MAX,
};

static const char *const store_vol[__STORE_MAX] = {
	[STORE_STATE] = UXC_VOL_CONFDIR "/state",
	[STORE_SECRETS] = UXC_VOL_SECRETDIR,
};

static const char *const store_sub[__STORE_MAX] = {
	[STORE_STATE] = "state",
	[STORE_SECRETS] = "secrets",
};

static int store_root(const char *regdir, int store, char *out, size_t len)
{
	int ret;

	if (!strcmp(regdir, UXC_VOL_CONFDIR))
		ret = snprintf(out, len, "%s", store_vol[store]);
	else
		ret = snprintf(out, len, "%s/%s", regdir, store_sub[store]);

	if (ret < 0 || (size_t)ret >= len)
		return -ENAMETOOLONG;

	return 0;
}

static int store_root_find(const char *name, int store, char *out, size_t len)
{
	struct blob_attr *tb[__CONF_MAX], *found;
	char regdir[PATH_MAX];
	int ret;

	found = registration_find(name, tb);
	if (!found)
		return -ENOENT;

	ret = registration_dir(blobmsg_name(found), regdir, sizeof(regdir));
	if (ret)
		return ret;

	return store_root(regdir, store, out, len);
}

static int store_dir(const char *name, int store, char *out, size_t len)
{
	char root[PATH_MAX];
	int ret;

	ret = store_root_find(name, store, root, sizeof(root));
	if (ret)
		return ret;

	ret = snprintf(out, len, "%s/%s", root, name);
	if (ret < 0 || (size_t)ret >= len)
		return -ENAMETOOLONG;

	return 0;
}

static int rundir_path(const char *name, const char *file, char *out, size_t len)
{
	int ret;

	if (file)
		ret = snprintf(out, len, "%s/%s/%s", UXC_RUN_DIR, name, file);
	else
		ret = snprintf(out, len, "%s/%s", UXC_RUN_DIR, name);

	if (ret < 0 || (size_t)ret >= len)
		return -ENAMETOOLONG;

	return 0;
}

static int rundir_prepare(const char *name, const char *file, char *out, size_t len)
{
	char dir[PATH_MAX];
	int ret;

	ret = rundir_path(name, NULL, dir, sizeof(dir));
	if (ret)
		return ret;

	if (mkdir(UXC_RUN_DIR, 0700) && errno != EEXIST)
		return -errno;

	if (mkdir(dir, 0700) && errno != EEXIST)
		return -errno;

	return rundir_path(name, file, out, len);
}

enum {
	LIST_INSTANCES,
	__LIST_MAX,
};

static const struct blobmsg_policy list_policy[__LIST_MAX] = {
	[LIST_INSTANCES] = { .name = "instances", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	INSTANCE_RUNNING,
	INSTANCE_PID,
	INSTANCE_INCARNATION,
	INSTANCE_EXITCODE,
	INSTANCE_JAIL,
	__INSTANCE_MAX,
};

static const struct blobmsg_policy instance_policy[__INSTANCE_MAX] = {
	[INSTANCE_RUNNING] = { .name = "running", .type = BLOBMSG_TYPE_BOOL },
	[INSTANCE_PID] = { .name = "pid", .type = BLOBMSG_TYPE_INT32 },
	[INSTANCE_INCARNATION] = { .name = "incarnation", .type = BLOBMSG_TYPE_INT64 },
	[INSTANCE_EXITCODE] = { .name = "exit_code", .type = BLOBMSG_TYPE_INT32 },
	[INSTANCE_JAIL] = { .name = "jail", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	JAIL_NAME,
	JAIL_STOP_TIMEOUT,
	__JAIL_MAX,
};

static const struct blobmsg_policy jail_policy[__JAIL_MAX] = {
	[JAIL_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[JAIL_STOP_TIMEOUT] = { .name = "stop_timeout", .type = BLOBMSG_TYPE_INT32 },
};

static struct runtime_state *
runtime_alloc(const char *container_name)
{
	struct runtime_state *s;
	char *new_name;
	s = calloc_a(sizeof(*s), &new_name, strlen(container_name) + 1);
	strcpy(new_name, container_name);
	s->container_name = new_name;
	s->avl.key = s->container_name;
	return s;
}

enum {
	STATE_OCIVERSION,
	STATE_ID,
	STATE_STATUS,
	STATE_PID,
	STATE_BUNDLE,
	STATE_ANNOTATIONS,
	STATE_NETWORK,
	STATE_CREATED,
	STATE_ROOTFS,
	__STATE_MAX,
};

static const struct blobmsg_policy state_policy[__STATE_MAX] = {
	[STATE_OCIVERSION] = { .name = "ociVersion", .type = BLOBMSG_TYPE_STRING },
	[STATE_ID] = { .name = "id", .type = BLOBMSG_TYPE_STRING },
	[STATE_STATUS] = { .name = "status", .type = BLOBMSG_TYPE_STRING },
	[STATE_PID] = { .name = "pid", .type = BLOBMSG_TYPE_INT32 },
	[STATE_BUNDLE] = { .name = "bundle", .type = BLOBMSG_TYPE_STRING },
	[STATE_ANNOTATIONS] = { .name = "annotations", .type = BLOBMSG_TYPE_TABLE },
	[STATE_NETWORK] = { .name = "org.openwrt.network", .type = BLOBMSG_TYPE_TABLE },
	[STATE_CREATED] = { .name = "created", .type = BLOBMSG_TYPE_STRING },
	[STATE_ROOTFS] = { .name = "rootfs", .type = BLOBMSG_TYPE_STRING },
};

enum {
	NET_NAMESPACE,
	NET_INTERFACES,
	__NET_MAX,
};

static const struct blobmsg_policy net_policy[__NET_MAX] = {
	[NET_NAMESPACE] = { .name = "namespace", .type = BLOBMSG_TYPE_STRING },
	[NET_INTERFACES] = { .name = "interfaces", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	NET_IF_NAME,
	NET_IF_ADDRESSES,
	__NET_IF_MAX,
};

static const struct blobmsg_policy net_if_policy[__NET_IF_MAX] = {
	[NET_IF_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[NET_IF_ADDRESSES] = { .name = "addresses", .type = BLOBMSG_TYPE_ARRAY },
};


static void ocistate_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr **ocistate = (struct blob_attr **)req->priv;
	struct blob_attr *tb[__STATE_MAX];

	blobmsg_parse(state_policy, __STATE_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[STATE_OCIVERSION] ||
	    !tb[STATE_ID] ||
	    !tb[STATE_STATUS] ||
	    !tb[STATE_BUNDLE])
		return;

	*ocistate = blob_memdup(msg);
}

static void get_ocistate(struct blob_attr **ocistate, const char *name)
{
	char *objname;
	unsigned int id;
	int ret;
	*ocistate = NULL;

	if (asprintf(&objname, "container.%s", name) == -1)
		exit(EXIT_FAILURE);

	ret = ubus_lookup_id(ctx, objname, &id);
	free(objname);
	if (ret)
		return;

	ubus_invoke(ctx, id, "state", NULL, ocistate_cb, ocistate, 3000);
}

static void list_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *cur, *curi, *tl[__LIST_MAX], *ti[__INSTANCE_MAX], *tj[__JAIL_MAX];
	int rem, remi;
	const char *container_name, *instance_name, *jail_name;
	bool running;
	uint64_t incarnation;
	int pid, exitcode;
	struct runtime_state *rs;

	blobmsg_for_each_attr(cur, msg, rem) {
		container_name = blobmsg_name(cur);
		blobmsg_parse(list_policy, __LIST_MAX, tl, blobmsg_data(cur), blobmsg_len(cur));
		if (!tl[LIST_INSTANCES])
			continue;

		blobmsg_for_each_attr(curi, tl[LIST_INSTANCES], remi) {
			instance_name = blobmsg_name(curi);
			blobmsg_parse(instance_policy, __INSTANCE_MAX, ti, blobmsg_data(curi), blobmsg_len(curi));

			if (!ti[INSTANCE_JAIL])
				continue;

			blobmsg_parse(jail_policy, __JAIL_MAX, tj, blobmsg_data(ti[INSTANCE_JAIL]), blobmsg_len(ti[INSTANCE_JAIL]));
			if (!tj[JAIL_NAME])
				continue;

			jail_name = blobmsg_get_string(tj[JAIL_NAME]);

			running = ti[INSTANCE_RUNNING] && blobmsg_get_bool(ti[INSTANCE_RUNNING]);

			if (ti[INSTANCE_PID])
				pid = blobmsg_get_u32(ti[INSTANCE_PID]);
			else
				pid = -1;

			if (ti[INSTANCE_EXITCODE])
				exitcode = blobmsg_get_u32(ti[INSTANCE_EXITCODE]);
			else
				exitcode = -1;

			if (ti[INSTANCE_INCARNATION])
				incarnation = blobmsg_get_u64(ti[INSTANCE_INCARNATION]);
			else
				incarnation = 0;

			rs = runtime_alloc(container_name);
			rs->instance_name = strdup(instance_name);
			rs->jail_name = strdup(jail_name);
			rs->runtime_pid = pid;
			rs->exitcode = exitcode;
			rs->incarnation = incarnation;
			rs->running = running;
			if (tj[JAIL_STOP_TIMEOUT])
				rs->stop_timeout = blobmsg_get_u32(tj[JAIL_STOP_TIMEOUT]);
			avl_insert(&runtime, &rs->avl);
		}
	}

	return;
}

struct uxc_incarnation_lookup {
	const char *service;
	const char *instance;
	uint64_t incarnation;
};

static void uxc_instance_incarnation_cb(struct ubus_request *req, int type,
					struct blob_attr *msg)
{
	struct blob_attr *cur, *curi, *tl[__LIST_MAX], *ti[__INSTANCE_MAX];
	struct uxc_incarnation_lookup *l = req->priv;
	int rem, remi;

	blobmsg_for_each_attr(cur, msg, rem) {
		if (strcmp(blobmsg_name(cur), l->service))
			continue;

		blobmsg_parse(list_policy, __LIST_MAX, tl, blobmsg_data(cur),
			      blobmsg_len(cur));
		if (!tl[LIST_INSTANCES])
			continue;

		blobmsg_for_each_attr(curi, tl[LIST_INSTANCES], remi) {
			if (strcmp(blobmsg_name(curi), l->instance))
				continue;

			blobmsg_parse(instance_policy, __INSTANCE_MAX, ti,
				      blobmsg_data(curi), blobmsg_len(curi));
			if (ti[INSTANCE_INCARNATION])
				l->incarnation =
					blobmsg_get_u64(ti[INSTANCE_INCARNATION]);
		}
	}
}

static uint64_t uxc_instance_incarnation(const char *service,
					 const char *instance)
{
	struct uxc_incarnation_lookup l = { 0 };
	uint32_t id;

	l.service = service;
	l.instance = instance;

	if (ubus_lookup_id(ctx, "container", &id))
		return 0;

	if (ubus_invoke(ctx, id, "list", NULL, uxc_instance_incarnation_cb, &l,
			3000))
		return 0;

	return l.incarnation;
}

static int runtime_load(void)
{
	struct runtime_state *item, *tmp;
	uint32_t id;

	avl_init(&runtime, avl_strcmp, false, NULL);
	if (ubus_lookup_id(ctx, "container", &id) ||
		ubus_invoke(ctx, id, "list", NULL, list_cb, &runtime, 3000))
		return -EIO;

	avl_for_each_element_safe(&runtime, item, avl, tmp)
		get_ocistate(&item->ocistate, item->jail_name);

	return 0;
}

static bool runtime_live(struct runtime_state *rs)
{
	struct blob_attr *tb[__STATE_MAX];

	if (!rs)
		return false;

	if (!rs->ocistate)
		return rs->running;

	blobmsg_parse(state_policy, __STATE_MAX, tb, blobmsg_data(rs->ocistate),
		      blobmsg_len(rs->ocistate));

	if (!tb[STATE_STATUS])
		return rs->running;

	return strcmp(blobmsg_get_string(tb[STATE_STATUS]), "stopped") != 0;
}

static void runtime_free(void)
{
	struct runtime_state *item, *tmp;

	avl_for_each_element_safe(&runtime, item, avl, tmp) {
		avl_delete(&runtime, &item->avl);
		free(item->instance_name);
		free(item->jail_name);
		free(item->ocistate);
		free(item);
	}

	return;
}

enum {
	VOL_NAME,
	VOL_MOUNTPOINT,
	VOL_SIZE,
	__VOL_MAX,
};

static const struct blobmsg_policy vol_policy[__VOL_MAX] = {
	[VOL_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[VOL_MOUNTPOINT] = { .name = "mountpoint", .type = BLOBMSG_TYPE_STRING },
	[VOL_SIZE] = { .name = "size", .type = BLOBMSG_TYPE_STRING },
};

#define UVOL_EXEC_TIMEOUT_DEFAULT	120
#define UVOL_TIMEOUT_MARGIN_MS		10000

enum {
	UVOL_CODE,
	UVOL_READY,
	UVOL_META,
	__UVOL_MAX,
};

static const struct blobmsg_policy uvol_policy[__UVOL_MAX] = {
	[UVOL_CODE] = { .name = "code", .type = BLOBMSG_TYPE_INT32 },
	[UVOL_READY] = { .name = "ready", .type = BLOBMSG_TYPE_BOOL },
	[UVOL_META] = { .name = "meta", .type = BLOBMSG_TYPE_BOOL },
};

struct uvol_reply {
	int code;
	bool answered;
	bool ready;
	bool meta;
};

static void uvol_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *tb[__UVOL_MAX];
	struct uvol_reply *reply = req->priv;

	if (!msg)
		return;

	blobmsg_parse(uvol_policy, __UVOL_MAX, tb, blob_data(msg), blob_len(msg));

	reply->answered = true;

	if (tb[UVOL_CODE])
		reply->code = blobmsg_get_u32(tb[UVOL_CODE]);

	if (tb[UVOL_READY])
		reply->ready = blobmsg_get_bool(tb[UVOL_READY]);

	if (tb[UVOL_META])
		reply->meta = blobmsg_get_bool(tb[UVOL_META]);
}

static void uci_value_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	static const struct blobmsg_policy pol = {
		.name = "value", .type = BLOBMSG_TYPE_STRING
	};
	struct blob_attr *tb;

	if (!msg)
		return;

	blobmsg_parse(&pol, 1, &tb, blob_data(msg), blob_len(msg));
	if (tb)
		*(int *)req->priv = atoi(blobmsg_get_string(tb));
}

static uint32_t uvol_ubus_id(void)
{
	static bool looked_up;
	static uint32_t id;

	if (!looked_up) {
		if (ubus_lookup_id(ctx, "uvol", &id))
			id = 0;

		looked_up = true;
	}

	return id;
}

static bool uvol_ubus_available(void)
{
	return uvol_ubus_id() != 0;
}

static int uvol_timeout(void)
{
	static struct blob_buf req;
	static int timeout_ms;
	int secs = UVOL_EXEC_TIMEOUT_DEFAULT;
	uint32_t id;

	if (timeout_ms)
		return timeout_ms;

	if (!ubus_lookup_id(ctx, "uci", &id)) {
		blob_buf_init(&req, 0);
		blobmsg_add_string(&req, "config", "rpcd");
		blobmsg_add_string(&req, "section", "@rpcd[0]");
		blobmsg_add_string(&req, "option", "timeout");
		ubus_invoke(ctx, id, "get", req.head, uci_value_cb, &secs, 3000);
	}

	if (secs < 1 || secs > 600)
		secs = UVOL_EXEC_TIMEOUT_DEFAULT;

	timeout_ms = secs * 1000 + UVOL_TIMEOUT_MARGIN_MS;

	return timeout_ms;
}

static int uvol_call(const char *method, struct blob_attr *args,
		     struct uvol_reply *reply)
{
	static struct blob_buf empty;

	memset(reply, 0, sizeof(*reply));

	if (!args) {
		blob_buf_init(&empty, 0);
		args = empty.head;
	}

	if (ubus_invoke(ctx, uvol_ubus_id(), method, args, uvol_cb, reply,
			uvol_timeout()))
		return -EIO;

	if (!reply->answered)
		return -EIO;

	return 0;
}

static int uvol_call_volume(const char *method, const char *vol)
{
	static struct blob_buf req;
	struct uvol_reply reply;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", vol);

	if (uvol_call(method, req.head, &reply))
		return -EIO;

	return reply.code;
}

static bool uvol_name_valid(const char *vol)
{
	size_t i;

	if (!vol || !*vol || strlen(vol) > 127)
		return false;

	if (!isalnum((unsigned char)vol[0]) && vol[0] != '_' && vol[0] != '.')
		return false;

	for (i = 0; vol[i]; i++)
		if (!isalnum((unsigned char)vol[i]) && vol[i] != '.' &&
		    vol[i] != '_' && vol[i] != '-')
			return false;

	return true;
}

static int uvol_name_check(const char *vol)
{
	if (uvol_name_valid(vol))
		return 0;

	fprintf(stderr, "uxc: refusing volume name '%s'\n", vol ? vol : "");

	return -EINVAL;
}

static const char *uvol_volume_name(const char *path)
{
	const char prefix[] = "/tmp/run/uvol/";
	const size_t plen = sizeof(prefix) - 1;

	if (!path || strncmp(path, prefix, plen))
		return NULL;

	if (!path[plen] || strchr(path + plen, '/'))
		return NULL;

	if (!uvol_name_valid(path + plen))
		return NULL;

	return path + plen;
}

static int run_uvol_argv(char *const argv[])
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid == 0) {
		execv(argv[0], argv);
		_exit(127);
	} else if (pid < 0) {
		return -errno;
	}

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR);

	if (!WIFEXITED(status))
		return -EIO;

	return WEXITSTATUS(status);
}

static int run_uvol(const char *action, const char *vol)
{
	char *argv[] = { "/usr/sbin/uvol", (char *)action, (char *)vol, NULL };

	if (uvol_name_check(vol))
		return -EINVAL;

	if (uvol_ubus_available())
		return uvol_call_volume(action, vol);

	return run_uvol_argv(argv);
}

static int run_uvol_create(const char *vol, long long size, const char *mode)
{
	char sizebytes[32];
	char *argv[] = { "/usr/sbin/uvol", "create", (char *)vol,
			 sizebytes, (char *)mode, NULL };
	static struct blob_buf req;
	struct uvol_reply reply;

	if (uvol_name_check(vol))
		return -EINVAL;

	snprintf(sizebytes, sizeof(sizebytes), "%lld", size);

	if (!uvol_ubus_available())
		return run_uvol_argv(argv);

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", vol);
	blobmsg_add_u64(&req, "size", size);
	blobmsg_add_string(&req, "mode", mode);

	if (uvol_call("create", req.head, &reply))
		return -EIO;

	return reply.code;
}

static int run_uvol_resize(const char *vol, long long size)
{
	char sizebytes[32];
	char *argv[] = { "/usr/sbin/uvol", "resize", (char *)vol, sizebytes, NULL };
	static struct blob_buf req;
	struct uvol_reply reply;

	if (uvol_name_check(vol))
		return -EINVAL;

	snprintf(sizebytes, sizeof(sizebytes), "%lld", size);

	if (!uvol_ubus_available())
		return run_uvol_argv(argv);

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", vol);
	blobmsg_add_u64(&req, "size", size);

	if (uvol_call("resize", req.head, &reply))
		return -EIO;

	return reply.code;
}

static int uvol_status(const char *vol)
{
	char *argv[] = { "/usr/sbin/uvol", "status", (char *)vol, NULL };

	if (uvol_name_check(vol))
		return -EINVAL;

	if (uvol_ubus_available())
		return uvol_call_volume("status", vol);

	return run_uvol_argv(argv);
}

static bool uvol_meta_pending(void)
{
	struct uvol_reply reply;

	if (!uvol_ubus_available())
		return uvol_status(".meta") != 0;

	if (uvol_call("ready", NULL, &reply))
		return true;

	return !reply.meta;
}

static bool uvol_backend_pending(void)
{
	struct uvol_reply reply;

	if (!uvol_ubus_available())
		return false;

	if (uvol_call("ready", NULL, &reply))
		return true;

	return !reply.ready;
}

static long long parse_size_bytes(const char *s)
{
	char *end;
	long long v;

	if (!s)
		return -1;

	v = strtoll(s, &end, 10);
	if (end == s || v < 0)
		return -1;

	switch (*end) {
	case 'g':
	case 'G':
		v *= 1024;
	case 'm':
	case 'M':
		v *= 1024;
	case 'k':
	case 'K':
		v *= 1024;
		++end;
		break;
	case '\0':
		break;
	default:
		return -1;
	}

	if (*end)
		return -1;

	return v;
}

static int create_rw_uvol(const char *volname, long long bytes)
{
	int ret, st;

	ret = run_uvol_create(volname, bytes, "rw");
	if (ret != -EIO)
		return ret;

	st = uvol_status(volname);
	if (st != 16 && st != 22)
		return ret;

	return run_uvol_create(volname, bytes, "rw");
}

static int provision_rw_uvol(const char *volname, const char *size)
{
	long long bytes;
	int st, rr;

	bytes = parse_size_bytes(size);
	if (bytes <= 0) {
		fprintf(stderr, "uxc: invalid size '%s' for volume %s\n", size, volname);
		return -EINVAL;
	}

	st = uvol_status(volname);
	if (st == 2) {
		if (create_rw_uvol(volname, bytes)) {
			fprintf(stderr, "uxc: failed to create volume %s\n", volname);
			return -EIO;
		}
	} else {
		rr = run_uvol_resize(volname, bytes);
		if (rr == 22)
			fprintf(stderr, "uxc: volume %s larger than requested, kept\n", volname);
		else if (rr) {
			fprintf(stderr, "uxc: failed to resize volume %s\n", volname);
			return -EIO;
		}
	}

	if (run_uvol("up", volname)) {
		fprintf(stderr, "uxc: failed to activate volume %s\n", volname);
		return -EIO;
	}

	return 0;
}

#define DATA_VOLUME_SIZE_DEFAULT	"64m"

static void data_volume_name(const char *container, const char *vol, char *buf, size_t len)
{
	snprintf(buf, len, "%s.%s", container, vol);
}

static int provision_data_volumes(const char *container, struct blob_attr *vols,
				  struct blob_buf *req)
{
	struct blob_attr *vcur, *vt[__VOL_MAX];
	char volname[256], bindspec[PATH_MAX];
	const char *vname, *vmount, *vsize;
	int vrem;

	blobmsg_for_each_attr(vcur, vols, vrem) {
		blobmsg_parse(vol_policy, __VOL_MAX, vt, blobmsg_data(vcur), blobmsg_len(vcur));
		if (!vt[VOL_NAME] || !vt[VOL_MOUNTPOINT])
			continue;

		vname = blobmsg_get_string(vt[VOL_NAME]);
		vmount = blobmsg_get_string(vt[VOL_MOUNTPOINT]);
		vsize = vt[VOL_SIZE] ? blobmsg_get_string(vt[VOL_SIZE]) : DATA_VOLUME_SIZE_DEFAULT;

		data_volume_name(container, vname, volname, sizeof(volname));
		if (provision_rw_uvol(volname, vsize))
			return -EIO;

		snprintf(bindspec, sizeof(bindspec), "/tmp/run/uvol/%s:%s", volname, vmount);
		blobmsg_add_string(req, bindspec, "2");
	}

	return 0;
}

static void data_volume_remove(const char *container, const char *vol)
{
	char volname[256];

	data_volume_name(container, vol, volname, sizeof(volname));
	if (run_uvol("remove", volname))
		fprintf(stderr, "uxc: warning: could not remove volume %s\n", volname);
}

static void reap_data_volumes(const char *container, struct blob_attr *vols)
{
	struct blob_attr *vcur, *vt[__VOL_MAX];
	int vrem;

	blobmsg_for_each_attr(vcur, vols, vrem) {
		blobmsg_parse(vol_policy, __VOL_MAX, vt, blobmsg_data(vcur), blobmsg_len(vcur));
		if (!vt[VOL_NAME])
			continue;

		data_volume_remove(container, blobmsg_get_string(vt[VOL_NAME]));
	}
}

static inline int setup_tios(int fd, struct termios *oldtios)
{
	struct termios newtios;

	if (!isatty(fd)) {
		return -EIO;
	}

	/* Get current termios */
	if (tcgetattr(fd, oldtios) < 0)
		return -errno;

	newtios = *oldtios;

	/* We use the same settings that ssh does. */
	newtios.c_iflag |= IGNPAR;
	newtios.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
	newtios.c_lflag &= ~(TOSTOP | ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
	newtios.c_oflag &= ~ONLCR;
	newtios.c_oflag |= OPOST;
	newtios.c_cc[VMIN] = 1;
	newtios.c_cc[VTIME] = 0;

	/* Set new attributes */
	if (tcsetattr(fd, TCSAFLUSH, &newtios) < 0)
	        return -errno;

	return 0;
}


static void client_cb(struct ustream *s, int bytes)
{
	char *buf;
	int len, rv;

	do {
		buf = ustream_get_read_buf(s, &len);
		if (!buf)
			break;

		rv = ustream_write(&lufd.stream, buf, len, false);

		if (rv > 0)
			ustream_consume(s, rv);

		if (rv <= len)
			break;
	} while(1);
}

static void local_cb(struct ustream *s, int bytes)
{
	char *buf;
	int len, rv;

	do {
		buf = ustream_get_read_buf(s, &len);
		if (!buf)
			break;

		if ((len > 0) && (buf[0] == 2))
				uloop_end();

		rv = ustream_write(&cufd.stream, buf, len, false);

		if (rv > 0)
			ustream_consume(s, rv);

		if (rv <= len)
			break;
	} while(1);
}

static int uxc_attach(const char *container_name)
{
	struct ubus_context *ctx;
	uint32_t id;
	static struct blob_buf req;
	int client_fd = -1, server_fd = -1, tty_fd = -1;
	struct termios oldtermios;
	bool tty_raw = false;
	int rc;

	ctx = ubus_connect(NULL);
	if (!ctx) {
		fprintf(stderr, "can't connect to ubus!\n");
		return -ECONNREFUSED;
	}

	client_fd = posix_openpt(O_RDWR | O_NOCTTY);
	if (client_fd < 0) {
		fprintf(stderr, "can't create virtual console!\n");
		rc = -EIO;
		goto out;
	}
	grantpt(client_fd);
	unlockpt(client_fd);
	server_fd = open(ptsname(client_fd), O_RDWR | O_NOCTTY);
	if (server_fd < 0) {
		fprintf(stderr, "can't open virtual console!\n");
		rc = -EIO;
		goto out;
	}

	tty_fd = open("/dev/tty", O_RDWR);
	if (tty_fd < 0) {
		fprintf(stderr, "can't open local console!\n");
		rc = -EIO;
		goto out;
	}
	if (!setup_tios(tty_fd, &oldtermios))
		tty_raw = true;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", container_name);
	blobmsg_add_string(&req, "instance", container_name);

	if (ubus_lookup_id(ctx, "container", &id)) {
		fprintf(stderr, "uxc: 'container' ubus object not found\n");
		blob_buf_free(&req);
		rc = -ENXIO;
		goto out;
	}
	rc = ubus_invoke_fd(ctx, id, "console_attach", req.head, NULL, NULL, 3000, server_fd);
	blob_buf_free(&req);
	if (rc) {
		if (rc == UBUS_STATUS_NOT_SUPPORTED)
			fprintf(stderr, "uxc: container '%s' has no console; "
				"re-create it with console=true (OCI process.terminal=true)\n",
				container_name);
		else
			fprintf(stderr, "uxc: console_attach failed: %s\n", ubus_strerror(rc));
		rc = -ENXIO;
		goto out;
	}

	close(server_fd);
	server_fd = -1;
	ubus_free(ctx);
	ctx = NULL;

	uloop_init();

	lufd.stream.notify_read = local_cb;
	ustream_fd_init(&lufd, tty_fd);

	cufd.stream.notify_read = client_cb;
	ustream_fd_init(&cufd, client_fd);

	fprintf(stderr, "attaching to jail console. press [CTRL]+[B] to exit.\n");
	close(0);
	close(1);
	close(2);
	uloop_run();

	ustream_free(&lufd.stream);
	ustream_free(&cufd.stream);
	rc = 0;

out:
	if (tty_raw && tty_fd >= 0)
		tcsetattr(tty_fd, TCSAFLUSH, &oldtermios);
	if (tty_fd >= 0)
		close(tty_fd);
	if (server_fd >= 0)
		close(server_fd);
	if (client_fd >= 0)
		close(client_fd);
	if (ctx)
		ubus_free(ctx);
	return rc;
}

static int uxc_exists(char *name)
{
	struct runtime_state *rsstate = NULL;
	rsstate = avl_find_element(&runtime, name, rsstate, avl);

	if (runtime_live(rsstate))
		return -EEXIST;

	return 0;
}

static void gen_secret(char *out, size_t outlen)
{
	static const char hex[] = "0123456789abcdef";
	unsigned char buf[24];
	size_t i, n;
	FILE *f;

	out[0] = '\0';
	f = fopen("/dev/urandom", "r");
	if (!f)
		return;
	n = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	if (n != sizeof(buf) || outlen < (n * 2 + 1))
		return;

	for (i = 0; i < n; i++) {
		out[i * 2] = hex[buf[i] >> 4];
		out[i * 2 + 1] = hex[buf[i] & 0xf];
	}
	out[n * 2] = '\0';
}

static void mkdir_path(const char *path, mode_t mode)
{
	char tmp[PATH_MAX];
	char *p;

	if (strlen(path) >= sizeof(tmp))
		return;
	strcpy(tmp, path);
	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		mkdir(tmp, mode);
		*p = '/';
	}
	mkdir(tmp, mode);
}

static bool shared_secret(const char *root, const char *scope, char *out,
			  size_t outlen)
{
	char dir[PATH_MAX], path[PATH_MAX], lockpath[PATH_MAX];
	const char *p;
	int lockfd;
	FILE *f;
	size_t n;
	bool ok = false;

	if (!scope || !*scope || *scope == '/' || strstr(scope, ".."))
		return false;
	for (p = scope; *p; p++)
		if (!isalnum((unsigned char)*p) && *p != '/' && *p != '-' &&
		    *p != '_' && *p != '.')
			return false;

	snprintf(dir, sizeof(dir), "%s/%s", root, scope);
	snprintf(path, sizeof(path), "%s/value", dir);
	snprintf(lockpath, sizeof(lockpath), "%s/.lock", root);

	mkdir_path(root, 0700);
	lockfd = open(lockpath, O_CREAT | O_RDWR, 0600);
	if (lockfd < 0)
		return false;
	flock(lockfd, LOCK_EX);

	f = fopen(path, "r");
	if (f) {
		n = fread(out, 1, outlen - 1, f);
		fclose(f);
		out[n] = '\0';
		while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
			out[--n] = '\0';
		ok = (out[0] != '\0');
	} else {
		gen_secret(out, outlen);
		if (out[0]) {
			mkdir_path(dir, 0700);
			f = fopen(path, "w");
			if (f) {
				fchmod(fileno(f), 0600);
				fprintf(f, "%s", out);
				fclose(f);
				ok = true;
			}
		}
	}

	flock(lockfd, LOCK_UN);
	close(lockfd);
	return ok;
}

static bool envfile_has_key(const char *path, const char *key)
{
	char line[4096];
	size_t klen = strlen(key);
	bool found = false;
	FILE *f;

	f = fopen(path, "r");
	if (!f)
		return false;
	while (fgets(line, sizeof(line), f))
		if (!strncmp(line, key, klen) && line[klen] == '=') {
			found = true;
			break;
		}
	fclose(f);
	return found;
}

static void materialise_initenv(const char *name, struct blob_attr *initenv)
{
	char statedir[PATH_MAX], dir[PATH_MAX], path[PATH_MAX], secret[64];
	char secrets[PATH_MAX];
	struct blob_attr *cur;
	const char *key, *val;
	int rem;
	FILE *f;

	if (store_root_find(name, STORE_STATE, statedir, sizeof(statedir)) ||
	    store_root_find(name, STORE_SECRETS, secrets, sizeof(secrets)))
		return;

	snprintf(dir, sizeof(dir), "%s/%s", statedir, name);
	snprintf(path, sizeof(path), "%s/env", dir);

	blobmsg_for_each_attr(cur, initenv, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;
		key = blobmsg_name(cur);
		if (!key || !*key || envfile_has_key(path, key))
			continue;

		val = blobmsg_get_string(cur);
		if (!strcmp(val, "generate")) {
			gen_secret(secret, sizeof(secret));
			if (!secret[0])
				continue;
			val = secret;
		} else if (!strncmp(val, "generate@", 9)) {
			if (!shared_secret(secrets, val + 9, secret, sizeof(secret)))
				continue;
			val = secret;
		}

		mkdir(statedir, 0700);
		mkdir(dir, 0700);
		f = fopen(path, "a");
		if (!f)
			return;
		fchmod(fileno(f), 0600);
		fprintf(f, "%s=%s\n", key, val);
		fclose(f);

		if (val == secret)
			fprintf(stderr, "uxc: generated %s for container %s\n", key, name);
	}
}

static void env_run_add_store(FILE *out, const char *path, struct blob_attr *env)
{
	char *line = NULL, *eq;
	size_t cap = 0;
	ssize_t n;
	FILE *f;

	f = fopen(path, "r");
	if (!f)
		return;

	while ((n = getline(&line, &cap, f)) > 0) {
		eq = strchr(line, '=');
		if (eq) {
			*eq = '\0';
			if (blob_has_key(env, line))
				continue;

			*eq = '=';
		}

		fputs(line, out);
		if (line[n - 1] != '\n')
			fputc('\n', out);
	}

	free(line);
	fclose(f);
}

static int env_run_write(const char *name, struct blob_attr *env)
{
	char dir[PATH_MAX], path[PATH_MAX], store[PATH_MAX];
	struct blob_attr *cur;
	char *buf = NULL;
	size_t len = 0;
	int rem, ret;
	FILE *out;

	ret = store_dir(name, STORE_STATE, dir, sizeof(dir));
	if (ret)
		return ret;

	snprintf(store, sizeof(store), "%s/env", dir);
	ret = rundir_path(name, "env.run", path, sizeof(path));
	if (ret)
		return ret;

	out = open_memstream(&buf, &len);
	if (!out)
		return -errno;

	blobmsg_for_each_attr(cur, env, rem)
		if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
			fprintf(out, "%s=%s\n", blobmsg_name(cur), blobmsg_get_string(cur));

	env_run_add_store(out, store, env);
	fclose(out);

	if (!buf || !len) {
		free(buf);
		unlink(path);
		return 1;
	}

	ret = rundir_prepare(name, "env.run", path, sizeof(path));
	if (ret < 0) {
		free(buf);
		return ret;
	}

	ret = file_write_atomic(path, buf, len, 0600);
	free(buf);

	return ret;
}

static const char *uxc_delete_path;
static bool uxc_delete_replied;

static void uxc_delete_done_cb(struct ubus_request *req, int ret)
{
	uxc_delete_replied = true;
	uloop_end();
}

static void uxc_object_remove_cb(struct ubus_context *uctx,
				 struct ubus_event_handler *ev,
				 const char *type, struct blob_attr *msg)
{
	const char *path;

	if (!uxc_delete_path)
		return;

	path = uxc_object_remove_path(msg);
	if (!path || strcmp(path, uxc_delete_path))
		return;

	uloop_end();
}

static struct ubus_event_handler uxc_object_remove_ev = {
	.cb = uxc_object_remove_cb,
};

static void uxc_runtime_delete(const char *name)
{
	struct ubus_request req;
	char *objname;
	uint32_t id;

	if (asprintf(&objname, "container.%s", name) == -1)
		return;

	if (ubus_lookup_id(ctx, objname, &id))
		goto out;

	uxc_uloop_init();

	if (ubus_register_event_handler(ctx, &uxc_object_remove_ev,
					"ubus.object.remove")) {
		fprintf(stderr, "uxc: cannot watch for %s to be removed\n",
			objname);
		goto out;
	}

	if (ubus_invoke_async(ctx, id, "delete", NULL, &req))
		goto unregister;

	uxc_delete_path = objname;
	uxc_delete_replied = false;
	req.complete_cb = uxc_delete_done_cb;
	ubus_complete_request_async(ctx, &req);

	uloop_run();

	uxc_delete_path = NULL;
	if (!uxc_delete_replied)
		ubus_abort_request(ctx, &req);

unregister:
	ubus_unregister_event_handler(ctx, &uxc_object_remove_ev);
out:
	free(objname);
}

static void uxc_instance_drop(const char *name)
{
	static struct blob_buf req;
	uint32_t id;

	uxc_runtime_delete(name);

	if (ubus_lookup_id(ctx, "container", &id))
		return;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", name);
	blobmsg_add_string(&req, "instance", name);
	ubus_invoke(ctx, id, "delete", req.head, NULL, NULL, 3000);
	blob_buf_free(&req);
}

static void uxc_runtime_diagnose(const char *name)
{
	struct runtime_state *rsstate = NULL;

	rsstate = avl_find_element(&runtime, name, rsstate, avl);
	if (!rsstate) {
		fprintf(stderr, "uxc: %s has not been created\n", name);
		return;
	}

	if (rsstate->exitcode >= 0)
		fprintf(stderr, "uxc: the runtime of %s is gone, it exited "
				"with %d\n", name, rsstate->exitcode);
	else
		fprintf(stderr, "uxc: the runtime of %s is gone\n", name);
}

enum {
	UPDATE_REPLY_REASON,
	UPDATE_REPLY_ERRNO,
	__UPDATE_REPLY_MAX,
};

static const struct blobmsg_policy update_reply_policy[__UPDATE_REPLY_MAX] = {
	[UPDATE_REPLY_REASON] = { .name = "reason", .type = BLOBMSG_TYPE_STRING },
	[UPDATE_REPLY_ERRNO] = { .name = "errno", .type = BLOBMSG_TYPE_INT32 },
};

struct uxc_update_reply {
	char *reason;
	size_t rlen;
	int err;
};

static void uxc_update_reply_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct uxc_update_reply *reply = req->priv;
	struct blob_attr *tb[__UPDATE_REPLY_MAX];

	blobmsg_parse(update_reply_policy, __UPDATE_REPLY_MAX, tb, blobmsg_data(msg),
		      blobmsg_len(msg));
	if (tb[UPDATE_REPLY_REASON])
		snprintf(reply->reason, reply->rlen, "%s",
			 blobmsg_get_string(tb[UPDATE_REPLY_REASON]));

	if (tb[UPDATE_REPLY_ERRNO])
		reply->err = blobmsg_get_u32(tb[UPDATE_REPLY_ERRNO]);
}

static int uxc_update_blob(const char *name, struct blob_attr *table, char *reason,
			   size_t rlen, int *err)
{
	struct uxc_update_reply reply = { reason, rlen, 0 };
	static struct blob_buf req;
	struct blob_attr *cur;
	char *objname;
	int rem, ret;
	uint32_t id;

	snprintf(reason, rlen, "linux.resources");
	*err = 0;

	if (asprintf(&objname, "container.%s", name) == -1)
		return -ENOMEM;

	ret = ubus_lookup_id(ctx, objname, &id);
	free(objname);
	if (ret) {
		uxc_runtime_diagnose(name);
		*err = ENOENT;
		return -ENOENT;
	}

	blob_buf_init(&req, 0);
	blobmsg_for_each_attr(cur, table, rem)
		blobmsg_add_blob(&req, cur);

	ret = ubus_invoke(ctx, id, "update", req.head, uxc_update_reply_cb,
			  &reply, 3000);
	blob_buf_free(&req);

	switch (ret) {
	case UBUS_STATUS_OK:
		return 0;
	case UBUS_STATUS_PERMISSION_DENIED:
		ret = -EPERM;
		break;
	case UBUS_STATUS_NOT_SUPPORTED:
		ret = -ENOTSUP;
		break;
	case UBUS_STATUS_INVALID_ARGUMENT:
		ret = -EINVAL;
		break;
	case UBUS_STATUS_NOT_FOUND:
		ret = -ENOENT;
		break;
	default:
		ret = -EIO;
		break;
	}

	*err = reply.err ?: -ret;

	return ret;
}

static int uxc_invoker_pidfd(void)
{
	pid_t ppid;
	int fd;

	ppid = getppid();
	fd = syscall(SYS_pidfd_open, ppid, 0);
	if (fd < 0) {
		fprintf(stderr, "uxc: warning: cannot watch the invoker, it will not be notified: %s\n",
			strerror(errno));
		return -1;
	}

	if (getppid() != ppid) {
		close(fd);
		return -1;
	}

	return fd;
}

struct settings_key {
	const char *name;
	const char *excludes;
	const char *entry;
	const char *entry_key;
	int type;
	int (*validate)(const struct settings_key *key, struct blob_attr *value,
			struct blob_attr **reg_tb, struct settings *us, const char *name);
	int (*unset)(const struct settings_key *key, const char *id,
		     struct blob_attr **reg_tb, struct settings *us, const char *name);
	int (*check)(struct blob_attr *value, struct blob_attr **reg_tb);
	bool (*merge)(struct blob_buf *out, struct blob_attr *old,
		      struct blob_attr *patch);
	int (*apply)(const struct settings_key *key, struct blob_attr *value,
		     struct blob_attr **reg_tb, struct settings *us, const char *name);
	int (*commit)(const struct settings_key *key, struct blob_attr *value,
		      struct blob_attr **reg_tb, struct settings *us, const char *name);
};

static const char *settings_entry_id(struct blob_attr *entry, const char *field)
{
	struct blob_attr *id;

	if (blobmsg_type(entry) != BLOBMSG_TYPE_TABLE)
		return NULL;

	id = blob_key_find(entry, field);
	if (!id || blobmsg_type(id) != BLOBMSG_TYPE_STRING)
		return NULL;

	return blobmsg_get_string(id);
}

static struct blob_attr *settings_array_find(struct blob_attr *array, const char *field,
					     const char *val)
{
	struct blob_attr *cur;
	const char *id;
	int rem;

	blobmsg_for_each_attr(cur, array, rem) {
		id = settings_entry_id(cur, field);
		if (id && !strcmp(id, val))
			return cur;
	}

	return NULL;
}

static const char *settings_member_id(const struct settings_key *key, struct blob_attr *member)
{
	if (key->type == BLOBMSG_TYPE_TABLE)
		return blobmsg_name(member);

	return settings_entry_id(member, key->entry_key);
}

static struct blob_attr *settings_member_find(const struct settings_key *key,
					      struct blob_attr *container, const char *id)
{
	if (key->type == BLOBMSG_TYPE_TABLE)
		return blob_key_find(container, id);

	return settings_array_find(container, key->entry_key, id);
}

static int abspath_validate(const struct settings_key *key, struct blob_attr *value,
			    struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	if (blobmsg_get_string(value)[0] != '/')
		return -EINVAL;

	return 0;
}

static int size_validate(const struct settings_key *key, struct blob_attr *value,
			 struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	if (parse_size_bytes(blobmsg_get_string(value)) <= 0)
		return -EINVAL;

	return 0;
}

static int string_array_validate(const struct settings_key *key, struct blob_attr *value,
				 struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, value, rem)
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			return -EINVAL;

	return 0;
}

static int ascii_validate(const struct settings_key *key, struct blob_attr *value,
			  struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	const unsigned char *s = (const unsigned char *)blobmsg_get_string(value);

	if (!*s)
		return -EINVAL;

	for (; *s; s++)
		if (*s < 0x20 || *s > 0x7e)
			return -EINVAL;

	return 0;
}

static long long data_volume_size(struct blob_attr *set, struct blob_attr *reg)
{
	if (set)
		return parse_size_bytes(blobmsg_get_string(set));

	if (reg)
		return parse_size_bytes(blobmsg_get_string(reg));

	return parse_size_bytes(DATA_VOLUME_SIZE_DEFAULT);
}

static struct blob_attr *data_volume_find(struct blob_attr *vols, const char *vname,
					  struct blob_attr **vt)
{
	struct blob_attr *entry;

	entry = settings_array_find(vols, "name", vname);
	if (!entry)
		return NULL;

	blobmsg_parse(vol_policy, __VOL_MAX, vt, blobmsg_data(entry), blobmsg_len(entry));

	return entry;
}

static int data_volume_entry_validate(const char *name, struct blob_attr *entry,
				      struct blob_attr *patch, struct blob_attr *reg_vols,
				      struct blob_attr *set_vols)
{
	struct blob_attr *vt[__VOL_MAX], *rt[__VOL_MAX], *st[__VOL_MAX];
	struct blob_attr *reg, *set;
	char volname[256];
	const char *vname;
	long long size;

	if (blobmsg_type(entry) != BLOBMSG_TYPE_TABLE)
		return -EINVAL;

	blobmsg_parse(vol_policy, __VOL_MAX, vt, blobmsg_data(entry), blobmsg_len(entry));
	if (!vt[VOL_NAME] || !vt[VOL_MOUNTPOINT])
		return -EINVAL;

	vname = blobmsg_get_string(vt[VOL_NAME]);
	data_volume_name(name, vname, volname, sizeof(volname));
	if (!uvol_name_valid(volname) || blobmsg_get_string(vt[VOL_MOUNTPOINT])[0] != '/')
		return -EINVAL;

	if (vt[VOL_SIZE] && parse_size_bytes(blobmsg_get_string(vt[VOL_SIZE])) <= 0)
		return -EINVAL;

	if (settings_array_find(patch, "name", vname) != entry)
		return -EINVAL;

	reg = data_volume_find(reg_vols, vname, rt);
	set = data_volume_find(set_vols, vname, st);
	size = data_volume_size(vt[VOL_SIZE], reg ? rt[VOL_SIZE] : NULL);

	if (reg && (!rt[VOL_MOUNTPOINT] ||
		    strcmp(blobmsg_get_string(vt[VOL_MOUNTPOINT]),
			   blobmsg_get_string(rt[VOL_MOUNTPOINT]))))
		return -EINVAL;

	if (reg && size < data_volume_size(NULL, rt[VOL_SIZE]))
		return -EINVAL;

	if (set && size < data_volume_size(st[VOL_SIZE], reg ? rt[VOL_SIZE] : NULL))
		return -EINVAL;

	return 0;
}

static int data_volumes_validate(const struct settings_key *key, struct blob_attr *value,
				 struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	struct blob_attr *set_vols = us ? us->tb[CONF_DATA_VOLUMES] : NULL;
	struct blob_attr *cur;
	int rem, ret;

	blobmsg_for_each_attr(cur, value, rem) {
		ret = data_volume_entry_validate(name, cur, value, reg_tb[CONF_DATA_VOLUMES],
						 set_vols);
		if (ret)
			return ret;
	}

	return 0;
}

static int data_volumes_effective(struct blob_attr *reg, struct blob_attr *set,
				  struct blob_buf *out)
{
	struct blob_attr *cur, *over;
	const char *vname;
	int rem, n = 0;
	void *a;

	blob_buf_init(out, 0);
	a = blobmsg_open_array(out, "data-volumes");

	blobmsg_for_each_attr(cur, reg, rem) {
		vname = settings_entry_id(cur, "name");
		over = vname ? settings_array_find(set, "name", vname) : NULL;
		if (over)
			blob_table_overlay(out, cur, over);
		else
			blobmsg_add_blob(out, cur);

		n++;
	}

	blobmsg_for_each_attr(cur, set, rem) {
		vname = settings_entry_id(cur, "name");
		if (vname && settings_array_find(reg, "name", vname))
			continue;

		blobmsg_add_blob(out, cur);
		n++;
	}

	blobmsg_close_array(out, a);

	return n;
}

static bool data_volume_settings_only(struct blob_attr **reg_tb, struct settings *us,
				      const char *id)
{
	if (!id || !us || !settings_array_find(us->tb[CONF_DATA_VOLUMES], "name", id))
		return false;

	return !settings_array_find(reg_tb[CONF_DATA_VOLUMES], "name", id);
}

static int data_volumes_unset_check(const struct settings_key *key, const char *id,
				    struct blob_attr **reg_tb, struct settings *us,
				    const char *name)
{
	struct runtime_state *rs = NULL;

	if (!data_volume_settings_only(reg_tb, us, id))
		return 0;

	rs = avl_find_element(&runtime, name, rs, avl);

	return runtime_live(rs) ? -EBUSY : 0;
}

static int data_volumes_commit(const struct settings_key *key, struct blob_attr *value,
			       struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	const char *id;

	if (blobmsg_type(value) != BLOBMSG_TYPE_STRING)
		return 0;

	id = strchr(blobmsg_get_string(value), '=');
	if (!id || !data_volume_settings_only(reg_tb, us, id + 1))
		return 0;

	data_volume_remove(name, id + 1);

	return 0;
}

static bool env_key_valid(const char *key)
{
	const char *p;

	if (!isalpha((unsigned char)*key) && *key != '_')
		return false;

	for (p = key + 1; *p; p++)
		if (!isalnum((unsigned char)*p) && *p != '_')
			return false;

	return true;
}

static int env_validate(const struct settings_key *key, struct blob_attr *value,
			struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, value, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			return -EINVAL;

		if (!env_key_valid(blobmsg_name(cur)) || strchr(blobmsg_get_string(cur), '\n'))
			return -EINVAL;

		if (blob_key_find(value, blobmsg_name(cur)) != cur)
			return -EINVAL;
	}

	return 0;
}

enum {
	RESPAWN_ENABLE,
	RESPAWN_MIN,
	RESPAWN_MAX,
	RESPAWN_MULTIPLIER,
	RESPAWN_MAX_RETRIES,
	RESPAWN_RESET_PERIOD,
	__RESPAWN_MAX,
};

static const struct blobmsg_policy respawn_table_policy[__RESPAWN_MAX] = {
	[RESPAWN_ENABLE] = { .name = "enable", .type = BLOBMSG_TYPE_BOOL },
	[RESPAWN_MIN] = { .name = "min", .type = BLOBMSG_TYPE_INT32 },
	[RESPAWN_MAX] = { .name = "max", .type = BLOBMSG_TYPE_INT32 },
	[RESPAWN_MULTIPLIER] = { .name = "multiplier", .type = BLOBMSG_TYPE_INT32 },
	[RESPAWN_MAX_RETRIES] = { .name = "max-retries", .type = BLOBMSG_TYPE_INT32 },
	[RESPAWN_RESET_PERIOD] = { .name = "reset-period", .type = BLOBMSG_TYPE_INT32 },
};

struct respawn_policy {
	uint32_t min;
	uint32_t max;
	uint32_t multiplier;
	uint32_t max_retries;
	uint32_t reset_period;
	bool enable;
};

static int respawn_policy_parse(struct blob_attr *table, struct respawn_policy *p)
{
	struct blob_attr *tb[__RESPAWN_MAX];
	int i;

	blobmsg_parse(respawn_table_policy, __RESPAWN_MAX, tb, blobmsg_data(table),
		      blobmsg_len(table));
	for (i = 0; i < __RESPAWN_MAX; i++)
		if (!tb[i])
			return -EINVAL;

	p->enable = blobmsg_get_bool(tb[RESPAWN_ENABLE]);
	p->min = blobmsg_get_u32(tb[RESPAWN_MIN]);
	p->max = blobmsg_get_u32(tb[RESPAWN_MAX]);
	p->multiplier = blobmsg_get_u32(tb[RESPAWN_MULTIPLIER]);
	p->max_retries = blobmsg_get_u32(tb[RESPAWN_MAX_RETRIES]);
	p->reset_period = blobmsg_get_u32(tb[RESPAWN_RESET_PERIOD]);

	if (!p->min || p->max < p->min || p->multiplier < 1000)
		return -EINVAL;

	if (p->max > INT_MAX / 1000)
		return -ERANGE;

	return 0;
}

static struct blob_attr *respawn_policy_effective(struct blob_attr *reg, struct blob_attr *set)
{
	static struct blob_buf merged;

	if (!set || !reg)
		return set ? set : reg;

	blob_buf_init(&merged, 0);
	blob_table_overlay(&merged, reg, set);

	return blob_data(merged.head);
}

static int respawn_validate(const struct settings_key *key, struct blob_attr *value,
			    struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, value, rem)
		if (blob_key_find(value, blobmsg_name(cur)) != cur)
			return -EINVAL;

	return 0;
}

static int respawn_check(struct blob_attr *value, struct blob_attr **reg_tb)
{
	struct respawn_policy policy;

	if (!value)
		return 0;

	return respawn_policy_parse(respawn_policy_effective(reg_tb[CONF_RESPAWN], value),
				    &policy);
}

static int stop_timeout_validate(const struct settings_key *key, struct blob_attr *value,
				 struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	uint32_t seconds = blobmsg_get_u32(value);

	if (!seconds)
		return -EINVAL;

	if (seconds > INT_MAX / 1000)
		return -ERANGE;

	return 0;
}

static int stop_timeout_commit(const struct settings_key *key, struct blob_attr *value,
			       struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	struct runtime_state *rs = NULL;

	rs = avl_find_element(&runtime, name, rs, avl);
	if (runtime_live(rs))
		fprintf(stderr, "uxc: the stop timeout of %s takes effect at the next create\n",
			name);

	return 0;
}

struct resources_leaf {
	const char *table;
	const char *leaf;
};

static const struct resources_leaf resources_leaves[] = {
	{ "memory", "limit" },
	{ "memory", "swap" },
	{ "cpu", "quota" },
	{ "cpu", "period" },
	{ "cpu", "burst" },
	{ "pids", "limit" },
};

static bool resources_leaf_known(const char *table, const char *leaf)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(resources_leaves); i++) {
		if (strcmp(resources_leaves[i].table, table))
			continue;

		if (!leaf || !strcmp(resources_leaves[i].leaf, leaf))
			return true;
	}

	return false;
}

static long long resources_leaf_value(struct blob_attr *leaf)
{
	switch (blobmsg_type(leaf)) {
	case BLOBMSG_TYPE_INT32:
		return (int32_t)blobmsg_get_u32(leaf);
	case BLOBMSG_TYPE_INT64:
		return (int64_t)blobmsg_get_u64(leaf);
	}

	return 0;
}

static int resources_table_validate(const char *table, struct blob_attr *value)
{
	struct blob_attr *cur;
	long long v;
	int rem;

	blobmsg_for_each_attr(cur, value, rem) {
		if (!resources_leaf_known(table, blobmsg_name(cur)) ||
		    blob_key_find(value, blobmsg_name(cur)) != cur)
			return -EINVAL;

		v = resources_leaf_value(cur);
		if (v != -1 && v <= 0)
			return -EINVAL;
	}

	return 0;
}

static int resources_validate(const struct settings_key *key, struct blob_attr *value,
			      struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	struct blob_attr *cur;
	int rem, ret;

	blobmsg_for_each_attr(cur, value, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE ||
		    !resources_leaf_known(blobmsg_name(cur), NULL) ||
		    blob_key_find(value, blobmsg_name(cur)) != cur)
			return -EINVAL;

		ret = resources_table_validate(blobmsg_name(cur), cur);
		if (ret)
			return ret;
	}

	return 0;
}

static bool resources_leaf_dropped(struct blob_attr *leaf)
{
	return leaf && resources_leaf_value(leaf) == -1;
}

static int resources_leaves_kept(struct blob_attr *old, struct blob_attr *patch)
{
	struct blob_attr *cur;
	int rem, n = 0;

	blobmsg_for_each_attr(cur, old, rem)
		if (!resources_leaf_dropped(blob_key_find(patch, blobmsg_name(cur))))
			n++;

	blobmsg_for_each_attr(cur, patch, rem)
		if (!blob_key_find(old, blobmsg_name(cur)) && !resources_leaf_dropped(cur))
			n++;

	return n;
}

static bool resources_table_merge(struct blob_buf *out, const char *name,
				  struct blob_attr *old, struct blob_attr *patch)
{
	struct blob_attr *cur, *rep;
	bool changed = false;
	void *c;
	int rem;

	if (!resources_leaves_kept(old, patch))
		return old != NULL;

	c = blobmsg_open_table(out, name);

	blobmsg_for_each_attr(cur, old, rem) {
		rep = blob_key_find(patch, blobmsg_name(cur));
		if (resources_leaf_dropped(rep)) {
			changed = true;
			continue;
		}

		if (!rep) {
			blobmsg_add_blob(out, cur);
			continue;
		}

		if (!blob_attr_equal(cur, rep))
			changed = true;

		blobmsg_add_blob(out, rep);
	}

	blobmsg_for_each_attr(cur, patch, rem) {
		if (blob_key_find(old, blobmsg_name(cur)) || resources_leaf_dropped(cur))
			continue;

		blobmsg_add_blob(out, cur);
		changed = true;
	}

	blobmsg_close_table(out, c);

	return changed;
}

static bool resources_merge(struct blob_buf *out, struct blob_attr *old,
			    struct blob_attr *patch)
{
	struct blob_attr *cur;
	bool changed = false;
	int rem, n = 0;
	void *c;

	blobmsg_for_each_attr(cur, old, rem)
		n += resources_leaves_kept(cur, blob_key_find(patch, blobmsg_name(cur)));

	blobmsg_for_each_attr(cur, patch, rem)
		if (!blob_key_find(old, blobmsg_name(cur)))
			n += resources_leaves_kept(NULL, cur);

	if (!n)
		return old != NULL;

	c = blobmsg_open_table(out, "resources");

	blobmsg_for_each_attr(cur, old, rem)
		if (resources_table_merge(out, blobmsg_name(cur), cur,
					  blob_key_find(patch, blobmsg_name(cur))))
			changed = true;

	blobmsg_for_each_attr(cur, patch, rem)
		if (!blob_key_find(old, blobmsg_name(cur)) &&
		    resources_table_merge(out, blobmsg_name(cur), NULL, cur))
			changed = true;

	blobmsg_close_table(out, c);

	return changed;
}

static void resources_leaf_live(struct blob_buf *out, const char *table,
				struct blob_attr *leaf, bool negate)
{
	const char *name = blobmsg_name(leaf);

	if (!negate && !resources_leaf_dropped(leaf)) {
		blobmsg_add_blob(out, leaf);
		return;
	}

	if (strcmp(table, "cpu") || !strcmp(name, "quota")) {
		blobmsg_add_u32(out, name, (uint32_t)-1);
		return;
	}

	if (!strcmp(name, "burst"))
		blobmsg_add_u32(out, name, 0);
}

static void resources_live(struct blob_buf *out, struct blob_attr *table, bool negate)
{
	struct blob_attr *sub, *leaf;
	int rem, lrem;
	void *c;

	blob_buf_init(out, 0);
	blobmsg_for_each_attr(sub, table, rem) {
		c = blobmsg_open_table(out, blobmsg_name(sub));
		blobmsg_for_each_attr(leaf, sub, lrem)
			resources_leaf_live(out, blobmsg_name(sub), leaf, negate);
		blobmsg_close_table(out, c);
	}
}

static int resources_apply(const struct settings_key *key, struct blob_attr *value,
			   struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	bool negate = blobmsg_type(value) == BLOBMSG_TYPE_STRING;
	struct runtime_state *rs = NULL;
	struct blob_attr *table = value;
	static struct blob_buf live;
	char reason[128];
	int ret, err;

	rs = avl_find_element(&runtime, name, rs, avl);
	if (!runtime_live(rs))
		return 0;

	if (negate) {
		table = us ? us->tb[CONF_RESOURCES] : NULL;
		if (!table)
			return 0;
	}

	resources_live(&live, table, negate);
	ret = uxc_update_blob(name, live.head, reason, sizeof(reason), &err);
	blob_buf_free(&live);

	if (ret)
		fprintf(stderr, "uxc: resources rejected: %s: %s\n", reason, strerror(err));

	return ret;
}

static const struct settings_key settings_keys[] = {
	{ .name = "autostart", .type = BLOBMSG_TYPE_BOOL },
	{ .name = "pidfile", .type = BLOBMSG_TYPE_STRING, .validate = abspath_validate },
	{ .name = "temp-overlay-size", .excludes = "write-overlay-path",
	  .type = BLOBMSG_TYPE_STRING, .validate = size_validate },
	{ .name = "write-overlay-path", .excludes = "temp-overlay-size",
	  .type = BLOBMSG_TYPE_STRING, .validate = abspath_validate },
	{ .name = "volumes", .type = BLOBMSG_TYPE_ARRAY, .validate = string_array_validate },
	{ .name = "module-version", .type = BLOBMSG_TYPE_STRING, .validate = ascii_validate },
	{ .name = "data-volumes", .entry = "data-volume", .entry_key = "name",
	  .type = BLOBMSG_TYPE_ARRAY, .validate = data_volumes_validate,
	  .unset = data_volumes_unset_check, .commit = data_volumes_commit },
	{ .name = "env", .entry = "env", .type = BLOBMSG_TYPE_TABLE, .validate = env_validate },
	{ .name = "respawn", .entry = "respawn", .type = BLOBMSG_TYPE_TABLE,
	  .validate = respawn_validate, .check = respawn_check },
	{ .name = "stop-timeout", .type = BLOBMSG_TYPE_INT32,
	  .validate = stop_timeout_validate, .commit = stop_timeout_commit },
	{ .name = "resources", .type = BLOBMSG_TYPE_TABLE,
	  .validate = resources_validate, .merge = resources_merge,
	  .apply = resources_apply },
};

static const struct settings_key *settings_key_find(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(settings_keys); i++)
		if (!strcmp(settings_keys[i].name, name))
			return &settings_keys[i];

	return NULL;
}

static const struct settings_key *settings_unset_find(const char *spec, const char **id)
{
	const char *eq = strchr(spec, '=');
	size_t i, n;

	*id = NULL;
	if (!eq)
		return settings_key_find(spec);

	n = eq - spec;
	for (i = 0; i < ARRAY_SIZE(settings_keys); i++) {
		if (!settings_keys[i].entry || strlen(settings_keys[i].entry) != n ||
		    strncmp(settings_keys[i].entry, spec, n))
			continue;

		*id = eq + 1;
		return &settings_keys[i];
	}

	return NULL;
}

static struct blob_attr *settings_unset_first(struct blob_attr *unset, const char *spec)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, unset, rem)
		if (!strcmp(blobmsg_get_string(cur), spec))
			return cur;

	return NULL;
}

static bool settings_unset_has(struct blob_attr *unset, const char *name)
{
	return !!settings_unset_first(unset, name);
}

static int settings_patch_check(struct blob_attr *patch, struct blob_attr *unset,
				struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	const struct settings_key *key;
	struct blob_attr *cur;
	int rem, ret;

	blobmsg_for_each_attr(cur, patch, rem) {
		key = settings_key_find(blobmsg_name(cur));
		if (!key || blobmsg_type(cur) != key->type)
			return -EINVAL;

		if (blob_key_find(patch, key->name) != cur)
			return -EINVAL;

		if (key->excludes && blob_has_key(patch, key->excludes))
			return -EINVAL;

		if (settings_unset_has(unset, key->name))
			return -EINVAL;

		if (!key->validate)
			continue;

		ret = key->validate(key, cur, reg_tb, us, name);
		if (ret)
			return ret;
	}

	return 0;
}

static int settings_unset_check(struct blob_attr *unset, struct blob_attr *patch,
				struct blob_attr **reg_tb, struct settings *us,
				const char *name)
{
	struct blob_attr *cur, *old, *add;
	const struct settings_key *key;
	const char *id;
	int rem, ret;

	blobmsg_for_each_attr(cur, unset, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			return -EINVAL;

		key = settings_unset_find(blobmsg_get_string(cur), &id);
		if (!key)
			return -EINVAL;

		if (id && settings_unset_first(unset, blobmsg_get_string(cur)) != cur)
			return -EINVAL;

		old = blob_key_find(us ? us->file : NULL, key->name);
		if (id && !settings_member_find(key, old, id))
			return -ENOENT;

		add = blob_key_find(patch, key->name);
		if (id && settings_member_find(key, add, id))
			return -EINVAL;

		if (!key->unset)
			continue;

		ret = key->unset(key, id, reg_tb, us, name);
		if (ret)
			return ret;
	}

	return 0;
}

static bool settings_unset_matches(struct blob_attr *unset, const struct settings_key *key,
				   const char *id)
{
	const struct settings_key *ukey;
	struct blob_attr *cur;
	const char *uid;
	int rem;

	blobmsg_for_each_attr(cur, unset, rem) {
		ukey = settings_unset_find(blobmsg_get_string(cur), &uid);
		if (ukey != key)
			continue;

		if (!uid || (id && !strcmp(uid, id)))
			return true;
	}

	return false;
}

static bool settings_entry_kept(const struct settings_key *key, struct blob_attr *old,
				struct blob_attr *unset, const char *id)
{
	if (!id || !settings_member_find(key, old, id))
		return false;

	return !settings_unset_matches(unset, key, id);
}

static int settings_member_merge_count(const struct settings_key *key, struct blob_attr *old,
				       struct blob_attr *patch, struct blob_attr *unset)
{
	struct blob_attr *cur;
	int rem, n = 0;

	blobmsg_for_each_attr(cur, old, rem)
		if (!settings_unset_matches(unset, key, settings_member_id(key, cur)))
			n++;

	blobmsg_for_each_attr(cur, patch, rem)
		if (!settings_entry_kept(key, old, unset, settings_member_id(key, cur)))
			n++;

	return n;
}

static bool settings_member_merge(struct blob_buf *out, const struct settings_key *key,
				  struct blob_attr *old, struct blob_attr *patch,
				  struct blob_attr *unset)
{
	struct blob_attr *cur, *rep;
	bool changed = false;
	const char *id;
	void *c;
	int rem;

	if (!settings_member_merge_count(key, old, patch, unset))
		return true;

	c = blob_container_open(out, key->name, key->type);

	blobmsg_for_each_attr(cur, old, rem) {
		id = settings_member_id(key, cur);
		if (settings_unset_matches(unset, key, id)) {
			changed = true;
			continue;
		}

		rep = id ? settings_member_find(key, patch, id) : NULL;
		if (!rep) {
			blobmsg_add_blob(out, cur);
			continue;
		}

		if (!blob_attr_equal(cur, rep))
			changed = true;

		blobmsg_add_blob(out, rep);
	}

	blobmsg_for_each_attr(cur, patch, rem) {
		if (settings_entry_kept(key, old, unset, settings_member_id(key, cur)))
			continue;

		blobmsg_add_blob(out, cur);
		changed = true;
	}

	blob_nest_end(out, c);

	return changed;
}

static bool settings_kept_copy(struct blob_buf *out, struct blob_attr *file,
			       struct blob_attr *patch, struct blob_attr *unset)
{
	const struct settings_key *key;
	struct blob_attr *cur;
	bool changed = false;
	int rem;

	blobmsg_for_each_attr(cur, file, rem) {
		if (!strcmp(blobmsg_name(cur), "name"))
			continue;

		key = settings_key_find(blobmsg_name(cur));
		if (key && key->excludes && blob_has_key(patch, key->excludes))
			continue;

		if (key && key->entry) {
			if (settings_member_merge(out, key, cur,
						  blob_key_find(patch, key->name), unset))
				changed = true;
			continue;
		}

		if (key && key->merge && blob_has_key(patch, key->name)) {
			if (key->merge(out, cur, blob_key_find(patch, key->name)))
				changed = true;
			continue;
		}

		if (blob_has_key(patch, blobmsg_name(cur)))
			continue;

		if (settings_unset_has(unset, blobmsg_name(cur))) {
			changed = true;
			continue;
		}

		blobmsg_add_blob(out, cur);
	}

	return changed;
}

static bool settings_patch_add(struct blob_buf *out, struct blob_attr *file,
			       struct blob_attr *patch)
{
	const struct settings_key *key;
	struct blob_attr *cur, *old;
	bool changed = false;
	int rem;

	blobmsg_for_each_attr(cur, patch, rem) {
		key = settings_key_find(blobmsg_name(cur));
		old = blob_key_find(file, blobmsg_name(cur));
		if (old && (key->entry || key->merge))
			continue;

		if (key->merge) {
			if (key->merge(out, NULL, cur))
				changed = true;
			continue;
		}

		if (!blob_attr_equal(old, cur))
			changed = true;

		blobmsg_add_blob(out, cur);
	}

	return changed;
}

static int settings_apply_run(struct blob_attr *patch, struct blob_attr *unset,
			      struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	const struct settings_key *key;
	struct blob_attr *cur;
	const char *id;
	int rem, ret;

	blobmsg_for_each_attr(cur, patch, rem) {
		key = settings_key_find(blobmsg_name(cur));
		if (!key->apply)
			continue;

		ret = key->apply(key, cur, reg_tb, us, name);
		if (ret)
			return ret;
	}

	blobmsg_for_each_attr(cur, unset, rem) {
		key = settings_unset_find(blobmsg_get_string(cur), &id);
		if (!key->apply)
			continue;

		ret = key->apply(key, cur, reg_tb, us, name);
		if (ret)
			return ret;
	}

	return 0;
}

static int settings_commit_run(struct blob_attr *patch, struct blob_attr *unset,
			       struct blob_attr **reg_tb, struct settings *us, const char *name)
{
	const struct settings_key *key;
	struct blob_attr *cur;
	const char *id;
	int rem, ret;

	blobmsg_for_each_attr(cur, patch, rem) {
		key = settings_key_find(blobmsg_name(cur));
		if (!key->commit)
			continue;

		ret = key->commit(key, cur, reg_tb, us, name);
		if (ret)
			return ret;
	}

	blobmsg_for_each_attr(cur, unset, rem) {
		key = settings_unset_find(blobmsg_get_string(cur), &id);
		if (!key->commit)
			continue;

		ret = key->commit(key, cur, reg_tb, us, name);
		if (ret)
			return ret;
	}

	return 0;
}

static bool settings_key_touched(const struct settings_key *key, struct blob_attr *patch,
				 struct blob_attr *unset)
{
	struct blob_attr *cur;
	const char *id;
	int rem;

	if (blob_has_key(patch, key->name))
		return true;

	blobmsg_for_each_attr(cur, unset, rem)
		if (settings_unset_find(blobmsg_get_string(cur), &id) == key)
			return true;

	return false;
}

static int settings_result_check(struct blob_attr *file, struct blob_attr *patch,
				 struct blob_attr *unset, struct blob_attr **reg_tb)
{
	const struct settings_key *key;
	size_t i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(settings_keys); i++) {
		key = &settings_keys[i];
		if (!key->check || !settings_key_touched(key, patch, unset))
			continue;

		ret = key->check(blob_key_find(file, key->name), reg_tb);
		if (ret)
			return ret;
	}

	return 0;
}

static int json_file_write(const char *path, struct blob_attr *root, mode_t mode)
{
	char *json, *buf;
	int len, ret;

	json = blobmsg_format_json_indent(root, true, 0);
	if (!json)
		return -ENOMEM;

	len = asprintf(&buf, "%s\n", json);
	free(json);
	if (len < 0)
		return -ENOMEM;

	ret = file_write_atomic(path, buf, len, mode);
	free(buf);

	return ret;
}

static int settings_edit(const char *name, struct blob_attr *patch, struct blob_attr *unset)
{
	struct blob_attr *reg_tb[__CONF_MAX];
	struct settings *us = NULL;
	static struct blob_buf out;
	struct blob_attr *reg;
	char path[PATH_MAX];
	const char *fpath;
	bool changed;
	int ret;

	reg = registration_find(name, reg_tb);
	if (!reg)
		return -ENOENT;

	us = avl_find_element(&settings, name, us, avl);

	ret = settings_patch_check(patch, unset, reg_tb, us, name);
	if (ret)
		return ret;

	ret = settings_unset_check(unset, patch, reg_tb, us, name);
	if (ret)
		return ret;

	blob_buf_init(&out, 0);
	blobmsg_add_string(&out, "name", name);
	changed = settings_kept_copy(&out, us ? us->file : NULL, patch, unset);
	if (settings_patch_add(&out, us ? us->file : NULL, patch))
		changed = true;

	ret = settings_result_check(out.head, patch, unset, reg_tb);
	if (!ret)
		ret = settings_apply_run(patch, unset, reg_tb, us, name);

	if (ret) {
		blob_buf_free(&out);
		return ret;
	}

	if (!changed) {
		blob_buf_free(&out);
		return 0;
	}

	fpath = us ? us->fname : path;
	if (!us)
		ret = settings_path_new(blobmsg_name(reg), name, path, sizeof(path));

	if (!ret)
		ret = json_file_write(fpath, out.head, 0600);

	blob_buf_free(&out);
	if (ret)
		return ret;

	ret = settings_commit_run(patch, unset, reg_tb, us, name);
	if (ret)
		return ret;

	return 1;
}

static int uxc_create(char *name, bool immediately, const char *console_socket,
		      bool systemd_cgroup, const char *seccomp_mode)
{
	static struct blob_buf vols;
	static struct blob_buf req;
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem, ret = 0;
	int notify_fd;
	uint32_t id;
	struct settings *usettings = NULL;
	char *path = NULL, *jailname = NULL, *pidfile = NULL, *tmprwsize = NULL, *writepath = NULL;
	const char *imgvol = NULL;
	char *seccomp_log = NULL;
	char overlaypath[PATH_MAX];
	char envpath[PATH_MAX];
	char hostsbind[PATH_MAX];
	char provbind[2 * PATH_MAX];
	char reason[128];
	struct blob_attr *ptb[__PROV_MAX];
	struct runtime_state *rsstate = NULL;
	struct uxc_wait_state wait_state;
	int err;

	void *in, *ins, *j, *m;

	if (!registration_find(name, tb))
		return -ENOENT;

	rsstate = avl_find_element(&runtime, name, rsstate, avl);
	if (rsstate && !runtime_live(rsstate))
		uxc_instance_drop(name);

	path = blobmsg_get_string(tb[CONF_PATH]);

	imgvol = uvol_volume_name(path);
	if (imgvol && run_uvol("up", imgvol)) {
		fprintf(stderr, "uxc: failed to activate image volume %s\n", imgvol);
		return -EIO;
	}

	if (tb[CONF_PIDFILE])
		pidfile = blobmsg_get_string(tb[CONF_PIDFILE]);

	if (tb[CONF_TEMP_OVERLAY_SIZE])
		tmprwsize = blobmsg_get_string(tb[CONF_TEMP_OVERLAY_SIZE]);

	if (tb[CONF_WRITE_OVERLAY_PATH])
		writepath = blobmsg_get_string(tb[CONF_WRITE_OVERLAY_PATH]);

	if (tb[CONF_JAIL])
		jailname = blobmsg_get_string(tb[CONF_JAIL]);

	usettings = avl_find_element(&settings, blobmsg_get_string(tb[CONF_NAME]), usettings, avl);
	if (usettings) {
		if (usettings->writepath) {
			writepath = usettings->writepath;
			tmprwsize = NULL;
		}
		if (usettings->tmprwsize) {
			tmprwsize = usettings->tmprwsize;
			writepath = NULL;
		}
	}

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", name);
	ins = blobmsg_open_table(&req, "instances");
	in = blobmsg_open_table(&req, name);
	blobmsg_add_string(&req, "bundle", path);
	if (seccomp_mode) {
		blobmsg_add_string(&req, "seccomp_mode", seccomp_mode);
		if (asprintf(&seccomp_log, "/tmp/uxc-%s.%s.json", name, seccomp_mode) > 0) {
			blobmsg_add_string(&req, "seccomp_log", seccomp_log);
			fprintf(stderr, "uxc: %s log: %s\n", seccomp_mode, seccomp_log);
			free(seccomp_log);
		}
	}
	j = blobmsg_open_table(&req, "jail");
	blobmsg_add_string(&req, "name", jailname?:name);
	blobmsg_add_u8(&req, "immediately", immediately);

	if (pidfile)
		blobmsg_add_string(&req, "pidfile", pidfile);

	if (console_socket)
		blobmsg_add_string(&req, "consolesocket", console_socket);

	if (systemd_cgroup)
		blobmsg_add_u8(&req, "systemdcgroup", 1);

	if (tb[CONF_IDMAP_OFFSET])
		blobmsg_add_string(&req, "idmap_offset", blobmsg_get_string(tb[CONF_IDMAP_OFFSET]));

	if (usettings && usettings->tb[CONF_STOP_TIMEOUT])
		blobmsg_add_u32(&req, "stop_timeout",
				blobmsg_get_u32(usettings->tb[CONF_STOP_TIMEOUT]));

	if (tb[CONF_INITENV])
		materialise_initenv(name, tb[CONF_INITENV]);

	ret = env_run_write(name, usettings ? usettings->tb[CONF_ENV] : NULL);
	if (ret < 0) {
		fprintf(stderr, "uxc: failed to write the environment of %s: %s\n",
			name, strerror(-ret));
		blob_buf_free(&req);
		return ret;
	}

	if (!ret && !rundir_path(name, "env.run", envpath, sizeof(envpath)))
		blobmsg_add_string(&req, "envfile", envpath);

	m = blobmsg_open_table(&req, "mount");
	data_volumes_effective(tb[CONF_DATA_VOLUMES],
			       usettings ? usettings->tb[CONF_DATA_VOLUMES] : NULL, &vols);
	ret = provision_data_volumes(name, blob_data(vols.head), &req);
	blob_buf_free(&vols);
	if (ret) {
		blobmsg_close_table(&req, m);
		blob_buf_free(&req);
		return ret;
	}
	if (tb[CONF_HOSTS_FILE]) {
		snprintf(hostsbind, sizeof(hostsbind), "%s:/etc/hosts",
			 blobmsg_get_string(tb[CONF_HOSTS_FILE]));
		blobmsg_add_string(&req, hostsbind, "4");
	}
	if (tb[CONF_PROVISION]) {
		blobmsg_for_each_attr(cur, tb[CONF_PROVISION], rem) {
			blobmsg_parse(prov_policy, __PROV_MAX, ptb,
				      blobmsg_data(cur), blobmsg_len(cur));
			if (!ptb[PROV_SOURCE] || !ptb[PROV_DESTINATION])
				continue;
			snprintf(provbind, sizeof(provbind), "%s:%s",
				 blobmsg_get_string(ptb[PROV_SOURCE]),
				 blobmsg_get_string(ptb[PROV_DESTINATION]));
			blobmsg_add_string(&req, provbind,
					   (ptb[PROV_SECRET] && blobmsg_get_bool(ptb[PROV_SECRET])) ? "3" : "4");
		}
	}
	blobmsg_close_table(&req, m);

	blobmsg_close_table(&req, j);

	if (!writepath && !tmprwsize && tb[CONF_OVERLAY_SIZE]) {
		if (provision_rw_uvol(name, blobmsg_get_string(tb[CONF_OVERLAY_SIZE]))) {
			blob_buf_free(&req);
			return -EIO;
		}
		snprintf(overlaypath, sizeof(overlaypath), "/tmp/run/uvol/%s", name);
		writepath = overlaypath;
	}

	if (writepath)
		blobmsg_add_string(&req, "overlaydir", writepath);

	if (tmprwsize)
		blobmsg_add_string(&req, "tmpoverlaysize", tmprwsize);

	blobmsg_close_table(&req, in);
	blobmsg_close_table(&req, ins);

	if (verbose) {
		char *tmp;
		tmp = blobmsg_format_json_indent(req.head, true, 1);
		if (!tmp)
			return -ENOMEM;

		fprintf(stderr, "adding container to procd:\n\t%s\n", tmp);
		free(tmp);
	}

	if (ubus_lookup_id(ctx, "container", &id)) {
		blob_buf_free(&req);
		return -EIO;
	}

	memset(&wait_state, 0, sizeof(wait_state));
	wait_state.service = name;
	wait_state.instance = name;
	wait_state.success_event = "instance.ready";
	wait_state.fail_event = "instance.create_failed";
	wait_state.since_incarnation = uxc_instance_incarnation(name, name) + 1;

	if (uxc_wait_arm(&wait_state))
		fprintf(stderr, "uxc: warning: cannot arm instance.* watcher\n");

	notify_fd = uxc_invoker_pidfd();
	ret = ubus_invoke_fd(ctx, id, "add", req.head, NULL, NULL, 3000,
			     stdio_notify_fds_send(stdio_fds, notify_fd));
	if (notify_fd >= 0)
		close(notify_fd);

	if (ret) {
		blob_buf_free(&req);
		uxc_wait_disarm();
		return -EIO;
	}

	uxc_wait_run(&wait_state, 30000);
	uxc_wait_disarm();
	if (wait_state.result == UXC_WAIT_FAILED) {
		fprintf(stderr, "uxc: create %s failed: %s\n", name,
			uxc_wait_why(&wait_state) ?:
				"the container was not created");
		uxc_instance_drop(name);
		return -EIO;
	}
	if (wait_state.result == UXC_WAIT_STOPPED) {
		fprintf(stderr, "uxc: create %s failed: %s\n", name,
			uxc_wait_why(&wait_state) ?:
				"container exited before ready");
		uxc_instance_drop(name);
		return -EIO;
	}
	if (wait_state.result == UXC_WAIT_UNSET) {
		fprintf(stderr, "uxc: create %s failed: the container did not reach created state\n", name);
		uxc_instance_drop(name);
		return -ETIMEDOUT;
	}

	if (!usettings || !usettings->tb[CONF_RESOURCES])
		return 0;

	ret = uxc_update_blob(name, usettings->tb[CONF_RESOURCES], reason,
			      sizeof(reason), &err);
	if (!ret)
		return 0;

	if (immediately) {
		fprintf(stderr, "uxc: warning: resources of %s rejected: %s: %s\n",
			name, reason, strerror(err));
		return 0;
	}

	fprintf(stderr, "uxc: resources rejected: %s: %s\n", reason, strerror(err));
	uxc_instance_drop(name);

	return ret;
}

static int uxc_state(char *name)
{
	struct runtime_state *rsstate = avl_find_element(&runtime, name, rsstate, avl);
	struct blob_attr *ocistate = NULL;
	struct blob_attr *tb[__CONF_MAX];
	static struct blob_buf buf;
	char *jail_name = NULL;
	char *bundle = NULL;
	char *state = NULL;
	char *tmp;

	if (rsstate)
		ocistate = rsstate->ocistate;

	if (ocistate) {
		state = blobmsg_format_json_indent(ocistate, true, 0);
		if (!state)
			return -ENOMEM;

		printf("%s\n", state);
		free(state);
		return 0;
	}

	if (!registration_find(name, tb))
		return -ENOENT;

	if (tb[CONF_JAIL])
		jail_name = blobmsg_get_string(tb[CONF_JAIL]);
	else
		jail_name = name;

	bundle = blobmsg_get_string(tb[CONF_PATH]);

	blob_buf_init(&buf, 0);
	blobmsg_add_string(&buf, "ociVersion", OCI_VERSION_STRING);
	blobmsg_add_string(&buf, "id", jail_name);
	blobmsg_add_string(&buf, "status", rsstate?"stopped":"uninitialized");
	blobmsg_add_string(&buf, "bundle", bundle);
	blobmsg_close_table(&buf, blobmsg_open_table(&buf, "annotations"));

	tmp = blobmsg_format_json_indent(buf.head, true, 0);
	if (!tmp) {
		blob_buf_free(&buf);
		return -ENOMEM;
	}

	printf("%s\n", tmp);
	free(tmp);

	blob_buf_free(&buf);

	return 0;
}

static void netinfo_str(struct blob_attr *netinfo, char *out, size_t outlen)
{
	struct blob_attr *tn[__NET_MAX], *ti[__NET_IF_MAX];
	struct blob_attr *curif, *curaddr;
	const char *ifname;
	size_t len = 0;
	int remif, remaddr;
	int ifcount = 0;

	snprintf(out, outlen, "-");
	if (!netinfo)
		return;

	blobmsg_parse(net_policy, __NET_MAX, tn,
		      blobmsg_data(netinfo), blobmsg_len(netinfo));
	if (tn[NET_NAMESPACE] &&
	    !strcmp(blobmsg_get_string(tn[NET_NAMESPACE]), "host")) {
		snprintf(out, outlen, "host");
		return;
	}
	if (!tn[NET_INTERFACES])
		return;

	blobmsg_for_each_attr(curif, tn[NET_INTERFACES], remif)
		ifcount++;

	blobmsg_for_each_attr(curif, tn[NET_INTERFACES], remif) {
		blobmsg_parse(net_if_policy, __NET_IF_MAX, ti,
			      blobmsg_data(curif), blobmsg_len(curif));
		if (!ti[NET_IF_ADDRESSES])
			continue;

		ifname = ti[NET_IF_NAME] ?
			blobmsg_get_string(ti[NET_IF_NAME]) : "?";
		blobmsg_for_each_attr(curaddr, ti[NET_IF_ADDRESSES], remaddr) {
			if (blobmsg_type(curaddr) != BLOBMSG_TYPE_STRING)
				continue;

			len += snprintf(out + len, outlen - len, "%s%s%s%s",
					len ? "," : "",
					ifcount > 1 ? ifname : "",
					ifcount > 1 ? "=" : "",
					blobmsg_get_string(curaddr));
			if (len >= outlen)
				len = outlen - 1;
		}
	}
}

static int uxc_list(void)
{
	struct blob_attr *cur, *tb[__CONF_MAX], *ts[__STATE_MAX], *netinfo;
	int rem, pass;
	struct runtime_state *rsstate = NULL;
	char *name, *bundle, *ocistatus, *status, *created, *rootfs, *tmp;
	int container_pid;
	static struct blob_buf buf;
	void *arr, *obj, *ann;
	size_t id_w = 2, pid_w = 3, status_w = 6, bundle_w = 6, created_w = 7, owner_w = 5;
	char pidstr[12];
	char netstr[512];

	if (quiet_output) {
		blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
			blobmsg_parse(conf_policy, __CONF_MAX, tb,
				      blobmsg_data(cur), blobmsg_len(cur));
			if (!tb[CONF_NAME] || !tb[CONF_PATH])
				continue;

			printf("%s\n", blobmsg_get_string(tb[CONF_NAME]));
		}
		return 0;
	}

	if (json_output) {
		blob_buf_init(&buf, 0);
		arr = blobmsg_open_array(&buf, "");
	}

	for (pass = json_output ? 1 : 0; pass < 2; pass++) {
		if (pass == 1 && !json_output)
			printf("%-*s %-*s %-*s %-*s %-*s %-*s %s\n",
			       (int)id_w, "ID", (int)pid_w, "PID",
			       (int)status_w, "STATUS", (int)bundle_w, "BUNDLE",
			       (int)created_w, "CREATED", (int)owner_w, "OWNER",
			       "NET");

		blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
			blobmsg_parse(conf_policy, __CONF_MAX, tb,
				      blobmsg_data(cur), blobmsg_len(cur));
			if (!tb[CONF_NAME] || !tb[CONF_PATH])
				continue;

			name = blobmsg_get_string(tb[CONF_NAME]);
			bundle = blobmsg_get_string(tb[CONF_PATH]);

			ocistatus = NULL;
			container_pid = 0;
			created = "-";
			rootfs = NULL;
			netinfo = NULL;
			rsstate = avl_find_element(&runtime, name, rsstate, avl);
			if (rsstate && rsstate->ocistate) {
				blobmsg_parse(state_policy, __STATE_MAX, ts,
					      blobmsg_data(rsstate->ocistate),
					      blobmsg_len(rsstate->ocistate));
				if (ts[STATE_STATUS])
					ocistatus = blobmsg_get_string(ts[STATE_STATUS]);
				if (ts[STATE_PID])
					container_pid = blobmsg_get_u32(ts[STATE_PID]);
				if (ts[STATE_BUNDLE])
					bundle = blobmsg_get_string(ts[STATE_BUNDLE]);
				if (ts[STATE_CREATED])
					created = blobmsg_get_string(ts[STATE_CREATED]);
				rootfs = ts[STATE_ROOTFS] ? blobmsg_get_string(ts[STATE_ROOTFS]) : NULL;
				netinfo = ts[STATE_NETWORK];
			}
			status = ocistatus?:(rsstate && rsstate->running)?"creating":(rsstate?"stopped":"uninitialized");

			if (container_pid > 0)
				snprintf(pidstr, sizeof(pidstr), "%d", container_pid);
			else
				snprintf(pidstr, sizeof(pidstr), "%s", "-");

			if (pass == 0) {
				if (strlen(name) > id_w) id_w = strlen(name);
				if (strlen(pidstr) > pid_w) pid_w = strlen(pidstr);
				if (strlen(status) > status_w) status_w = strlen(status);
				if (strlen(bundle) > bundle_w) bundle_w = strlen(bundle);
				if (strlen(created) > created_w) created_w = strlen(created);
				continue;
			}

			if (json_output) {
				obj = blobmsg_open_table(&buf, "");
				blobmsg_add_string(&buf, "ociVersion", OCI_VERSION_STRING);
				blobmsg_add_string(&buf, "id", name);
				if (container_pid > 0)
					blobmsg_add_u32(&buf, "pid", container_pid);
				blobmsg_add_string(&buf, "status", status);
				blobmsg_add_string(&buf, "bundle", bundle);
				if (rsstate && rsstate->ocistate && ts[STATE_ANNOTATIONS]) {
					blobmsg_add_blob(&buf, ts[STATE_ANNOTATIONS]);
				} else {
					ann = blobmsg_open_table(&buf, "annotations");
					blobmsg_close_table(&buf, ann);
				}
				if (rsstate && rsstate->ocistate && ts[STATE_NETWORK])
					blobmsg_add_blob(&buf, ts[STATE_NETWORK]);
				if (rootfs)
					blobmsg_add_string(&buf, "rootfs", rootfs);

				if (strcmp(created, "-"))
					blobmsg_add_string(&buf, "created", created);

				blobmsg_add_string(&buf, "owner", "root");
				blobmsg_close_table(&buf, obj);
			} else {
				netinfo_str(netinfo, netstr, sizeof(netstr));
				printf("%-*s %-*s %-*s %-*s %-*s %-*s %s\n",
				       (int)id_w, name, (int)pid_w, pidstr,
				       (int)status_w, status, (int)bundle_w, bundle,
				       (int)created_w, created, (int)owner_w, "root",
				       netstr);
			}
		}
	}

	if (json_output) {
		blobmsg_close_array(&buf, arr);
		tmp = blobmsg_format_json_indent(buf.head, true, 0);
		if (!tmp) {
			blob_buf_free(&buf);
			return -ENOMEM;
		}
		printf("%s\n", tmp);
		free(tmp);
		blob_buf_free(&buf);
	}

	return 0;
}

static int uxc_start(const char *name, bool console)
{
	struct uxc_wait_state wait_state;
	char *objname;
	unsigned int id;
	pid_t pid;
	int ret;

	if (console) {
		pid = fork();
		if (pid > 0)
			exit(uxc_attach(name) ? EXIT_FAILURE : 0);
	}

	if (asprintf(&objname, "container.%s", name) == -1)
		return -ENOMEM;

	if (ubus_lookup_id(ctx, objname, &id)) {
		free(objname);
		uxc_runtime_diagnose(name);
		return -ENOENT;
	}
	free(objname);

	memset(&wait_state, 0, sizeof(wait_state));
	wait_state.service = name;
	wait_state.instance = name;
	wait_state.success_event = "instance.running";
	wait_state.since_incarnation = uxc_instance_incarnation(name, name);

	if (uxc_wait_arm(&wait_state))
		fprintf(stderr, "uxc: warning: cannot arm instance.* watcher\n");

	ret = ubus_invoke(ctx, id, "start", NULL, NULL, NULL, 3000);
	if (ret) {
		fprintf(stderr, "uxc: start %s: %s\n", name, ubus_strerror(ret));
		uxc_wait_disarm();
		return -EIO;
	}

	uxc_wait_run(&wait_state, 30000);
	uxc_wait_disarm();
	if (wait_state.result == UXC_WAIT_UNSET) {
		fprintf(stderr, "uxc: start %s failed: the container did not "
				"reach running state\n", name);
		return -ETIMEDOUT;
	}
	if (wait_state.result == UXC_WAIT_STOPPED && wait_state.reason[0])
		fprintf(stderr, "uxc: %s stopped before running: %s\n", name,
			uxc_wait_why(&wait_state));

	return 0;
}

struct uxc_exec_reply {
	int status;
};

static void uxc_exec_reply_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	enum { REPLY_STATUS, REPLY_PID, __REPLY_MAX };
	static const struct blobmsg_policy reply_policy[__REPLY_MAX] = {
		[REPLY_STATUS] = { "status", BLOBMSG_TYPE_INT32 },
		[REPLY_PID]    = { "pid",    BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *tb[__REPLY_MAX];
	struct uxc_exec_reply *r = req->priv;

	blobmsg_parse(reply_policy, __REPLY_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[REPLY_STATUS])
		r->status = blobmsg_get_u32(tb[REPLY_STATUS]);
}

static int uxc_exec(const char *name, const char *process_file,
		    const char *pid_file, bool detach, bool tty,
		    const char *console_socket,
		    char **cmd_argv, int cmd_argc)
{
	static struct blob_buf req;
	struct uxc_exec_reply reply = { .status = 0 };
	char *objname;
	uint32_t id;
	int notify_fd;
	int ret;

	if (tty && !console_socket) {
		fprintf(stderr, "uxc: --tty requires --console-socket\n");
		return -EINVAL;
	}

	blob_buf_init(&req, 0);

	if (process_file) {
		if (!blobmsg_add_json_from_file(&req, process_file)) {
			fprintf(stderr, "uxc: cannot parse %s as JSON\n", process_file);
			blob_buf_free(&req);
			return -EINVAL;
		}
	} else {
		void *arr;
		int i;

		if (cmd_argc < 1) {
			fprintf(stderr, "uxc: exec requires --process or a command\n");
			blob_buf_free(&req);
			return -EINVAL;
		}
		arr = blobmsg_open_array(&req, "args");
		for (i = 0; i < cmd_argc; i++)
			blobmsg_add_string(&req, NULL, cmd_argv[i]);
		blobmsg_close_array(&req, arr);
	}

	if (pid_file)
		blobmsg_add_string(&req, "pidfile", pid_file);
	if (detach)
		blobmsg_add_u8(&req, "detach", 1);
	if (tty)
		blobmsg_add_u8(&req, "terminal", 1);
	if (console_socket)
		blobmsg_add_string(&req, "consolesocket", console_socket);

	if (asprintf(&objname, "container.%s", name) == -1) {
		blob_buf_free(&req);
		return -ENOMEM;
	}

	ret = ubus_lookup_id(ctx, objname, &id);
	free(objname);
	if (ret) {
		blob_buf_free(&req);
		uxc_runtime_diagnose(name);
		return -ENOENT;
	}

	notify_fd = uxc_invoker_pidfd();
	ret = ubus_invoke_fd(ctx, id, "exec", req.head,
			     uxc_exec_reply_cb, &reply, 0,
			     stdio_notify_fds_send(tty ? NULL : stdio_fds, notify_fd));
	if (notify_fd >= 0)
		close(notify_fd);
	blob_buf_free(&req);

	if (ret)
		return -EIO;

	return reply.status;
}

static int uxc_update(const char *name, const char *resources_file)
{
	static struct blob_buf req;
	char reason[128];
	int ret, err;

	if (!resources_file) {
		fprintf(stderr, "uxc: update requires --resources <file>\n");
		return -EINVAL;
	}

	blob_buf_init(&req, 0);
	if (!blobmsg_add_json_from_file(&req, resources_file)) {
		fprintf(stderr, "uxc: cannot parse %s as JSON\n", resources_file);
		blob_buf_free(&req);
		return -EINVAL;
	}

	ret = uxc_update_blob(name, req.head, reason, sizeof(reason), &err);
	blob_buf_free(&req);
	if (ret)
		fprintf(stderr, "uxc: resources rejected: %s: %s\n", reason, strerror(err));

	return ret;
}

static int uxc_kill(char *name, int signal, bool all)
{
	struct runtime_state *rsstate = NULL;
	struct uxc_wait_state wait_state;
	struct blob_attr *tb[__CONF_MAX];
	bool wait_stop = (signal < 0);
	static struct blob_buf req;
	unsigned int id;
	char *objname;
	int ret;

	if (!registration_find(name, tb))
		return -ENOENT;

	rsstate = avl_find_element(&runtime, name, rsstate, avl);

	if (!rsstate) {
		uxc_runtime_diagnose(name);
		return -ENOENT;
	}

	if (!runtime_live(rsstate)) {
		fprintf(stderr, "uxc: %s is not running\n", name);
		return -ENOENT;
	}

	blob_buf_init(&req, 0);
	blobmsg_add_u32(&req, "signal", signal);
	blobmsg_add_string(&req, "name", name);
	if (all)
		blobmsg_add_u8(&req, "all", 1);

	if (asprintf(&objname, "container.%s", name) == -1)
		return -ENOMEM;

	if (ubus_lookup_id(ctx, objname, &id)) {
		uxc_runtime_diagnose(name);
		ret = -ENOENT;
		goto out;
	}

	if (wait_stop) {
		memset(&wait_state, 0, sizeof(wait_state));
		wait_state.service = name;
		wait_state.instance = name;
		wait_state.object = objname;
		wait_state.success_event = "instance.stopped";
		wait_state.since_incarnation = rsstate->incarnation;
		ret = uxc_wait_arm(&wait_state);
		if (ret) {
			fprintf(stderr, "uxc: cannot watch for %s to stop\n", name);
			goto out;
		}
	}

	ret = ubus_invoke(ctx, id, "kill", req.head, NULL, NULL, 3000);
	if (ret) {
		if (wait_stop)
			uxc_wait_disarm();
		ret = (ret == UBUS_STATUS_NOT_FOUND) ? -ENOENT : -EIO;
		goto out;
	}

	if (wait_stop) {
		uxc_wait_run(&wait_state, 0);
		uxc_wait_disarm();
		if (wait_state.result == UXC_WAIT_GONE) {
			fprintf(stderr, "uxc: the runtime of %s exited before reporting a stop\n",
				name);
			ret = -EIO;
		} else if (wait_state.result == UXC_WAIT_UNSET) {
			fprintf(stderr, "uxc: interrupted while waiting for %s to stop\n", name);
			ret = -EINTR;
		}
	}

out:
	free(objname);
	return ret;
}

static int uxc_restart(char *name, bool systemd_cgroup)
{
	struct runtime_state *rsstate = NULL;
	struct blob_attr *tb[__CONF_MAX];
	int ret;

	if (!registration_find(name, tb))
		return -ENOENT;

	rsstate = avl_find_element(&runtime, name, rsstate, avl);
	if (runtime_live(rsstate)) {
		ret = uxc_kill(name, -1, false);
		if (ret)
			return ret;
	}

	runtime_free();
	ret = runtime_load();
	if (ret)
		return ret;

	rsstate = avl_find_element(&runtime, name, rsstate, avl);
	if (runtime_live(rsstate)) {
		fprintf(stderr, "uxc: %s did not stop\n", name);
		return -EBUSY;
	}

	ret = uxc_create(name, false, NULL, systemd_cgroup, NULL);
	if (ret)
		return ret;

	return uxc_start(name, false);
}

static int registration_write(const char *name, struct blob_attr *root)
{
	char *fname;
	int ret;

	if (mkdir(confdir, 0755) && errno != EEXIST)
		return -errno;

	if (asprintf(&fname, "%s/%s.json", confdir, name) == -1)
		return -ENOMEM;

	ret = json_file_write(fname, root, 0644);
	free(fname);
	if (ret)
		return ret;

	return 1;
}

static void volumes_array_add(struct blob_buf *buf, char *list)
{
	char *curvol, *tmp, *tok;
	void *arr;

	arr = blobmsg_open_array(buf, "volumes");
	for (tok = list; ; tok = NULL) {
		curvol = strtok_r(tok, ",;", &tmp);
		if (!curvol)
			break;

		blobmsg_add_string(buf, NULL, curvol);
	}
	blobmsg_close_array(buf, arr);
}

static int data_volume_arg_add(struct blob_buf *buf, char *arg)
{
	char *mnt, *size;
	void *t;

	mnt = strchr(arg, ':');
	if (!mnt || mnt == arg)
		return -EINVAL;

	*mnt++ = '\0';
	size = strchr(mnt, ':');
	if (size)
		*size++ = '\0';

	if (!*mnt || (size && !*size))
		return -EINVAL;

	t = blobmsg_open_table(buf, NULL);
	blobmsg_add_string(buf, "name", arg);
	blobmsg_add_string(buf, "mountpoint", mnt);
	if (size)
		blobmsg_add_string(buf, "size", size);

	blobmsg_close_table(buf, t);

	return 0;
}

static int env_arg_add(struct blob_buf *buf, char *arg)
{
	char *val;

	val = strchr(arg, '=');
	if (!val || val == arg)
		return -EINVAL;

	*val++ = '\0';
	blobmsg_add_string(buf, arg, val);

	return 0;
}

static int respawn_arg_add(struct blob_buf *buf, char *arg)
{
	char *key, *val, *end, *next;
	unsigned long long n;
	int i;

	for (key = arg; key; key = next) {
		next = strchr(key, ',');
		if (next)
			*next++ = '\0';

		val = strchr(key, '=');
		if (!val || val == key || !isdigit((unsigned char)val[1]))
			return -EINVAL;

		*val++ = '\0';
		n = strtoull(val, &end, 10);
		if (*end || n > UINT32_MAX)
			return -EINVAL;

		for (i = 0; i < __RESPAWN_MAX; i++)
			if (!strcmp(respawn_table_policy[i].name, key))
				break;

		if (i == __RESPAWN_MAX)
			return -EINVAL;

		if (respawn_table_policy[i].type == BLOBMSG_TYPE_INT32) {
			blobmsg_add_u32(buf, key, n);
			continue;
		}

		if (n > 1)
			return -EINVAL;

		blobmsg_add_u8(buf, key, n);
	}

	return 0;
}

static int stop_timeout_arg_add(struct blob_buf *buf, const char *arg)
{
	unsigned long long n;
	char *end;

	if (!isdigit((unsigned char)*arg))
		return -EINVAL;

	n = strtoull(arg, &end, 10);
	if (*end || n > UINT32_MAX)
		return -EINVAL;

	blobmsg_add_u32(buf, "stop-timeout", n);

	return 0;
}

static int uxc_set(char *name, char *path, signed char autostart, char *pidfile, char *tmprwsize, char *writepath, char *requiredmounts)
{
	struct settings *usettings = NULL;
	struct blob_attr *tb[__CONF_MAX];
	static struct blob_buf req;
	struct blob_attr *found;
	struct stat sb;
	int ret;

	/* nothing to do */
	if (!path && (autostart<0) && !pidfile && !tmprwsize && !writepath && !requiredmounts)
		return 0;

	found = registration_find(name, tb);
	if (found && path)
		return -EEXIST;

	if (!found && !path)
		return -ENOENT;

	if (path) {
		if (stat(path, &sb) == -1)
			return -ENOENT;

		if ((sb.st_mode & S_IFMT) != S_IFDIR)
			return -ENOTDIR;

		usettings = avl_find_element(&settings, name, usettings, avl);
		if (usettings)
			return -EIO;
	}

	blob_buf_init(&req, 0);
	if (path) {
		blobmsg_add_string(&req, "name", name);
		blobmsg_add_string(&req, "path", path);
	}

	if (autostart >= 0)
		blobmsg_add_u8(&req, "autostart", !!autostart);

	if (pidfile)
		blobmsg_add_string(&req, "pidfile", pidfile);

	if (tmprwsize)
		blobmsg_add_string(&req, "temp-overlay-size", tmprwsize);

	if (writepath)
		blobmsg_add_string(&req, "write-overlay-path", writepath);

	if (requiredmounts)
		volumes_array_add(&req, requiredmounts);

	if (path)
		ret = registration_write(name, req.head);
	else
		ret = settings_edit(name, req.head, NULL);

	blob_buf_free(&req);

	return ret;
}

enum {
	BLOCK_INFO_DEVICE,
	BLOCK_INFO_UUID,
	BLOCK_INFO_TARGET,
	BLOCK_INFO_TYPE,
	BLOCK_INFO_MOUNT,
	__BLOCK_INFO_MAX,
};

static const struct blobmsg_policy block_info_policy[__BLOCK_INFO_MAX] = {
	[BLOCK_INFO_DEVICE] = { .name = "device", .type = BLOBMSG_TYPE_STRING },
	[BLOCK_INFO_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_STRING },
	[BLOCK_INFO_TARGET] = { .name = "target", .type = BLOBMSG_TYPE_STRING },
	[BLOCK_INFO_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
	[BLOCK_INFO_MOUNT] = { .name = "mount", .type = BLOBMSG_TYPE_STRING },
};


/* check if device 'devname' is mounted according to blockd */
static bool checkblock(const char *uuid)
{
	struct blob_attr *tb[__BLOCK_INFO_MAX];
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, blockinfo, rem) {
		blobmsg_parse(block_info_policy, __BLOCK_INFO_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[BLOCK_INFO_UUID] || !tb[BLOCK_INFO_MOUNT])
			continue;

		if (!strcmp(uuid, blobmsg_get_string(tb[BLOCK_INFO_UUID])))
			return false;
	}

	return true;
}

enum {
	UCI_FSTAB_UUID,
	UCI_FSTAB_ANONYMOUS,
	__UCI_FSTAB_MAX,
};

static const struct blobmsg_policy uci_fstab_policy[__UCI_FSTAB_MAX] = {
	[UCI_FSTAB_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_STRING },
	[UCI_FSTAB_ANONYMOUS] = { .name = ".anonymous", .type = BLOBMSG_TYPE_BOOL },
};

static const char *resolveuuid(const char *volname)
{
	struct blob_attr *tb[__UCI_FSTAB_MAX];
	struct blob_attr *cur;
	const char *mntname;
	char *tmpvolname, *replc;
	int rem, res;

	blobmsg_for_each_attr(cur, fstabinfo, rem) {
		blobmsg_parse(uci_fstab_policy, __UCI_FSTAB_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[UCI_FSTAB_UUID])
			continue;

		if (tb[UCI_FSTAB_ANONYMOUS] && blobmsg_get_bool(tb[UCI_FSTAB_ANONYMOUS]))
			continue;

		mntname = blobmsg_name(cur);
		if (!mntname)
			continue;

		tmpvolname = strdup(volname);
		while ((replc = strchr(tmpvolname, '-')))
			*replc = '_';

		res = strcmp(tmpvolname, mntname);
		free(tmpvolname);

		if (!res)
			return blobmsg_get_string(tb[UCI_FSTAB_UUID]);
	};

	return volname;
};

/* check status of each required volume */
static bool checkvolumes(struct blob_attr *volumes)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, volumes, rem) {
		if (checkblock(resolveuuid(blobmsg_get_string(cur))))
			return true;
	}

	return false;
}

static void block_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	blockinfo = blob_memdup(blobmsg_data(msg));
}

static void fstab_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	fstabinfo = blob_memdup(blobmsg_data(msg));
}

static int uxc_boot(const char *mountpoint)
{
	struct blob_attr *cur, *tb[__CONF_MAX];
	struct runtime_state *rsstate = NULL;
	struct settings *usettings = NULL;
	static struct blob_buf req, vols;
	int rem, nvols, ret = 0;
	const char *imgvol;
	unsigned int id;
	bool autostart;
	char *name;

	ret = ubus_lookup_id(ctx, "block", &id);
	if (ret)
		return -ENOENT;

	ret = ubus_invoke(ctx, id, "info", NULL, block_cb, NULL, 3000);
	if (ret)
		return -ENXIO;

	ret = ubus_lookup_id(ctx, "uci", &id);
	if (ret)
		return -ENOENT;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "config", "fstab");
	blobmsg_add_string(&req, "type", "mount");

	ret = ubus_invoke(ctx, id, "get", req.head, fstab_cb, NULL, 3000);
	if (ret)
		return -EIO;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		if (mountpoint && strncmp(blobmsg_name(cur), mountpoint, strlen(mountpoint)))
			continue;

		rsstate = avl_find_element(&runtime, blobmsg_get_string(tb[CONF_NAME]), rsstate, avl);
		if (rsstate)
			continue;

		autostart = false;
		if (tb[CONF_AUTOSTART])
			autostart = blobmsg_get_bool(tb[CONF_AUTOSTART]);

		usettings = avl_find_element(&settings, blobmsg_get_string(tb[CONF_NAME]), usettings, avl);
		if (usettings && (usettings->autostart >= 0))
			autostart = !!(usettings->autostart);

		if (!autostart)
			continue;

		/* make sure all volumes are ready before starting */
		if (tb[CONF_VOLUMES])
			if (checkvolumes(tb[CONF_VOLUMES]))
				continue;

		if (usettings && usettings->volumes)
			if (checkvolumes(usettings->volumes))
				continue;

		nvols = data_volumes_effective(tb[CONF_DATA_VOLUMES],
					       usettings ? usettings->tb[CONF_DATA_VOLUMES] : NULL,
					       &vols);
		blob_buf_free(&vols);
		if ((nvols || tb[CONF_OVERLAY_SIZE]) && uvol_meta_pending())
			continue;

		name = strdup(blobmsg_get_string(tb[CONF_NAME]));
		if (uxc_exists(name)) {
			free(name);
			continue;
		}

		imgvol = uvol_volume_name(blobmsg_get_string(tb[CONF_PATH]));
		if (imgvol && uvol_backend_pending()) {
			free(name);
			continue;
		}

		if (imgvol && uvol_status(imgvol)) {
			ERROR("uxc: %s image %s missing (interrupted upgrade?); run 'apk fix %s'\n",
			      name, imgvol, name);
			free(name);
			continue;
		}

		if (uxc_create(name, true, NULL, false, NULL)) {
			fprintf(stderr, "uxc: boot: could not start %s\n", name);
			ret = -EIO;
		}

		free(name);
	}

	return ret;
}

static bool uxc_registered(const char *name)
{
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (tb[CONF_NAME] && !strcmp(name, blobmsg_get_string(tb[CONF_NAME])))
			return true;
	}

	return false;
}

static int purge_cb(const char *path, const struct stat *sb, int typeflag,
		    struct FTW *ftwbuf)
{
	return remove(path);
}

static int tree_purge(const char *path)
{
	struct stat sb;

	if (lstat(path, &sb) || !S_ISDIR(sb.st_mode))
		return 0;

	return nftw(path, purge_cb, 16, FTW_DEPTH | FTW_PHYS) ? -EIO : 0;
}

static int reconcile_purge(const char *base, const char *name, const char *statedir)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/settings/%s.json", base, name);
	unlink(path);

	if (nftw(statedir, purge_cb, 16, FTW_DEPTH | FTW_PHYS)) {
		fprintf(stderr, "uxc: reconcile: could not purge state for %s\n", name);
		return -EIO;
	}

	fprintf(stderr, "uxc: reconcile: purged orphaned state for %s\n", name);

	return 0;
}

static int reconcile_base(const char *base, int *purged)
{
	char root[PATH_MAX], glob_pat[PATH_MAX];
	const char *name;
	int i, ret = 0;
	glob_t gl;

	if (store_root(base, STORE_STATE, root, sizeof(root)))
		return 0;

	snprintf(glob_pat, sizeof(glob_pat), "%s/*", root);
	if (glob(glob_pat, GLOB_NOSORT, NULL, &gl))
		return 0;

	for (i = 0; i < gl.gl_pathc; i++) {
		name = strrchr(gl.gl_pathv[i], '/');
		name = name ? name + 1 : gl.gl_pathv[i];
		if (uxc_registered(name))
			continue;
		if (reconcile_purge(base, name, gl.gl_pathv[i])) {
			ret = -EIO;
			continue;
		}
		++*purged;
	}

	globfree(&gl);

	return ret;
}

static int uxc_reconcile(void)
{
	const char *bases[] = { confdir, UXC_VOL_CONFDIR };
	int purged = 0, ret = 0, err;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(bases); i++) {
		if (i && !strcmp(bases[i], bases[0]))
			continue;

		err = reconcile_base(bases[i], &purged);
		if (err)
			ret = err;
	}

	if (purged)
		fprintf(stderr, "uxc: purged %d orphaned container(s)\n", purged);

	return ret;
}

static int uxc_delete(char *name, bool force, bool volumes)
{
	struct runtime_state *rsstate = NULL;
	struct settings *usettings = NULL;
	static struct blob_buf req, vols;
	struct blob_attr *tb[__CONF_MAX];
	const char *statevol = NULL;
	const char *sfname = NULL;
	struct blob_attr *found;
	char rundir[PATH_MAX];
	const char *cfname;
	struct stat sb;
	uint32_t id;
	int ret = 0;
	bool live;

	found = registration_find(name, tb);
	if (!found)
		return -ENOENT;

	cfname = blobmsg_name(found);

	ret = rundir_path(name, NULL, rundir, sizeof(rundir));
	if (ret)
		return ret;

	if (tb[CONF_ORIGIN] && !strcmp(blobmsg_get_string(tb[CONF_ORIGIN]), "package")) {
		fprintf(stderr, "uxc: %s is provided by a package; use 'apk del' to remove it\n", name);
		return -EPERM;
	}

	rsstate = avl_find_element(&runtime, name, rsstate, avl);
	live = runtime_live(rsstate);

	if (live && !force) {
		ret = -EWOULDBLOCK;
		goto errout;
	}

	if (live) {
		ret = uxc_kill(name, SIGKILL, true);
		if (ret && ret != -ENOENT)
			goto errout;
		ret = 0;
	}

	if (rsstate) {
		if (ubus_lookup_id(ctx, "container", &id)) {
			ret = -EIO;
			goto errout;
		}

		uxc_runtime_delete(rsstate->container_name);

		blob_buf_init(&req, 0);
		blobmsg_add_string(&req, "name", rsstate->container_name);
		blobmsg_add_string(&req, "instance", rsstate->instance_name);

		ret = ubus_invoke(ctx, id, "delete", req.head, NULL, NULL, 3000);
		if (ret && ret != UBUS_STATUS_NOT_FOUND) {
			blob_buf_free(&req);
			ret = -EIO;
			goto errout;
		}

		ret = 0;
	}

	usettings = avl_find_element(&settings, name, usettings, avl);
	if (usettings)
		sfname = usettings->fname;

	data_volumes_effective(tb[CONF_DATA_VOLUMES],
			       usettings ? usettings->tb[CONF_DATA_VOLUMES] : NULL, &vols);

	if (usettings && usettings->writepath)
		statevol = uvol_volume_name(usettings->writepath);
	else if (tb[CONF_WRITE_OVERLAY_PATH])
		statevol = uvol_volume_name(blobmsg_get_string(tb[CONF_WRITE_OVERLAY_PATH]));
	else if (tb[CONF_OVERLAY_SIZE])
		statevol = name;

	if (sfname && unlink(sfname) == -1 && errno != ENOENT) {
		ret = -errno;
		goto errout;
	}

	if (stat(cfname, &sb) == -1) {
		ret = -ENOENT;
		goto errout;
	}

	if (unlink(cfname) == -1)
		ret = -errno;
	else if (tree_purge(rundir))
		fprintf(stderr, "uxc: could not remove the run-time state of %s\n", name);

	if (!ret && volumes && statevol) {
		if (run_uvol("remove", statevol))
			fprintf(stderr, "uxc: warning: could not remove state volume %s\n", statevol);
	}

	if (!ret && volumes)
		reap_data_volumes(name, blob_data(vols.head));

errout:
	blob_buf_free(&vols);
	return ret;
}

static void reload_conf(void)
{
	blob_buf_free(&conf);
	conf_load(false);
	settings_free();
	blob_buf_free(&settingsbuf);
	conf_load(true);
	settings_add();
}

static int get_signum(const char *name)
{
	char *endptr;
	long sig;
	int i;

	sig = strtol(name, &endptr, 10);
	if (endptr == name + strlen(name) && sig < NSIG)
		/* string is a valid signal number */
		return sig;

	if (strncasecmp(name, "SIG", 3) == 0)
		name += 3;

	for (i = 0; i < ARRAY_SIZE(signames); ++i) {
		if (!strcmp(name, signames[i].name))
			return signames[i].signal;
	}

	return -1;
}

static void patch_members_add(struct blob_buf *patch, const char *name,
			      struct blob_attr *members, int type)
{
	struct blob_attr *cur;
	void *c;
	int rem;

	if (!blob_len(members))
		return;

	c = blob_container_open(patch, name, type);
	blobmsg_for_each_attr(cur, members, rem)
		blobmsg_add_blob(patch, cur);

	blob_nest_end(patch, c);
}

static int set_args_parse(int argc, char **argv, struct blob_buf *patch,
			  struct blob_buf *unset, const char **name)
{
	static struct blob_buf vols, envs, respawn, resources;
	int c, ret = 0;

	if (argc < 2 || argv[1][0] == '-')
		return -EINVAL;

	*name = argv[1];
	argc--;
	argv++;

	blob_buf_init(&vols, 0);
	blob_buf_init(&envs, 0);
	blob_buf_init(&respawn, 0);
	blob_buf_init(&resources, 0);
	while (!ret && (c = getopt_long(argc, argv, "+", set_opts, NULL)) != -1) {
		switch (c) {
		case OPT_AUTOSTART:
			if (strcmp(optarg, "0") && strcmp(optarg, "1"))
				ret = -EINVAL;
			else
				blobmsg_add_u8(patch, "autostart", optarg[0] == '1');
			break;
		case OPT_PID_FILE:
			blobmsg_add_string(patch, "pidfile", optarg);
			break;
		case OPT_TEMP_OVERLAY_SIZE:
			blobmsg_add_string(patch, "temp-overlay-size", optarg);
			break;
		case OPT_WRITE_OVERLAY_PATH:
			blobmsg_add_string(patch, "write-overlay-path", optarg);
			break;
		case OPT_MOUNTS:
			volumes_array_add(patch, optarg);
			break;
		case OPT_MODULE_VERSION:
			blobmsg_add_string(patch, "module-version", optarg);
			break;
		case OPT_DATA_VOLUME:
			ret = data_volume_arg_add(&vols, optarg);
			break;
		case OPT_ENV:
			ret = env_arg_add(&envs, optarg);
			break;
		case OPT_RESPAWN:
			ret = respawn_arg_add(&respawn, optarg);
			break;
		case OPT_STOP_TIMEOUT:
			ret = stop_timeout_arg_add(patch, optarg);
			break;
		case OPT_RESOURCES:
			if (!blobmsg_add_json_from_file(&resources, optarg))
				ret = -EINVAL;
			break;
		case OPT_UNSET:
			blobmsg_add_string(unset, NULL, optarg);
			break;
		default:
			ret = -EINVAL;
			break;
		}
	}

	if (!ret && optind != argc)
		ret = -EINVAL;

	if (!ret) {
		patch_members_add(patch, "data-volumes", vols.head, BLOBMSG_TYPE_ARRAY);
		patch_members_add(patch, "env", envs.head, BLOBMSG_TYPE_TABLE);
		patch_members_add(patch, "respawn", respawn.head, BLOBMSG_TYPE_TABLE);
		patch_members_add(patch, "resources", resources.head, BLOBMSG_TYPE_TABLE);
	}

	blob_buf_free(&vols);
	blob_buf_free(&envs);
	blob_buf_free(&respawn);
	blob_buf_free(&resources);

	return ret;
}

int main(int argc, char **argv)
{
	static struct blob_buf set_patch, set_unset;
	int ret = -EINVAL;
	const char *verb;
	const char *log_path = NULL;
	const char *log_format = NULL;
	const char *criu_path = NULL;
	bool systemd_cgroup = false;
	const char *set_name;
	int verb_argc, c, i;
	char **verb_argv;

	for (i = 1; i < argc; ++i) {
		const char *a = argv[i];
		const char *eq;

		if (a[0] != '-')
			break;

		if (!strcmp(a, "--")) {
			++i;
			break;
		}

		if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
			printf("uxc %s\nspec: %s\n", UXC_VERSION, OCI_VERSION_STRING);
			return 0;
		}

		if (!strcmp(a, "-v") || !strcmp(a, "--verbose") || !strcmp(a, "--debug")) {
			verbose = true;
			continue;
		}

		if (!strcmp(a, "--systemd-cgroup")) {
			systemd_cgroup = true;
			continue;
		}

		eq = strchr(a, '=');

#define GLOBAL_OPT_VAL(name, dst) \
		do { \
			size_t _n = strlen(name); \
			if (eq && !strncmp(a, name, _n) && a[_n] == '=') { \
				dst = eq + 1; \
				goto next_global; \
			} \
			if (!strcmp(a, name)) { \
				if (i + 1 >= argc) { \
					fprintf(stderr, "uxc: %s requires an argument\n", a); \
					return EXIT_FAILURE; \
				} \
				dst = argv[++i]; \
				goto next_global; \
			} \
		} while (0)

		GLOBAL_OPT_VAL("--root",       confdir);
		GLOBAL_OPT_VAL("--log",        log_path);
		GLOBAL_OPT_VAL("--log-format", log_format);
		GLOBAL_OPT_VAL("--criu",       criu_path);
#undef GLOBAL_OPT_VAL

		if (eq && !strncmp(a, "--rootless=", 11))
			continue;
		if (!strcmp(a, "--rootless"))
			continue;

		fprintf(stderr, "uxc: unknown option '%s'\n", a);
		usage();
		return EXIT_FAILURE;
next_global:
		continue;
	}

	if (i >= argc) {
		usage();
		return EXIT_FAILURE;
	}

	if (log_path) {
		int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (fd < 0) {
			fprintf(stderr, "uxc: cannot open --log path %s: %m\n", log_path);
			return EXIT_FAILURE;
		}
		stdio_fds[2] = dup(STDERR_FILENO);
		if (stdio_fds[2] < 0) {
			fprintf(stderr, "uxc: cannot preserve stderr: %m\n");
			close(fd);
			return EXIT_FAILURE;
		}
		if (dup2(fd, STDERR_FILENO) < 0) {
			dprintf(fd, "uxc: dup2(--log path) failed: %m\n");
			close(fd);
			return EXIT_FAILURE;
		}
		close(fd);
	}

	if (log_format && strcmp(log_format, "text"))
		fprintf(stderr, "uxc: --log-format=%s accepted but only text output is emitted\n",
			log_format);

	if (criu_path)
		fprintf(stderr, "uxc: --criu=%s accepted but ignored (no checkpoint/restore support)\n",
			criu_path);

	verb = argv[i];
	verb_argc = argc - i;
	verb_argv = argv + i;

	ctx = ubus_connect(NULL);
	if (!ctx)
		return EXIT_FAILURE;

	ret = conf_load(false);
	if (ret < 0)
		goto out;

	ret = conf_load(true);
	if (ret < 0)
		goto conf_out;

	ret = settings_add();
	if (ret < 0)
		goto settings_out;

	ret = runtime_load();
	if (ret)
		goto settings_avl_out;

	optind = 1;
	opterr = 1;

	if (!strcmp(verb, "list")) {
		while ((c = getopt_long(verb_argc, verb_argv, "f:jq", list_opts, NULL)) != -1) {
			switch (c) {
			case 'f':
				if (!strcmp(optarg, "json")) {
					json_output = true;
				} else if (!strcmp(optarg, "table")) {
					json_output = false;
				} else {
					fprintf(stderr, "uxc: invalid format '%s'\n", optarg);
					goto usage_out;
				}
				break;
			case 'j': json_output = true; break;
			case 'q': quiet_output = true; break;
			default: goto usage_out;
			}
		}
		if (optind != verb_argc)
			goto usage_out;
		ret = uxc_list();
	} else if (!strcmp(verb, "attach")) {
		if (verb_argc != 2)
			goto usage_out;
		ret = uxc_attach(verb_argv[1]);
	} else if (!strcmp(verb, "boot")) {
		if (verb_argc != 1 && verb_argc != 2)
			goto usage_out;
		uxc_reconcile();
		ret = uxc_boot(verb_argc == 2 ? verb_argv[1] : NULL);
	} else if (!strcmp(verb, "reconcile")) {
		if (verb_argc != 1)
			goto usage_out;
		ret = uxc_reconcile();
	} else if (!strcmp(verb, "start")) {
		bool console = false;

		while ((c = getopt_long(verb_argc, verb_argv, "c", start_opts, NULL)) != -1) {
			switch (c) {
			case 'c': console = true; break;
			default: goto usage_out;
			}
		}
		if (optind != verb_argc - 1)
			goto usage_out;
		ret = uxc_start(verb_argv[optind], console);
	} else if (!strcmp(verb, "trace") || !strcmp(verb, "audit") ||
		   !strcmp(verb, "complain")) {
		if (verb_argc != 2)
			goto usage_out;
		ret = uxc_create(verb_argv[1], true, NULL, false, verb);
	} else if (!strcmp(verb, "state")) {
		if (verb_argc != 2)
			goto usage_out;
		ret = uxc_state(verb_argv[1]);
	} else if (!strcmp(verb, "kill")) {
		int signal = -1;
		bool signal_from_flag = false;
		bool all = false;

		while ((c = getopt_long(verb_argc, verb_argv, "+s:a", kill_opts, NULL)) != -1) {
			switch (c) {
			case 's':
				signal = get_signum(optarg);
				if (signal < 0)
					goto usage_out;
				signal_from_flag = true;
				break;
			case 'a':
				all = true;
				break;
			default: goto usage_out;
			}
		}
		if (optind == verb_argc - 2) {
			if (signal_from_flag)
				goto usage_out;
			signal = get_signum(verb_argv[optind + 1]);
			if (signal < 0)
				goto usage_out;
		} else if (optind != verb_argc - 1) {
			goto usage_out;
		}
		if (all && signal != SIGKILL) {
			fprintf(stderr, "uxc: --all is only valid with SIGKILL\n");
			ret = -ENOTSUP;
			goto runtime_out;
		}
		ret = uxc_kill(verb_argv[optind], signal, all);
	} else if (!strcmp(verb, "restart")) {
		if (verb_argc != 2)
			goto usage_out;
		ret = uxc_restart(verb_argv[1], systemd_cgroup);
	} else if (!strcmp(verb, "enable")) {
		if (verb_argc != 2)
			goto usage_out;
		ret = uxc_set(verb_argv[1], NULL, 1, NULL, NULL, NULL, NULL);
		if (ret > 0)
			ret = 0;
	} else if (!strcmp(verb, "disable")) {
		if (verb_argc != 2)
			goto usage_out;
		ret = uxc_set(verb_argv[1], NULL, 0, NULL, NULL, NULL, NULL);
		if (ret > 0)
			ret = 0;
	} else if (!strcmp(verb, "set")) {
		blob_buf_init(&set_patch, 0);
		blob_buf_init(&set_unset, 0);
		if (set_args_parse(verb_argc, verb_argv, &set_patch, &set_unset, &set_name)) {
			blob_buf_free(&set_patch);
			blob_buf_free(&set_unset);
			goto usage_out;
		}
		ret = settings_edit(set_name, set_patch.head, set_unset.head);
		blob_buf_free(&set_patch);
		blob_buf_free(&set_unset);
		if (ret > 0)
			ret = 0;
	} else if (!strcmp(verb, "delete")) {
		bool force = false;
		bool volumes = false;

		while ((c = getopt_long(verb_argc, verb_argv, "fV", delete_opts, NULL)) != -1) {
			switch (c) {
			case 'f': force = true; break;
			case 'V': volumes = true; break;
			default: goto usage_out;
			}
		}
		if (optind != verb_argc - 1)
			goto usage_out;
		ret = uxc_delete(verb_argv[optind], force, volumes);
	} else if (!strcmp(verb, "create")) {
		char *bundle = NULL, *pidfile = NULL;
		char *tmprwsize = NULL, *writepath = NULL, *requiredmounts = NULL;
		char *console_socket = NULL;
		signed char autostart = -1;
		char *name;

		while ((c = getopt_long(verb_argc, verb_argv, "ab:m:p:t:w:",
					create_opts, NULL)) != -1) {
			switch (c) {
			case 'a': autostart = 1; break;
			case 'b': bundle = optarg; break;
			case 'm': requiredmounts = optarg; break;
			case 'p': pidfile = optarg; break;
			case 't': tmprwsize = optarg; break;
			case 'w': writepath = optarg; break;
			case OPT_CONSOLE_SOCKET:
				console_socket = optarg;
				break;
			case OPT_NO_PIVOT:
				fprintf(stderr, "uxc: --no-pivot accepted but ignored (ujail does not pivot_root in this mode)\n");
				break;
			case OPT_NO_NEW_KEYRING:
				fprintf(stderr, "uxc: --no-new-keyring accepted but ignored (ujail does not create kernel keyrings)\n");
				break;
			case OPT_PRESERVE_FDS:
				fprintf(stderr, "uxc: --preserve-fds=%s accepted but ignored\n", optarg);
				break;
			default: goto usage_out;
			}
		}
		if (optind != verb_argc - 1)
			goto usage_out;
		name = verb_argv[optind];

		ret = uxc_exists(name);
		if (ret)
			goto runtime_out;

		ret = uxc_set(name, bundle, autostart, pidfile,
			      tmprwsize, writepath, requiredmounts);
		if (ret < 0)
			goto runtime_out;
		if (ret > 0)
			reload_conf();

		ret = uxc_create(name, false, console_socket, systemd_cgroup, NULL);
	} else if (!strcmp(verb, "exec")) {
		const char *process_file = NULL;
		const char *pid_file = NULL;
		const char *console_socket = NULL;
		bool detach = false;
		bool tty = false;

		while ((c = getopt_long(verb_argc, verb_argv, "+dp:t",
					exec_opts, NULL)) != -1) {
			switch (c) {
			case 'd': detach = true; break;
			case 'p': pid_file = optarg; break;
			case 't': tty = true; break;
			case OPT_PROCESS: process_file = optarg; break;
			case OPT_CONSOLE_SOCKET: console_socket = optarg; break;
			case OPT_PRESERVE_FDS:
				fprintf(stderr, "uxc: --preserve-fds=%s accepted but ignored\n", optarg);
				break;
			default: goto usage_out;
			}
		}
		if (optind >= verb_argc)
			goto usage_out;
		{
			const char *id = verb_argv[optind];
			int cmd_start = optind + 1;
			if (cmd_start < verb_argc && !strcmp(verb_argv[cmd_start], "--"))
				cmd_start++;
			ret = uxc_exec(id, process_file, pid_file, detach, tty,
				       console_socket,
				       verb_argv + cmd_start,
				       verb_argc - cmd_start);
		}
	} else if (!strcmp(verb, "update")) {
		const char *resources_file = NULL;

		while ((c = getopt_long(verb_argc, verb_argv, "+",
					update_opts, NULL)) != -1) {
			switch (c) {
			case OPT_RESOURCES: resources_file = optarg; break;
			default: goto usage_out;
			}
		}
		if (optind != verb_argc - 1)
			goto usage_out;
		ret = uxc_update(verb_argv[optind], resources_file);
	} else if (!strcmp(verb, "pause") || !strcmp(verb, "resume")) {
		char *objname;
		uint32_t id;

		if (verb_argc != 2)
			goto usage_out;
		if (asprintf(&objname, "container.%s", verb_argv[1]) == -1) {
			ret = -ENOMEM;
			goto runtime_out;
		}
		ret = ubus_lookup_id(ctx, objname, &id);
		free(objname);
		if (ret) {
			ret = -ENOENT;
			goto runtime_out;
		}
		ret = ubus_invoke(ctx, id, verb, NULL, NULL, NULL, 3000);
		if (ret)
			ret = -EIO;
	} else if (!strcmp(verb, "events") || !strcmp(verb, "checkpoint") ||
		   !strcmp(verb, "restore")) {
		fprintf(stderr, "uxc: '%s' is not supported\n", verb);
		ret = -ENOTSUP;
	} else {
		fprintf(stderr, "uxc: unknown command '%s'\n", verb);
		goto usage_out;
	}

	goto runtime_out;

usage_out:
	usage();
	ret = EXIT_FAILURE;
runtime_out:
	runtime_free();
settings_avl_out:
	settings_free();
settings_out:
	blob_buf_free(&settingsbuf);
conf_out:
	blob_buf_free(&conf);
out:
	ubus_free(ctx);

	if (ret < 0) {
		fprintf(stderr, "uxc error: %s\n", strerror(-ret));
		return EXIT_FAILURE;
	}

	return ret;
}
