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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
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

#include "log.h"

#define UXC_VERSION "0.3"
#define OCI_VERSION_STRING "1.0.2"
#define UXC_ETC_CONFDIR "/etc/uxc"
#define UXC_VOL_CONFDIR "/tmp/run/uvol/.meta/uxc"

static bool verbose = false;
static bool json_output = false;
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
	struct blob_attr *ocistate;
};

struct settings {
	struct avl_node avl;
	char *container_name;
	const char *fname;
	char *tmprwsize;
	char *writepath;
	signed char autostart;
	struct blob_attr *volumes;
};

enum {
	OPT_CONSOLE_SOCKET	= 0x100,
	OPT_NO_PIVOT,
	OPT_NO_NEW_KEYRING,
	OPT_PRESERVE_FDS,
	OPT_PROCESS,
	OPT_RESOURCES,
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
	{"json",		no_argument,		0,	'j'	},
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

static int usage(void) {
	printf("syntax: uxc [global options] <command> [parameters ...]\n");
	printf("global options:\n");
	printf("\t[--debug|-v] [--log <path>] [--log-format <text|json>]\n");
	printf("\t[--root <dir>] [--rootless[=auto|true|false]]\n");
	printf("\t[--systemd-cgroup] [--criu <path>]\n");
	printf("commands:\n");
	printf("\tlist [--json]\t\t\t\tlist all configured containers (runc-compatible)\n");
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
	printf("\tenable <conf>\t\t\t\tstart container <conf> on boot\n");
	printf("\tdisable <conf>\t\t\t\tdon't start container <conf> on boot\n");
	printf("\tdelete <conf> [--force] [--volumes]\tdelete <conf>; --volumes also reaps its rw state and per-container volumes\n");
	printf("\tpause <conf>\t\t\t\tfreeze every process in container <conf>'s cgroup\n");
	printf("\tresume <conf>\t\t\t\tthaw a previously paused container <conf>\n");
	printf("\texec <conf> [--process <file>] [-d] [-p <pid-file>] [-- cmd args]\n");
	printf("\t\t\t\t\t\trun a command inside running container <conf>\n");
	printf("\tupdate <conf> --resources <file>\tapply linux.resources from <file> to running container <conf>\n");
	return -EINVAL;
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

	if (res < 0)
		return 0;

	for (j = 0; j < gl.gl_pathc; j++) {
		o = blobmsg_open_table(target, strdup(gl.gl_pathv[j]));
		if (!blobmsg_add_json_from_file(target, gl.gl_pathv[j])) {
			ERROR("uxc: failed to load %s\n", gl.gl_pathv[j]);
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
	INSTANCE_EXITCODE,
	INSTANCE_JAIL,
	__INSTANCE_MAX,
};

static const struct blobmsg_policy instance_policy[__INSTANCE_MAX] = {
	[INSTANCE_RUNNING] = { .name = "running", .type = BLOBMSG_TYPE_BOOL },
	[INSTANCE_PID] = { .name = "pid", .type = BLOBMSG_TYPE_INT32 },
	[INSTANCE_EXITCODE] = { .name = "exit_code", .type = BLOBMSG_TYPE_INT32 },
	[INSTANCE_JAIL] = { .name = "jail", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	JAIL_NAME,
	__JAIL_MAX,
};

static const struct blobmsg_policy jail_policy[__JAIL_MAX] = {
	[JAIL_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
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
	__STATE_MAX,
};

static const struct blobmsg_policy state_policy[__STATE_MAX] = {
	[STATE_OCIVERSION] = { .name = "ociVersion", .type = BLOBMSG_TYPE_STRING },
	[STATE_ID] = { .name = "id", .type = BLOBMSG_TYPE_STRING },
	[STATE_STATUS] = { .name = "status", .type = BLOBMSG_TYPE_STRING },
	[STATE_PID] = { .name = "pid", .type = BLOBMSG_TYPE_INT32 },
	[STATE_BUNDLE] = { .name = "bundle", .type = BLOBMSG_TYPE_STRING },
	[STATE_ANNOTATIONS] = { .name = "annotations", .type = BLOBMSG_TYPE_TABLE },
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
		exit(ENOMEM);

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

			rs = runtime_alloc(container_name);
			rs->instance_name = strdup(instance_name);
			rs->jail_name = strdup(jail_name);
			rs->runtime_pid = pid;
			rs->exitcode = exitcode;
			rs->running = running;
			avl_insert(&runtime, &rs->avl);
		}
	}

	return;
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

static int uxc_state(char *name)
{
	struct runtime_state *rsstate = avl_find_element(&runtime, name, rsstate, avl);
	struct blob_attr *ocistate = NULL;
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem;
	char *bundle = NULL;
	char *jail_name = NULL;
	char *state = NULL;
	char *tmp;
	static struct blob_buf buf;

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

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		if (!strcmp(name, blobmsg_get_string(tb[CONF_NAME]))) {
			if (tb[CONF_JAIL])
				jail_name = blobmsg_get_string(tb[CONF_JAIL]);
			else
				jail_name = name;

			bundle = blobmsg_get_string(tb[CONF_PATH]);
			break;
		}
	}

	if (!bundle)
		return -ENOENT;

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

static int uxc_list(void)
{
	struct blob_attr *cur, *tb[__CONF_MAX], *ts[__STATE_MAX];
	int rem, pass;
	struct runtime_state *rsstate = NULL;
	char *name, *bundle, *ocistatus, *status, *created, *tmp;
	int container_pid;
	static struct blob_buf buf;
	void *arr, *obj, *ann;
	size_t id_w = 2, pid_w = 3, status_w = 6, bundle_w = 6, created_w = 7;
	char pidstr[12];

	if (json_output) {
		blob_buf_init(&buf, 0);
		arr = blobmsg_open_array(&buf, "");
	}

	for (pass = json_output ? 1 : 0; pass < 2; pass++) {
		if (pass == 1 && !json_output)
			printf("%-*s %-*s %-*s %-*s %-*s %s\n",
			       (int)id_w, "ID", (int)pid_w, "PID",
			       (int)status_w, "STATUS", (int)bundle_w, "BUNDLE",
			       (int)created_w, "CREATED", "OWNER");

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
				blobmsg_add_string(&buf, "owner", "root");
				blobmsg_close_table(&buf, obj);
			} else {
				printf("%-*s %-*s %-*s %-*s %-*s %s\n",
				       (int)id_w, name, (int)pid_w, pidstr,
				       (int)status_w, status, (int)bundle_w, bundle,
				       (int)created_w, created, "root");
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

static int uxc_exists(char *name)
{
	struct runtime_state *rsstate = NULL;
	rsstate = avl_find_element(&runtime, name, rsstate, avl);

	if (rsstate && (rsstate->running))
		return -EEXIST;

	return 0;
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

static int uvol_status(const char *vol);
static const char *uvol_volume_name(const char *path);
static int run_uvol(const char *action, const char *vol);
static int provision_rw_uvol(const char *volname, const char *size);
static int provision_data_volumes(const char *container, struct blob_attr *vols,
				  struct blob_buf *req);

static int uxc_create(char *name, bool immediately, const char *console_socket,
		      bool systemd_cgroup, const char *seccomp_mode)
{
	static struct blob_buf req;
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem, ret = 0;
	uint32_t id;
	struct settings *usettings = NULL;
	char *path = NULL, *jailname = NULL, *pidfile = NULL, *tmprwsize = NULL, *writepath = NULL;
	const char *imgvol = NULL;
	char *seccomp_log = NULL;
	char overlaypath[PATH_MAX];

	void *in, *ins, *j, *m;
	bool found = false;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		if (strcmp(name, blobmsg_get_string(tb[CONF_NAME])))
			continue;

		found = true;
		break;
	}

	if (!found)
		return -ENOENT;

	path = blobmsg_get_string(tb[CONF_PATH]);

	imgvol = uvol_volume_name(path);
	if (imgvol)
		run_uvol("up", imgvol);

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

	if (tb[CONF_IDMAP_OFFSET])
		blobmsg_add_string(&req, "idmap_offset", blobmsg_get_string(tb[CONF_IDMAP_OFFSET]));
	if (console_socket)
		blobmsg_add_string(&req, "consolesocket", console_socket);

	if (systemd_cgroup)
		blobmsg_add_u8(&req, "systemdcgroup", 1);

	m = blobmsg_open_table(&req, "mount");
	if (tb[CONF_DATA_VOLUMES]) {
		ret = provision_data_volumes(name, tb[CONF_DATA_VOLUMES], &req);
		if (ret) {
			blobmsg_close_table(&req, m);
			blob_buf_free(&req);
			return ret;
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

	if (ubus_lookup_id(ctx, "container", &id) ||
		ubus_invoke(ctx, id, "add", req.head, NULL, NULL, 3000)) {
		blob_buf_free(&req);
		ret = -EIO;
	}

	return ret;
}

static int uxc_start(const char *name, bool console)
{
	char *objname;
	unsigned int id;
	pid_t pid;

	if (console) {
		pid = fork();
		if (pid > 0)
			exit(uxc_attach(name));
	}

	if (asprintf(&objname, "container.%s", name) == -1)
		return -ENOMEM;

	if (ubus_lookup_id(ctx, objname, &id))
		return -ENOENT;

	free(objname);
	return ubus_invoke(ctx, id, "start", NULL, NULL, NULL, 3000);
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
		return -ENOENT;
	}

	ret = ubus_invoke(ctx, id, "exec", req.head,
			  uxc_exec_reply_cb, &reply, 0);
	blob_buf_free(&req);

	if (ret)
		return -EIO;

	return reply.status;
}

static int uxc_update(const char *name, const char *resources_file)
{
	static struct blob_buf req;
	char *objname;
	uint32_t id;
	int ret;

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

	if (asprintf(&objname, "container.%s", name) == -1) {
		blob_buf_free(&req);
		return -ENOMEM;
	}

	ret = ubus_lookup_id(ctx, objname, &id);
	free(objname);
	if (ret) {
		blob_buf_free(&req);
		return -ENOENT;
	}

	ret = ubus_invoke(ctx, id, "update", req.head, NULL, NULL, 3000);
	blob_buf_free(&req);
	return ret ? -EIO : 0;
}

static int uxc_kill(char *name, int signal, bool all)
{
	static struct blob_buf req;
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem, ret;
	char *objname;
	unsigned int id;
	struct runtime_state *rsstate = NULL;
	bool found = false;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		if (strcmp(name, blobmsg_get_string(tb[CONF_NAME])))
			continue;

		found = true;
		break;
	}

	if (!found)
		return -ENOENT;

	rsstate = avl_find_element(&runtime, name, rsstate, avl);

	if (!rsstate || !(rsstate->running))
		return -ENOENT;

	blob_buf_init(&req, 0);
	blobmsg_add_u32(&req, "signal", signal);
	blobmsg_add_string(&req, "name", name);
	if (all)
		blobmsg_add_u8(&req, "all", 1);

	if (asprintf(&objname, "container.%s", name) == -1)
		return -ENOMEM;

	ret = ubus_lookup_id(ctx, objname, &id);
	free(objname);
	if (ret)
		return -ENOENT;

	if (ubus_invoke(ctx, id, "kill", req.head, NULL, NULL, 3000))
		return -EIO;

	return 0;
}


static int uxc_set(char *name, char *path, signed char autostart, char *pidfile, char *tmprwsize, char *writepath, char *requiredmounts)
{
	static struct blob_buf req;
	struct settings *usettings = NULL;
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem, ret;
	const char *cfname = NULL;
	const char *sfname = NULL;
	char *fname = NULL;
	char *curvol, *tmp, *mnttok;
	void *mntarr;
	int f;
	struct stat sb;

	/* nothing to do */
	if (!path && (autostart<0) && !pidfile && !tmprwsize && !writepath && !requiredmounts)
		return 0;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		if (strcmp(name, blobmsg_get_string(tb[CONF_NAME])))
			continue;

		cfname = blobmsg_name(cur);
		break;
	}

	if (cfname && path)
		return -EEXIST;

	if (!cfname && !path)
		return -ENOENT;

	if (path) {
		if (stat(path, &sb) == -1)
			return -ENOENT;

		if ((sb.st_mode & S_IFMT) != S_IFDIR)
			return -ENOTDIR;
	}

	usettings = avl_find_element(&settings, blobmsg_get_string(tb[CONF_NAME]), usettings, avl);
	if (path && usettings)
		return -EIO;

	if (usettings) {
		sfname = usettings->fname;
		if (!tmprwsize && !writepath) {
			if (usettings->tmprwsize) {
				tmprwsize = usettings->tmprwsize;
				writepath = NULL;
			}
			if (usettings->writepath) {
				writepath = usettings->writepath;
				tmprwsize = NULL;
			}
		}
		if (usettings->autostart >= 0 && autostart < 0)
			autostart = !!(usettings->autostart);
	}

	if (path) {
		ret = mkdir(confdir, 0755);

		if (ret && errno != EEXIST)
			return -errno;

		if (asprintf(&fname, "%s/%s.json", confdir, name) == -1)
			return -ENOMEM;

		f = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (f < 0)
			return -errno;

		free(fname);
	} else {
		if (sfname) {
			f = open(sfname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		} else {
			char *t1, *t2;
			t1 = strdup(cfname);
			t2 = strrchr(t1, '/');
			if (!t2)
				return -EINVAL;

			*t2 = '\0';

			if (asprintf(&t2, "%s/settings", t1) == -1)
				return -ENOMEM;

			ret = mkdir(t2, 0755);
			if (ret && ret != EEXIST)
				return -ret;

			free(t2);
			if (asprintf(&t2, "%s/settings/%s.json", t1, name) == -1)
				return -ENOMEM;

			free(t1);
			f = open(t2, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			free(t2);
		}
		if (f < 0)
			return -errno;
	}

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", name);
	if (path)
		blobmsg_add_string(&req, "path", path);

	if (autostart >= 0)
		blobmsg_add_u8(&req, "autostart", !!autostart);

	if (pidfile)
		blobmsg_add_string(&req, "pidfile", pidfile);

	if (tmprwsize)
		blobmsg_add_string(&req, "temp-overlay-size", tmprwsize);

	if (writepath)
		blobmsg_add_string(&req, "write-overlay-path", writepath);

	if (!requiredmounts && usettings && usettings->volumes)
		blobmsg_add_blob(&req, usettings->volumes);

	if (requiredmounts) {
		mntarr = blobmsg_open_array(&req, "volumes");
		for (mnttok = requiredmounts; ; mnttok = NULL) {
			curvol = strtok_r(mnttok, ",;", &tmp);
			if (!curvol)
				break;

			blobmsg_add_string(&req, NULL, curvol);
		}
		blobmsg_close_array(&req, mntarr);
	}

	tmp = blobmsg_format_json_indent(req.head, true, 0);
	if (tmp) {
		dprintf(f, "%s\n", tmp);
		free(tmp);
	}

	blob_buf_free(&req);
	close(f);

	return 1;
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
	static struct blob_buf req;
	int rem, ret = 0;
	char *name;
	unsigned int id;
	bool autostart;

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
		return ret;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		if (mountpoint && strncmp(blobmsg_name(cur), mountpoint, strlen(mountpoint)))
			continue;

		rsstate = avl_find_element(&runtime, blobmsg_get_string(tb[CONF_NAME]), rsstate, avl);
		if (rsstate)
			continue;

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

		if ((tb[CONF_DATA_VOLUMES] || tb[CONF_OVERLAY_SIZE]) && uvol_status(".meta"))
			continue;

		name = strdup(blobmsg_get_string(tb[CONF_NAME]));
		if (uxc_exists(name))
			continue;

		if (uxc_create(name, true, NULL, false, NULL))
			++ret;

		free(name);
	}

	return ret;
}

static const char *uvol_volume_name(const char *path)
{
	const char prefix[] = "/tmp/run/uvol/";
	const size_t plen = sizeof(prefix) - 1;

	if (!path || strncmp(path, prefix, plen))
		return NULL;

	if (!path[plen] || strchr(path + plen, '/'))
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

	return run_uvol_argv(argv);
}

static int run_uvol_create(const char *vol, const char *size, const char *type)
{
	char *argv[] = { "/usr/sbin/uvol", "create", (char *)vol,
			 (char *)size, (char *)type, NULL };

	return run_uvol_argv(argv);
}

static int run_uvol_resize(const char *vol, const char *size)
{
	char *argv[] = { "/usr/sbin/uvol", "resize", (char *)vol, (char *)size, NULL };

	return run_uvol_argv(argv);
}

static int uvol_status(const char *vol)
{
	char *argv[] = { "/usr/sbin/uvol", "status", (char *)vol, NULL };

	return run_uvol_argv(argv);
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

static int provision_rw_uvol(const char *volname, const char *size)
{
	char sizebytes[32];
	long long bytes;
	int st, rr;

	bytes = parse_size_bytes(size);
	if (bytes <= 0) {
		fprintf(stderr, "uxc: invalid size '%s' for volume %s\n", size, volname);
		return -EINVAL;
	}
	snprintf(sizebytes, sizeof(sizebytes), "%lld", bytes);

	st = uvol_status(volname);
	if (st == 2) {
		if (run_uvol_create(volname, sizebytes, "rw")) {
			fprintf(stderr, "uxc: failed to create volume %s\n", volname);
			return -EIO;
		}
	} else {
		rr = run_uvol_resize(volname, sizebytes);
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
		vsize = vt[VOL_SIZE] ? blobmsg_get_string(vt[VOL_SIZE]) : "64m";

		snprintf(volname, sizeof(volname), "%s.%s", container, vname);
		if (provision_rw_uvol(volname, vsize))
			return -EIO;

		snprintf(bindspec, sizeof(bindspec), "/tmp/run/uvol/%s:%s", volname, vmount);
		blobmsg_add_string(req, bindspec, "2");
	}

	return 0;
}

static void reap_data_volumes(const char *container, struct blob_attr *vols)
{
	struct blob_attr *vcur, *vt[__VOL_MAX];
	char volname[256];
	int vrem;

	blobmsg_for_each_attr(vcur, vols, vrem) {
		blobmsg_parse(vol_policy, __VOL_MAX, vt, blobmsg_data(vcur), blobmsg_len(vcur));
		if (!vt[VOL_NAME])
			continue;
		snprintf(volname, sizeof(volname), "%s.%s", container,
			 blobmsg_get_string(vt[VOL_NAME]));
		if (run_uvol("remove", volname))
			fprintf(stderr, "uxc: warning: could not remove volume %s\n", volname);
	}
}

static int uxc_delete(char *name, bool force, bool volumes)
{
	struct blob_attr *cur, *tb[__CONF_MAX];
	struct runtime_state *rsstate = NULL;
	struct settings *usettings = NULL;
	static struct blob_buf req;
	uint32_t id;
	int rem, ret = 0;
	const char *cfname = NULL;
	const char *sfname = NULL;
	struct stat sb;
	const char *statevol = NULL;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		if (strcmp(name, blobmsg_get_string(tb[CONF_NAME])))
			continue;

		cfname = blobmsg_name(cur);
		break;
	}

	if (!cfname)
		return -ENOENT;

	rsstate = avl_find_element(&runtime, name, rsstate, avl);

	if (rsstate && rsstate->running) {
		if (force) {
			ret = uxc_kill(name, SIGKILL, true);
			if (ret)
				goto errout;

		} else {
			ret = -EWOULDBLOCK;
			goto errout;
		}
	}

	if (rsstate) {
		ret = ubus_lookup_id(ctx, "container", &id);
		if (ret)
			goto errout;

		blob_buf_init(&req, 0);
		blobmsg_add_string(&req, "name", rsstate->container_name);
		blobmsg_add_string(&req, "instance", rsstate->instance_name);

		if (ubus_invoke(ctx, id, "delete", req.head, NULL, NULL, 3000)) {
			blob_buf_free(&req);
			ret = -EIO;
			goto errout;
		}
	}

	usettings = avl_find_element(&settings, name, usettings, avl);
	if (usettings)
		sfname = usettings->fname;

	if (usettings && usettings->writepath)
		statevol = uvol_volume_name(usettings->writepath);
	else if (tb[CONF_WRITE_OVERLAY_PATH])
		statevol = uvol_volume_name(blobmsg_get_string(tb[CONF_WRITE_OVERLAY_PATH]));
	else if (tb[CONF_OVERLAY_SIZE])
		statevol = name;

	if (sfname) {
		if (stat(sfname, &sb) == -1) {
			ret = -ENOENT;
			goto errout;
		}

		if (unlink(sfname) == -1) {
			ret = -errno;
			goto errout;
		}
	}

	if (stat(cfname, &sb) == -1) {
		ret = -ENOENT;
		goto errout;
	}

	if (unlink(cfname) == -1)
		ret = -errno;

	if (!ret && volumes && statevol) {
		if (run_uvol("remove", statevol))
			fprintf(stderr, "uxc: warning: could not remove state volume %s\n", statevol);
	}

	if (!ret && volumes && tb[CONF_DATA_VOLUMES])
		reap_data_volumes(name, tb[CONF_DATA_VOLUMES]);

errout:
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

int main(int argc, char **argv)
{
	int ret = -EINVAL;
	const char *verb;
	const char *log_path = NULL;
	const char *log_format = NULL;
	const char *criu_path = NULL;
	bool systemd_cgroup = false;
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
					return -EINVAL; \
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
		return usage();
next_global:
		continue;
	}

	if (i >= argc)
		return usage();

	if (log_path) {
		int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (fd < 0) {
			fprintf(stderr, "uxc: cannot open --log path %s: %m\n", log_path);
			return -EIO;
		}
		if (dup2(fd, STDERR_FILENO) < 0) {
			dprintf(fd, "uxc: dup2(--log path) failed: %m\n");
			close(fd);
			return -EIO;
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
		return -ENODEV;

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
		while ((c = getopt_long(verb_argc, verb_argv, "j", list_opts, NULL)) != -1) {
			switch (c) {
			case 'j': json_output = true; break;
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
		ret = uxc_boot(verb_argc == 2 ? verb_argv[1] : NULL);
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
	} else if (!strcmp(verb, "enable")) {
		if (verb_argc != 2)
			goto usage_out;
		ret = uxc_set(verb_argv[1], NULL, 1, NULL, NULL, NULL, NULL);
	} else if (!strcmp(verb, "disable")) {
		if (verb_argc != 2)
			goto usage_out;
		ret = uxc_set(verb_argv[1], NULL, 0, NULL, NULL, NULL, NULL);
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
	ret = usage();
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

	if (ret < 0)
		fprintf(stderr, "uxc error: %s\n", strerror(-ret));

	return ret;
}
