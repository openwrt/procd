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
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libubus.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/ustream.h>

#include "log.h"

#define UXC_VERSION "0.3"
#define OCI_VERSION_STRING "1.0.2"
#define UXC_ETC_CONFDIR "/etc/uxc"
#define UXC_VOL_CONFDIR "/tmp/run/uvol/.meta/uxc"

static bool verbose = false;
static bool json_output = false;
static char *confdir = UXC_ETC_CONFDIR;
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

enum uxc_cmd {
	CMD_ATTACH,
	CMD_LIST,
	CMD_BOOT,
	CMD_START,
	CMD_STATE,
	CMD_KILL,
	CMD_ENABLE,
	CMD_DISABLE,
	CMD_DELETE,
	CMD_CREATE,
	CMD_UNKNOWN
};

#define OPT_ARGS "ab:fjm:p:t:vVw:"
static struct option long_options[] = {
	{"autostart",		no_argument,		0,	'a'	},
	{"console",		no_argument,		0,	'c'	},
	{"bundle",		required_argument,	0,	'b'	},
	{"force",		no_argument,		0,	'f'	},
	{"json",		no_argument,		0,	'j'	},
	{"mounts",		required_argument,	0,	'm'	},
	{"pid-file",		required_argument,	0,	'p'	},
	{"temp-overlay-size",	required_argument,	0,	't'	},
	{"write-overlay-path",	required_argument,	0,	'w'	},
	{"verbose",		no_argument,		0,	'v'	},
	{"version",		no_argument,		0,	'V'	},
	{0,			0,			0,	0	}
};

AVL_TREE(runtime, avl_strcmp, false, NULL);
AVL_TREE(settings, avl_strcmp, false, NULL);
static struct blob_buf conf;
static struct blob_buf settingsbuf;
static struct blob_attr *blockinfo;
static struct blob_attr *fstabinfo;
static struct ubus_context *ctx;

static int usage(void) {
	printf("syntax: uxc <command> [parameters ...]\n");
	printf("commands:\n");
	printf("\tlist [--json]\t\t\t\tlist all configured containers\n");
	printf("\tattach <conf>\t\t\t\tattach to container console\n");
	printf("\tcreate <conf>\t\t\t\t(re-)create <conf>\n");
	printf("\t\t[--bundle <path>]\t\t\tOCI bundle at <path>\n");
	printf("\t\t[--autostart]\t\t\t\tstart on boot\n");
	printf("\t\t[--temp-overlay-size <size>]\t\tuse tmpfs overlay with {size}\n");
	printf("\t\t[--write-overlay-path <path>]\t\tuse overlay on {path}\n");
	printf("\t\t[--mounts <v1>,<v2>,...,<vN>]\t\trequire filesystems to be available\n");
	printf("\tstart [--console] <conf>\t\tstart container <conf>\n");
	printf("\tstate <conf>\t\t\t\tget state of container <conf>\n");
	printf("\tkill <conf> [<signal>]\t\t\tsend signal to container <conf>\n");
	printf("\tenable <conf>\t\t\t\tstart container <conf> on boot\n");
	printf("\tdisable <conf>\t\t\t\tdon't start container <conf> on boot\n");
	printf("\tdelete <conf> [--force]\t\t\tdelete <conf>\n");
	return EINVAL;
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

	if (asprintf(&globstr, "%s/%s*.json", UXC_ETC_CONFDIR, load_settings?"settings/":"") == -1)
		return ENOMEM;

	res = glob(globstr, gl_flags, NULL, &gl);
	if (res == 0)
		gl_flags |= GLOB_APPEND;

	free(globstr);

	if (!stat(UXC_VOL_CONFDIR, &sb)) {
		if (sb.st_mode & S_IFDIR) {
			if (asprintf(&globstr, "%s/%s*.json",  UXC_VOL_CONFDIR, load_settings?"settings/":"") == -1)
				return ENOMEM;

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

	blob_buf_free(&settingsbuf);
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
		return EIO;

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
		return -1;
	}

	/* Get current termios */
	if (tcgetattr(fd, oldtios))
		return -1;

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
	if (tcsetattr(fd, TCSAFLUSH, &newtios))
	        return -1;

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
	int client_fd, server_fd, tty_fd;
	struct termios oldtermios;

	ctx = ubus_connect(NULL);
	if (!ctx) {
		fprintf(stderr, "can't connect to ubus!\n");
		return -1;
	}

	/* open pseudo-terminal pair */
	client_fd = posix_openpt(O_RDWR | O_NOCTTY);
	if (client_fd < 0) {
		fprintf(stderr, "can't create virtual console!\n");
		ubus_free(ctx);
		return -1;
	}
	setup_tios(client_fd, &oldtermios);
	grantpt(client_fd);
	unlockpt(client_fd);
	server_fd = open(ptsname(client_fd), O_RDWR | O_NOCTTY);
	if (server_fd < 0) {
		fprintf(stderr, "can't open virtual console!\n");
		close(client_fd);
		ubus_free(ctx);
		return -1;
	}
	setup_tios(server_fd, &oldtermios);

	tty_fd = open("/dev/tty", O_RDWR);
	if (tty_fd < 0) {
		fprintf(stderr, "can't open local console!\n");
		close(server_fd);
		close(client_fd);
		ubus_free(ctx);
		return -1;
	}
	setup_tios(tty_fd, &oldtermios);

	/* register server-side with procd */
	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", container_name);
	blobmsg_add_string(&req, "instance", container_name);

	if (ubus_lookup_id(ctx, "container", &id) ||
	    ubus_invoke_fd(ctx, id, "console_attach", req.head, NULL, NULL, 3000, server_fd)) {
		fprintf(stderr, "ubus request failed\n");
		close(tty_fd);
		close(server_fd);
		close(client_fd);
		blob_buf_free(&req);
		ubus_free(ctx);
		return -2;
	}

	close(server_fd);
	blob_buf_free(&req);
	ubus_free(ctx);

	uloop_init();

	/* forward between stdio and client_fd until detach is requested */
	lufd.stream.notify_read = local_cb;
	ustream_fd_init(&lufd, tty_fd);

	cufd.stream.notify_read = client_cb;
/* ToDo: handle remote close and other events */
//	cufd.stream.notify_state = client_state_cb;
	ustream_fd_init(&cufd, client_fd);

	fprintf(stderr, "attaching to jail console. press [CTRL]+[B] to exit.\n");
	close(0);
	close(1);
	close(2);
	uloop_run();

	tcsetattr(tty_fd, TCSAFLUSH, &oldtermios);
	ustream_free(&lufd.stream);
	ustream_free(&cufd.stream);
	close(client_fd);

	return 0;
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
			return 1;

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
		return ENOENT;

	blob_buf_init(&buf, 0);
	blobmsg_add_string(&buf, "ociVersion", OCI_VERSION_STRING);
	blobmsg_add_string(&buf, "id", jail_name);
	blobmsg_add_string(&buf, "status", rsstate?"stopped":"uninitialized");
	blobmsg_add_string(&buf, "bundle", bundle);

	tmp = blobmsg_format_json_indent(buf.head, true, 0);
	if (!tmp) {
		blob_buf_free(&buf);
		return ENOMEM;
	}

	printf("%s\n", tmp);
	free(tmp);

	blob_buf_free(&buf);

	return 0;
}

static int uxc_list(void)
{
	struct blob_attr *cur, *tb[__CONF_MAX], *ts[__STATE_MAX];
	int rem;
	struct runtime_state *rsstate = NULL;
	struct settings *usettings = NULL;
	char *name, *ocistatus, *status, *tmp;
	int container_pid = -1;
	bool autostart;
	static struct blob_buf buf;
	void *arr, *obj;

	if (json_output) {
		blob_buf_init(&buf, 0);
		arr = blobmsg_open_array(&buf, "");
	}

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		autostart = tb[CONF_AUTOSTART] && blobmsg_get_bool(tb[CONF_AUTOSTART]);

		ocistatus = NULL;
		container_pid = 0;
		name = blobmsg_get_string(tb[CONF_NAME]);
		rsstate = avl_find_element(&runtime, name, rsstate, avl);

		if (rsstate && rsstate->ocistate) {
			blobmsg_parse(state_policy, __STATE_MAX, ts, blobmsg_data(rsstate->ocistate), blobmsg_len(rsstate->ocistate));
			ocistatus = blobmsg_get_string(ts[STATE_STATUS]);
			container_pid = blobmsg_get_u32(ts[STATE_PID]);
		}

		status = ocistatus?:(rsstate && rsstate->running)?"creating":"stopped";

		usettings = avl_find_element(&settings, name, usettings, avl);

		if (usettings && (usettings->autostart >= 0))
			autostart = !!(usettings->autostart);

		if (json_output) {
			obj = blobmsg_open_table(&buf, "");
			blobmsg_add_string(&buf, "name", name);
			blobmsg_add_string(&buf, "status", status);
			blobmsg_add_u8(&buf, "autostart", autostart);
		} else {
			printf("[%c] %s %s", autostart?'*':' ', name, status);
		}

		if (rsstate && !rsstate->running && (rsstate->exitcode >= 0)) {
			if (json_output)
				blobmsg_add_u32(&buf, "exitcode", rsstate->exitcode);
			else
				printf(" exitcode: %d (%s)", rsstate->exitcode, strerror(rsstate->exitcode));
		}

		if (rsstate && rsstate->running && (rsstate->runtime_pid >= 0)) {
			if (json_output)
				blobmsg_add_u32(&buf, "runtime_pid", rsstate->runtime_pid);
			else
				printf(" runtime pid: %d", rsstate->runtime_pid);
		}

		if (rsstate && rsstate->running && (container_pid >= 0)) {
			if (json_output)
				blobmsg_add_u32(&buf, "container_pid", container_pid);
			else
				printf(" container pid: %d", container_pid);
		}

		if (!json_output)
			printf("\n");
		else
			blobmsg_close_table(&buf, obj);
	}

	if (json_output) {
		blobmsg_close_array(&buf, arr);
		tmp = blobmsg_format_json_indent(buf.head, true, 0);
		if (!tmp) {
			blob_buf_free(&buf);
			return ENOMEM;
		}
		printf("%s\n", tmp);
		free(tmp);
		blob_buf_free(&buf);
	};

	return 0;
}

static int uxc_exists(char *name)
{
	struct runtime_state *rsstate = NULL;
	rsstate = avl_find_element(&runtime, name, rsstate, avl);

	if (rsstate && (rsstate->running))
		return EEXIST;

	return 0;
}

static int uxc_create(char *name, bool immediately)
{
	static struct blob_buf req;
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem, ret;
	uint32_t id;
	struct settings *usettings = NULL;
	char *path = NULL, *jailname = NULL, *pidfile = NULL, *tmprwsize = NULL, *writepath = NULL;

	void *in, *ins, *j;
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
		return ENOENT;

	path = blobmsg_get_string(tb[CONF_PATH]);

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
	j = blobmsg_open_table(&req, "jail");
	blobmsg_add_string(&req, "name", jailname?:name);
	blobmsg_add_u8(&req, "immediately", immediately);

	if (pidfile)
		blobmsg_add_string(&req, "pidfile", pidfile);

	blobmsg_close_table(&req, j);

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
			return ENOMEM;

		fprintf(stderr, "adding container to procd:\n\t%s\n", tmp);
		free(tmp);
	}

	ret = 0;
	if (ubus_lookup_id(ctx, "container", &id) ||
		ubus_invoke(ctx, id, "add", req.head, NULL, NULL, 3000)) {
		blob_buf_free(&req);
		ret = EIO;
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
		return ENOMEM;

	if (ubus_lookup_id(ctx, objname, &id))
		return ENOENT;

	free(objname);
	return ubus_invoke(ctx, id, "start", NULL, NULL, NULL, 3000);
}

static int uxc_kill(char *name, int signal)
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
		return ENOENT;

	rsstate = avl_find_element(&runtime, name, rsstate, avl);

	if (!rsstate || !(rsstate->running))
		return ENOENT;

	blob_buf_init(&req, 0);
	blobmsg_add_u32(&req, "signal", signal);
	blobmsg_add_string(&req, "name", name);

	if (asprintf(&objname, "container.%s", name) == -1)
		return ENOMEM;

	ret = ubus_lookup_id(ctx, objname, &id);
	free(objname);
	if (ret)
		return ENOENT;

	if (ubus_invoke(ctx, id, "kill", req.head, NULL, NULL, 3000))
		return EIO;

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
		return EEXIST;

	if (!cfname && !path)
		return ENOENT;

	if (path) {
		if (stat(path, &sb) == -1)
			return ENOENT;

		if ((sb.st_mode & S_IFMT) != S_IFDIR)
			return ENOTDIR;
	}

	usettings = avl_find_element(&settings, blobmsg_get_string(tb[CONF_NAME]), usettings, avl);
	if (path && usettings)
		return EIO;

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
			return ret;

		if (asprintf(&fname, "%s/%s.json", confdir, name) == -1)
			return ENOMEM;

		f = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (f < 0)
			return errno;

		free(fname);
	} else {
		if (sfname) {
			f = open(sfname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		} else {
			char *t1, *t2;
			t1 = strdup(cfname);
			t2 = strrchr(t1, '/');
			*t2 = '\0';

			if (asprintf(&t2, "%s/settings", t1, name) == -1)
				return ENOMEM;

			ret = mkdir(t2, 0755);
			if (ret && ret != EEXIST)
				return ret;

			free(t2);
			if (asprintf(&t2, "%s/settings/%s.json", t1, name) == -1)
				return ENOMEM;

			free(t1);
			f = open(t2, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			free(t2);
		}
		if (f < 0)
			return errno;
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

	return 0;
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
static int checkblock(const char *uuid)
{
	struct blob_attr *tb[__BLOCK_INFO_MAX];
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, blockinfo, rem) {
		blobmsg_parse(block_info_policy, __BLOCK_INFO_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[BLOCK_INFO_UUID] || !tb[BLOCK_INFO_MOUNT])
			continue;

		if (!strcmp(uuid, blobmsg_get_string(tb[BLOCK_INFO_UUID])))
			return 0;
	}

	return 1;
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
static int checkvolumes(struct blob_attr *volumes)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, volumes, rem) {
		if (checkblock(resolveuuid(blobmsg_get_string(cur))))
			return 1;
	}

	return 0;
}

static void block_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	blockinfo = blob_memdup(blobmsg_data(msg));
}

static void fstab_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	fstabinfo = blob_memdup(blobmsg_data(msg));
}

static int uxc_boot(void)
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
		return ENOENT;

	ret = ubus_invoke(ctx, id, "info", NULL, block_cb, NULL, 3000);
	if (ret)
		return ENXIO;

	ret = ubus_lookup_id(ctx, "uci", &id);
	if (ret)
		return ENOENT;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "config", "fstab");
	blobmsg_add_string(&req, "type", "mount");

	ret = ubus_invoke(ctx, id, "get", req.head, fstab_cb, NULL, 3000);
	if (ret)
		return ENXIO;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
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

		name = strdup(blobmsg_get_string(tb[CONF_NAME]));
		if (uxc_exists(name))
			continue;

		ret += uxc_create(name, true);
		free(name);
	}

	return ret;
}

static int uxc_delete(char *name, bool force)
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
		return ENOENT;

	rsstate = avl_find_element(&runtime, name, rsstate, avl);

	if (rsstate && rsstate->running) {
		if (force) {
			ret = uxc_kill(name, SIGKILL);
			if (ret)
				goto errout;

		} else {
			ret = EWOULDBLOCK;
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
			ret = EIO;
			goto errout;
		}
	}

	usettings = avl_find_element(&settings, name, usettings, avl);
	if (usettings)
		sfname = usettings->fname;

	if (sfname) {
		if (stat(sfname, &sb) == -1) {
			ret = ENOENT;
			goto errout;
		}

		if (unlink(sfname) == -1) {
			ret = errno;
			goto errout;
		}
	}

	if (stat(cfname, &sb) == -1) {
		ret = ENOENT;
		goto errout;
	}

	if (unlink(cfname) == -1)
		ret = errno;

errout:
	return ret;
}

static void reload_conf(void)
{
	blob_buf_free(&conf);
	conf_load(false);
	settings_free();
	conf_load(true);
	settings_add();
}

int main(int argc, char **argv)
{
	enum uxc_cmd cmd = CMD_UNKNOWN;
	int ret = EINVAL;
	char *bundle = NULL;
	char *pidfile = NULL;
	char *tmprwsize = NULL;
	char *writepath = NULL;
	char *requiredmounts = NULL;
	signed char autostart = -1;
	bool force = false;
	bool console = false;
	int signal = SIGTERM;
	int c;

	if (argc < 2)
		return usage();

	ctx = ubus_connect(NULL);
	if (!ctx)
		return ENODEV;

	ret = conf_load(false);
	if (ret)
		goto out;

	conf_load(true);
	settings_add();

	ret = runtime_load();
	if (ret)
		goto conf_out;

	while (true) {
		int option_index = 0;
		c = getopt_long(argc, argv, OPT_ARGS, long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				autostart = 1;
				break;

			case 'b':
				bundle = optarg;
				break;

			case 'c':
				console = true;
				break;

			case 'f':
				force = true;
				break;

			case 'j':
				json_output = true;
				break;

			case 'p':
				pidfile = optarg;
				break;

			case 't':
				tmprwsize = optarg;
				break;

			case 'v':
				verbose = true;
				break;

			case 'V':
				printf("uxc %s\n", UXC_VERSION);
				exit(0);

			case 'w':
				writepath = optarg;
				break;

			case 'm':
				requiredmounts = optarg;
				break;
		}
	}

	if (optind == argc)
		goto usage_out;

	if (!strcmp("list", argv[optind]))
		cmd = CMD_LIST;
	else if (!strcmp("attach", argv[optind]))
		cmd = CMD_ATTACH;
	else if (!strcmp("boot", argv[optind]))
		cmd = CMD_BOOT;
	else if(!strcmp("start", argv[optind]))
		cmd = CMD_START;
	else if(!strcmp("state", argv[optind]))
		cmd = CMD_STATE;
	else if(!strcmp("kill", argv[optind]))
		cmd = CMD_KILL;
	else if(!strcmp("enable", argv[optind]))
		cmd = CMD_ENABLE;
	else if(!strcmp("disable", argv[optind]))
		cmd = CMD_DISABLE;
	else if(!strcmp("delete", argv[optind]))
		cmd = CMD_DELETE;
	else if(!strcmp("create", argv[optind]))
		cmd = CMD_CREATE;

	switch (cmd) {
		case CMD_ATTACH:
			if (optind != argc - 2)
				goto usage_out;

			ret = uxc_attach(argv[optind + 1]);
			break;

		case CMD_LIST:
			ret = uxc_list();
			break;

		case CMD_BOOT:
			ret = uxc_boot();
			break;

		case CMD_START:
			if (optind != argc - 2)
				goto usage_out;

			ret = uxc_start(argv[optind + 1], console);
			break;

		case CMD_STATE:
			if (optind != argc - 2)
				goto usage_out;

			ret = uxc_state(argv[optind + 1]);
			break;

		case CMD_KILL:
			if (optind == (argc - 3))
				signal = atoi(argv[optind + 2]);
			else if (optind > argc - 2)
				goto usage_out;

			ret = uxc_kill(argv[optind + 1], signal);
			break;

		case CMD_ENABLE:
			if (optind != argc - 2)
				goto usage_out;

			ret = uxc_set(argv[optind + 1], NULL, 1, NULL, NULL, NULL, NULL);
			break;

		case CMD_DISABLE:
			if (optind != argc - 2)
				goto usage_out;

			ret = uxc_set(argv[optind + 1], NULL, 0, NULL, NULL, NULL, NULL);
			break;

		case CMD_DELETE:
			if (optind != argc - 2)
				goto usage_out;

			ret = uxc_delete(argv[optind + 1], force);
			break;

		case CMD_CREATE:
			if (optind != argc - 2)
				goto usage_out;

			ret = uxc_exists(argv[optind + 1]);
			if (ret)
				goto runtime_out;

			ret = uxc_set(argv[optind + 1], bundle, autostart, pidfile, tmprwsize, writepath, requiredmounts);
			if (ret)
				goto runtime_out;

			reload_conf();

			ret = uxc_create(argv[optind + 1], false);
			break;

		default:
			goto usage_out;
	}

	goto runtime_out;

usage_out:
	usage();
runtime_out:
	runtime_free();
conf_out:
	blob_buf_free(&conf);
out:
	ubus_free(ctx);

	if (ret != 0)
		fprintf(stderr, "uxc error: %s\n", strerror(ret));

	return ret;
}
