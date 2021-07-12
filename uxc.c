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

#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <libubus.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <glob.h>
#include <signal.h>

#include "log.h"

#define UXC_VERSION "0.2"
#define OCI_VERSION_STRING "1.0.2"
#define UXC_CONFDIR "/etc/uxc"

static bool verbose = false;

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

enum uxc_cmd {
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

#define OPT_ARGS "ab:fp:t:vVw:"
static struct option long_options[] = {
	{"autostart",		no_argument,		0,	'a'	},
	{"bundle",		required_argument,	0,	'b'	},
	{"force",		no_argument,		0,	'f'	},
	{"pid-file",		required_argument,	0,	'p'	},
	{"temp-overlay-size",	required_argument,	0,	't'	},
	{"write-overlay-path",	required_argument,	0,	'w'	},
	{"verbose",		no_argument,		0,	'v'	},
	{"version",		no_argument,		0,	'V'	},
	{0,			0,			0,	0	}
};

AVL_TREE(runtime, avl_strcmp, false, NULL);
static struct blob_buf conf;
static struct ubus_context *ctx;

static int usage(void) {
	printf("syntax: uxc <command> [parameters ...]\n");
	printf("commands:\n");
	printf("\tlist\t\t\t\t\t\tlist all configured containers\n");
	printf("\tcreate <conf> [--bundle <path>] [--autostart]\tcreate <conf> for OCI bundle at <path>\n");
	printf("\tstart <conf>\t\t\t\t\tstart container <conf>\n");
	printf("\tstate <conf>\t\t\t\t\tget state of container <conf>\n");
	printf("\tkill <conf> [<signal>]\t\t\t\tsend signal to container <conf>\n");
	printf("\tenable <conf>\t\t\t\t\tstart container <conf> on boot\n");
	printf("\tdisable <conf>\t\t\t\t\tdon't start container <conf> on boot\n");
	printf("\tdelete <conf> [--force]\t\t\t\tdelete <conf>\n");
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
};

static int conf_load(void)
{
	int gl_flags = GLOB_NOESCAPE | GLOB_MARK;
	int j, res;
	glob_t gl;
	char *globstr;
	void *c, *o;

	if (asprintf(&globstr, "%s/*.json", UXC_CONFDIR) == -1)
		return ENOMEM;

	blob_buf_init(&conf, 0);
	c = blobmsg_open_table(&conf, NULL);

	res = glob(globstr, gl_flags, NULL, &gl);
	free(globstr);
	if (res < 0)
		return 0;

	for (j = 0; j < gl.gl_pathc; j++) {
		o = blobmsg_open_table(&conf, strdup(gl.gl_pathv[j]));
		if (!blobmsg_add_json_from_file(&conf, gl.gl_pathv[j])) {
			ERROR("uxc: failed to load %s\n", gl.gl_pathv[j]);
			continue;
		}
		blobmsg_close_table(&conf, o);
	}
	blobmsg_close_table(&conf, c);
	globfree(&gl);

	return 0;
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

	asprintf(&objname, "container.%s", name);
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

static int uxc_state(char *name)
{
	struct runtime_state *s = avl_find_element(&runtime, name, s, avl);
	struct blob_attr *ocistate = NULL;
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem;
	char *bundle = NULL;
	char *jail_name = NULL;
	static struct blob_buf buf;

	if (s)
		ocistate = s->ocistate;

	if (ocistate) {
		printf("%s\n", blobmsg_format_json_indent(ocistate, true, 0));
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
	blobmsg_add_string(&buf, "status", s?"stopped":"uninitialized");
	blobmsg_add_string(&buf, "bundle", bundle);

	printf("%s\n", blobmsg_format_json_indent(buf.head, true, 0));
	blob_buf_free(&buf);

	return 0;
}

static int uxc_list(void)
{
	struct blob_attr *cur, *tb[__CONF_MAX], *ts[__STATE_MAX];
	int rem;
	struct runtime_state *s = NULL;
	char *name;
	char *ocistatus;
	int container_pid = -1;
	bool autostart;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		autostart = tb[CONF_AUTOSTART] && blobmsg_get_bool(tb[CONF_AUTOSTART]);
		ocistatus = NULL;
		container_pid = 0;
		name = blobmsg_get_string(tb[CONF_NAME]);
		s = avl_find_element(&runtime, name, s, avl);

		if (s && s->ocistate) {
			blobmsg_parse(state_policy, __STATE_MAX, ts, blobmsg_data(s->ocistate), blobmsg_len(s->ocistate));
			ocistatus = blobmsg_get_string(ts[STATE_STATUS]);
			container_pid = blobmsg_get_u32(ts[STATE_PID]);
		}

		printf("[%c] %s %s", autostart?'*':' ', name, ocistatus?:(s && s->running)?"creating":"stopped");

		if (s && !s->running && (s->exitcode >= 0))
			printf(" exitcode: %d (%s)", s->exitcode, strerror(s->exitcode));

		if (s && s->running && (s->runtime_pid >= 0))
			printf(" runtime pid: %d", s->runtime_pid);

		if (s && s->running && (container_pid >= 0))
			printf(" container pid: %d", container_pid);

		printf("\n");
	}

	return 0;
}

static int uxc_create(char *name, bool immediately)
{
	static struct blob_buf req;
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem, ret;
	uint32_t id;
	struct runtime_state *s = NULL;
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
		path = strdup(blobmsg_get_string(tb[CONF_PATH]));

		if (tb[CONF_PIDFILE])
			pidfile = strdup(blobmsg_get_string(tb[CONF_PIDFILE]));

		if (tb[CONF_TEMP_OVERLAY_SIZE])
			tmprwsize = strdup(blobmsg_get_string(tb[CONF_TEMP_OVERLAY_SIZE]));

		if (tb[CONF_WRITE_OVERLAY_PATH])
			writepath = strdup(blobmsg_get_string(tb[CONF_WRITE_OVERLAY_PATH]));

		break;
	}

	if (!found)
		return ENOENT;

	s = avl_find_element(&runtime, name, s, avl);

	if (s && (s->running))
		return EEXIST;

	if (tb[CONF_JAIL])
		jailname = strdup(blobmsg_get_string(tb[CONF_JAIL]));

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

	if (verbose)
		fprintf(stderr, "adding container to procd:\n\t%s\n",
			blobmsg_format_json_indent(req.head, true, 1));

	ret = 0;
	if (ubus_lookup_id(ctx, "container", &id) ||
		ubus_invoke(ctx, id, "add", req.head, NULL, NULL, 3000)) {
		ret = EIO;
	}

	free(jailname);
	free(path);
	blob_buf_free(&req);

	return ret;
}

static int uxc_start(const char *name)
{
	char *objname;
	unsigned int id;

	asprintf(&objname, "container.%s", name);
	if (ubus_lookup_id(ctx, objname, &id))
		return ENOENT;

	return ubus_invoke(ctx, id, "start", NULL, NULL, NULL, 3000);
}

static int uxc_kill(char *name, int signal)
{
	static struct blob_buf req;
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem, ret;
	char *objname;
	unsigned int id;
	struct runtime_state *s = NULL;
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

	s = avl_find_element(&runtime, name, s, avl);

	if (!s || !(s->running))
		return ENOENT;

	blob_buf_init(&req, 0);
	blobmsg_add_u32(&req, "signal", signal);
	blobmsg_add_string(&req, "name", name);

	asprintf(&objname, "container.%s", name);
	ret = ubus_lookup_id(ctx, objname, &id);
	free(objname);
	if (ret)
		return ENOENT;

	if (ubus_invoke(ctx, id, "kill", req.head, NULL, NULL, 3000))
		return EIO;

	return 0;
}


static int uxc_set(char *name, char *path, bool autostart, bool add, char *pidfile, char *_tmprwsize, char *_writepath)
{
	static struct blob_buf req;
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem, ret;
	bool found = false;
	char *fname = NULL;
	char *keeppath = NULL;
	char *tmprwsize = _tmprwsize;
	char *writepath = _writepath;

	int f;
	struct stat sb;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		if (strcmp(name, blobmsg_get_string(tb[CONF_NAME])))
			continue;

		found = true;
		break;
	}

	if (found && add)
		return EEXIST;

	if (!found && !add)
		return ENOENT;

	if (add && !path)
		return EINVAL;

	if (path) {
		if (stat(path, &sb) == -1)
			return ENOENT;

		if ((sb.st_mode & S_IFMT) != S_IFDIR)
			return ENOTDIR;
	}

	ret = mkdir(UXC_CONFDIR, 0755);

	if (ret && errno != EEXIST)
		return ret;

	if (asprintf(&fname, "%s/%s.json", UXC_CONFDIR, name) < 1)
		return ENOMEM;

	f = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (f < 0)
		return errno;

	if (!add) {
		keeppath = strdup(blobmsg_get_string(tb[CONF_PATH]));
		if (tb[CONF_WRITE_OVERLAY_PATH])
			writepath = strdup(blobmsg_get_string(tb[CONF_WRITE_OVERLAY_PATH]));

		if (tb[CONF_TEMP_OVERLAY_SIZE])
			tmprwsize = strdup(blobmsg_get_string(tb[CONF_TEMP_OVERLAY_SIZE]));
	}

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", name);
	blobmsg_add_string(&req, "path", path?:keeppath);
	blobmsg_add_u8(&req, "autostart", autostart);
	if (pidfile)
		blobmsg_add_string(&req, "pidfile", pidfile);

	if (tmprwsize)
		blobmsg_add_string(&req, "temp-overlay-size", tmprwsize);

	if (writepath)
		blobmsg_add_string(&req, "write-overlay-path", writepath);

	dprintf(f, "%s\n", blobmsg_format_json_indent(req.head, true, 0));

	if (!add)
		free(keeppath);

	blob_buf_free(&req);

	return 0;
}

static int uxc_boot(void)
{
	struct blob_attr *cur, *tb[__CONF_MAX];
	int rem, ret = 0;
	char *name;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH] || !tb[CONF_AUTOSTART] || !blobmsg_get_bool(tb[CONF_AUTOSTART]))
			continue;

		name = strdup(blobmsg_get_string(tb[CONF_NAME]));
		ret += uxc_create(name, true);
		free(name);
	}

	return ret;
}

static int uxc_delete(char *name, bool force)
{
	struct blob_attr *cur, *tb[__CONF_MAX];
	struct runtime_state *s = NULL;
	static struct blob_buf req;
	uint32_t id;
	int rem, ret = 0;
	bool found = false;
	char *fname;
	struct stat sb;

	blobmsg_for_each_attr(cur, blob_data(conf.head), rem) {
		blobmsg_parse(conf_policy, __CONF_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		if (!tb[CONF_NAME] || !tb[CONF_PATH])
			continue;

		if (strcmp(name, blobmsg_get_string(tb[CONF_NAME])))
			continue;

		fname = strdup(blobmsg_name(cur));
		if (!fname)
			return errno;

		found = true;
		break;
	}

	if (!found)
		return ENOENT;

	s = avl_find_element(&runtime, name, s, avl);

	if (s && s->running) {
		if (force) {
			ret = uxc_kill(name, SIGKILL);
			if (ret)
				goto errout;

		} else {
			ret = EWOULDBLOCK;
			goto errout;
		}
	}

	if (s) {
		ret = ubus_lookup_id(ctx, "container", &id);
		if (ret)
			goto errout;

		blob_buf_init(&req, 0);
		blobmsg_add_string(&req, "name", s->container_name);
		blobmsg_add_string(&req, "instance", s->instance_name);

		if (ubus_invoke(ctx, id, "delete", req.head, NULL, NULL, 3000)) {
			blob_buf_free(&req);
			ret=EIO;
			goto errout;
		}
	}

	if (stat(fname, &sb) == -1) {
		ret=ENOENT;
		goto errout;
	}

	if (unlink(fname) == -1)
		ret=errno;

errout:
	free(fname);
	return ret;
}

static void reload_conf(void)
{
	blob_buf_free(&conf);
	conf_load();
}

int main(int argc, char **argv)
{
	enum uxc_cmd cmd = CMD_UNKNOWN;
	int ret = EINVAL;
	char *bundle = NULL;
	char *pidfile = NULL;
	char *tmprwsize = NULL;
	char *writepath = NULL;
	bool autostart = false;
	bool force = false;
	int signal = SIGTERM;
	int c;

	if (argc < 2)
		return usage();

	ctx = ubus_connect(NULL);
	if (!ctx)
		return ENODEV;

	ret = conf_load();
	if (ret)
		goto out;

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
				autostart = true;
				break;

			case 'b':
				bundle = optarg;
				break;

			case 'f':
				force = true;
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
		}
	}

	if (optind == argc)
		goto usage_out;

	if (!strcmp("list", argv[optind]))
		cmd = CMD_LIST;
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
		case CMD_LIST:
			ret = uxc_list();
			break;

		case CMD_BOOT:
			ret = uxc_boot();
			break;

		case CMD_START:
			if (optind != argc - 2)
				goto usage_out;

			ret = uxc_start(argv[optind + 1]);
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

			ret = uxc_set(argv[optind + 1], NULL, true, false, NULL, NULL, NULL);
			break;

		case CMD_DISABLE:
			if (optind != argc - 2)
				goto usage_out;

			ret = uxc_set(argv[optind + 1], NULL, false, false, NULL, NULL, NULL);
			break;

		case CMD_DELETE:
			if (optind != argc - 2)
				goto usage_out;

			ret = uxc_delete(argv[optind + 1], force);
			break;

		case CMD_CREATE:
			if (optind != argc - 2)
				goto usage_out;

			if (bundle) {
				ret = uxc_set(argv[optind + 1], bundle, autostart, true, pidfile, tmprwsize, writepath);
				if (ret)
					goto runtime_out;

				reload_conf();
			}

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
