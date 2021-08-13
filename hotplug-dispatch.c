/*
 * Copyright (C) 2021 Daniel Golle <daniel@makrotopia.org>
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

#include <sys/inotify.h>
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubus.h>

#include "procd.h"

#define HOTPLUG_BASEDIR "/etc/hotplug.d"
#define HOTPLUG_OBJECT_PREFIX "hotplug."

#define INOTIFY_SZ (sizeof(struct inotify_event) + PATH_MAX + 1)

struct ubus_context *ctx;
static char *inotify_buffer;
static struct uloop_fd fd_inotify_read;

static LIST_HEAD(subsystems);

extern char **environ;

struct hotplug_subsys {
	struct list_head list;
	struct ubus_object ubus;
};

struct envlist {
	struct avl_node avl;
	char *env;
};

struct hotplug_process {
	struct ubus_object *ubus;
	char **envp;
	struct uloop_timeout timeout;
	struct uloop_process process;
	glob_t globbuf;
	unsigned int cnt;
	int ret;
};

static void env_free(char **envp)
{
	char **tmp;

	tmp = envp;
	while (*tmp)
		free(*(tmp++));
	free(envp);
}

static void hotplug_free(struct hotplug_process *pc)
{
	env_free(pc->envp);
	globfree(&pc->globbuf);
	free(pc);
}

static void hotplug_done(struct uloop_process *c, int ret)
{
	struct hotplug_process *pc = container_of(c, struct hotplug_process, process);

	pc->ret = ret;

	uloop_timeout_set(&pc->timeout, 50);
}

static void hotplug_exec(struct uloop_timeout *t)
{
	struct hotplug_process *pc = container_of(t, struct hotplug_process, timeout);
	char *script;
	char *exec_argv[4];
	/* we have reached the last entry in the globbuf */
	if (pc->cnt == pc->globbuf.gl_pathc) {
		hotplug_free(pc);
		return;
	}

	if (asprintf(&script, ". /lib/functions.sh\n. %s\n", pc->globbuf.gl_pathv[pc->cnt++]) == -1) {
		pc->ret = ENOMEM;
		return;
	}

	/* prepare for execve() */
	exec_argv[0] = "/bin/sh";
	exec_argv[1] = "-c";
	exec_argv[2] = script;
	exec_argv[3] = NULL;

	/* set callback in uloop_process */
	pc->process.cb = hotplug_done;
	pc->process.pid = fork();
	if (pc->process.pid == 0) {
		/* child */
		exit(execve(exec_argv[0], exec_argv, pc->envp));
	} else if (pc->process.pid < 0) {
		/* fork error */
		free(script);
		hotplug_free(pc);
		return;
	}
	/* parent */
	free(script);
	uloop_process_add(&pc->process);
}

static int avl_envcmp(const void *k1, const void *k2, void *ptr)
{
	const char *tmp;

	tmp = strchr(k1, '=');
	if (!tmp)
		return -1;

	/*
	 * compare the variable name only, ie. limit strncmp to check
	 * only up to and including the '=' sign
	 */
	return strncmp(k1, k2, (tmp - (char *)k1) + 1);
}

/* validate NULL-terminated environment variable name */
static int validate_envvarname(const char *envvarname)
{
	const char *tmp = envvarname;

	/* check for illegal characters in env variable name */
	while (tmp[0] != '\0') {
		if (!((tmp[0] >= 'a' && tmp[0] <= 'z') ||
		      (tmp[0] >= 'A' && tmp[0] <= 'Z') ||
		      (tmp[0] == '_') ||
		      /* allow numbers unless they are at the first character */
		      ((tmp != envvarname) && tmp[0] >= '0' && tmp[0] <= '9')))
			return EINVAL;
		++tmp;
	}

	return 0;
}

enum {
	HOTPLUG_ENV,
	__HOTPLUG_MAX
};

static const struct blobmsg_policy hotplug_policy[__HOTPLUG_MAX] = {
	[HOTPLUG_ENV] = { .name = "env", .type = BLOBMSG_TYPE_ARRAY },
};

static int hotplug_call(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	const char *subsys = &obj->name[strlen(HOTPLUG_OBJECT_PREFIX)];
	struct blob_attr *tb[__HOTPLUG_MAX], *cur;
	AVL_TREE(env, avl_envcmp, false, NULL);
	struct envlist *envle, *p;
	int rem;
	char **envp, *globstr, *tmp, **tmpenv;
	size_t envz = 0;
	struct hotplug_process *pc;
	bool async = true;
	int err = UBUS_STATUS_UNKNOWN_ERROR;

	blobmsg_parse(hotplug_policy, __HOTPLUG_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[HOTPLUG_ENV])
		return UBUS_STATUS_INVALID_ARGUMENT;

	tmpenv = environ;

	/* first adding existing environment to avl_tree */
	while (*tmpenv) {
		envle = calloc(1, sizeof(struct envlist));
		if (!envle)
			goto err_envle;

		envle->env = strdup(*tmpenv);
		if (!envle->env) {
			free(envle);
			goto err_envle;
		}
		envle->avl.key = envle->env;
		if (avl_insert(&env, &envle->avl) == -1) {
			free(envle->env);
			free(envle);
			goto err_envle;
		}

		++tmpenv;
	}

	/* then adding additional variables from ubus call */
	blobmsg_for_each_attr(cur, tb[HOTPLUG_ENV], rem) {
		char *enve = blobmsg_get_string(cur);
		if (!enve)
			continue;

		if (!strncmp(enve, "LD_", 3))
			continue;

		if (!strcmp(enve, "PATH"))
			continue;

		if (strlen(enve) < 3)
			continue;

		if (!(tmp = strchr(enve, '=')))
			continue;

		*tmp = '\0';
		if (validate_envvarname(enve))
			continue;
		*tmp = '=';

		if (!strlen(++tmp))
			continue;

		if (!strcmp(enve, "ASYNC=0"))
			async = false;

		envle = calloc(1, sizeof(struct envlist));
		if (!envle)
			goto err_envle;

		envle->env = strdup(enve);
		if (!envle->env) {
			free(envle);
			goto err_envle;
		}
		envle->avl.key = envle->env;
		if (avl_insert(&env, &envle->avl)) {
			/* do not override existing env values, just skip */
			free((void*)envle->env);
			free(envle);
		}
	}

	/* synchronous calls are unsupported for now */
	if (!async) {
		err = UBUS_STATUS_NOT_SUPPORTED;
		goto err_envle;
	}

	/* allocating new environment */
	avl_for_each_element(&env, envle, avl)
		++envz;

	envp = calloc(envz + 1, sizeof(char *));
	if (!envp)
		goto err_envle;

	/* populating new environment */
	envz = 0;
	avl_for_each_element_safe(&env, envle, avl, p) {
		envp[envz++] = envle->env;
		avl_delete(&env, &envle->avl);
		free(envle);
	}

	pc = calloc(1, sizeof(struct hotplug_process));
	if (!pc) {
		env_free(envp);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}
	pc->timeout.cb = hotplug_exec;
	pc->envp = envp;
	pc->cnt = 0;
	pc->ubus = obj;

	/* glob'ing for hotplug scripts */
	if (asprintf(&globstr, "%s/%s/*", HOTPLUG_BASEDIR, subsys) == -1) {
		hotplug_free(pc);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (glob(globstr, GLOB_DOOFFS, NULL, &pc->globbuf)) {
		free(globstr);
		hotplug_free(pc);
		return UBUS_STATUS_OK;
	}

	free(globstr);

	/* asynchronous call to hotplug_exec() */
	uloop_timeout_set(&pc->timeout, 50);

	return UBUS_STATUS_OK;

err_envle:
	avl_for_each_element_safe(&env, envle, avl, p) {
		if (envle->env)
			free(envle->env);

		avl_delete(&env, &envle->avl);
		free(envle);
	}

	return err;
}

static const struct ubus_method hotplug_methods[] = {
	UBUS_METHOD("call", hotplug_call, hotplug_policy),
};

static struct ubus_object_type hotplug_object_type =
	UBUS_OBJECT_TYPE("hotplug", hotplug_methods);

static void add_subsystem(int nlen, char *newname)
{
	struct hotplug_subsys *nh = calloc(1, sizeof(struct hotplug_subsys));
	char *name;

	if (asprintf(&name, "%s%.*s", HOTPLUG_OBJECT_PREFIX, nlen, newname) == -1)
		exit(ENOMEM);

	/* prepare and add ubus object */
	nh->ubus.name = name;
	nh->ubus.type = &hotplug_object_type;
	nh->ubus.methods = hotplug_object_type.methods;
	nh->ubus.n_methods = hotplug_object_type.n_methods;
	list_add(&nh->list, &subsystems);
	ubus_add_object(ctx, &nh->ubus);
}

static void remove_subsystem(int nlen, char *name)
{
	struct hotplug_subsys *n, *h;

	/* find match subsystem object by name or any if not given */
	list_for_each_entry_safe(h, n, &subsystems, list) {
		if (nlen && (strlen(h->ubus.name) != strnlen(name, nlen) + strlen(HOTPLUG_OBJECT_PREFIX)))
			continue;
		if (nlen && (strncmp(name, &h->ubus.name[strlen(HOTPLUG_OBJECT_PREFIX)], nlen)))
			continue;

		list_del(&h->list);
		ubus_remove_object(ctx, &h->ubus);
		free((void*)h->ubus.name);
		free(h);
	}
}

static int init_subsystems(void)
{
	DIR *dir;
	struct dirent *dirent;

	dir = opendir(HOTPLUG_BASEDIR);
	if (dir == NULL)
		return ENOENT;

	while ((dirent = readdir(dir))) {
		/* skip everything but directories */
		if (dirent->d_type != DT_DIR)
			continue;

		/* skip '.' and '..' as well as hidden files */
		if (dirent->d_name[0] == '.')
			continue;

		add_subsystem(strlen(dirent->d_name), dirent->d_name);
	}
	closedir(dir);

	return 0;
}

static void inotify_read_handler(struct uloop_fd *u, unsigned int events)
{
	int rc;
	char *p;
	struct inotify_event *in;

	/* read inotify events */
	while ((rc = read(u->fd, inotify_buffer, INOTIFY_SZ)) == -1 && errno == EINTR);

	if (rc <= 0)
		return;

	/* process events from buffer */
	for (p = inotify_buffer;
	     rc - (p - inotify_buffer) >= (int)sizeof(struct inotify_event);
	     p += sizeof(struct inotify_event) + in->len) {
		in = (struct inotify_event*)p;

		/* skip everything but directories */
		if (!(in->mask & IN_ISDIR))
			continue;

		if (in->len < 1)
			continue;

		/* skip hidden files */
		if (in->name[0] == '.')
			continue;

		/* add/remove subsystem objects */
		if (in->mask & (IN_CREATE | IN_MOVED_TO))
			add_subsystem(in->len, in->name);
		else if (in->mask & (IN_DELETE | IN_MOVED_FROM))
			remove_subsystem(in->len, in->name);
	}
}

void ubus_init_hotplug(struct ubus_context *newctx)
{
	ctx = newctx;
	remove_subsystem(0, NULL);
	if (init_subsystems()) {
		printf("failed to initialize hotplug subsystems from %s\n", HOTPLUG_BASEDIR);
		return;
	}
	fd_inotify_read.fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	fd_inotify_read.cb = inotify_read_handler;
	if (fd_inotify_read.fd == -1) {
		printf("failed to initialize inotify handler for %s\n", HOTPLUG_BASEDIR);
		return;
	}

	inotify_buffer = calloc(1, INOTIFY_SZ);
	if (!inotify_buffer)
		return;

	if (inotify_add_watch(fd_inotify_read.fd, HOTPLUG_BASEDIR,
		IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM | IN_ONLYDIR) == -1)
		return;

	uloop_fd_add(&fd_inotify_read, ULOOP_READ);
}
