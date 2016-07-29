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

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libubox/blobmsg_json.h>
#include <libubox/json_script.h>
#include <libubox/runqueue.h>
#include <libubox/ustream.h>
#include <libubox/uloop.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>

#include "../procd.h"

struct trigger {
	struct list_head list;

	void *id;
	char *type;
	int timeout;

	struct blob_attr *rule;
	struct blob_attr *data;

	struct json_script_ctx jctx;
};

struct trigger_command {
	struct avl_node avl;
	struct uloop_timeout delay;
	bool requeue;

	struct runqueue_process proc;
	struct json_script_ctx jctx;

	struct blob_attr data[];
};

static LIST_HEAD(triggers);
static RUNQUEUE(q, 1);
static AVL_TREE(trigger_pending, avl_blobcmp, false, NULL);

static const char* rule_handle_var(struct json_script_ctx *ctx, const char *name, struct blob_attr *vars)
{
	return NULL;
}

static struct json_script_file *
rule_load_script(struct json_script_ctx *ctx, const char *name)
{
	struct trigger *t = container_of(ctx, struct trigger, jctx);

	if (strcmp(name, t->type) != 0)
		return NULL;

	return json_script_file_from_blobmsg(t->type, t->rule, blob_pad_len(t->rule));
}

static void trigger_free(struct trigger *t)
{
	json_script_free(&t->jctx);
	free(t->data);
	list_del(&t->list);
	free(t);
}

static void trigger_command_complete(struct runqueue *q, struct runqueue_task *p)
{
	struct trigger_command *cmd = container_of(p, struct trigger_command, proc.task);

	if (cmd->requeue) {
		cmd->requeue = false;
		runqueue_task_add(q, p, false);
		return;
	}

	avl_delete(&trigger_pending, &cmd->avl);
	free(cmd);
}

static void trigger_command_run(struct runqueue *q, struct runqueue_task *t)
{
	struct trigger_command *cmd = container_of(t, struct trigger_command, proc.task);
	struct blob_attr *cur;
	char **argv;
	pid_t pid;
	int n = 0;
	int rem;

	pid = fork();
	if (pid < 0) {
		trigger_command_complete(q, t);
		return;
	}

	if (pid) {
		runqueue_process_add(q, &cmd->proc, pid);
		return;
	}

	if (debug < 3) {
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	blobmsg_for_each_attr(cur, cmd->data, rem)
		n++;

	argv = alloca((n + 1) * sizeof(*argv));
	n = 0;
	blobmsg_for_each_attr(cur, cmd->data, rem)
		argv[n++] = blobmsg_get_string(cur);
	argv[n] = NULL;

	if (n > 0)
		execvp(argv[0], &argv[0]);

	exit(1);
}

static void trigger_command_start(struct uloop_timeout *timeout)
{
	static const struct runqueue_task_type trigger_command_type = {
		.run = trigger_command_run,
		.cancel = runqueue_process_cancel_cb,
		.kill = runqueue_process_kill_cb,
	};
	struct trigger_command *cmd = container_of(timeout, struct trigger_command, delay);

	cmd->proc.task.type = &trigger_command_type;
	cmd->proc.task.complete = trigger_command_complete;
	runqueue_task_add(&q, &cmd->proc.task, false);
}

static void trigger_command_add(struct trigger *t, struct blob_attr *data)
{
	struct trigger_command *cmd;
	int remaining;

	cmd = avl_find_element(&trigger_pending, data, cmd, avl);
	if (cmd) {
		/* Command currently running? */
		if (!cmd->delay.pending) {
			cmd->requeue = true;
			return;
		}

		/* Extend timer if trigger timeout is bigger than remaining time */
		remaining = uloop_timeout_remaining(&cmd->delay);
		if (remaining < t->timeout)
			uloop_timeout_set(&cmd->delay, t->timeout);

		return;
	}

	cmd = calloc(1, sizeof(*cmd) + blob_pad_len(data));
	if (!cmd)
		return;

	cmd->avl.key = cmd->data;
	cmd->delay.cb = trigger_command_start;
	memcpy(cmd->data, data, blob_pad_len(data));
	avl_insert(&trigger_pending, &cmd->avl);
	uloop_timeout_set(&cmd->delay, t->timeout > 0 ? t->timeout : 1);
}

static void rule_handle_command(struct json_script_ctx *ctx, const char *name,
				struct blob_attr *exec, struct blob_attr *vars)
{
	struct trigger *t = container_of(ctx, struct trigger, jctx);

	if (!strcmp(name, "run_script")) {
		trigger_command_add(t, exec);
		return;
	}
}

static void rule_handle_error(struct json_script_ctx *ctx, const char *msg,
				struct blob_attr *context)
{
	char *s;

	s = blobmsg_format_json(context, false);
	ERROR("ERROR: %s in block: %s\n", msg, s);
	free(s);
}

static struct trigger* _trigger_add(char *type, struct blob_attr *rule, int timeout, void *id)
{
	char *_t;
	struct blob_attr *_r;
	struct trigger *t = calloc_a(sizeof(*t), &_t, strlen(type) + 1, &_r, blob_pad_len(rule));

	t->type = _t;
	t->rule = _r;
	t->timeout = timeout;
	t->id = id;
	t->jctx.handle_var = rule_handle_var,
	t->jctx.handle_error = rule_handle_error,
	t->jctx.handle_command = rule_handle_command,
	t->jctx.handle_file = rule_load_script,

	strcpy(t->type, type);
	memcpy(t->rule, rule, blob_pad_len(rule));

	list_add(&t->list, &triggers);
	json_script_init(&t->jctx);

	return t;
}

void trigger_add(struct blob_attr *rule, void *id)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, rule, rem) {
		struct blob_attr *_cur, *type = NULL, *script = NULL, *timeout = NULL;
		int _rem;
		int i = 0;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_ARRAY)
			continue;

		blobmsg_for_each_attr(_cur, cur, _rem) {
			switch (i++) {
			case 0:
				if (blobmsg_type(_cur) == BLOBMSG_TYPE_STRING)
					type = _cur;
				break;

			case 1:
				if (blobmsg_type(_cur) == BLOBMSG_TYPE_ARRAY)
					script = _cur;
				break;

			case 2:
				if (blobmsg_type(_cur) == BLOBMSG_TYPE_INT32)
					timeout = _cur;
				break;
			}
		}

		if (type && script) {
			int t = 0;

			if (timeout)
				t = blobmsg_get_u32(timeout);
			_trigger_add(blobmsg_get_string(type), script, t, id);
		}
	}
}

void trigger_del(void *id)
{
	struct trigger *t, *n;

	list_for_each_entry_safe(t, n, &triggers, list) {
		if (t->id != id)
			continue;

		trigger_free(t);
	}
}

static bool trigger_match(const char *event, const char *match)
{
	char *wildcard = strstr(match, ".*");
	if (wildcard)
		return !strncmp(event, match, wildcard - match);
	return !strcmp(event, match);
}

void trigger_event(const char *type, struct blob_attr *data)
{
	struct trigger *t;

	list_for_each_entry(t, &triggers, list) {
		if (!trigger_match(type, t->type))
			continue;
		json_script_run(&t->jctx, t->type, data);
	}
}
