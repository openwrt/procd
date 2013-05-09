/*
 * runqueue-example.c
 *
 * Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <libubox/uloop.h>
#include <libubox/runqueue.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <glob.h>

#include <libubox/ustream.h>

#include "procd.h"
#include "rcS.h"

static struct runqueue q;

struct initd {
	struct ustream_fd fd;
	struct runqueue_process proc;
	char *file;
	char *param;
};

static void pipe_cb(struct ustream *s, int bytes)
{
	struct ustream_buf *buf = s->r.head;
	char *newline, *str;
	int len;

	do {
		str = ustream_get_read_buf(s, NULL);
		if (!str)
			break;
		newline = strchr(buf->data, '\n');
		if (!newline)
			break;
		*newline = 0;
		len = newline + 1 - str;
		SYSLOG(6, buf->data);
		ustream_consume(s, len);
	} while (1);
}

static void q_initd_run(struct runqueue *q, struct runqueue_task *t)
{
	struct initd *s = container_of(t, struct initd, proc.task);
	int pipefd[2];
	pid_t pid;

	DEBUG(1, "start %s %s \n", s->file, s->param);
	if (pipe(pipefd) == -1) {
		ERROR("Failed to create pipe\n");
		return;
	}

	pid = fork();
	if (pid < 0)
		return;

	if (pid) {
		close(pipefd[1]);
		s->fd.stream.string_data = true,
		s->fd.stream.notify_read = pipe_cb,
		runqueue_process_add(q, &s->proc, pid);
		ustream_fd_init(&s->fd, pipefd[0]);
		return;
	}
	close(pipefd[0]);
	dup2(pipefd[1], STDOUT_FILENO);
	dup2(pipefd[1], STDERR_FILENO);

	execlp(s->file, s->file, s->param, NULL);
	exit(1);
}

static void q_initd_complete(struct runqueue *q, struct runqueue_process *p, int ret)
{
	struct initd *s = container_of(p, struct initd, proc);

	DEBUG(1, "stop %s %s \n", s->file, s->param);
	ustream_free(&s->fd.stream);
	close(s->fd.fd.fd);
	free(s);
}

static void add_initd(char *file, char *param)
{
	static const struct runqueue_task_type initd_type = {
		.run = q_initd_run,
		.cancel = runqueue_process_cancel_cb,
		.kill = runqueue_process_kill_cb,
	};
	struct initd *s;

	s = calloc(1, sizeof(*s));
	s->proc.task.type = &initd_type;
	s->proc.complete = q_initd_complete;
	s->param = param;
	s->file = file;
	runqueue_task_add(&q, &s->proc.task, false);
}

int rcS(char *pattern, char *param, void (*q_empty)(struct runqueue *))
{
	char dir[16];
	glob_t gl;
	int j;

	runqueue_init(&q);
	q.empty_cb = q_empty;
	q.max_running_tasks = 1;

	DEBUG(1, "running /etc/rc.d/%s %s\n", pattern, param);
	snprintf(dir, sizeof(dir), "/etc/rc.d/%s*", pattern);
	if (glob(dir, GLOB_NOESCAPE | GLOB_MARK, NULL, &gl)) {
		printf("glob failed on %s\n", dir);
		return -1;
	}

	for (j = 0; j < gl.gl_pathc; j++)
		add_initd(gl.gl_pathv[j], param);

	return 0;
}
