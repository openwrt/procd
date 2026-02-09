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
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glob.h>

#include <libubox/ustream.h>

#include "procd.h"
#include "rcS.h"

static struct runqueue q, r;

struct initd {
	struct ustream_fd fd;
	struct runqueue_process proc;
	struct timespec ts_start;
	char *file;
	char *param;
};

static void pipe_cb(struct ustream *s, int bytes)
{
	struct initd *initd = container_of(s, struct initd, fd.stream);
	char *newline, *str;
	int len;

	do {
		str = ustream_get_read_buf(s, NULL);
		if (!str)
			break;
		newline = strchr(str, '\n');
		if (!newline)
			break;
		*newline = 0;
		len = newline + 1 - str;
		ULOG_NOTE("%s: %s", initd->file, str);
#ifdef SHOW_BOOT_ON_CONSOLE
		fprintf(stderr, "%s: %s\n", initd->file, str);
#endif
		ustream_consume(s, len);
	} while (1);
}

static void q_initd_run(struct runqueue *q, struct runqueue_task *t)
{
	struct initd *s = container_of(t, struct initd, proc.task);
	int pipefd[2];
	pid_t pid;

	clock_gettime(CLOCK_MONOTONIC_RAW, &s->ts_start);
	DEBUG(2, "start %s %s \n", s->file, s->param);
	if (pipe(pipefd) == -1) {
		ERROR("Failed to create pipe: %m\n");
		return;
	}

	pid = fork();
	if (pid < 0)
		return;

	if (pid) {
		close(pipefd[1]);
		fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
		s->fd.stream.string_data = true,
		s->fd.stream.notify_read = pipe_cb,
		runqueue_process_add(q, &s->proc, pid);
		ustream_fd_init(&s->fd, pipefd[0]);
		return;
	}
	close(pipefd[0]);

	int devnull = open("/dev/null", O_RDONLY);
	dup2(devnull, STDIN_FILENO);
	dup2(pipefd[1], STDOUT_FILENO);
	dup2(pipefd[1], STDERR_FILENO);

	if (devnull > STDERR_FILENO)
		close(devnull);

	execlp(s->file, s->file, s->param, NULL);
	exit(1);
}

static void q_initd_complete(struct runqueue *q, struct runqueue_task *p)
{
	struct initd *s = container_of(p, struct initd, proc.task);
	struct timespec ts_stop, ts_res;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts_stop);
	ts_res.tv_sec = ts_stop.tv_sec - s->ts_start.tv_sec;
	ts_res.tv_nsec = ts_stop.tv_nsec - s->ts_start.tv_nsec;
	if (ts_res.tv_nsec < 0) {
		--ts_res.tv_sec;
		ts_res.tv_nsec += 1000000000;
	}

	DEBUG(2, "stop %s %s - took %" PRId64 ".%09" PRId64 "s\n", s->file, s->param, (int64_t)ts_res.tv_sec, (int64_t)ts_res.tv_nsec);
	ustream_free(&s->fd.stream);
	close(s->fd.fd.fd);
	free(s);
}

static bool find_runqueue_list_entry(struct list_head *list, const char *file, const char *param)
{
	struct initd *s;

	list_for_each_entry(s, list, proc.task.list.list)
		if (!strcmp(s->file, file) && !strcmp(s->param, param))
			return true;
	return false;
}

static void add_initd(struct runqueue *q, const char *file, const char *param)
{
	static const struct runqueue_task_type initd_type = {
		.run = q_initd_run,
		.cancel = runqueue_process_cancel_cb,
		.kill = runqueue_process_kill_cb,
	};
	struct initd *s;
	char *p, *f;

	if (!strcmp(param, "running") &&
	    (find_runqueue_list_entry(&q->tasks_active.list, file, param) ||
	     find_runqueue_list_entry(&q->tasks_inactive.list, file, param)))
		return;

	s = calloc_a(sizeof(*s), &f, strlen(file) + 1, &p, strlen(param) + 1);
	if (!s) {
		ERROR("Out of memory in %s.\n", file);
		return;
	}
	s->proc.task.type = &initd_type;
	s->proc.task.complete = q_initd_complete;
	if (!strcmp(param, "stop") || !strcmp(param, "shutdown")) {
		s->proc.task.run_timeout = 15000;
		s->proc.task.cancel_timeout = 10000;
	}
	s->param = p;
	s->file = f;
	strcpy(s->param, param);
	strcpy(s->file, file);
	runqueue_task_add(q, &s->proc.task, false);
}

static int _rc(struct runqueue *q, const char *path, const char *file, const char *pattern, const char *param)
{
	char *dir = alloca(2 + strlen(path) + strlen(file) + strlen(pattern));
	glob_t gl;
	int j;

	if (!dir) {
		ERROR("Out of memory in %s.\n", file);
		return -1;
	}

	DEBUG(2, "running %s/%s%s %s\n", path, file, pattern, param);
	sprintf(dir, "%s/%s%s", path, file, pattern);
	if (glob(dir, GLOB_NOESCAPE | GLOB_MARK, NULL, &gl)) {
		DEBUG(2, "glob failed on %s\n", dir);
		return -1;
	}

	for (j = 0; j < gl.gl_pathc; j++)
		add_initd(q, gl.gl_pathv[j], param);

	globfree(&gl);

	return 0;
}

int rcS(const char *pattern, const char *param, void (*q_empty)(struct runqueue *))
{
	runqueue_init(&q);
	q.empty_cb = q_empty;
	q.max_running_tasks = 1;

	return _rc(&q, "/etc/rc.d", pattern, "*", param);
}

int rc(const char *file, const char *param)
{
	return _rc(&r, "/etc/init.d", file, "", param);
}

static void r_empty(struct runqueue *q)
{

}

static void __attribute__((constructor)) rc_init() {
	runqueue_init(&r);
	r.empty_cb = r_empty;
	r.max_running_tasks = 8;
}
