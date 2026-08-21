/*
 * seccomp syscall tracer for ujail
 *
 * Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org>
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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <libubox/blob.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/list.h>
#include <libubox/utils.h>

#include <udebug.h>

#include "log.h"
#include "seccomp-inject.h"
#include "seccomp-trace.h"
#include "../syscall-names.h"

#ifndef __WALL
#define __WALL		0x40000000
#endif

#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC	4
#endif

#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP	7
#endif

#define SECCOMP_TRACE_KILL_DATA	0xffffU

enum trace_phase {
	PHASE_LINKER = 0,
	PHASE_INIT,
	PHASE_APP,
};

#define TRACE_NSYS	1024

struct trace_proc {
	struct list_head list;
	pid_t pid;
	int phase;
	int in_syscall;
	int expect_main;
	int main_argidx;
	int errno_pending;
	int pending_errno;
	char comm[24];
	struct seccomp_bp bp_at_entry;
	struct seccomp_bp bp_lsm;
	struct seccomp_bp bp_main;
};

static LIST_HEAD(trace_procs);
static int trace_nprocs;

static struct udebug ud;
static struct udebug_buf udb;
static struct udebug_buf_meta ring_meta;
static char ring_name[64];
static int udebug_ready;

static struct blob_buf event_b;
static int trace_mode;
static int trace_log_fd = -1;
static int trace_dedup;
static int trace_main_boundary;

static uint32_t seen[3][TRACE_NSYS / 32];

static const char *phase_name(int phase)
{
	switch (phase) {
	case PHASE_LINKER:
		return "linker";
	case PHASE_INIT:
		return "init";
	default:
		return "app";
	}
}

static int dedup_seen(int phase, long nr)
{
	uint32_t bit;

	if (!trace_dedup)
		return 0;
	if (nr < 0 || nr >= TRACE_NSYS || phase < 0 || phase > 2)
		return 0;

	bit = 1u << (nr & 31);
	if (seen[phase][nr / 32] & bit)
		return 1;

	seen[phase][nr / 32] |= bit;
	return 0;
}

static void read_comm(pid_t pid, char *buf, size_t len)
{
	char path[32];
	ssize_t rd;
	int fd;

	buf[0] = '\0';
	snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;

	rd = read(fd, buf, len - 1);
	close(fd);
	if (rd <= 0) {
		buf[0] = '\0';
		return;
	}

	buf[rd] = '\0';
	if (buf[rd - 1] == '\n')
		buf[rd - 1] = '\0';
}

static void trace_emit(void)
{
	char *json;

	if (udebug_ready) {
		udebug_entry_init(&udb);
		udebug_entry_append(&udb, blob_data(event_b.head),
				    blob_len(event_b.head));
		udebug_entry_add(&udb);
	}

	if (trace_log_fd >= 0) {
		json = blobmsg_format_json(event_b.head, true);
		if (json) {
			dprintf(trace_log_fd, "%s\n", json);
			free(json);
		}
	}
}

static void emit_marker(struct trace_proc *p, const char *event)
{
	blob_buf_init(&event_b, 0);
	blobmsg_add_string(&event_b, "event", event);
	blobmsg_add_u32(&event_b, "pid", p->pid);
	if (p->comm[0])
		blobmsg_add_string(&event_b, "comm", p->comm);
	trace_emit();
}

static void emit_event(struct trace_proc *p, long nr, long *args,
		       const char *action, int errnoval)
{
	const char *name;
	void *arr;
	int i;

	blob_buf_init(&event_b, 0);
	blobmsg_add_string(&event_b, "event", "syscall");
	blobmsg_add_u32(&event_b, "pid", p->pid);
	if (p->comm[0])
		blobmsg_add_string(&event_b, "comm", p->comm);
	blobmsg_add_string(&event_b, "phase", phase_name(p->phase));
	blobmsg_add_u32(&event_b, "nr", (uint32_t)nr);

	name = syscall_name((unsigned)nr);
	if (name)
		blobmsg_add_string(&event_b, "syscall", name);

	arr = blobmsg_open_array(&event_b, "args");
	for (i = 0; i < 6; i++)
		blobmsg_add_u64(&event_b, NULL, (uint64_t)(unsigned long)args[i]);
	blobmsg_close_array(&event_b, arr);

	blobmsg_add_string(&event_b, "action", action);
	if (errnoval >= 0)
		blobmsg_add_u32(&event_b, "errno", (uint32_t)errnoval);
	trace_emit();
}

static void emit_syscall(struct trace_proc *p)
{
	long nr, args[6];

	if (seccomp_read_syscall(p->pid, &nr, args))
		return;
	if (dedup_seen(p->phase, nr))
		return;

	emit_event(p, nr, args, "allow", -1);
}

static struct trace_proc *proc_get(pid_t pid)
{
	struct trace_proc *p;

	list_for_each_entry(p, &trace_procs, list)
		if (p->pid == pid)
			return p;

	return NULL;
}

static struct trace_proc *proc_new(pid_t pid)
{
	struct trace_proc *p;

	p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;

	p->pid = pid;
	p->phase = PHASE_APP;
	list_add_tail(&p->list, &trace_procs);
	trace_nprocs++;

	return p;
}

static void proc_del(struct trace_proc *p)
{
	list_del(&p->list);
	free(p);
	trace_nprocs--;
}

static void proc_arm_markers(struct trace_proc *p)
{
	unsigned long at_entry, lsm;

	p->expect_main = 0;
	p->main_argidx = 0;
	p->bp_at_entry.armed = 0;
	p->bp_lsm.armed = 0;
	p->bp_main.armed = 0;

	if (seccomp_marker_addrs(p->pid, &at_entry, &lsm, &p->main_argidx))
		return;

	if (at_entry)
		seccomp_bp_arm(p->pid, at_entry, &p->bp_at_entry);
}

static void proc_setopts(struct trace_proc *p)
{
	unsigned long opt = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
			    PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
			    PTRACE_O_TRACEEXEC;

	if (trace_mode != SECCOMP_MODE_TRACE)
		opt |= PTRACE_O_TRACESECCOMP;

	ptrace(PTRACE_SETOPTIONS, p->pid, 0, (void *)opt);
}

static void proc_start_root(struct trace_proc *p)
{
	proc_setopts(p);
	read_comm(p->pid, p->comm, sizeof(p->comm));
	p->in_syscall = 0;

	if (trace_mode == SECCOMP_MODE_TRACE) {
		p->phase = PHASE_LINKER;
		proc_arm_markers(p);
	} else {
		p->phase = PHASE_APP;
	}
}

static void proc_start_child(struct trace_proc *p)
{
	proc_setopts(p);
	read_comm(p->pid, p->comm, sizeof(p->comm));
	p->phase = PHASE_APP;
	p->in_syscall = 0;
}

static void proc_exec(struct trace_proc *p)
{
	read_comm(p->pid, p->comm, sizeof(p->comm));
	p->in_syscall = 0;

	if (trace_mode == SECCOMP_MODE_TRACE) {
		p->phase = PHASE_LINKER;
		proc_arm_markers(p);
	}
}

static void handle_bp(struct trace_proc *p)
{
	struct seccomp_bp *bps[3];
	long nr, args[6];
	unsigned long mainaddr, at_entry, lsm;
	int hit;

	bps[0] = &p->bp_at_entry;
	bps[1] = &p->bp_lsm;
	bps[2] = &p->bp_main;

	hit = seccomp_bp_match(p->pid, bps, 3);
	switch (hit) {
	case 0:
		emit_marker(p, "at_entry");
		if (trace_main_boundary &&
		    !seccomp_marker_addrs(p->pid, &at_entry, &lsm, &p->main_argidx) &&
		    lsm && !seccomp_bp_arm(p->pid, lsm, &p->bp_lsm))
			p->expect_main = 1;
		p->phase = p->expect_main ? PHASE_INIT : PHASE_APP;
		break;
	case 1:
		if (seccomp_read_syscall(p->pid, &nr, args))
			break;
		mainaddr = (unsigned long)args[p->main_argidx];
		if (mainaddr)
			seccomp_bp_arm(p->pid, mainaddr, &p->bp_main);
		break;
	case 2:
		emit_marker(p, "main");
		p->phase = PHASE_APP;
		break;
	default:
		break;
	}
}

enum seccomp_resume {
	SECCOMP_RESUME_NORMAL = 0,
	SECCOMP_RESUME_STEP_EXIT,
};

static int handle_seccomp(struct trace_proc *p)
{
	long nr, args[6];
	unsigned long data = 0;
	int err, rc;

	ptrace(PTRACE_GETEVENTMSG, p->pid, 0, &data);
	if (seccomp_read_syscall(p->pid, &nr, args))
		return SECCOMP_RESUME_NORMAL;

	if (data == SECCOMP_TRACE_KILL_DATA) {
		emit_event(p, nr, args, "kill", -1);
		if (trace_mode == SECCOMP_MODE_AUDIT)
			kill(p->pid, SIGKILL);
		return SECCOMP_RESUME_NORMAL;
	}

	err = (int)data;
	emit_event(p, nr, args, "deny", err);

	if (trace_mode != SECCOMP_MODE_AUDIT)
		return SECCOMP_RESUME_NORMAL;

	rc = seccomp_force_errno(p->pid, err);
	if (rc < 0) {
		kill(p->pid, SIGKILL);
		return SECCOMP_RESUME_NORMAL;
	}
	if (rc == 0)
		return SECCOMP_RESUME_NORMAL;

	p->errno_pending = 1;
	p->pending_errno = err;

	return SECCOMP_RESUME_STEP_EXIT;
}

static void trace_resume(pid_t pid, int sig)
{
	if (trace_mode == SECCOMP_MODE_TRACE)
		ptrace(PTRACE_SYSCALL, pid, 0, (void *)(long)sig);
	else
		ptrace(PTRACE_CONT, pid, 0, (void *)(long)sig);
}

static int udebug_setup(const char *name)
{
	snprintf(ring_name, sizeof(ring_name), "ujail:%s", name ? name : "trace");
	ring_meta.name = ring_name;
	ring_meta.format = UDEBUG_FORMAT_BLOBMSG;

	udebug_init(&ud);
	udebug_auto_connect(&ud, NULL);
	if (udebug_buf_init(&udb, 1024, 256 * 1024))
		return -1;
	if (udebug_buf_add(&ud, &udb, &ring_meta))
		return -1;

	return 0;
}

static void udebug_teardown(void)
{
	if (!udebug_ready)
		return;

	udebug_buf_free(&udb);
	udebug_free(&ud);
	udebug_ready = 0;
}

int seccomp_trace_run(pid_t pid, const struct seccomp_trace_opts *o)
{
	struct trace_proc *p, *root;
	int status;
	pid_t wpid;
	int sig, ev;

	trace_mode = o->mode;
	trace_log_fd = o->log_fd;
	trace_dedup = o->dedup;
	trace_main_boundary = o->main_boundary;
	memset(seen, 0, sizeof(seen));

	if (!udebug_setup(o->name))
		udebug_ready = 1;

	root = proc_new(pid);
	if (!root) {
		udebug_teardown();
		return -1;
	}

	proc_start_root(root);
	trace_resume(pid, 0);

	while (trace_nprocs > 0) {
		wpid = waitpid(-1, &status, __WALL);
		if (wpid < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		p = proc_get(wpid);
		if (!p) {
			p = proc_new(wpid);
			if (!p)
				continue;
			proc_start_child(p);
			trace_resume(wpid, 0);
			continue;
		}

		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			proc_del(p);
			continue;
		}

		if (!WIFSTOPPED(status)) {
			trace_resume(wpid, 0);
			continue;
		}

		sig = WSTOPSIG(status);
		ev = (status >> 16) & 0xff;

		if (ev) {
			if (ev == PTRACE_EVENT_SECCOMP) {
				if (handle_seccomp(p) == SECCOMP_RESUME_STEP_EXIT) {
					ptrace(PTRACE_SYSCALL, wpid, 0, 0);
					continue;
				}
			} else if (ev == PTRACE_EVENT_EXEC) {
				proc_exec(p);
			}
			trace_resume(wpid, 0);
			continue;
		}

		if (sig == (SIGTRAP | 0x80)) {
			if (p->errno_pending) {
				if (seccomp_force_errno_exit(wpid, p->pending_errno))
					kill(wpid, SIGKILL);
				p->errno_pending = 0;
				trace_resume(wpid, 0);
				continue;
			}
			if (!p->in_syscall)
				emit_syscall(p);
			p->in_syscall = !p->in_syscall;
			trace_resume(wpid, 0);
			continue;
		}

		if (sig == SIGTRAP) {
			handle_bp(p);
			trace_resume(wpid, 0);
			continue;
		}

		trace_resume(wpid, (int)sig);
	}

	while (!list_empty(&trace_procs)) {
		p = list_first_entry(&trace_procs, struct trace_proc, list);
		proc_del(p);
	}

	udebug_teardown();

	return 0;
}
