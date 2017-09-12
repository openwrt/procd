/*
 * Copyright (C) 2015 John Crispin <blogic@openwrt.org>
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
#include <fcntl.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#ifndef PTRACE_EVENT_STOP
/* PTRACE_EVENT_STOP is defined in linux/ptrace.h, but this header
 * collides with musl's sys/ptrace.h */
#define PTRACE_EVENT_STOP 128
#endif

#include <libubox/ulog.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "../syscall-names.h"

#define _offsetof(a, b) __builtin_offsetof(a,b)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifdef __amd64__
#define reg_syscall_nr	_offsetof(struct user, regs.orig_rax)
#elif defined(__i386__)
#define reg_syscall_nr	_offsetof(struct user, regs.orig_eax)
#elif defined(__mips)
# ifndef EF_REG2
# define EF_REG2	8
# endif
#define reg_syscall_nr	(EF_REG2 / 4)
#elif defined(__arm__)
#include <asm/ptrace.h>		/* for PTRACE_SET_SYSCALL */
#define reg_syscall_nr	_offsetof(struct user, regs.uregs[7])
# if defined(__ARM_EABI__)
# define reg_retval_nr	_offsetof(struct user, regs.uregs[0])
# endif
#else
#error tracing is not supported on this architecture
#endif

enum mode {
	UTRACE,
	SECCOMP_TRACE,
} mode = UTRACE;

struct tracee {
	struct uloop_process proc;
	int in_syscall;
};

static struct tracee tracer;
static int syscall_count[SYSCALL_COUNT];
static int violation_count;
static struct blob_buf b;
static int debug;
char *json = NULL;
int ptrace_restart;

static void set_syscall(const char *name, int val)
{
	int i;

	for (i = 0; i < SYSCALL_COUNT; i++) {
		int sc = syscall_index_to_number(i);
		if (syscall_name(sc) && !strcmp(syscall_name(sc), name)) {
			syscall_count[i] = val;
			return;
		}
	}
}

struct syscall {
	int syscall;
	int count;
};

static int cmp_count(const void *a, const void *b)
{
	return ((struct syscall*)b)->count - ((struct syscall*)a)->count;
}

static void print_syscalls(int policy, const char *json)
{
	void *c;
	int i;

	if (mode == UTRACE) {
		set_syscall("rt_sigaction", 1);
		set_syscall("sigreturn", 1);
		set_syscall("rt_sigreturn", 1);
		set_syscall("exit_group", 1);
		set_syscall("exit", 1);
	}

	struct syscall sorted[SYSCALL_COUNT];

	for (i = 0; i < SYSCALL_COUNT; i++) {
		sorted[i].syscall = syscall_index_to_number(i);
		sorted[i].count = syscall_count[i];
	}

	qsort(sorted, SYSCALL_COUNT, sizeof(sorted[0]), cmp_count);

	blob_buf_init(&b, 0);
	c = blobmsg_open_array(&b, "whitelist");

	for (i = 0; i < SYSCALL_COUNT; i++) {
		int sc = sorted[i].syscall;
		if (!sorted[i].count)
			break;
		if (syscall_name(sc)) {
			if (debug)
				printf("syscall %d (%s) was called %d times\n",
				       sc, syscall_name(sc), sorted[i].count);
			blobmsg_add_string(&b, NULL, syscall_name(sc));
		} else {
			ULOG_ERR("no name found for syscall(%d)\n", sc);
		}
	}
	blobmsg_close_array(&b, c);
	blobmsg_add_u32(&b, "policy", policy);
	if (json) {
		FILE *fp = fopen(json, "w");
		if (fp) {
			fprintf(fp, "%s", blobmsg_format_json_indent(b.head, true, 0));
			fclose(fp);
			ULOG_INFO("saving syscall trace to %s\n", json);
		} else {
			ULOG_ERR("failed to open %s\n", json);
		}
	} else {
		printf("%s\n",
			blobmsg_format_json_indent(b.head, true, 0));
	}

}

static void report_seccomp_vialation(pid_t pid, unsigned syscall)
{
	char buf[200];
	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	int f = open(buf, O_RDONLY);
	int r = read(f, buf, sizeof(buf) - 1);
	if (r >= 0)
		buf[r] = 0;
	else
		strcpy(buf, "unknown?");
	close(f);

	if (violation_count < INT_MAX)
		violation_count++;
	int i = syscall_index(syscall);
	if (i >= 0) {
		syscall_count[i]++;
		ULOG_ERR("%s[%u] tried to call non-whitelisted syscall: %s (see %s)\n",
			 buf, pid,  syscall_name(syscall), json);
	} else {
		ULOG_ERR("%s[%u] tried to call non-whitelisted syscall: %d (see %s)\n",
			 buf, pid,  syscall, json);
	}
}

static void tracer_cb(struct uloop_process *c, int ret)
{
	struct tracee *tracee = container_of(c, struct tracee, proc);
	int inject_signal = 0;

	/* We explicitely check for events in upper 16 bits, because
	 * musl (as opposed to glibc) does not report
	 * PTRACE_EVENT_STOP as WIFSTOPPED */
	if (WIFSTOPPED(ret) || (ret >> 16)) {
		if (WSTOPSIG(ret) & 0x80) {
			if (!tracee->in_syscall) {
				int syscall = ptrace(PTRACE_PEEKUSER, c->pid, reg_syscall_nr);
				int i = syscall_index(syscall);
				if (i >= 0) {
					syscall_count[i]++;
					if (debug)
						fprintf(stderr, "%s()\n", syscall_name(syscall));
				} else if (debug) {
					fprintf(stderr, "syscal(%d)\n", syscall);
				}
			}
			tracee->in_syscall = !tracee->in_syscall;
		} else if ((ret >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) ||
			   (ret >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)) ||
			   (ret >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
			struct tracee *child = calloc(1, sizeof(struct tracee));

			ptrace(PTRACE_GETEVENTMSG, c->pid, 0, &child->proc.pid);
			child->proc.cb = tracer_cb;
			ptrace(ptrace_restart, child->proc.pid, 0, 0);
			uloop_process_add(&child->proc);
			if (debug)
				fprintf(stderr, "Tracing new child %d\n", child->proc.pid);
		} else if ((ret >> 16) == PTRACE_EVENT_STOP) {
			/* Nothing special to do here */
		} else if ((ret >> 8) == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
			int syscall = ptrace(PTRACE_PEEKUSER, c->pid, reg_syscall_nr);
#if defined(__arm__)
			ptrace(PTRACE_SET_SYSCALL, c->pid, 0, -1);
			ptrace(PTRACE_POKEUSER, c->pid, reg_retval_nr, -ENOSYS);
#else
			ptrace(PTRACE_POKEUSER, c->pid, reg_syscall_nr, -1);
#endif
			report_seccomp_vialation(c->pid, syscall);
		} else {
			inject_signal = WSTOPSIG(ret);
			if (debug)
				fprintf(stderr, "Injecting signal %d into pid %d\n",
					inject_signal, tracee->proc.pid);
		}
	} else if (WIFEXITED(ret) || (WIFSIGNALED(ret) && WTERMSIG(ret))) {
		if (tracee == &tracer) {
			uloop_end(); /* Main process exit */
		} else {
			if (debug)
				fprintf(stderr, "Child %d exited\n", tracee->proc.pid);
			free(tracee);
		}
		return;
	}

	ptrace(ptrace_restart, c->pid, 0, inject_signal);
	uloop_process_add(c);
}

static void sigterm_handler(int signum)
{
	/* When we receive SIGTERM, we forward it to the tracee. After
	 * the tracee exits, trace_cb() will be called and make us
	 * exit too. */
	kill(tracer.proc.pid, SIGTERM);
}


int main(int argc, char **argv, char **envp)
{
	int status, ch, policy = EPERM;
	pid_t child;

	/* When invoked via seccomp-trace symlink, work as seccomp
	 * violation logger rather than as syscall tracer */
	if (strstr(argv[0], "seccomp-trace"))
		mode = SECCOMP_TRACE;

	while ((ch = getopt(argc, argv, "f:p:")) != -1) {
		switch (ch) {
		case 'f':
			json = optarg;
			break;
		case 'p':
			policy = atoi(optarg);
			break;
		}
	}

	if (!json)
		json = getenv("SECCOMP_FILE");

	argc -= optind;
	argv += optind;

	if (!argc)
		return -1;

	if (getenv("TRACE_DEBUG"))
		debug = 1;
	unsetenv("TRACE_DEBUG");

	child = fork();

	if (child == 0) {
		char **_argv = calloc(argc + 1, sizeof(char *));
		char **_envp;
		char *preload = NULL;
		const char *old_preload = getenv("LD_PRELOAD");
		int newenv = 0;
		int envc = 0;
		int ret;

		memcpy(_argv, argv, argc * sizeof(char *));

		while (envp[envc++])
			;

		_envp = calloc(envc + 2, sizeof(char *));
		switch (mode) {
		case UTRACE:
			preload = "/lib/libpreload-trace.so";
			newenv = 1;
			break;
		case SECCOMP_TRACE:
			preload = "/lib/libpreload-seccomp.so";
			newenv = 2;
			asprintf(&_envp[1], "SECCOMP_FILE=%s", json ? json : "");
			kill(getpid(), SIGSTOP);
			break;
		}
		asprintf(&_envp[0], "LD_PRELOAD=%s%s%s", preload,
			 old_preload ? ":" : "",
			 old_preload ? old_preload : "");
		memcpy(&_envp[newenv], envp, envc * sizeof(char *));

		ret = execve(_argv[0], _argv, _envp);
		ULOG_ERR("failed to exec %s: %s\n", _argv[0], strerror(errno));

		free(_argv);
		free(_envp);
		return ret;
	}

	if (child < 0)
		return -1;

	waitpid(child, &status, WUNTRACED);
	if (!WIFSTOPPED(status)) {
		ULOG_ERR("failed to start %s\n", *argv);
		return -1;
	}

	int ptrace_options = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
	switch (mode) {
	case UTRACE:
		ptrace_options |= PTRACE_O_TRACESYSGOOD;
		ptrace_restart = PTRACE_SYSCALL;
		break;
	case SECCOMP_TRACE:
		ptrace_options |= PTRACE_O_TRACESECCOMP;
		ptrace_restart = PTRACE_CONT;
		break;
	}
	if (ptrace(PTRACE_SEIZE, child, 0, ptrace_options) == -1) {
		ULOG_ERR("PTRACE_SEIZE: %s\n", strerror(errno));
		return -1;
	}
	if (ptrace(ptrace_restart, child, 0, SIGCONT) == -1) {
		ULOG_ERR("ptrace_restart: %s\n", strerror(errno));
		return -1;
	}

	uloop_init();
	tracer.proc.pid = child;
	tracer.proc.cb = tracer_cb;
	uloop_process_add(&tracer.proc);
	signal(SIGTERM, sigterm_handler); /* Override uloop's SIGTERM handler */
	uloop_run();
	uloop_done();


	switch (mode) {
	case UTRACE:
		if (!json)
			if (asprintf(&json, "/tmp/%s.%u.json", basename(*argv), child) < 0)
				ULOG_ERR("failed to allocate output path: %s\n", strerror(errno));
		break;
	case SECCOMP_TRACE:
		if (!violation_count)
			return 0;
		asprintf(&json, "/tmp/%s.%u.violations.json", basename(*argv), child);
		break;
	}
	print_syscalls(policy, json);
	return 0;
}
