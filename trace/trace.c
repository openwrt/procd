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
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>

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
#define reg_syscall_nr	_offsetof(struct user, regs.uregs[7])
#else
#error tracing is not supported on this architecture
#endif

#define INFO(fmt, ...) do { \
	fprintf(stderr, "utrace: "fmt, ## __VA_ARGS__); \
} while (0)

#define ERROR(fmt, ...) do { \
	syslog(LOG_ERR, "utrace: "fmt, ## __VA_ARGS__); \
	fprintf(stderr, "utrace: "fmt, ## __VA_ARGS__); \
} while (0)

static struct uloop_process tracer;
static int *syscall_count;
static struct blob_buf b;
static int syscall_max;
static int in_syscall;
static int debug;

static int max_syscall = ARRAY_SIZE(syscall_names);

static void set_syscall(const char *name, int val)
{
	int i;

	for (i = 0; i < max_syscall; i++)
		if (syscall_names[i] && !strcmp(syscall_names[i], name)) {
			syscall_count[i] = val;
			return;
		}
}

static void print_syscalls(int policy, const char *json)
{
	void *c;
	int i;

	set_syscall("rt_sigaction", 1);
	set_syscall("sigreturn", 1);
	set_syscall("rt_sigreturn", 1);
	set_syscall("exit_group", 1);
	set_syscall("exit", 1);

	blob_buf_init(&b, 0);
	c = blobmsg_open_array(&b, "whitelist");

	for (i = 0; i < ARRAY_SIZE(syscall_names); i++) {
		if (!syscall_count[i])
			continue;
		if (syscall_names[i]) {
			if (debug)
				printf("syscall %d (%s) was called %d times\n",
					i, syscall_names[i], syscall_count[i]);
			blobmsg_add_string(&b, NULL, syscall_names[i]);
		} else {
			ERROR("no name found for syscall(%d)\n", i);
		}
	}
	blobmsg_close_array(&b, c);
	blobmsg_add_u32(&b, "policy", policy);
	if (json) {
		FILE *fp = fopen(json, "w");
		if (fp) {
			fprintf(fp, "%s", blobmsg_format_json_indent(b.head, true, 0));
			fclose(fp);
			INFO("saving syscall trace to %s\n", json);
		} else {
			ERROR("failed to open %s\n", json);
		}
	} else {
		printf("%s\n",
			blobmsg_format_json_indent(b.head, true, 0));
	}

}

static void tracer_cb(struct uloop_process *c, int ret)
{
	if (WIFSTOPPED(ret) && WSTOPSIG(ret) & 0x80) {
		if (!in_syscall) {
			int syscall = ptrace(PTRACE_PEEKUSER, c->pid, reg_syscall_nr);

			if (syscall < syscall_max) {
				syscall_count[syscall]++;
				if (debug)
					fprintf(stderr, "%s()\n", syscall_names[syscall]);
			} else if (debug) {
				fprintf(stderr, "syscal(%d)\n", syscall);
			}
		}
		in_syscall = !in_syscall;
	} else if (WIFEXITED(ret)) {
		uloop_end();
		return;
	}
	ptrace(PTRACE_SYSCALL, c->pid, 0, 0);
	uloop_process_add(&tracer);
}

int main(int argc, char **argv, char **envp)
{
	char *json = NULL;
	int status, ch, policy = EPERM;
	pid_t child;

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
		char *preload = "LD_PRELOAD=/lib/libpreload-trace.so";
		int envc = 1;
		int ret;

		memcpy(_argv, argv, argc * sizeof(char *));

		while (envp[envc++])
			;

		_envp = calloc(envc, sizeof(char *));
		memcpy(&_envp[1], _envp, envc * sizeof(char *));
		*_envp = preload;

		ret = execve(_argv[0], _argv, _envp);
		ERROR("failed to exec %s: %s\n", _argv[0], strerror(errno));

		free(_argv);
		free(_envp);
		return ret;
	}

	if (child < 0)
		return -1;

	syscall_max = ARRAY_SIZE(syscall_names);
	syscall_count = calloc(syscall_max, sizeof(int));
	waitpid(child, &status, 0);
	if (!WIFSTOPPED(status)) {
		ERROR("failed to start %s\n", *argv);
		return -1;
	}

	ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
	ptrace(PTRACE_SYSCALL, child, 0, 0);

	uloop_init();
	tracer.pid = child;
	tracer.cb = tracer_cb;
	uloop_process_add(&tracer);
	uloop_run();
	uloop_done();

	if (!json)
		if (asprintf(&json, "/tmp/%s.%u.json", basename(*argv), child) < 0)
			ERROR("failed to allocate output path: %s\n", strerror(errno));

	print_syscalls(policy, json);

	return 0;
}
