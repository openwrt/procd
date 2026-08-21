/*
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
#ifndef _JAIL_SECCOMP_TRACE_H_
#define _JAIL_SECCOMP_TRACE_H_

#include <sys/types.h>

enum seccomp_mode {
	SECCOMP_MODE_ENFORCE = 0,
	SECCOMP_MODE_TRACE,
	SECCOMP_MODE_AUDIT,
	SECCOMP_MODE_COMPLAIN,
};

struct seccomp_trace_opts {
	enum seccomp_mode mode;
	const char *name;
	int log_fd;
	int main_boundary;
	int dedup;
};

#ifdef SECCOMP_SUPPORT
int seccomp_trace_run(pid_t pid, const struct seccomp_trace_opts *o);
#else
static inline int seccomp_trace_run(pid_t pid, const struct seccomp_trace_opts *o)
{
	return -1;
}
#endif

#endif
