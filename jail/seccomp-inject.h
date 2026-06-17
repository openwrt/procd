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
#ifndef _JAIL_SECCOMP_INJECT_H_
#define _JAIL_SECCOMP_INJECT_H_

#include <sys/types.h>
#include <linux/filter.h>

struct seccomp_bp {
	unsigned long addr;
	unsigned char saved[16];
	unsigned char len;
	unsigned char armed;
};

#ifdef SECCOMP_SUPPORT
int seccomp_inject(pid_t pid, struct sock_fprog *prog);
int seccomp_run_to_entry(pid_t pid);
int seccomp_run_to_main(pid_t pid);
int seccomp_run_to_main_from_entry(pid_t pid);
int seccomp_read_syscall(pid_t pid, long *nr, long *args);
int seccomp_marker_addrs(pid_t pid, unsigned long *at_entry, unsigned long *lsm, int *main_argidx);
int seccomp_bp_arm(pid_t pid, unsigned long addr, struct seccomp_bp *bp);
int seccomp_bp_match(pid_t pid, struct seccomp_bp **bps, int n);
int seccomp_force_errno(pid_t pid, int err);
int seccomp_force_errno_exit(pid_t pid, int err);
#else
static inline int seccomp_inject(pid_t pid, struct sock_fprog *prog) {
	return -1;
}
static inline int seccomp_run_to_entry(pid_t pid) {
	return -1;
}
static inline int seccomp_run_to_main(pid_t pid) {
	return -1;
}
static inline int seccomp_run_to_main_from_entry(pid_t pid) {
	return -1;
}
static inline int seccomp_read_syscall(pid_t pid, long *nr, long *args) {
	return -1;
}
static inline int seccomp_marker_addrs(pid_t pid, unsigned long *at_entry, unsigned long *lsm, int *main_argidx) {
	return -1;
}
static inline int seccomp_bp_arm(pid_t pid, unsigned long addr, struct seccomp_bp *bp) {
	return -1;
}
static inline int seccomp_bp_match(pid_t pid, struct seccomp_bp **bps, int n) {
	return -1;
}
static inline int seccomp_force_errno(pid_t pid, int err) {
	return -1;
}
static inline int seccomp_force_errno_exit(pid_t pid, int err) {
	return -1;
}
#endif

#endif
