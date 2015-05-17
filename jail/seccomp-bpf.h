/*
 * seccomp example for x86 (32-bit and 64-bit) with BPF macros
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Will Drewry <wad@chromium.org>
 *  Kees Cook <keescook@chromium.org>
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef _SECCOMP_BPF_H_
#define _SECCOMP_BPF_H_

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>

#include <sys/prctl.h>
#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif

#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>

#ifdef HAVE_LINUX_SECCOMP_H
# include <linux/seccomp.h>
#endif

#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. */
#define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
#define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ERRNO	0x00050000U /* returns an errno */
#define SECCOMP_RET_LOG		0x00070000U
#define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */
#define SECCOMP_RET_ERROR(x)	(SECCOMP_RET_ERRNO | ((x) & 0x0000ffffU))
#define SECCOMP_RET_LOGGER(x)	(SECCOMP_RET_LOG | ((x) & 0x0000ffffU))

struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};
#endif

#ifndef SYS_SECCOMP
# define SYS_SECCOMP 1
#endif

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#if defined(__i386__)
# define REG_SYSCALL	REG_EAX
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define REG_SYSCALL	REG_RAX
# define ARCH_NR	AUDIT_ARCH_X86_64
#elif defined(__mips__)
# define REG_SYSCALL	regs[2]
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define ARCH_NR	AUDIT_ARCH_MIPSEL
# else
#  define ARCH_NR	AUDIT_ARCH_MIPS
# endif
#elif defined(__arm__) && (defined(__ARM_EABI__) || defined(__thumb__))
# define REG_SYSCALL	regs.uregs[7]
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define ARCH_NR	AUDIT_ARCH_ARM
# else
#  define ARCH_NR	AUDIT_ARCH_ARMEB
# endif
#else
# warning "Platform does not support seccomp filter yet"
# define REG_SYSCALL	0
# define ARCH_NR	0
#endif

#endif /* _SECCOMP_BPF_H_ */
