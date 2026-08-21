/*
 * Apply a compiled cBPF seccomp filter to a freshly-execve'd workload by
 * injecting prctl(PR_SET_NO_NEW_PRIVS) and seccomp(SET_MODE_FILTER) into the
 * tracee via ptrace. The tracee does PTRACE_TRACEME before its final execve;
 * the parent catches the post-execve stop (before the workload's first
 * userspace instruction), pokes the filter into the tracee's stack, drives the
 * two syscalls by single-stepping a temporary trap instruction at the program
 * counter, restores the saved registers and code, then detaches. This arms the
 * filter for statically and dynamically linked workloads alike, closing the
 * gap left by an LD_PRELOAD-based installer (which static binaries ignore).
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
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <limits.h>

#include "log.h"
#include "seccomp-inject.h"
#include "elf.h"

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef AT_NULL
#define AT_NULL 0
#endif
#ifndef AT_ENTRY
#define AT_ENTRY 9
#endif
#ifndef AT_BASE
#define AT_BASE 7
#endif
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif
#ifndef PTRACE_SET_SYSCALL
#define PTRACE_SET_SYSCALL 23
#endif

#if defined(__x86_64__)
typedef struct user_regs_struct inj_regs;
#define INJ_SYSCALL_ASM	"syscall"
#define INJ_BP_ASM	"int3"
static unsigned long inj_pc(const inj_regs *r)
{
	return r->rip;
}

static void inj_set_pc(inj_regs *r, unsigned long pc)
{
	r->rip = pc;
}

static unsigned long inj_sp(const inj_regs *r)
{
	return r->rsp;
}

static long inj_ret(const inj_regs *r)
{
	return r->rax;
}

static void inj_clear_restart(inj_regs *r)
{
	r->orig_rax = (unsigned long)-1;
}
static void inj_set_call(inj_regs *r, long nr, long a0, long a1, long a2,
			 long a3, long a4, long a5)
{
	r->rax = nr;
	r->orig_rax = nr;
	r->rdi = a0;
	r->rsi = a1;
	r->rdx = a2;
	r->r10 = a3;
	r->r8 = a4;
	r->r9 = a5;
}

static void inj_get_call(const inj_regs *r, long *nr, long *args)
{
	*nr = r->orig_rax;
	args[0] = r->rdi;
	args[1] = r->rsi;
	args[2] = r->rdx;
	args[3] = r->r10;
	args[4] = r->r8;
	args[5] = r->r9;
}

#elif defined(__i386__)
typedef struct user_regs_struct inj_regs;
#define INJ_SYSCALL_ASM	"int $0x80"
#define INJ_BP_ASM	"int3"
static unsigned long inj_pc(const inj_regs *r)
{
	return r->eip;
}

static void inj_set_pc(inj_regs *r, unsigned long pc)
{
	r->eip = pc;
}

static unsigned long inj_sp(const inj_regs *r)
{
	return r->esp;
}

static long inj_ret(const inj_regs *r)
{
	return r->eax;
}

static void inj_clear_restart(inj_regs *r)
{
	r->orig_eax = (unsigned long)-1;
}
static void inj_set_call(inj_regs *r, long nr, long a0, long a1, long a2,
			 long a3, long a4, long a5)
{
	r->eax = nr;
	r->orig_eax = nr;
	r->ebx = a0;
	r->ecx = a1;
	r->edx = a2;
	r->esi = a3;
	r->edi = a4;
	r->ebp = a5;
}

static void inj_get_call(const inj_regs *r, long *nr, long *args)
{
	*nr = r->orig_eax;
	args[0] = r->ebx;
	args[1] = r->ecx;
	args[2] = r->edx;
	args[3] = r->esi;
	args[4] = r->edi;
	args[5] = r->ebp;
}

#elif defined(__aarch64__)
typedef struct { unsigned long long regs[31], sp, pc, pstate; } inj_regs;
#define INJ_SYSCALL_ASM	"svc #0"
#define INJ_BP_ASM	"brk #0"
static unsigned long inj_pc(const inj_regs *r)
{
	return r->pc;
}

static void inj_set_pc(inj_regs *r, unsigned long pc)
{
	r->pc = pc;
}

static unsigned long inj_sp(const inj_regs *r)
{
	return r->sp;
}

static long inj_ret(const inj_regs *r)
{
	return r->regs[0];
}

static void inj_clear_restart(inj_regs *r)
{
	(void)r;
}
static void inj_set_call(inj_regs *r, long nr, long a0, long a1, long a2,
			 long a3, long a4, long a5)
{
	r->regs[8] = nr;
	r->regs[0] = a0;
	r->regs[1] = a1;
	r->regs[2] = a2;
	r->regs[3] = a3;
	r->regs[4] = a4;
	r->regs[5] = a5;
}

static void inj_get_call(const inj_regs *r, long *nr, long *args)
{
	*nr = r->regs[8];
	args[0] = r->regs[0];
	args[1] = r->regs[1];
	args[2] = r->regs[2];
	args[3] = r->regs[3];
	args[4] = r->regs[4];
	args[5] = r->regs[5];
}

#elif defined(__arm__)
typedef struct { unsigned long uregs[18]; } inj_regs;
#define INJ_SYSCALL_ASM	"svc #0"
static unsigned long inj_pc(const inj_regs *r)
{
	return r->uregs[15];
}

static void inj_set_pc(inj_regs *r, unsigned long pc)
{
	r->uregs[15] = pc;
}

static unsigned long inj_sp(const inj_regs *r)
{
	return r->uregs[13];
}

static long inj_ret(const inj_regs *r)
{
	return r->uregs[0];
}

static void inj_clear_restart(inj_regs *r) __attribute__((unused));
static void inj_clear_restart(inj_regs *r)
{
	(void)r;
}
static void inj_set_call(inj_regs *r, long nr, long a0, long a1, long a2,
			 long a3, long a4, long a5)
{
	r->uregs[7] = nr;
	r->uregs[0] = a0;
	r->uregs[1] = a1;
	r->uregs[2] = a2;
	r->uregs[3] = a3;
	r->uregs[4] = a4;
	r->uregs[5] = a5;
}

static void inj_get_call(const inj_regs *r, long *nr, long *args)
{
	*nr = r->uregs[7];
	args[0] = r->uregs[0];
	args[1] = r->uregs[1];
	args[2] = r->uregs[2];
	args[3] = r->uregs[3];
	args[4] = r->uregs[4];
	args[5] = r->uregs[5];
}

static int inj_thumb(const inj_regs *r)
{
	return (r->uregs[16] >> 5) & 1;
}

#elif defined(__riscv) && __riscv_xlen == 64
typedef struct {
	unsigned long pc, ra, sp, gp, tp, t0, t1, t2, s0, s1;
	unsigned long a0, a1, a2, a3, a4, a5, a6, a7;
	unsigned long s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;
	unsigned long t3, t4, t5, t6;
} inj_regs;
#define INJ_SYSCALL_ASM	"ecall"
#define INJ_BP_ASM	"ebreak"
#define INJ_NO_SINGLESTEP	1
static unsigned long inj_pc(const inj_regs *r)
{
	return r->pc;
}

static void inj_set_pc(inj_regs *r, unsigned long pc)
{
	r->pc = pc;
}

static unsigned long inj_sp(const inj_regs *r)
{
	return r->sp;
}

static long inj_ret(const inj_regs *r)
{
	return r->a0;
}

static void inj_clear_restart(inj_regs *r)
{
	(void)r;
}
static void inj_set_call(inj_regs *r, long nr, long a0, long a1, long a2,
			 long a3, long a4, long a5)
{
	r->a7 = nr;
	r->a0 = a0;
	r->a1 = a1;
	r->a2 = a2;
	r->a3 = a3;
	r->a4 = a4;
	r->a5 = a5;
}

static void inj_get_call(const inj_regs *r, long *nr, long *args)
{
	*nr = r->a7;
	args[0] = r->a0;
	args[1] = r->a1;
	args[2] = r->a2;
	args[3] = r->a3;
	args[4] = r->a4;
	args[5] = r->a5;
}

#elif defined(__loongarch__) && __loongarch_grlen == 64
typedef struct { unsigned long regs[32], orig_a0, csr_era, csr_badv, reserved[10]; } inj_regs;
#define INJ_SYSCALL_ASM	"syscall 0"
#define INJ_BP_ASM	"break 0"
#define INJ_NO_SINGLESTEP	1
static unsigned long inj_pc(const inj_regs *r)
{
	return r->csr_era;
}

static void inj_set_pc(inj_regs *r, unsigned long pc)
{
	r->csr_era = pc;
}

static unsigned long inj_sp(const inj_regs *r)
{
	return r->regs[3];
}

static long inj_ret(const inj_regs *r)
{
	return r->regs[4];
}

static void inj_clear_restart(inj_regs *r)
{
	(void)r;
}
static void inj_set_call(inj_regs *r, long nr, long a0, long a1, long a2,
			 long a3, long a4, long a5)
{
	r->regs[11] = nr;
	r->regs[4] = a0;
	r->regs[5] = a1;
	r->regs[6] = a2;
	r->regs[7] = a3;
	r->regs[8] = a4;
	r->regs[9] = a5;
}

static void inj_get_call(const inj_regs *r, long *nr, long *args)
{
	*nr = r->regs[11];
	args[0] = r->regs[4];
	args[1] = r->regs[5];
	args[2] = r->regs[6];
	args[3] = r->regs[7];
	args[4] = r->regs[8];
	args[5] = r->regs[9];
}

#elif defined(__mips__)
#ifndef ELF_NGREG
#define ELF_NGREG 45
#endif
#if _MIPS_SIM == _ABIO32
#define MIPS_EF_V0	8
#define MIPS_EF_A0	10
#define MIPS_EF_SP	35
#define MIPS_EF_A3	13
#define MIPS_EF_EPC	40
#else
#define MIPS_EF_V0	2
#define MIPS_EF_A0	4
#define MIPS_EF_SP	29
#define MIPS_EF_A3	7
#define MIPS_EF_EPC	34
#endif
typedef struct { unsigned long gregs[ELF_NGREG]; } inj_regs;
#define INJ_SYSCALL_ASM	"syscall"
#define INJ_BP_ASM	"break"
#define INJ_NO_SINGLESTEP	1
static unsigned long inj_pc(const inj_regs *r)
{
	return r->gregs[MIPS_EF_EPC];
}

static void inj_set_pc(inj_regs *r, unsigned long pc)
{
	r->gregs[MIPS_EF_EPC] = pc;
}

static unsigned long inj_sp(const inj_regs *r)
{
	return r->gregs[MIPS_EF_SP];
}

#if _MIPS_SIM == _ABIO32
static void inj_set_sp(inj_regs *r, unsigned long sp)
{
	r->gregs[MIPS_EF_SP] = sp;
}
#endif

static long inj_ret(const inj_regs *r)
{
	if (r->gregs[MIPS_EF_A3])
		return -(long)r->gregs[MIPS_EF_V0];

	return r->gregs[MIPS_EF_V0];
}

static void inj_clear_restart(inj_regs *r)
{
	(void)r;
}
static void inj_set_call(inj_regs *r, long nr, long a0, long a1, long a2,
			 long a3, long a4, long a5)
{
	r->gregs[MIPS_EF_V0] = nr;
	r->gregs[MIPS_EF_A0] = a0;
	r->gregs[MIPS_EF_A0 + 1] = a1;
	r->gregs[MIPS_EF_A0 + 2] = a2;
	r->gregs[MIPS_EF_A0 + 3] = a3;
#if _MIPS_SIM != _ABIO32
	r->gregs[MIPS_EF_A0 + 4] = a4;
	r->gregs[MIPS_EF_A0 + 5] = a5;
	r->gregs[MIPS_EF_A0 + 6] = 0;
	r->gregs[MIPS_EF_A0 + 7] = 0;
#else
	(void)a4;
	(void)a5;
#endif
}

static void inj_get_call(const inj_regs *r, long *nr, long *args)
{
	*nr = r->gregs[MIPS_EF_V0];
	args[0] = r->gregs[MIPS_EF_A0];
	args[1] = r->gregs[MIPS_EF_A0 + 1];
	args[2] = r->gregs[MIPS_EF_A0 + 2];
	args[3] = r->gregs[MIPS_EF_A0 + 3];
#if _MIPS_SIM != _ABIO32
	args[4] = r->gregs[MIPS_EF_A0 + 4];
	args[5] = r->gregs[MIPS_EF_A0 + 5];
#else
	args[4] = 0;
	args[5] = 0;
#endif
}

#elif defined(__powerpc64__)
typedef struct {
	unsigned long gpr[32];
	unsigned long nip, msr, orig_gpr3, ctr, link, xer, ccr, softe;
	unsigned long trap, dar, dsisr, result;
} inj_regs;
#define INJ_SYSCALL_ASM	"sc"
#define INJ_BP_ASM	"trap"
static unsigned long inj_pc(const inj_regs *r)
{
	return r->nip;
}

static void inj_set_pc(inj_regs *r, unsigned long pc)
{
	r->nip = pc;
}

static unsigned long inj_sp(const inj_regs *r)
{
	return r->gpr[1];
}

static long inj_ret(const inj_regs *r)
{
	if (r->ccr & 0x10000000UL)
		return -(long)r->gpr[3];
	return r->gpr[3];
}

static void inj_clear_restart(inj_regs *r)
{
	(void)r;
}
static void inj_set_call(inj_regs *r, long nr, long a0, long a1, long a2,
			 long a3, long a4, long a5)
{
	r->gpr[0] = nr;
	r->gpr[3] = a0;
	r->gpr[4] = a1;
	r->gpr[5] = a2;
	r->gpr[6] = a3;
	r->gpr[7] = a4;
	r->gpr[8] = a5;
}

static void inj_get_call(const inj_regs *r, long *nr, long *args)
{
	*nr = r->gpr[0];
	args[0] = r->gpr[3];
	args[1] = r->gpr[4];
	args[2] = r->gpr[5];
	args[3] = r->gpr[6];
	args[4] = r->gpr[7];
	args[5] = r->gpr[8];
}

#elif defined(__powerpc__)
typedef struct {
	unsigned long gpr[32];
	unsigned long nip, msr, orig_gpr3, ctr, link, xer, ccr, mq;
	unsigned long trap, dar, dsisr, result;
} inj_regs;
#define INJ_SYSCALL_ASM	"sc"
#define INJ_BP_ASM	"trap"
static unsigned long inj_pc(const inj_regs *r)
{
	return r->nip;
}

static void inj_set_pc(inj_regs *r, unsigned long pc)
{
	r->nip = pc;
}

static unsigned long inj_sp(const inj_regs *r)
{
	return r->gpr[1];
}

static long inj_ret(const inj_regs *r)
{
	if (r->ccr & 0x10000000UL)
		return -(long)r->gpr[3];
	return r->gpr[3];
}

static void inj_clear_restart(inj_regs *r)
{
	(void)r;
}
static void inj_set_call(inj_regs *r, long nr, long a0, long a1, long a2,
			 long a3, long a4, long a5)
{
	r->gpr[0] = nr;
	r->gpr[3] = a0;
	r->gpr[4] = a1;
	r->gpr[5] = a2;
	r->gpr[6] = a3;
	r->gpr[7] = a4;
	r->gpr[8] = a5;
}

static void inj_get_call(const inj_regs *r, long *nr, long *args)
{
	*nr = r->gpr[0];
	args[0] = r->gpr[3];
	args[1] = r->gpr[4];
	args[2] = r->gpr[5];
	args[3] = r->gpr[6];
	args[4] = r->gpr[7];
	args[5] = r->gpr[8];
}

#else
#error "unsupported architecture for seccomp ptrace injection"
#endif

#if defined(__arm__)
__asm__ (
	".pushsection .text\n"
	".arm\n"
	".globl inj_syscall_insn_arm\ninj_syscall_insn_arm:\n\t" INJ_SYSCALL_ASM "\n"
	".globl inj_syscall_insn_arm_end\ninj_syscall_insn_arm_end:\n"
	".globl inj_bp_insn_arm\ninj_bp_insn_arm:\n\t.inst 0xe7f001f0\n"
	".globl inj_bp_insn_arm_end\ninj_bp_insn_arm_end:\n"
	".thumb\n"
	".globl inj_syscall_insn_thumb\ninj_syscall_insn_thumb:\n\t" INJ_SYSCALL_ASM "\n"
	".globl inj_syscall_insn_thumb_end\ninj_syscall_insn_thumb_end:\n"
	".globl inj_bp_insn_thumb\ninj_bp_insn_thumb:\n\t.inst.n 0xde01\n"
	".globl inj_bp_insn_thumb_end\ninj_bp_insn_thumb_end:\n"
	".popsection\n"
);
extern const unsigned char inj_syscall_insn_arm[], inj_syscall_insn_arm_end[];
extern const unsigned char inj_syscall_insn_thumb[], inj_syscall_insn_thumb_end[];
extern const unsigned char inj_bp_insn_arm[], inj_bp_insn_arm_end[];
extern const unsigned char inj_bp_insn_thumb[], inj_bp_insn_thumb_end[];

#define INJ_INSN_MAX		16
#else
__asm__ (
	".pushsection .text\n"
	".globl inj_syscall_insn\ninj_syscall_insn:\n\t" INJ_SYSCALL_ASM "\n"
	".globl inj_syscall_insn_end\ninj_syscall_insn_end:\n"
	".globl inj_bp_insn\ninj_bp_insn:\n\t" INJ_BP_ASM "\n"
	".globl inj_bp_insn_end\ninj_bp_insn_end:\n"
	".popsection\n"
);
extern const unsigned char inj_syscall_insn[], inj_syscall_insn_end[];
extern const unsigned char inj_bp_insn[], inj_bp_insn_end[];

#define inj_syscall_len()	((size_t)(inj_syscall_insn_end - inj_syscall_insn))
#define inj_bp_len()		((size_t)(inj_bp_insn_end - inj_bp_insn))
#define INJ_INSN_MAX		16
#endif

static int inj_getregs(pid_t pid, inj_regs *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(*regs);

	return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static int inj_setregs(pid_t pid, inj_regs *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(*regs);

	return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

int seccomp_read_syscall(pid_t pid, long *nr, long *args)
{
	inj_regs regs;

	if (inj_getregs(pid, &regs))
		return -1;

	inj_get_call(&regs, nr, args);

	return 0;
}

static int inj_poke(pid_t pid, unsigned long addr, const void *src, size_t len)
{
	unsigned long word;
	size_t off, chunk;

	for (off = 0; off < len; off += sizeof(long)) {
		chunk = (len - off < sizeof(long)) ? (len - off) : sizeof(long);
		errno = 0;
		word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(addr + off), 0);
		if (word == (unsigned long)-1 && errno)
			return -1;
		memcpy(&word, (const char *)src + off, chunk);
		if (ptrace(PTRACE_POKETEXT, pid, (void *)(addr + off), (void *)word))
			return -1;
	}

	return 0;
}

static int inj_peek(pid_t pid, unsigned long addr, void *dst, size_t len)
{
	unsigned long word;
	size_t off, chunk;

	for (off = 0; off < len; off += sizeof(long)) {
		chunk = (len - off < sizeof(long)) ? (len - off) : sizeof(long);
		errno = 0;
		word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(addr + off), 0);
		if (word == (unsigned long)-1 && errno)
			return -1;
		memcpy((char *)dst + off, &word, chunk);
	}

	return 0;
}

#if !defined(__arm__)
#ifdef INJ_NO_SINGLESTEP
static int inj_step(pid_t pid, unsigned long pc, int *status)
{
	unsigned long bpaddr = pc + inj_syscall_len();
	unsigned char saved[INJ_INSN_MAX];
	size_t bplen = inj_bp_len();
	int rc = -1;

	if (inj_peek(pid, bpaddr, saved, bplen))
		return -1;
	if (inj_poke(pid, bpaddr, inj_bp_insn, bplen))
		return -1;

	if (ptrace(PTRACE_CONT, pid, 0, 0))
		goto out;
	if (waitpid(pid, status, 0) < 0)
		goto out;
	rc = 0;

out:
	inj_poke(pid, bpaddr, saved, bplen);
	return rc;
}
#else
static int inj_step(pid_t pid, unsigned long pc, int *status)
{
	(void)pc;

	if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0))
		return -1;
	if (waitpid(pid, status, 0) < 0)
		return -1;

	return 0;
}
#endif

static int inj_call(pid_t pid, const inj_regs *base, unsigned long pc,
		    long nr, long a0, long a1, long a2,
		    long a3, long a4, long a5, long *ret)
{
	inj_regs regs;
	int status;
#if defined(__mips__) && _MIPS_SIM == _ABIO32
	unsigned long scratch;
	unsigned long stkargs[4];
#endif

	for (;;) {
		regs = *base;
		inj_set_pc(&regs, pc);
		inj_set_call(&regs, nr, a0, a1, a2, a3, a4, a5);
#if defined(__mips__) && _MIPS_SIM == _ABIO32
		scratch = (inj_sp(base) - 256) & ~0xfUL;
		stkargs[0] = a4;
		stkargs[1] = a5;
		stkargs[2] = 0;
		stkargs[3] = 0;
		inj_set_sp(&regs, scratch);
		if (inj_poke(pid, scratch + 16, stkargs, sizeof(stkargs)))
			return -1;
#endif
		if (inj_setregs(pid, &regs))
			return -1;

		if (inj_step(pid, pc, &status))
			return -1;
		if (WIFEXITED(status) || WIFSIGNALED(status))
			return -1;
		if (inj_getregs(pid, &regs))
			return -1;
		if (inj_pc(&regs) != pc)
			break;
	}

	*ret = inj_ret(&regs);

	return 0;
}
#endif

static int read_auxv(pid_t pid, unsigned long type, unsigned long *val)
{
	char path[64];
	unsigned long pair[2];
	int fd;
	ssize_t n;
	int ret = -1;

	snprintf(path, sizeof(path), "/proc/%d/auxv", (int)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	while ((n = read(fd, pair, sizeof(pair))) == (ssize_t)sizeof(pair)) {
		if (pair[0] == type) {
			*val = pair[1];
			ret = 0;
			break;
		}
		if (pair[0] == AT_NULL)
			break;
	}

	close(fd);
	return ret;
}

#if defined(__arm__)

static int arm_thumb_at(unsigned long entry)
{
	return (int)(entry & 1UL);
}

static const unsigned char *arm_bp_insn(int thumb, size_t *len)
{
	if (thumb) {
		*len = (size_t)(inj_bp_insn_thumb_end - inj_bp_insn_thumb);
		return inj_bp_insn_thumb;
	}
	*len = (size_t)(inj_bp_insn_arm_end - inj_bp_insn_arm);
	return inj_bp_insn_arm;
}

static const unsigned char *arm_syscall_insn(int thumb, size_t *len)
{
	if (thumb) {
		*len = (size_t)(inj_syscall_insn_thumb_end - inj_syscall_insn_thumb);
		return inj_syscall_insn_thumb;
	}
	*len = (size_t)(inj_syscall_insn_arm_end - inj_syscall_insn_arm);
	return inj_syscall_insn_arm;
}

static int inj_call_arm(pid_t pid, const inj_regs *base, unsigned long pc,
			int thumb, long nr, long a0, long a1, long a2,
			long a3, long a4, long a5, long *ret)
{
	const unsigned char *sci, *bpi;
	size_t scilen, bpilen;
	unsigned char saved[INJ_INSN_MAX];
	inj_regs regs;
	int status;

	sci = arm_syscall_insn(thumb, &scilen);
	bpi = arm_bp_insn(thumb, &bpilen);

	if (inj_peek(pid, pc, saved, scilen + bpilen))
		return -1;
	if (inj_poke(pid, pc, sci, scilen))
		return -1;
	if (inj_poke(pid, pc + scilen, bpi, bpilen))
		goto restore;

	regs = *base;
	inj_set_pc(&regs, pc);
	inj_set_call(&regs, nr, a0, a1, a2, a3, a4, a5);
	if (inj_setregs(pid, &regs))
		goto restore;

	if (ptrace(PTRACE_CONT, pid, 0, 0))
		goto restore;
	if (waitpid(pid, &status, 0) < 0)
		goto restore;
	if (!WIFSTOPPED(status))
		goto restore;

	if (inj_getregs(pid, &regs))
		goto restore;

	inj_poke(pid, pc, saved, scilen + bpilen);
	*ret = inj_ret(&regs);

	return 0;

restore:
	inj_poke(pid, pc, saved, scilen + bpilen);
	return -1;
}

static int seccomp_run_to_entry_arm(pid_t pid)
{
	const unsigned char *bp;
	size_t bplen;
	unsigned char saved[INJ_INSN_MAX];
	unsigned long entry, addr;
	inj_regs regs;
	int status, sig = 0, thumb;

	if (read_auxv(pid, AT_ENTRY, &entry)) {
		ERROR("seccomp-inject: cannot read AT_ENTRY: %m\n");
		return -1;
	}

	thumb = arm_thumb_at(entry);
	addr = entry & ~1UL;
	bp = arm_bp_insn(thumb, &bplen);

	if (inj_peek(pid, addr, saved, bplen)) {
		ERROR("seccomp-inject: read entry: %m\n");
		return -1;
	}
	if (inj_poke(pid, addr, bp, bplen)) {
		ERROR("seccomp-inject: poke entry breakpoint: %m\n");
		return -1;
	}

	for (;;) {
		if (ptrace(PTRACE_CONT, pid, 0, (void *)(long)sig)) {
			ERROR("seccomp-inject: PTRACE_CONT to entry: %m\n");
			goto restore;
		}
		if (waitpid(pid, &status, 0) < 0) {
			ERROR("seccomp-inject: waitpid to entry: %m\n");
			goto restore;
		}
		if (!WIFSTOPPED(status)) {
			ERROR("seccomp-inject: workload exited before entry\n");
			return -1;
		}
		if (WSTOPSIG(status) == SIGTRAP)
			break;
		sig = WSTOPSIG(status);
	}

	if (inj_getregs(pid, &regs)) {
		ERROR("seccomp-inject: GETREGSET at entry: %m\n");
		goto restore;
	}
	inj_set_pc(&regs, addr);
	if (inj_setregs(pid, &regs)) {
		ERROR("seccomp-inject: SETREGSET at entry: %m\n");
		goto restore;
	}
	inj_poke(pid, addr, saved, bplen);

	return 0;

restore:
	inj_poke(pid, addr, saved, bplen);
	return -1;
}

static int seccomp_inject_arm(pid_t pid, struct sock_fprog *prog)
{
	inj_regs saved;
	struct sock_fprog rprog;
	unsigned long sp, pc, filter_addr, prog_addr;
	size_t filterlen;
	long ret;
	int thumb;

	if (inj_getregs(pid, &saved)) {
		ERROR("seccomp-inject: GETREGSET: %m\n");
		return -1;
	}

	thumb = inj_thumb(&saved);

	pc = inj_pc(&saved);
	sp = inj_sp(&saved);
	filterlen = (size_t)prog->len * sizeof(struct sock_filter);

	filter_addr = (sp - 4096 - filterlen - sizeof(rprog)) & ~0xfUL;
	prog_addr = (filter_addr + filterlen + 0xf) & ~0xfUL;

	if (inj_poke(pid, filter_addr, prog->filter, filterlen)) {
		ERROR("seccomp-inject: poke filter: %m\n");
		return -1;
	}

	rprog.len = prog->len;
	rprog.filter = (struct sock_filter *)(uintptr_t)filter_addr;
	if (inj_poke(pid, prog_addr, &rprog, sizeof(rprog))) {
		ERROR("seccomp-inject: poke fprog: %m\n");
		return -1;
	}

	if (inj_call_arm(pid, &saved, pc, thumb, SYS_prctl,
			 PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0, &ret)) {
		ERROR("seccomp-inject: drive prctl: %m\n");
		goto restore;
	}
	if (ret) {
		ERROR("seccomp-inject: PR_SET_NO_NEW_PRIVS returned %ld\n", ret);
		goto restore;
	}

	if (inj_call_arm(pid, &saved, pc, thumb, SYS_seccomp,
			 SECCOMP_SET_MODE_FILTER, 0, (long)prog_addr, 0, 0, 0, &ret)) {
		ERROR("seccomp-inject: drive seccomp: %m\n");
		goto restore;
	}
	if (ret) {
		ERROR("seccomp-inject: seccomp(SET_MODE_FILTER) returned %ld\n", ret);
		goto restore;
	}

	if (inj_setregs(pid, &saved)) {
		ERROR("seccomp-inject: restore SETREGSET: %m\n");
		return -1;
	}

	return 0;

restore:
	inj_setregs(pid, &saved);
	return -1;
}
#endif

#if !defined(__arm__)
static int run_to_addr(pid_t pid, unsigned long addr)
{
	const unsigned char *bp = inj_bp_insn;
	size_t bplen = inj_bp_len();
	unsigned char saved[INJ_INSN_MAX];
	inj_regs regs;
	int status, sig = 0;

	if (inj_peek(pid, addr, saved, bplen)) {
		ERROR("seccomp-inject: read bp target: %m\n");
		return -1;
	}
	if (inj_poke(pid, addr, bp, bplen)) {
		ERROR("seccomp-inject: poke breakpoint: %m\n");
		return -1;
	}

	for (;;) {
		if (ptrace(PTRACE_CONT, pid, 0, (void *)(long)sig)) {
			ERROR("seccomp-inject: PTRACE_CONT to bp: %m\n");
			goto restore;
		}
		if (waitpid(pid, &status, 0) < 0) {
			ERROR("seccomp-inject: waitpid to bp: %m\n");
			goto restore;
		}
		if (!WIFSTOPPED(status)) {
			ERROR("seccomp-inject: workload exited before reaching target\n");
			return -1;
		}
		if (WSTOPSIG(status) == SIGTRAP)
			break;
		sig = WSTOPSIG(status);
	}

	if (inj_getregs(pid, &regs)) {
		ERROR("seccomp-inject: GETREGSET at bp: %m\n");
		goto restore;
	}
	inj_set_pc(&regs, addr);
	if (inj_setregs(pid, &regs)) {
		ERROR("seccomp-inject: SETREGSET at bp: %m\n");
		goto restore;
	}
	inj_poke(pid, addr, saved, bplen);

	return 0;

restore:
	inj_poke(pid, addr, saved, bplen);
	return -1;
}
#endif

int seccomp_run_to_entry(pid_t pid)
{
#if defined(__arm__)
	return seccomp_run_to_entry_arm(pid);
#else
	unsigned long entry;

	if (read_auxv(pid, AT_ENTRY, &entry)) {
		ERROR("seccomp-inject: cannot read AT_ENTRY: %m\n");
		return -1;
	}

	return run_to_addr(pid, entry);
#endif
}

#if !defined(__arm__) && !defined(__i386__)
static unsigned long find_libc_init(pid_t pid, int *main_argidx)
{
	char path[64], line[600], rooted[PATH_MAX + 64], p[PATH_MAX];
	char seen[48][256];
	unsigned long bases[48];
	unsigned long lo, hi, val;
	int nseen = 0, i;
	FILE *f;

	*main_argidx = 0;
	snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
	f = fopen(path, "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx %*s %*s %*s %*s %4095s", &lo, &hi, p) < 3)
			continue;
		if (p[0] != '/')
			continue;
		for (i = 0; i < nseen; i++)
			if (!strcmp(seen[i], p))
				break;
		if (i < nseen || nseen >= 48)
			continue;
		strncpy(seen[nseen], p, sizeof(seen[0]) - 1);
		seen[nseen][sizeof(seen[0]) - 1] = '\0';
		bases[nseen] = lo;
		nseen++;
	}
	fclose(f);

	for (i = 0; i < nseen; i++) {
		snprintf(rooted, sizeof(rooted), "/proc/%d/root%s", (int)pid, seen[i]);
		val = elf_dynsym_value(rooted, "__libc_start_main");
		if (val) {
			*main_argidx = 0;
			return bases[i] + val;
		}
	}
	for (i = 0; i < nseen; i++) {
		snprintf(rooted, sizeof(rooted), "/proc/%d/root%s", (int)pid, seen[i]);
		val = elf_dynsym_value(rooted, "__libc_init");
		if (val) {
			*main_argidx = 2;
			return bases[i] + val;
		}
	}
	return 0;
}
#endif

int seccomp_marker_addrs(pid_t pid, unsigned long *at_entry, unsigned long *lsm, int *main_argidx)
{
	*at_entry = 0;
	*lsm = 0;
	*main_argidx = 0;

	if (read_auxv(pid, AT_ENTRY, at_entry))
		return -1;

#if !defined(__arm__) && !defined(__i386__)
	*lsm = find_libc_init(pid, main_argidx);
#endif

	return 0;
}

int seccomp_run_to_main(pid_t pid)
{
#if defined(__arm__)
	return seccomp_run_to_entry(pid);
#else
	unsigned long at_entry, lsm, mainaddr;
	long nr, args[6];
	int main_argidx;

	if (seccomp_marker_addrs(pid, &at_entry, &lsm, &main_argidx))
		return -1;
	if (!lsm)
		return seccomp_run_to_entry(pid);

	if (run_to_addr(pid, lsm))
		return -1;
	if (seccomp_read_syscall(pid, &nr, args))
		return -1;

	mainaddr = (unsigned long)args[main_argidx];
	if (!mainaddr)
		return -1;

	return run_to_addr(pid, mainaddr);
#endif
}

int seccomp_run_to_main_from_entry(pid_t pid)
{
#if defined(__arm__)
	return 1;
#else
	unsigned long at_entry, lsm, mainaddr;
	long nr, args[6];
	int main_argidx;

	if (seccomp_marker_addrs(pid, &at_entry, &lsm, &main_argidx))
		return -1;
	if (!lsm)
		return 1;

	if (run_to_addr(pid, lsm))
		return -1;
	if (seccomp_read_syscall(pid, &nr, args))
		return -1;

	mainaddr = (unsigned long)args[main_argidx];
	if (!mainaddr)
		return -1;

	if (run_to_addr(pid, mainaddr))
		return -1;

	return 0;
#endif
}

int seccomp_bp_arm(pid_t pid, unsigned long addr, struct seccomp_bp *bp)
{
#if defined(__arm__)
	const unsigned char *ins;
	size_t len;
	int thumb;

	thumb = arm_thumb_at(addr);
	bp->addr = addr & ~1UL;
	ins = arm_bp_insn(thumb, &len);
#else
	const unsigned char *ins = inj_bp_insn;
	size_t len = inj_bp_len();

	bp->addr = addr;
#endif

	if (len > sizeof(bp->saved))
		return -1;
	if (inj_peek(pid, bp->addr, bp->saved, len))
		return -1;
	if (inj_poke(pid, bp->addr, ins, len))
		return -1;

	bp->len = (unsigned char)len;
	bp->armed = 1;

	return 0;
}

int seccomp_bp_match(pid_t pid, struct seccomp_bp **bps, int n)
{
	inj_regs regs;
	unsigned long pc;
	int i;

	if (inj_getregs(pid, &regs))
		return -1;

	pc = inj_pc(&regs);
#if defined(__arm__)
	pc &= ~1UL;
#endif

	for (i = 0; i < n; i++) {
		if (!bps[i] || !bps[i]->armed)
			continue;
		if (pc != bps[i]->addr && pc != bps[i]->addr + bps[i]->len)
			continue;

		inj_poke(pid, bps[i]->addr, bps[i]->saved, bps[i]->len);
		inj_set_pc(&regs, bps[i]->addr);
		if (inj_setregs(pid, &regs))
			return -1;
		bps[i]->armed = 0;

		return i;
	}

	return -1;
}

int seccomp_force_errno(pid_t pid, int err)
{
#if defined(__aarch64__)
	inj_regs regs;
	int scno = -1;
	struct iovec iov;

	iov.iov_base = &scno;
	iov.iov_len = sizeof(scno);
	if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_SYSTEM_CALL, &iov))
		return -1;
	if (inj_getregs(pid, &regs))
		return -1;
	regs.regs[0] = (unsigned long long)(long long)-err;
	if (inj_setregs(pid, &regs))
		return -1;

	return 0;
#elif defined(__arm__)
	inj_regs regs;

	if (ptrace(PTRACE_SET_SYSCALL, pid, 0, (void *)-1L))
		return -1;
	if (inj_getregs(pid, &regs))
		return -1;
	regs.uregs[0] = (unsigned long)(long)-err;
	if (inj_setregs(pid, &regs))
		return -1;

	return 0;
#elif defined(__mips__)
	inj_regs regs;

	if (inj_getregs(pid, &regs))
		return -1;
	regs.gregs[MIPS_EF_V0] = (unsigned long)(long)-1;
	if (inj_setregs(pid, &regs))
		return -1;

	return 1;
#elif defined(__x86_64__) || defined(__i386__) || \
      (defined(__riscv) && __riscv_xlen == 64) || \
      (defined(__loongarch__) && __loongarch_grlen == 64) || \
      defined(__powerpc64__) || defined(__powerpc__)
	inj_regs regs;

	if (inj_getregs(pid, &regs))
		return -1;

#if defined(__x86_64__)
	regs.orig_rax = (unsigned long)-1;
	regs.rax = (unsigned long)(long)-err;
#elif defined(__i386__)
	regs.orig_eax = (unsigned long)-1;
	regs.eax = (unsigned long)(long)-err;
#elif defined(__riscv) && __riscv_xlen == 64
	regs.a7 = (unsigned long)-1;
	regs.a0 = (unsigned long)(long)-err;
#elif defined(__loongarch__) && __loongarch_grlen == 64
	regs.regs[11] = (unsigned long)-1;
	regs.regs[4] = (unsigned long)(long)-err;
#else
	regs.gpr[0] = (unsigned long)-1;
	regs.gpr[3] = (unsigned long)err;
	regs.ccr |= 0x10000000UL;
#endif

	if (inj_setregs(pid, &regs))
		return -1;

	return 0;
#else
	(void)pid;
	(void)err;
	return -1;
#endif
}

int seccomp_force_errno_exit(pid_t pid, int err)
{
#if defined(__mips__)
	inj_regs regs;

	if (inj_getregs(pid, &regs))
		return -1;

	regs.gregs[MIPS_EF_V0] = (unsigned long)(long)err;
	regs.gregs[MIPS_EF_A3] = 1;

	if (inj_setregs(pid, &regs))
		return -1;

	return 0;
#else
	(void)pid;
	(void)err;
	return -1;
#endif
}

int seccomp_inject(pid_t pid, struct sock_fprog *prog)
{
#if defined(__arm__)
	return seccomp_inject_arm(pid, prog);
#else
	inj_regs saved;
	struct sock_fprog rprog;
	unsigned char savedinsn[INJ_INSN_MAX];
	unsigned long sp, pc, filter_addr, prog_addr;
	size_t filterlen;
	long ret;

	if (inj_getregs(pid, &saved)) {
		ERROR("seccomp-inject: GETREGSET: %m\n");
		return -1;
	}

	pc = inj_pc(&saved);
	sp = inj_sp(&saved);
	filterlen = (size_t)prog->len * sizeof(struct sock_filter);

	filter_addr = (sp - 4096 - filterlen - sizeof(rprog)) & ~0xfUL;
	prog_addr = (filter_addr + filterlen + 0xf) & ~0xfUL;

	if (inj_peek(pid, pc, savedinsn, inj_syscall_len())) {
		ERROR("seccomp-inject: read pc: %m\n");
		return -1;
	}
	if (inj_poke(pid, pc, inj_syscall_insn, inj_syscall_len())) {
		ERROR("seccomp-inject: poke trap: %m\n");
		return -1;
	}
	if (inj_poke(pid, filter_addr, prog->filter, filterlen)) {
		ERROR("seccomp-inject: poke filter: %m\n");
		goto restore;
	}

	rprog.len = prog->len;
	rprog.filter = (struct sock_filter *)(uintptr_t)filter_addr;
	if (inj_poke(pid, prog_addr, &rprog, sizeof(rprog))) {
		ERROR("seccomp-inject: poke fprog: %m\n");
		goto restore;
	}

	if (inj_call(pid, &saved, pc, SYS_prctl,
		     PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0, &ret)) {
		ERROR("seccomp-inject: drive prctl: %m\n");
		goto restore;
	}
	if (ret) {
		ERROR("seccomp-inject: PR_SET_NO_NEW_PRIVS returned %ld\n", ret);
		goto restore;
	}

	if (inj_call(pid, &saved, pc, SYS_seccomp,
		     SECCOMP_SET_MODE_FILTER, 0, (long)prog_addr, 0, 0, 0, &ret)) {
		ERROR("seccomp-inject: drive seccomp: %m\n");
		goto restore;
	}
	if (ret) {
		ERROR("seccomp-inject: seccomp(SET_MODE_FILTER) returned %ld\n", ret);
		goto restore;
	}

	inj_poke(pid, pc, savedinsn, inj_syscall_len());
	inj_clear_restart(&saved);
	if (inj_setregs(pid, &saved)) {
		ERROR("seccomp-inject: restore SETREGSET: %m\n");
		return -1;
	}

	return 0;

restore:
	inj_poke(pid, pc, savedinsn, inj_syscall_len());
	inj_clear_restart(&saved);
	inj_setregs(pid, &saved);

	return -1;
#endif
}
