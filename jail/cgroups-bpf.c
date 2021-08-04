/*
 * Copyright (C) 2021 Daniel Golle <daniel@makrotopia.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * somehow emulate devices.allow/devices.deny using eBPF
 *
 * OCI run-time spec defines the syntax for allowing/denying access
 * to devices according to the definition of cgroup-v1 in the Kernel
 * as described in Documentation/admin-guide/cgroup-v1.
 */

#include <assert.h>
#include <linux/bpf.h>
#ifdef __GLIBC__
#include <sys/cdefs.h>
#else
#include <sys/reg.h>
#endif
#include <sys/syscall.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/list.h>

#include "cgroups.h"
#include "cgroups-bpf.h"
#include "log.h"

static struct bpf_insn *program = NULL;
static int bpf_total_insn = 0;
static const char *license = "GPL";

static int
syscall_bpf (int cmd, union bpf_attr *attr, unsigned int size)
{
	return (int) syscall (__NR_bpf, cmd, attr, size);
}

/* from crun/src/libcrun/ebpf.c */
#define BPF_ALU32_IMM(OP, DST, IMM) \
	((struct bpf_insn){ .code = BPF_ALU | BPF_OP (OP) | BPF_K, .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM })

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) \
	((struct bpf_insn){                    \
		.code = BPF_LDX | BPF_SIZE (SIZE) | BPF_MEM, .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0 })

#define BPF_MOV64_REG(DST, SRC) \
	((struct bpf_insn){ .code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0 })

#define BPF_JMP_A(OFF) \
	((struct bpf_insn){ .code = BPF_JMP | BPF_JA, .dst_reg = 0, .src_reg = 0, .off = OFF, .imm = 0 })

#define BPF_JMP_IMM(OP, DST, IMM, OFF) \
	((struct bpf_insn){ .code = BPF_JMP | BPF_OP (OP) | BPF_K, .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM })

#define BPF_JMP_REG(OP, DST, SRC, OFF) \
	((struct bpf_insn){ .code = BPF_JMP | BPF_OP (OP) | BPF_X, .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0 })

#define BPF_MOV64_IMM(DST, IMM) \
	((struct bpf_insn){ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM })

#define BPF_MOV32_REG(DST, SRC) \
	((struct bpf_insn){ .code = BPF_ALU | BPF_MOV | BPF_X, .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0 })

#define BPF_EXIT_INSN() \
	((struct bpf_insn){ .code = BPF_JMP | BPF_EXIT, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 })

/* taken from systemd.  */
static const struct bpf_insn pre_insn[] = {
	/* type -> R2.  */
	BPF_LDX_MEM (BPF_W, BPF_REG_2, BPF_REG_1, 0),
	BPF_ALU32_IMM (BPF_AND, BPF_REG_2, 0xFFFF),
	/* access -> R3.  */
	BPF_LDX_MEM (BPF_W, BPF_REG_3, BPF_REG_1, 0),
	BPF_ALU32_IMM (BPF_RSH, BPF_REG_3, 16),
	/* major -> R4.  */
	BPF_LDX_MEM (BPF_W, BPF_REG_4, BPF_REG_1, 4),
	/* minor -> R5.  */
	BPF_LDX_MEM (BPF_W, BPF_REG_5, BPF_REG_1, 8),
};

enum {
	OCI_LINUX_CGROUPS_DEVICES_ALLOW,
	OCI_LINUX_CGROUPS_DEVICES_TYPE,
	OCI_LINUX_CGROUPS_DEVICES_MAJOR,
	OCI_LINUX_CGROUPS_DEVICES_MINOR,
	OCI_LINUX_CGROUPS_DEVICES_ACCESS,
	__OCI_LINUX_CGROUPS_DEVICES_MAX,
};

static const struct blobmsg_policy oci_linux_cgroups_devices_policy[] = {
	[OCI_LINUX_CGROUPS_DEVICES_ALLOW] = { "allow", BLOBMSG_TYPE_BOOL },
	[OCI_LINUX_CGROUPS_DEVICES_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[OCI_LINUX_CGROUPS_DEVICES_MAJOR] = { "major", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_CGROUPS_DEVICES_MINOR] = { "minor", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_CGROUPS_DEVICES_ACCESS] = { "access", BLOBMSG_TYPE_STRING },
};

/*
 * cgroup-v1 devices got a (default) behaviour and a list of exceptions.
 * define datatypes similar to the legacy kernel code.
 */
#define DEVCG_DEV_ALL (BPF_DEVCG_DEV_BLOCK | BPF_DEVCG_DEV_CHAR)
#define DEVCG_ACC_ALL (BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD)

enum devcg_behavior {
	DEVCG_DEFAULT_NONE,
	DEVCG_DEFAULT_ALLOW,
	DEVCG_DEFAULT_DENY,
};

struct dev_exception_item {
	uint32_t		major, minor;
	short			type;
	short			access;
	struct list_head	list;
	bool			allow;
};

/*
 * add a bunch of default rules
 */
static int add_default_exceptions(struct list_head *exceptions)
{
	int i, ret = 0;
	struct dev_exception_item *cur;
	/* from crun/src/libcrun/cgroup.c */
	const struct dev_exception_item defrules[] = {
		/* always allow mknod */
		{ .allow = true, .type = BPF_DEVCG_DEV_CHAR,  .major = ~0,  .minor = ~0,  .access = BPF_DEVCG_ACC_MKNOD },
		{ .allow = true, .type = BPF_DEVCG_DEV_BLOCK, .major = ~0,  .minor = ~0,  .access = BPF_DEVCG_ACC_MKNOD },
		/* /dev/null */
		{ .allow = true, .type = BPF_DEVCG_DEV_CHAR,  .major = 1,   .minor = 3,   .access = DEVCG_ACC_ALL },
		/* /dev/random */
		{ .allow = true, .type = BPF_DEVCG_DEV_CHAR,  .major = 1,   .minor = 8,   .access = DEVCG_ACC_ALL },
		/* /dev/full */
		{ .allow = true, .type = BPF_DEVCG_DEV_CHAR,  .major = 1,   .minor = 7,   .access = DEVCG_ACC_ALL },
		/* /dev/tty */
		{ .allow = true, .type = BPF_DEVCG_DEV_CHAR,  .major = 5,   .minor = 0,   .access = DEVCG_ACC_ALL },
		/* /dev/zero */
		{ .allow = true, .type = BPF_DEVCG_DEV_CHAR,  .major = 1,   .minor = 5,   .access = DEVCG_ACC_ALL },
		/* /dev/urandom */
		{ .allow = true, .type = BPF_DEVCG_DEV_CHAR,  .major = 1,   .minor = 9,   .access = DEVCG_ACC_ALL },
		/* /dev/console */
		{ .allow = true, .type = BPF_DEVCG_DEV_CHAR,  .major = 5,   .minor = 1,   .access = DEVCG_ACC_ALL },
		/* /dev/pts/[0-255] */
		{ .allow = true, .type = BPF_DEVCG_DEV_CHAR,  .major = 136, .minor = ~0,  .access = DEVCG_ACC_ALL },
		/* /dev/ptmx */
		{ .allow = true, .type = BPF_DEVCG_DEV_CHAR,  .major = 5,   .minor = 2,   .access = DEVCG_ACC_ALL },
		/* /dev/net/tun */
		{ .allow = true, .type = BPF_DEVCG_DEV_CHAR,  .major = 10,  .minor = 200, .access = DEVCG_ACC_ALL },
	};

	for (i = 0; i < (sizeof(defrules) / sizeof(struct dev_exception_item)); ++i) {
		cur = malloc(sizeof(struct dev_exception_item));
		if (!cur) {
			ret = ENOMEM;
			break;
		}
		/* add defaults to list in reverse order (last item will be first in list) */
		memcpy(cur, &defrules[i], sizeof(struct dev_exception_item));
		list_add(&cur->list, exceptions);
	}

	return ret;
}

/*
 * free all exceptions in the list
 */
static void flush_exceptions(struct list_head *freelist)
{
	struct dev_exception_item *dl, *dln;

	if (!list_empty(freelist))
		list_for_each_entry_safe(dl, dln, freelist, list) {
			list_del(&dl->list);
			free(dl);
		}
}

/*
 * parse OCI cgroups devices and translate into cgroups-v2 eBPF program
 */
int parseOCIlinuxcgroups_devices(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_CGROUPS_DEVICES_MAX];
	struct blob_attr *cur;
	int rem, ret = 0;
	int bpf_type, bpf_access;
	unsigned char acidx;
	bool allow = false,
	     has_access = false,
	     has_type = false,
	     has_major = false,
	     has_minor = false;
	int total_ins = 0,
	    cur_ins = 0,
	    pre_insn_len = sizeof(pre_insn) / sizeof(struct bpf_insn),
	    next_ins;
	char *access, *devtype;
	uint32_t devmajor, devminor;
	struct dev_exception_item *dl;
	struct list_head exceptions;
	enum devcg_behavior behavior = DEVCG_DEFAULT_ALLOW;
	INIT_LIST_HEAD(&exceptions);

	/* parse according to OCI spec */
	blobmsg_for_each_attr(cur, msg, rem) {
		blobmsg_parse(oci_linux_cgroups_devices_policy, __OCI_LINUX_CGROUPS_DEVICES_MAX,
			      tb, blobmsg_data(cur), blobmsg_len(cur));

		if (!tb[OCI_LINUX_CGROUPS_DEVICES_ALLOW]) {
			ret = EINVAL;
			goto out;
		}

		allow = blobmsg_get_bool(tb[OCI_LINUX_CGROUPS_DEVICES_ALLOW]);

		bpf_access = 0;
		if (tb[OCI_LINUX_CGROUPS_DEVICES_ACCESS]) {
			access = blobmsg_get_string(tb[OCI_LINUX_CGROUPS_DEVICES_ACCESS]);
			if ((strlen(access) > 3) || (strlen(access) == 0)) {
				ret = EINVAL;
				goto out;
			}

			for (acidx = 0; acidx < strlen(access); ++acidx) {
				switch (access[acidx]) {
					case 'r':
						bpf_access |= BPF_DEVCG_ACC_READ;
						break;
					case 'w':
						bpf_access |= BPF_DEVCG_ACC_WRITE;
						break;
					case 'm':
						bpf_access |= BPF_DEVCG_ACC_MKNOD;
						break;
					default:
						ret = EINVAL;
						goto out;
				}
			}
		}

		if (!bpf_access)
			bpf_access = DEVCG_ACC_ALL;

		bpf_type = 0;
		if (tb[OCI_LINUX_CGROUPS_DEVICES_TYPE]) {
			devtype = blobmsg_get_string(tb[OCI_LINUX_CGROUPS_DEVICES_TYPE]);

			switch (devtype[0]) {
				case 'c':
					bpf_type = BPF_DEVCG_DEV_CHAR;
					break;
				case 'b':
					bpf_type = BPF_DEVCG_DEV_BLOCK;
					break;
				case 'a':
					bpf_type = DEVCG_DEV_ALL;
					break;
				default:
					ret = EINVAL;
					goto out;
			}
		}

		if (!bpf_type)
			bpf_type = DEVCG_DEV_ALL;

		if (tb[OCI_LINUX_CGROUPS_DEVICES_MAJOR])
			devmajor = blobmsg_cast_u64(tb[OCI_LINUX_CGROUPS_DEVICES_MAJOR]);
		else
			devmajor = ~0;

		if (tb[OCI_LINUX_CGROUPS_DEVICES_MINOR])
			devminor = blobmsg_cast_u64(tb[OCI_LINUX_CGROUPS_DEVICES_MINOR]);
		else
			devminor = ~0;

		if (bpf_type == DEVCG_DEV_ALL) {
			/* wildcard => change default policy and flush all existing rules */
			flush_exceptions(&exceptions);
			behavior = allow?DEVCG_DEFAULT_ALLOW:DEVCG_DEFAULT_DENY;
		} else {
			/* allocate and populate record for exception */
			dl = malloc(sizeof(struct dev_exception_item));
			if (!dl) {
				ret = ENOSPC;
				break;
			}
			dl->allow = allow;
			dl->type = bpf_type;
			dl->access = bpf_access;
			dl->major = devmajor;
			dl->minor = devminor;

			/* push to exceptions list, last goes first */
			list_add(&dl->list, &exceptions);
		}
	}
	if (ret)
		goto out;

	/* add default rules */
	ret = add_default_exceptions(&exceptions);
	if (ret)
		goto out;

	/* calculate number of instructions to allocate */
	list_for_each_entry(dl, &exceptions, list) {
		has_access = dl->access != DEVCG_ACC_ALL;
		has_type = dl->type != DEVCG_DEV_ALL;
		has_major = dl->major != ~0;
		has_minor = dl->minor != ~0;

		total_ins += (has_type ? 1 : 0) + (has_access ? 3 : 0) + (has_major ? 1 : 0) + (has_minor ? 1 : 0) + 2;
	}

	/* acccount for loader instructions */
	total_ins += pre_insn_len;

	/* final accept/deny block */
	total_ins += 2;

	/* allocate memory for eBPF program */
	program = calloc(total_ins, sizeof(struct bpf_insn));
	if (!program) {
		ret = ENOMEM;
		goto out;
	}

	/* copy program loader instructions */
	memcpy(program, &pre_insn, sizeof(pre_insn));
	cur_ins = pre_insn_len;

	/* generate eBPF program */
	list_for_each_entry(dl, &exceptions, list) {
		has_access = dl->access != DEVCG_ACC_ALL;
		has_type = dl->type != DEVCG_DEV_ALL;
		has_major = dl->major != ~0;
		has_minor = dl->minor != ~0;

		next_ins = (has_type ? 1 : 0) + (has_access ? 3 : 0) + (has_major ? 1 : 0) + (has_minor ? 1 : 0) + 1;

		if (has_type) {
			program[cur_ins++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_2, dl->type, next_ins);
			--next_ins;
		}

		if (has_access) {
			program[cur_ins++] = BPF_MOV32_REG(BPF_REG_1, BPF_REG_3);
			program[cur_ins++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_1, dl->access);
			program[cur_ins++] = BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, next_ins - 2);
			next_ins -= 3;
		}

		if (has_major) {
			program[cur_ins++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_4, dl->major, next_ins);
			--next_ins;
		}

		if (has_minor) {
			program[cur_ins++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_5, dl->minor, next_ins);
			--next_ins;
		}

		program[cur_ins++] = BPF_MOV64_IMM(BPF_REG_0, dl->allow ? 1 : 0);
		program[cur_ins++] = BPF_EXIT_INSN();
	}

	/* default behavior */
	program[cur_ins++] = BPF_MOV64_IMM(BPF_REG_0, (behavior == DEVCG_DEFAULT_ALLOW)?1:0);
	program[cur_ins++] = BPF_EXIT_INSN();

	if (debug) {
		fprintf(stderr, "cgroup devices:\na > devices.%s\n",
			(behavior == DEVCG_DEFAULT_ALLOW)?"allow":"deny");

		list_for_each_entry(dl, &exceptions, list)
			fprintf(stderr, "%c %d:%d %s%s%s > devices.%s\n",
				(dl->type == DEVCG_DEV_ALL)?'a':
					(dl->type == BPF_DEVCG_DEV_CHAR)?'c':'b',
				(dl->major == ~0)?-1:dl->major,
				(dl->minor == ~0)?-1:dl->minor,
				(dl->access & BPF_DEVCG_ACC_READ)?"r":"",
				(dl->access & BPF_DEVCG_ACC_WRITE)?"w":"",
				(dl->access & BPF_DEVCG_ACC_MKNOD)?"m":"",
				(dl->allow)?"allow":"deny");

		fprintf(stderr, "generated cgroup-devices eBPF program:\n");
		fprintf(stderr, " [idx]\tcode\t dest\t src\t off\t imm\n");
		for (cur_ins=0; cur_ins<total_ins; cur_ins++)
			fprintf(stderr, " [%03d]\t%02hhx\t%3hhu\t%3hhu\t%04hx\t%d\n", cur_ins,
				program[cur_ins].code,
				program[cur_ins].dst_reg,
				program[cur_ins].src_reg,
				program[cur_ins].off,
				program[cur_ins].imm);
	}

	assert(cur_ins == total_ins);
	bpf_total_insn = total_ins;
	ret = 0;

out:
	flush_exceptions(&exceptions);
	return ret;
}

/*
 * attach eBPF program to cgroup
 */
int attach_cgroups_ebpf(int cgroup_dirfd) {
	int prog_fd;
#if ( __WORDSIZE == 64 )
	uint64_t program_ptr = (uint64_t)program;
	uint64_t license_ptr = (uint64_t)license;
#elif ( __WORDSIZE == 32 )
	uint32_t program_ptr = (uint32_t)program;
	uint32_t license_ptr = (uint32_t)license;
#else
#error
#endif
	union bpf_attr load_attr = {
		.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE,
		.license   = license_ptr,
		.insns     = program_ptr,
		.insn_cnt  = bpf_total_insn,
	};

	if (!program)
		return 0;

	prog_fd = syscall_bpf(BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
	if (prog_fd < 0)
		return EIO;

	union bpf_attr attach_attr = {
		.attach_type = BPF_CGROUP_DEVICE,
		.target_fd = cgroup_dirfd,
		.attach_bpf_fd = prog_fd,
	};

	return syscall_bpf(BPF_PROG_ATTACH, &attach_attr, sizeof (attach_attr));
}
