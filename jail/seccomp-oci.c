/*
 * parse and setup OCI seccomp filter
 * Copyright (c) 2020 Daniel Golle <daniel@makrotopia.org>
 * seccomp example with syscall reporting
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Kees Cook <keescook@chromium.org>
 *  Will Drewry <wad@chromium.org>
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#define _GNU_SOURCE 1
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <libubox/utils.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "log.h"
#include "seccomp-bpf.h"
#include "seccomp-oci.h"
#include "../syscall-names.h"
#include "seccomp-syscalls-helpers.h"

static uint32_t resolve_action(char *actname)
{
	if (!strcmp(actname, "SCMP_ACT_KILL"))
		return SECCOMP_RET_KILL;
	else if (!strcmp(actname, "SCMP_ACT_KILL_PROCESS"))
		return SECCOMP_RET_KILLPROCESS;
	else if (!strcmp(actname, "SCMP_ACT_TRAP"))
		return SECCOMP_RET_TRAP;
	else if (!strcmp(actname, "SCMP_ACT_ERRNO"))
		return SECCOMP_RET_ERRNO;
	else if (!strcmp(actname, "SCMP_ACT_ERROR"))
		return SECCOMP_RET_ERRNO;
	else if (!strcmp(actname, "SCMP_ACT_TRACE"))
		return SECCOMP_RET_TRACE;
	else if (!strcmp(actname, "SCMP_ACT_ALLOW"))
		return SECCOMP_RET_ALLOW;
	else if (!strcmp(actname, "SCMP_ACT_LOG"))
		return SECCOMP_RET_LOGALLOW;
	else {
		ERROR("unknown seccomp action %s\n", actname);
		return SECCOMP_RET_KILL;
	}
}

static uint32_t resolve_architecture(char *archname)
{
	if (!archname)
		return 0;

	if (!strcmp(archname, "SCMP_ARCH_X86"))
		return AUDIT_ARCH_I386;
	else if (!strcmp(archname, "SCMP_ARCH_X86_64"))
		return AUDIT_ARCH_X86_64;
	else if (!strcmp(archname, "SCMP_ARCH_X32"))
		/*
		 * return AUDIT_ARCH_X86_64;
		 * 32-bit userland on 64-bit kernel is not supported yet
		 */
		return 0;
	else if (!strcmp(archname, "SCMP_ARCH_ARM"))
		return AUDIT_ARCH_ARM;
	else if (!strcmp(archname, "SCMP_ARCH_AARCH64"))
		return AUDIT_ARCH_AARCH64;
	else if (!strcmp(archname, "SCMP_ARCH_MIPS"))
		return AUDIT_ARCH_MIPS;
	else if (!strcmp(archname, "SCMP_ARCH_MIPS64"))
		return AUDIT_ARCH_MIPS64;
	else if (!strcmp(archname, "SCMP_ARCH_MIPS64N32"))
		return AUDIT_ARCH_MIPS64N32;
	else if (!strcmp(archname, "SCMP_ARCH_MIPSEL"))
		return AUDIT_ARCH_MIPSEL;
	else if (!strcmp(archname, "SCMP_ARCH_MIPSEL64"))
		return AUDIT_ARCH_MIPSEL64;
	else if (!strcmp(archname, "SCMP_ARCH_MIPSEL64N32"))
		return AUDIT_ARCH_MIPSEL64N32;
	else if (!strcmp(archname, "SCMP_ARCH_PPC"))
		return AUDIT_ARCH_PPC;
	else if (!strcmp(archname, "SCMP_ARCH_PPC64"))
		return AUDIT_ARCH_PPC64;
	else if (!strcmp(archname, "SCMP_ARCH_PPC64LE"))
		return AUDIT_ARCH_PPC64LE;
	else if (!strcmp(archname, "SCMP_ARCH_S390"))
		return AUDIT_ARCH_S390;
	else if (!strcmp(archname, "SCMP_ARCH_S390X"))
		return AUDIT_ARCH_S390X;
	else if (!strcmp(archname, "SCMP_ARCH_PARISC"))
		return AUDIT_ARCH_PARISC;
	else if (!strcmp(archname, "SCMP_ARCH_PARISC64"))
		return AUDIT_ARCH_PARISC64;
	else {
		ERROR("unknown seccomp architecture %s\n", archname);
		return 0;
	}
}

enum {
	OCI_LINUX_SECCOMP_DEFAULTACTION,
	OCI_LINUX_SECCOMP_ARCHITECTURES,
	OCI_LINUX_SECCOMP_FLAGS,
	OCI_LINUX_SECCOMP_SYSCALLS,
	__OCI_LINUX_SECCOMP_MAX,
};

static const struct blobmsg_policy oci_linux_seccomp_policy[] = {
	[OCI_LINUX_SECCOMP_DEFAULTACTION] = { "defaultAction", BLOBMSG_TYPE_STRING },
	[OCI_LINUX_SECCOMP_ARCHITECTURES] = { "architectures", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_SECCOMP_FLAGS] = { "flags", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_SECCOMP_SYSCALLS] = { "syscalls", BLOBMSG_TYPE_ARRAY },
};

enum {
	OCI_LINUX_SECCOMP_SYSCALLS_NAMES,
	OCI_LINUX_SECCOMP_SYSCALLS_ACTION,
	OCI_LINUX_SECCOMP_SYSCALLS_ERRNORET,
	OCI_LINUX_SECCOMP_SYSCALLS_ARGS,
	__OCI_LINUX_SECCOMP_SYSCALLS_MAX
};

static const struct blobmsg_policy oci_linux_seccomp_syscalls_policy[] = {
	[OCI_LINUX_SECCOMP_SYSCALLS_NAMES] = { "names", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_SECCOMP_SYSCALLS_ERRNORET] = { "errnoRet", BLOBMSG_TYPE_INT32 },
	[OCI_LINUX_SECCOMP_SYSCALLS_ARGS] = { "args", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_SECCOMP_SYSCALLS_ACTION] = { "action", BLOBMSG_TYPE_STRING },
};

enum {
	OCI_LINUX_SECCOMP_SYSCALLS_ARGS_INDEX,
	OCI_LINUX_SECCOMP_SYSCALLS_ARGS_VALUE,
	OCI_LINUX_SECCOMP_SYSCALLS_ARGS_VALUETWO,
	OCI_LINUX_SECCOMP_SYSCALLS_ARGS_OP,
	__OCI_LINUX_SECCOMP_SYSCALLS_ARGS_MAX
};

static const struct blobmsg_policy oci_linux_seccomp_syscalls_args_policy[] = {
	[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_INDEX] = { "index", BLOBMSG_TYPE_INT32 },
	[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_VALUE] = { "value", BLOBMSG_TYPE_INT64 },
	[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_VALUETWO] = { "valueTwo", BLOBMSG_TYPE_INT64 },
	[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_OP] = { "op", BLOBMSG_TYPE_STRING },
};

struct sock_fprog *parseOCIlinuxseccomp(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_SECCOMP_MAX];
	struct blob_attr *tbn[__OCI_LINUX_SECCOMP_SYSCALLS_MAX];
	struct blob_attr *tba[__OCI_LINUX_SECCOMP_SYSCALLS_ARGS_MAX];
	struct blob_attr *cur, *curn, *curarg;
	int rem, remn, remargs, sc;
	struct sock_filter *filter;
	struct sock_fprog *prog;
	int sz = 5, idx = 0;
	uint32_t default_policy = 0;
	uint32_t seccomp_arch;
	bool arch_matched;

	blobmsg_parse(oci_linux_seccomp_policy, __OCI_LINUX_SECCOMP_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_LINUX_SECCOMP_DEFAULTACTION]) {
		ERROR("seccomp: no default action set\n");
		return NULL;
	}

	default_policy = resolve_action(blobmsg_get_string(tb[OCI_LINUX_SECCOMP_DEFAULTACTION]));

	/* verify architecture while ignoring the x86_64 anomaly for now */
	if (tb[OCI_LINUX_SECCOMP_ARCHITECTURES]) {
		arch_matched = false;
		blobmsg_for_each_attr(cur, tb[OCI_LINUX_SECCOMP_ARCHITECTURES], rem) {
			seccomp_arch = resolve_architecture(blobmsg_get_string(cur));
			if (ARCH_NR == seccomp_arch) {
				arch_matched = true;
				break;
			}
		}
		if (!arch_matched) {
			ERROR("seccomp architecture doesn't match system\n");
			return NULL;
		}
	}

	blobmsg_for_each_attr(cur, tb[OCI_LINUX_SECCOMP_SYSCALLS], rem) {
		blobmsg_parse(oci_linux_seccomp_syscalls_policy, __OCI_LINUX_SECCOMP_SYSCALLS_MAX, tbn, blobmsg_data(cur), blobmsg_len(cur));
		blobmsg_for_each_attr(curn, tbn[OCI_LINUX_SECCOMP_SYSCALLS_NAMES], remn)
			sz += 2;

		if (tbn[OCI_LINUX_SECCOMP_SYSCALLS_ARGS])
			blobmsg_for_each_attr(curarg, tbn[OCI_LINUX_SECCOMP_SYSCALLS_ARGS], remargs)
				sz++;
	}

	prog = malloc(sizeof(struct sock_fprog));
	if (!prog)
		return NULL;

	filter = calloc(sz, sizeof(struct sock_filter));
	if (!filter) {
		ERROR("failed to allocate memory for seccomp filter\n");
		goto errout2;
	}

	/* validate arch */
	set_filter(&filter[idx++], BPF_LD + BPF_W + BPF_ABS, 0, 0, arch_nr);
	set_filter(&filter[idx++], BPF_JMP + BPF_JEQ + BPF_K, 1, 0, ARCH_NR);
	set_filter(&filter[idx++], BPF_RET + BPF_K, 0, 0, SECCOMP_RET_KILL);

	/* get syscall */
	set_filter(&filter[idx++], BPF_LD + BPF_W + BPF_ABS, 0, 0, syscall_nr);

	blobmsg_for_each_attr(cur, tb[OCI_LINUX_SECCOMP_SYSCALLS], rem) {
		uint32_t action;
		blobmsg_parse(oci_linux_seccomp_syscalls_policy, __OCI_LINUX_SECCOMP_SYSCALLS_MAX, tbn, blobmsg_data(cur), blobmsg_len(cur));
		action = resolve_action(blobmsg_get_string(tbn[OCI_LINUX_SECCOMP_SYSCALLS_ACTION]));
		if (tbn[OCI_LINUX_SECCOMP_SYSCALLS_ERRNORET]) {
			if (action != SECCOMP_RET_ERRNO)
				goto errout1;

			action = SECCOMP_RET_ERROR(blobmsg_get_u32(tbn[OCI_LINUX_SECCOMP_SYSCALLS_ERRNORET]));
		} else if (action == SECCOMP_RET_ERRNO)
			action = SECCOMP_RET_ERROR(EPERM);

		blobmsg_for_each_attr(curn, tbn[OCI_LINUX_SECCOMP_SYSCALLS_NAMES], remn) {
			sc = find_syscall(blobmsg_get_string(curn));
			if (sc == -1) {
				ERROR("unknown syscall '%s'\n", blobmsg_get_string(curn));
				/* TODO: support run.oci.seccomp_fail_unknown_syscall=1 annotation */
				continue;
			}

			/* add rule to filter */
			set_filter(&filter[idx++], BPF_JMP + BPF_JEQ + BPF_K, 0, 1, sc);
			set_filter(&filter[idx++], BPF_RET + BPF_K, 0, 0, action);

		}
		blobmsg_for_each_attr(curn, tbn[OCI_LINUX_SECCOMP_SYSCALLS_ARGS], remn) {
			blobmsg_parse(oci_linux_seccomp_syscalls_args_policy, __OCI_LINUX_SECCOMP_SYSCALLS_ARGS_MAX, tba, blobmsg_data(curn), blobmsg_len(curn));
			/* ToDo: process args */
		}
	}

	set_filter(&filter[idx], BPF_RET + BPF_K, 0, 0, default_policy);

	prog->len = (unsigned short) idx + 1;
	prog->filter = filter;

	return prog;

errout1:
	free(prog->filter);
errout2:
	free(prog);
	return NULL;
}


int applyOCIlinuxseccomp(struct sock_fprog *prog)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		ERROR("prctl(PR_SET_NO_NEW_PRIVS) failed: %m\n");
		goto errout;
	}

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)) {
		ERROR("prctl(PR_SET_SECCOMP) failed: %m\n");
		goto errout;
	}
	free(prog);

	return 0;

errout:
	free(prog->filter);
	free(prog);
	return errno;
}
