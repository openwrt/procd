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
 *
 * BPF control flow
 *
 * (check_arch)<t>---(check_syscall)<f>---+----[...]<f>---(return default_action)
 *       |<f>                |<t>         |
 *      KILL         (check_argument)<f>--+
 *                           |<t>
 *                         [...]
 *                           |<t>
 *                    (return action)
 */
#define _GNU_SOURCE 1
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include <libubox/utils.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include <sys/syscall.h>

#include "log.h"
#include "jail.h"
#include "seccomp-bpf.h"
#include "seccomp-oci.h"
#include "../syscall-names.h"
#include "seccomp-syscalls-helpers.h"

#ifndef MAX_ERRNO
#define MAX_ERRNO	4095
#endif

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC		(1UL << 0)
#endif

#ifndef SECCOMP_FILTER_FLAG_LOG
#define SECCOMP_FILTER_FLAG_LOG			(1UL << 1)
#endif

#ifndef SECCOMP_FILTER_FLAG_SPEC_ALLOW
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW		(1UL << 2)
#endif

#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV	(1UL << 5)
#endif

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER	(1UL << 3)
#endif

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF	0x7fc00000U
#endif

static unsigned long seccomp_filter_flags;
static char *seccomp_listener_path;
static char *seccomp_listener_metadata;
static bool seccomp_uses_notify;

static uint32_t resolve_action(char *actname)
{
	if (!strcmp(actname, "SCMP_ACT_KILL"))
		return SECCOMP_RET_KILL;
	else if (!strcmp(actname, "SCMP_ACT_KILL_THREAD"))
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
	else if (!strcmp(actname, "SCMP_ACT_NOTIFY"))
		return SECCOMP_RET_USER_NOTIF;
	else {
		ERROR("unknown seccomp action %s\n", actname);
		return SECCOMP_RET_KILL;
	}
}

static uint8_t resolve_op_ins(const char *op)
{
	if (!strcmp(op, "SCMP_CMP_NE")) /* invert EQ */
		return BPF_JEQ;
	else if (!strcmp(op, "SCMP_CMP_LT")) /* invert GE */
		return BPF_JGE;
	else if (!strcmp(op, "SCMP_CMP_LE")) /* invert GT */
		return BPF_JGT;
	else if (!strcmp(op, "SCMP_CMP_EQ"))
		return BPF_JEQ;
	else if (!strcmp(op, "SCMP_CMP_GE"))
		return BPF_JGE;
	else if (!strcmp(op, "SCMP_CMP_GT"))
		return BPF_JGT;
	else if (!strcmp(op, "SCMP_CMP_MASKED_EQ"))
		return BPF_JEQ;
	else {
		ERROR("unknown seccomp op %s\n", op);
		return 0;
	}
}

static bool resolve_op_is_masked(const char *op)
{
	if (!strcmp(op, "SCMP_CMP_MASKED_EQ"))
		return true;

	return false;
}

static bool resolve_op_inv(const char *op)
{
	if (!strcmp(op, "SCMP_CMP_NE") ||
	    !strcmp(op, "SCMP_CMP_LT") ||
	    !strcmp(op, "SCMP_CMP_LE"))
		return true;

	return false;
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
	else if (!strcmp(archname, "SCMP_ARCH_LOONGARCH64"))
		return AUDIT_ARCH_LOONGARCH64;
	else if (!strcmp(archname, "SCMP_ARCH_RISCV64"))
		return AUDIT_ARCH_RISCV64;
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
	OCI_LINUX_SECCOMP_DEFAULTERRNORET,
	OCI_LINUX_SECCOMP_ARCHITECTURES,
	OCI_LINUX_SECCOMP_FLAGS,
	OCI_LINUX_SECCOMP_LISTENERPATH,
	OCI_LINUX_SECCOMP_LISTENERMETADATA,
	OCI_LINUX_SECCOMP_SYSCALLS,
	__OCI_LINUX_SECCOMP_MAX,
};

static const struct blobmsg_policy oci_linux_seccomp_policy[] = {
	[OCI_LINUX_SECCOMP_DEFAULTACTION] = { "defaultAction", BLOBMSG_TYPE_STRING },
	[OCI_LINUX_SECCOMP_DEFAULTERRNORET] = { "defaultErrnoRet", BLOBMSG_TYPE_INT32 },
	[OCI_LINUX_SECCOMP_ARCHITECTURES] = { "architectures", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_SECCOMP_FLAGS] = { "flags", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_SECCOMP_LISTENERPATH] = { "listenerPath", BLOBMSG_TYPE_STRING },
	[OCI_LINUX_SECCOMP_LISTENERMETADATA] = { "listenerMetadata", BLOBMSG_TYPE_STRING },
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
	[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_VALUE] = { "value", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_VALUETWO] = { "valueTwo", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_OP] = { "op", BLOBMSG_TYPE_STRING },
};

#define SECCOMP_CHUNK_NAMES	240

struct sock_fprog *parseOCIlinuxseccomp(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_SECCOMP_MAX];
	struct blob_attr *tbn[__OCI_LINUX_SECCOMP_SYSCALLS_MAX];
	struct blob_attr *tba[__OCI_LINUX_SECCOMP_SYSCALLS_ARGS_MAX];
	struct blob_attr *cur, *curn, *curarg;
	int rem, remn, remargs, sc;
	struct sock_filter *filter;
	struct sock_fprog *prog;
	int sz = 4, idx = 0;
	uint32_t default_policy = 0;
	uint32_t seccomp_arch;
	bool arch_matched;
	char *op_str;

	blobmsg_parse(oci_linux_seccomp_policy, __OCI_LINUX_SECCOMP_MAX,
		      tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_LINUX_SECCOMP_DEFAULTACTION]) {
		ERROR("seccomp: no default action set\n");
		return NULL;
	}

	default_policy = resolve_action(blobmsg_get_string(tb[OCI_LINUX_SECCOMP_DEFAULTACTION]));

	free(seccomp_listener_path);
	free(seccomp_listener_metadata);
	seccomp_listener_path = NULL;
	seccomp_listener_metadata = NULL;
	seccomp_uses_notify = (default_policy == SECCOMP_RET_USER_NOTIF);

	if (tb[OCI_LINUX_SECCOMP_LISTENERPATH])
		seccomp_listener_path = strdup(blobmsg_get_string(tb[OCI_LINUX_SECCOMP_LISTENERPATH]));

	if (tb[OCI_LINUX_SECCOMP_LISTENERMETADATA])
		seccomp_listener_metadata = strdup(blobmsg_get_string(tb[OCI_LINUX_SECCOMP_LISTENERMETADATA]));

	seccomp_filter_flags = 0;
	if (tb[OCI_LINUX_SECCOMP_FLAGS]) {
		blobmsg_for_each_attr(cur, tb[OCI_LINUX_SECCOMP_FLAGS], rem) {
			const char *flag = blobmsg_get_string(cur);
			if (!strcmp(flag, "SECCOMP_FILTER_FLAG_LOG"))
				seccomp_filter_flags |= SECCOMP_FILTER_FLAG_LOG;
			else if (!strcmp(flag, "SECCOMP_FILTER_FLAG_SPEC_ALLOW"))
				seccomp_filter_flags |= SECCOMP_FILTER_FLAG_SPEC_ALLOW;
			else if (!strcmp(flag, "SECCOMP_FILTER_FLAG_TSYNC"))
				seccomp_filter_flags |= SECCOMP_FILTER_FLAG_TSYNC;
			else if (!strcmp(flag, "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV"))
				seccomp_filter_flags |= SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
			else {
				ERROR("seccomp: unknown filter flag %s\n", flag);
				return NULL;
			}
		}
	}

	if (default_policy == SECCOMP_RET_ERRNO) {
		uint32_t errnoret = EPERM;
		if (tb[OCI_LINUX_SECCOMP_DEFAULTERRNORET]) {
			errnoret = blobmsg_get_u32(tb[OCI_LINUX_SECCOMP_DEFAULTERRNORET]);
			if (errnoret < 1 || errnoret > MAX_ERRNO) {
				ERROR("seccomp: defaultErrnoRet %u out of range (1..%u)\n",
				      errnoret, MAX_ERRNO);
				return NULL;
			}
		}
		default_policy = SECCOMP_RET_ERROR(errnoret);
	} else if (tb[OCI_LINUX_SECCOMP_DEFAULTERRNORET]) {
		ERROR("seccomp: defaultErrnoRet only valid with SCMP_ACT_ERRNO defaultAction\n");
		return NULL;
	}

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
		int valid_names = 0;
		int arg_instrs = 0;
		int chunks;

		blobmsg_parse(oci_linux_seccomp_syscalls_policy,
			      __OCI_LINUX_SECCOMP_SYSCALLS_MAX,
			      tbn, blobmsg_data(cur), blobmsg_len(cur));
		blobmsg_for_each_attr(curn, tbn[OCI_LINUX_SECCOMP_SYSCALLS_NAMES], remn) {
			sc = find_syscall(blobmsg_get_string(curn));
			if (sc == -1) {
				DEBUG("unknown syscall '%s'\n", blobmsg_get_string(curn));
				/* TODO: support run.oci.seccomp_fail_unknown_syscall=1 annotation */
				continue;
			}
			++valid_names;
		}

		if (tbn[OCI_LINUX_SECCOMP_SYSCALLS_ARGS]) {
			blobmsg_for_each_attr(curarg, tbn[OCI_LINUX_SECCOMP_SYSCALLS_ARGS], remargs) {
				arg_instrs += 2; /* load and compare */

				blobmsg_parse(oci_linux_seccomp_syscalls_args_policy,
					      __OCI_LINUX_SECCOMP_SYSCALLS_ARGS_MAX,
					      tba, blobmsg_data(curarg), blobmsg_len(curarg));
				if (!tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_INDEX] ||
				    !tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_VALUE] ||
				    !tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_OP]) {
					ERROR("seccomp: syscall arg missing%s%s%s\n",
					      tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_INDEX] ? "" : " index",
					      tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_VALUE] ? "" : " value",
					      tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_OP] ? "" : " op");
					return NULL;
				}

				if (blobmsg_get_u32(tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_INDEX]) > 5) {
					ERROR("seccomp: syscall arg index %u out of range (max 5)\n",
					      blobmsg_get_u32(tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_INDEX]));
					return NULL;
				}

				op_str = blobmsg_get_string(tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_OP]);
				if (!resolve_op_ins(op_str))
					return NULL;

				if (resolve_op_is_masked(op_str))
					++arg_instrs; /* SCMP_CMP_MASKED_EQ needs an extra BPF_AND op */
			}
		}

		chunks = valid_names ? (valid_names + SECCOMP_CHUNK_NAMES - 1) / SECCOMP_CHUNK_NAMES : 1;
		sz += chunks * (1 + 1 + arg_instrs) + valid_names;
	}

	if (sz < 6) {
		ERROR("seccomp: filter is empty\n");
		return NULL;
	}

	prog = malloc(sizeof(struct sock_fprog));
	if (!prog) {
		ERROR("seccomp: failed to allocate sock_fprog\n");
		return NULL;
	}

	filter = calloc(sz, sizeof(struct sock_filter));
	if (!filter) {
		ERROR("failed to allocate memory for seccomp filter\n");
		goto errout2;
	}

	/* validate arch */
	set_filter(&filter[idx++], BPF_LD + BPF_W + BPF_ABS, 0, 0, arch_nr);
	set_filter(&filter[idx++], BPF_JMP + BPF_JEQ + BPF_K, 1, 0, ARCH_NR);
	set_filter(&filter[idx++], BPF_RET + BPF_K, 0, 0, SECCOMP_RET_KILL);

	blobmsg_for_each_attr(cur, tb[OCI_LINUX_SECCOMP_SYSCALLS], rem) {
		uint32_t action;
		uint32_t op_idx;
		uint8_t op_ins;
		bool op_inv, op_masked;
		uint64_t op_val, op_val2;
		int start_rule_idx;
		int next_rule_idx;
		int valid_names = 0;
		int names_emitted = 0;
		int chunk_size;

		blobmsg_parse(oci_linux_seccomp_syscalls_policy,
			      __OCI_LINUX_SECCOMP_SYSCALLS_MAX,
			      tbn, blobmsg_data(cur), blobmsg_len(cur));
		action = resolve_action(blobmsg_get_string(
				tbn[OCI_LINUX_SECCOMP_SYSCALLS_ACTION]));
		if (action == SECCOMP_RET_USER_NOTIF)
			seccomp_uses_notify = true;
		if (tbn[OCI_LINUX_SECCOMP_SYSCALLS_ERRNORET]) {
			uint32_t errnoret;

			if (action != SECCOMP_RET_ERRNO) {
				ERROR("seccomp: errnoRet set but action is not SCMP_ACT_ERRNO\n");
				goto errout1;
			}

			errnoret = blobmsg_get_u32(tbn[OCI_LINUX_SECCOMP_SYSCALLS_ERRNORET]);
			if (errnoret < 1 || errnoret > MAX_ERRNO) {
				ERROR("seccomp: errnoRet %u out of range (1..%u)\n",
				      errnoret, MAX_ERRNO);
				goto errout1;
			}
			action = SECCOMP_RET_ERROR(errnoret);
		} else if (action == SECCOMP_RET_ERRNO)
			action = SECCOMP_RET_ERROR(EPERM);

		blobmsg_for_each_attr(curn, tbn[OCI_LINUX_SECCOMP_SYSCALLS_NAMES], remn) {
			if (find_syscall(blobmsg_get_string(curn)) != -1)
				++valid_names;
		}

		if (!valid_names && !tbn[OCI_LINUX_SECCOMP_SYSCALLS_ARGS])
			continue;

		while (names_emitted < valid_names || names_emitted == 0) {
			int names_in_chunk;
			int names_seen;

			chunk_size = valid_names - names_emitted;
			if (chunk_size > SECCOMP_CHUNK_NAMES)
				chunk_size = SECCOMP_CHUNK_NAMES;
			names_in_chunk = chunk_size;

			set_filter(&filter[idx++], BPF_LD + BPF_W + BPF_ABS, 0, 0, syscall_nr);

			next_rule_idx = idx + names_in_chunk;
			start_rule_idx = next_rule_idx;

			blobmsg_for_each_attr(curn, tbn[OCI_LINUX_SECCOMP_SYSCALLS_ARGS], remn) {
				blobmsg_parse(oci_linux_seccomp_syscalls_args_policy,
					      __OCI_LINUX_SECCOMP_SYSCALLS_ARGS_MAX,
					      tba, blobmsg_data(curn), blobmsg_len(curn));
				next_rule_idx += 2;
				op_str = blobmsg_get_string(tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_OP]);
				if (resolve_op_is_masked(op_str))
					++next_rule_idx;
			}

			++next_rule_idx;

			names_seen = 0;
			blobmsg_for_each_attr(curn, tbn[OCI_LINUX_SECCOMP_SYSCALLS_NAMES], remn) {
				sc = find_syscall(blobmsg_get_string(curn));
				if (sc == -1)
					continue;
				if (names_seen < names_emitted) {
					++names_seen;
					continue;
				}
				if (names_seen >= names_emitted + names_in_chunk)
					break;
				set_filter(&filter[idx], BPF_JMP + BPF_JEQ + BPF_K,
					   start_rule_idx - (idx + 1),
					   ((idx + 1) == start_rule_idx)?(next_rule_idx - (idx + 1)):0,
					   sc);
				++idx;
				++names_seen;
			}

			assert(idx == start_rule_idx);

			blobmsg_for_each_attr(curn, tbn[OCI_LINUX_SECCOMP_SYSCALLS_ARGS], remn) {
				blobmsg_parse(oci_linux_seccomp_syscalls_args_policy,
					      __OCI_LINUX_SECCOMP_SYSCALLS_ARGS_MAX,
					      tba, blobmsg_data(curn), blobmsg_len(curn));

				op_str = blobmsg_get_string(tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_OP]);
				op_ins = resolve_op_ins(op_str);
				op_inv = resolve_op_inv(op_str);
				op_masked = resolve_op_is_masked(op_str);
				op_idx = blobmsg_get_u32(tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_INDEX]);
				op_val = blobmsg_cast_u64(tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_VALUE]);
				if (tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_VALUETWO])
					op_val2 = blobmsg_cast_u64(tba[OCI_LINUX_SECCOMP_SYSCALLS_ARGS_VALUETWO]);
				else
					op_val2 = 0;

				/* load argument */
				set_filter(&filter[idx++], BPF_LD + BPF_W + BPF_ABS, 0, 0, syscall_arg(op_idx));

				/* apply mask */
				if (op_masked)
					set_filter(&filter[idx++], BPF_ALU + BPF_K + BPF_AND, 0, 0, op_val);

				set_filter(&filter[idx], BPF_JMP + op_ins + BPF_K,
					   op_inv?(next_rule_idx - (idx + 1)):0,
					   op_inv?0:(next_rule_idx - (idx + 1)),
					   op_masked?op_val2:op_val);
				++idx;
			}

			set_filter(&filter[idx++], BPF_RET + BPF_K, 0, 0, action);

			assert(idx == next_rule_idx);

			names_emitted += chunk_size;
			if (!valid_names)
				break;
		}
	}

	set_filter(&filter[idx++], BPF_RET + BPF_K, 0, 0, default_policy);

	assert(idx == sz);

	prog->len = (unsigned short) idx;
	prog->filter = filter;

	DEBUG("generated seccomp-bpf program:\n");
	if (debug) {
		fprintf(stderr, " [idx]\tcode\t jt\t jf\tk\n");
		for (idx=0; idx<sz; idx++)
			fprintf(stderr, " [%03d]\t%04hx\t%3hhu\t%3hhu\t%08x\n", idx,
				filter[idx].code,
				filter[idx].jt,
				filter[idx].jf,
				filter[idx].k);
	}

	return prog;

errout1:
	free(filter);
errout2:
	free(prog);
	return NULL;
}


static int send_seccomp_listener_fd(int listener_fd, const char *container_id,
				    const char *bundle_path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct blob_buf bb = { 0 };
	void *fds_arr, *state;
	struct msghdr msg = { 0 };
	struct iovec iov;
	struct cmsghdr *cmsg;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	char *json;
	int sock;
	int ret = 0;
	int saved_err;

	if (strlen(seccomp_listener_path) >= sizeof(addr.sun_path)) {
		ERROR("seccomp: listenerPath too long: %s\n", seccomp_listener_path);
		return ENAMETOOLONG;
	}

	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "ociVersion", OCI_VERSION_STRING);
	fds_arr = blobmsg_open_array(&bb, "fds");
	blobmsg_add_string(&bb, NULL, "seccompFd");
	blobmsg_close_array(&bb, fds_arr);
	blobmsg_add_u32(&bb, "pid", getpid());
	if (seccomp_listener_metadata)
		blobmsg_add_string(&bb, "metadata", seccomp_listener_metadata);
	state = blobmsg_open_table(&bb, "state");
	blobmsg_add_string(&bb, "ociVersion", OCI_VERSION_STRING);
	if (container_id)
		blobmsg_add_string(&bb, "id", container_id);
	blobmsg_add_string(&bb, "status", "creating");
	blobmsg_add_u32(&bb, "pid", getpid());
	if (bundle_path)
		blobmsg_add_string(&bb, "bundle", bundle_path);
	blobmsg_close_table(&bb, state);

	json = blobmsg_format_json(bb.head, true);
	if (!json) {
		blob_buf_free(&bb);
		return ENOMEM;
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		ret = errno;
		ERROR("socket(AF_UNIX): %m\n");
		goto out;
	}

	memcpy(addr.sun_path, seccomp_listener_path, strlen(seccomp_listener_path) + 1);
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		ret = errno;
		ERROR("connect(%s): %m\n", seccomp_listener_path);
		saved_err = ret;
		close(sock);
		ret = saved_err;
		goto out;
	}

	iov.iov_base = json;
	iov.iov_len = strlen(json);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &listener_fd, sizeof(int));

	if (sendmsg(sock, &msg, 0) < 0) {
		ret = errno;
		ERROR("sendmsg(%s): %m\n", seccomp_listener_path);
	}

	saved_err = ret;
	close(sock);
	ret = saved_err;
out:
	free(json);
	blob_buf_free(&bb);
	return ret;
}

int applyOCIlinuxseccomp(struct sock_fprog *prog, const char *container_id,
			 const char *bundle_path)
{
	int listener_fd = -1;

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		ERROR("prctl(PR_SET_NO_NEW_PRIVS) failed: %m\n");
		goto errout;
	}

	if (seccomp_uses_notify) {
		if (!seccomp_listener_path) {
			ERROR("seccomp: SCMP_ACT_NOTIFY used without listenerPath\n");
			errno = EINVAL;
			goto errout;
		}

		listener_fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
				      seccomp_filter_flags | SECCOMP_FILTER_FLAG_NEW_LISTENER,
				      prog);
		if (listener_fd < 0) {
			ERROR("seccomp(SET_MODE_FILTER|NEW_LISTENER): %m\n");
			goto errout;
		}

		if (send_seccomp_listener_fd(listener_fd, container_id, bundle_path)) {
			int saved_err = errno;
			close(listener_fd);
			errno = saved_err;
			goto errout;
		}

		close(listener_fd);
	} else if (seccomp_filter_flags) {
		long r = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
				 seccomp_filter_flags, prog);
		if (r < 0) {
			ERROR("seccomp(SET_MODE_FILTER, %#lx): %m\n", seccomp_filter_flags);
			goto errout;
		}
		if (r > 0) {
			ERROR("seccomp(SET_MODE_FILTER, %#lx) TSYNC failed at tid %ld\n",
			      seccomp_filter_flags, r);
			errno = EAGAIN;
			goto errout;
		}
	} else if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)) {
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
