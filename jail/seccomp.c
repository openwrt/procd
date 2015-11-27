/*
 * seccomp example with syscall reporting
 *
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

#include "seccomp-bpf.h"
#include "seccomp.h"
#include "../syscall-names.h"

static int max_syscall = ARRAY_SIZE(syscall_names);

static int find_syscall(const char *name)
{
	int i;

	for (i = 0; i < max_syscall; i++)
		if (syscall_names[i] && !strcmp(syscall_names[i], name))
			return i;

	return -1;
}

static void set_filter(struct sock_filter *filter, __u16 code, __u8 jt, __u8 jf, __u32 k)
{
	filter->code = code;
	filter->jt = jt;
	filter->jf = jf;
	filter->k = k;
}

int install_syscall_filter(const char *argv, const char *file)
{
	enum {
		SECCOMP_WHITELIST,
		SECCOMP_POLICY,
		__SECCOMP_MAX
	};
	static const struct blobmsg_policy policy[__SECCOMP_MAX] = {
		[SECCOMP_WHITELIST] = { .name = "whitelist", .type = BLOBMSG_TYPE_ARRAY },
		[SECCOMP_POLICY] = { .name = "policy", .type = BLOBMSG_TYPE_INT32 },
	};
	struct blob_buf b = { 0 };
	struct blob_attr *tb[__SECCOMP_MAX];
	struct blob_attr *cur;
	int rem;

	struct sock_filter *filter;
	struct sock_fprog prog = { 0 };
	int sz = 5, idx = 0, default_policy = 0;

	INFO("%s: setting up syscall filter\n", argv);

	blob_buf_init(&b, 0);
	if (!blobmsg_add_json_from_file(&b, file)) {
		INFO("%s: failed to load %s\n", argv, file);
		return -1;
	}

	blobmsg_parse(policy, __SECCOMP_MAX, tb, blob_data(b.head), blob_len(b.head));
	if (!tb[SECCOMP_WHITELIST]) {
		INFO("%s: %s is missing the syscall table\n", argv, file);
		return -1;
	}

	if (tb[SECCOMP_POLICY])
		default_policy = blobmsg_get_u32(tb[SECCOMP_POLICY]);

	blobmsg_for_each_attr(cur, tb[SECCOMP_WHITELIST], rem)
		sz += 2;

	filter = calloc(sz, sizeof(struct sock_filter));
	if (!filter) {
		INFO("failed to allocate filter memory\n");
		return -1;
	}

	/* validate arch */
	set_filter(&filter[idx++], BPF_LD + BPF_W + BPF_ABS, 0, 0, arch_nr);
	set_filter(&filter[idx++], BPF_JMP + BPF_JEQ + BPF_K, 1, 0, ARCH_NR);
	set_filter(&filter[idx++], BPF_RET + BPF_K, 0, 0, SECCOMP_RET_KILL);

	/* get syscall */
	set_filter(&filter[idx++], BPF_LD + BPF_W + BPF_ABS, 0, 0, syscall_nr);

	blobmsg_for_each_attr(cur, tb[SECCOMP_WHITELIST], rem) {
		char *name = blobmsg_get_string(cur);
		int nr;

		if (!name) {
			INFO("%s: invalid syscall name\n", argv);
			continue;
		}

		nr  = find_syscall(name);
		if (nr == -1) {
			INFO("%s: unknown syscall %s\n", argv, name);
			continue;
		}

		/* add whitelist */
		set_filter(&filter[idx++], BPF_JMP + BPF_JEQ + BPF_K, 0, 1, nr);
		set_filter(&filter[idx++], BPF_RET + BPF_K, 0, 0, SECCOMP_RET_ALLOW);
	}

	if (default_policy)
		/* return -1 and set errno */
		set_filter(&filter[idx], BPF_RET + BPF_K, 0, 0, SECCOMP_RET_LOGGER(default_policy));
	else
		/* kill the process */
		set_filter(&filter[idx], BPF_RET + BPF_K, 0, 0, SECCOMP_RET_KILL);

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		INFO("%s: prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n", argv, strerror(errno));
		return errno;
	}

	prog.len = (unsigned short) idx + 1;
	prog.filter = filter;

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		INFO("%s: prctl(PR_SET_SECCOMP) failed: %s\n", argv, strerror(errno));
		return errno;
	}
	return 0;
}
