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

#include "seccomp.h"
#include "seccomp-oci.h"

int debug = 0;

int install_syscall_filter(const char *argv, const char *file)
{
	struct blob_buf b = { 0 };
	struct sock_fprog *prog = NULL;

	INFO("%s: setting up syscall filter\n", argv);

	blob_buf_init(&b, 0);
	if (!blobmsg_add_json_from_file(&b, file)) {
		ERROR("%s: failed to load %s\n", argv, file);
		return -1;
	}

	prog = parseOCIlinuxseccomp(b.head);
	if (!prog) {
		ERROR("%s: failed to parse seccomp filter rules %s\n", argv, file);
		return -1;
	}

	return applyOCIlinuxseccomp(prog);
}
