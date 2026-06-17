/*
 * Copyright (C) 2020 Daniel Golle <daniel@makrotopia.org>
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
#ifndef _JAIL_SECCOMP_OCI_H_
#define _JAIL_SECCOMP_OCI_H_

#include <stdbool.h>
#include <stdint.h>
#include <linux/filter.h>

#ifdef SECCOMP_SUPPORT
extern const char * const seccomp_linker_base[];
extern const char * const seccomp_init_base[];
extern const char * const seccomp_loader_files[];
#else
static const char * const seccomp_linker_base[] = { NULL };
static const char * const seccomp_init_base[] = { NULL };
static const char * const seccomp_loader_files[] = { NULL };
#endif

struct sock_fprog *parseOCIlinuxseccomp(struct blob_attr *msg,
					const char * const *extra_allow);
struct sock_fprog *seccomp_deny_delta(const char * const *names,
				      const struct sock_fprog *app);
int applyOCIlinuxseccomp(struct sock_fprog *prog, const char *container_id,
			 const char *bundle_path);
bool seccomp_oci_needs_inproc(void);
bool seccomp_profile_covers(const struct sock_fprog *prog, const char * const *names);

#ifndef SECCOMP_SUPPORT
struct sock_fprog *parseOCIlinuxseccomp(struct blob_attr *msg,
					const char * const *extra_allow) {
	return NULL;
}

int applyOCIlinuxseccomp(struct sock_fprog *prog, const char *container_id,
			 const char *bundle_path) {
	return ENOTSUP;
}

bool seccomp_oci_needs_inproc(void) {
	return false;
}
#endif

#endif
