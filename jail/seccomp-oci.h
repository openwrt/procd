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

#include <linux/filter.h>

struct sock_fprog *parseOCIlinuxseccomp(struct blob_attr *msg);
int applyOCIlinuxseccomp(struct sock_fprog *prog);

#ifndef SECCOMP_SUPPORT
struct sock_fprog *parseOCIlinuxseccomp(struct blob_attr *msg) {
	return NULL;
}

int applyOCIlinuxseccomp(struct sock_fprog *prog) {
	return ENOTSUP;
}
#endif

#endif
