/*
 * Copyright (C) 2015 Etienne CHAMPETIER <champetier.etienne@gmail.com>
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
#ifndef _JAIL_CAPABILITIES_H_
#define _JAIL_CAPABILITIES_H_

#include <libubox/blobmsg.h>
#include <linux/capability.h>

struct jail_capset {
	uint64_t bounding;
	uint64_t effective;
	uint64_t inheritable;
	uint64_t permitted;
	uint64_t ambient;
	uint8_t apply;
};

int parseOCIcapabilities(struct jail_capset *capset, struct blob_attr *msg);
int parseOCIcapabilities_from_file(struct jail_capset *capset, const char *file);
int applyOCIcapabilities(struct jail_capset capset, uint64_t retain);

/* capget/capset syscall wrappers are provided by libc */
extern int capget(cap_user_header_t header, cap_user_data_t data);
extern int capset(cap_user_header_t header, const cap_user_data_t data);

#endif
