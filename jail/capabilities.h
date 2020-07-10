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

struct jail_capset {
	uint64_t bounding;
	uint64_t effective;
	uint64_t inheritable;
	uint64_t permitted;
	uint64_t ambient;
	uint8_t apply;
};

int drop_capabilities(const char *file);

int parseOCIcapabilities(struct jail_capset *capset, struct blob_attr *msg);
int applyOCIcapabilities(struct jail_capset capset);

#endif
