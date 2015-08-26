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

#define _GNU_SOURCE 1
#include <syslog.h>
#include <sys/prctl.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "log.h"
#include "../capabilities-names.h"
#include "capabilities.h"

static int find_capabilities(const char *name)
{
	int i;

	for (i = 0; i <= CAP_LAST_CAP; i++)
		if (capabilities_names[i] && !strcmp(capabilities_names[i], name))
			return i;

	return -1;
}

int drop_capabilities(const char *file)
{
	enum {
		CAP_KEEP,
		CAP_DROP,
		__CAP_MAX
	};
	static const struct blobmsg_policy policy[__CAP_MAX] = {
		[CAP_KEEP] = { .name = "cap.keep", .type = BLOBMSG_TYPE_ARRAY },
		[CAP_DROP] = { .name = "cap.drop", .type = BLOBMSG_TYPE_ARRAY },
	};
	struct blob_buf b = { 0 };
	struct blob_attr *tb[__CAP_MAX];
	struct blob_attr *cur;
	int rem, cap;
	char *name;
	uint64_t capdrop = 0LLU;

	DEBUG("dropping capabilities\n");

	blob_buf_init(&b, 0);
	if (!blobmsg_add_json_from_file(&b, file)) {
		ERROR("failed to load %s\n", file);
		return -1;
	}

	blobmsg_parse(policy, __CAP_MAX, tb, blob_data(b.head), blob_len(b.head));
	if (!tb[CAP_KEEP] && !tb[CAP_DROP]) {
		ERROR("failed to parse %s\n", file);
		return -1;
	}

	blobmsg_for_each_attr(cur, tb[CAP_KEEP], rem) {
		name = blobmsg_get_string(cur);
		if (!name) {
			ERROR("invalid capability name in cap.keep\n");
			return -1;
		}
		cap = find_capabilities(name);
		if (cap == -1) {
			ERROR("unknown capability %s in cap.keep\n", name);
			return -1;
		}
		capdrop |= (1LLU << cap);
	}

	if (capdrop == 0LLU) {
		DEBUG("cap.keep empty -> only dropping capabilities from cap.drop (blacklist)\n");
		capdrop = 0xffffffffffffffffLLU;
	} else {
		DEBUG("cap.keep has at least one capability -> dropping every capabilities not in cap.keep (whitelist)\n");
	}

	blobmsg_for_each_attr(cur, tb[CAP_DROP], rem) {
		name = blobmsg_get_string(cur);
		if (!name) {
			ERROR("invalid capability name in cap.drop\n");
			return -1;
		}
		cap = find_capabilities(name);
		if (cap == -1) {
			ERROR("unknown capability %s in cap.drop\n", name);
			return -1;
		}
		capdrop &= ~(1LLU << cap);
	}

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		if ( (capdrop & (1LLU << cap)) == 0) {
			DEBUG("dropping capability %s (%d)\n", capabilities_names[cap], cap);
			if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) {
				ERROR("prctl(PR_CAPBSET_DROP, %d) failed: %s\n", cap, strerror(errno));
				return errno;
			}
		} else {
			DEBUG("keeping capability %s (%d)\n", capabilities_names[cap], cap);
		}
	}

	return 0;
}
