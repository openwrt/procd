/*
 * Copyright (C) 2015 Etienne CHAMPETIER <champetier.etienne@gmail.com>
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

#define _GNU_SOURCE 1
#include <syslog.h>
#include <sys/prctl.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "log.h"
#include "../capabilities-names.h"
#include "capabilities.h"

#define JAIL_CAP_ERROR (1LLU << (CAP_LAST_CAP+1))
#define JAIL_CAP_ALL (0xffffffffffffffffLLU)

static int find_capabilities(const char *name)
{
	int i;

	for (i = 0; i <= CAP_LAST_CAP; i++)
		if (capabilities_names[i] && !strcasecmp(capabilities_names[i], name))
			return i;

	return -1;
}

enum {
	OCI_CAPABILITIES_BOUNDING,
	OCI_CAPABILITIES_EFFECTIVE,
	OCI_CAPABILITIES_INHERITABLE,
	OCI_CAPABILITIES_PERMITTED,
	OCI_CAPABILITIES_AMBIENT,
	__OCI_CAPABILITIES_MAX
};

static const struct blobmsg_policy oci_capabilities_policy[] = {
	[OCI_CAPABILITIES_BOUNDING] = { "bounding", BLOBMSG_TYPE_ARRAY },
	[OCI_CAPABILITIES_EFFECTIVE] = { "effective", BLOBMSG_TYPE_ARRAY },
	[OCI_CAPABILITIES_INHERITABLE] = { "inheritable", BLOBMSG_TYPE_ARRAY },
	[OCI_CAPABILITIES_PERMITTED] = { "permitted", BLOBMSG_TYPE_ARRAY },
	[OCI_CAPABILITIES_AMBIENT] = { "ambient", BLOBMSG_TYPE_ARRAY },
};

static uint64_t parseOCIcap(struct blob_attr *msg)
{
	struct blob_attr *cur;
	int rem;
	uint64_t caps = 0;
	int capnum;

	/* each capset is optional, set all-1 mask if absent */
	if (!msg)
		return JAIL_CAP_ALL;

	blobmsg_for_each_attr(cur, msg, rem) {
		capnum = find_capabilities(blobmsg_get_string(cur));
		if (capnum < 0)
			return JAIL_CAP_ERROR;

		caps |= (1LLU << capnum);
	}

	return caps;
}

int parseOCIcapabilities(struct jail_capset *capset, struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_CAPABILITIES_MAX];
	uint64_t caps;
	blobmsg_parse(oci_capabilities_policy, __OCI_CAPABILITIES_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	caps = parseOCIcap(tb[OCI_CAPABILITIES_BOUNDING]);
	if (caps == JAIL_CAP_ERROR)
		return EINVAL;
	else
		capset->bounding = caps;

	caps = parseOCIcap(tb[OCI_CAPABILITIES_EFFECTIVE]);
	if (caps == JAIL_CAP_ERROR)
		return EINVAL;
	else
		capset->effective = caps;

	caps = parseOCIcap(tb[OCI_CAPABILITIES_INHERITABLE]);
	if (caps == JAIL_CAP_ERROR)
		return EINVAL;
	else
		capset->inheritable = caps;

	caps = parseOCIcap(tb[OCI_CAPABILITIES_PERMITTED]);
	if (caps == JAIL_CAP_ERROR)
		return EINVAL;
	else
		capset->permitted = caps;

	caps = parseOCIcap(tb[OCI_CAPABILITIES_AMBIENT]);
	if (caps == JAIL_CAP_ERROR)
		return EINVAL;
	else
		capset->ambient = caps;

	capset->apply = 1;

	return 0;
}


int applyOCIcapabilities(struct jail_capset ocicapset, uint64_t retain)
{
	struct __user_cap_header_struct uh = {};
	struct __user_cap_data_struct ud[2];
	int cap;
	int is_set;

	if (!ocicapset.apply)
		return 0;

	/* drop from bounding set */
	if (ocicapset.bounding != JAIL_CAP_ALL) {
		for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
			if (!prctl(PR_CAPBSET_READ, cap, 0, 0, 0)) {
				/* can't raise */
				if (ocicapset.bounding & (1LLU << cap))
					ERROR("capability %s (%d) is not in bounding set\n", capabilities_names[cap], cap);

				continue;
			}
			if ( ((ocicapset.bounding | retain) & (1LLU << cap)) == 0) {
				DEBUG("dropping capability %s (%d) from bounding set\n", capabilities_names[cap], cap);
				if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) {
					ERROR("prctl(PR_CAPBSET_DROP, %d) failed: %m\n", cap);
					return errno;
				}
			} else {
				DEBUG("keeping capability %s (%d)\n", capabilities_names[cap], cap);
			}
		}
	}

	/* set effective, permitted and inheritable */
	uh.version = _LINUX_CAPABILITY_VERSION_3;
	uh.pid = getpid();

	if (capget(&uh, ud)) {
		ERROR("capget() failed\n");
		return -1;
	}

	DEBUG("old capabilities: Pe=%016llx Pp=%016llx Pi=%016llx\n",
		0LLU | ud[0].effective | (0LLU | ud[1].effective) << 32,
		0LLU | ud[0].permitted | (0LLU | ud[1].permitted) << 32,
		0LLU | ud[0].inheritable | (0LLU | ud[1].inheritable) << 32);

	if (ocicapset.effective != JAIL_CAP_ALL) {
		ud[0].effective = (ocicapset.effective | retain) & 0xFFFFFFFFU;
		ud[1].effective = ((ocicapset.effective | retain) >> 32) & 0xFFFFFFFFU;
	}

	if (ocicapset.permitted != JAIL_CAP_ALL) {
		ud[0].permitted = (ocicapset.permitted | retain) & 0xFFFFFFFFU;
		ud[1].permitted = ((ocicapset.permitted | retain) >> 32) & 0xFFFFFFFFU;
	}

	if (ocicapset.inheritable != JAIL_CAP_ALL) {
		ud[0].inheritable = (ocicapset.inheritable | retain) & 0xFFFFFFFFU;
		ud[1].inheritable = ((ocicapset.inheritable | retain) >> 32) & 0xFFFFFFFFU;
	}

	DEBUG("new capabilities: Pe=%016llx Pp=%016llx Pi=%016llx\n",
		0LLU | ud[0].effective | (0LLU | ud[1].effective) << 32,
		0LLU | ud[0].permitted | (0LLU | ud[1].permitted) << 32,
		0LLU | ud[0].inheritable | (0LLU | ud[1].inheritable) << 32);

	if (capset(&uh, ud)) {
		ERROR("capset() failed\n");
		return -1;
	}

	/* edit ambient set */
	if (ocicapset.ambient != JAIL_CAP_ALL) {
		for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
			is_set = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0);
			if ( (ocicapset.ambient & (1LLU << cap)) == 0) {
				if (is_set) {
					DEBUG("dropping capability %s (%d) from ambient set\n", capabilities_names[cap], cap);
					if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, cap, 0, 0)) {
						ERROR("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, %d, 0, 0) failed: %m\n", cap);
						return errno;
					}
				}
			} else {
				if (!is_set) {
					DEBUG("raising capability %s (%d) to ambient set\n", capabilities_names[cap], cap);
					if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {\
						ERROR("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, %d, 0, 0) failed: %m\n", cap);
						return errno;
					}
				}
			}
		}
	}

	return 0;
}

int parseOCIcapabilities_from_file(struct jail_capset *capset, const char *file)
{
	struct blob_buf b = { 0 };
	int ret;

	blob_buf_init(&b, 0);
	ret = !blobmsg_add_json_from_file(&b, file);
	if (ret) {
		ERROR("failed to load %s\n", file);
		goto err;
	}

	ret = parseOCIcapabilities(capset, b.head);

err:
	blob_buf_free(&b);
	return ret;
}
