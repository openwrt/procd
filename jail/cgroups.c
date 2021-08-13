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
 *
 * reads unified cgroup config as proposed in
 * https://github.com/opencontainers/runtime-spec/pull/1040
 * attempt conversion from cgroup1 -> cgroup2
 * https://github.com/containers/crun/blob/0.14.1/crun.1.md#cgroup-v2
 *
 * ToDo:
 *  - convert cgroup1 net_prio and net_cls to eBPF program
 *  - rdma (anyone?) intelrdt (anyone?)
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <libgen.h>
#include <inttypes.h>

#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>
#include <libubox/utils.h>

#include "log.h"
#include "cgroups.h"
#include "cgroups-bpf.h"

#define CGROUP_ROOT "/sys/fs/cgroup/"
#define CGROUP_IO_WEIGHT_MAX 10000

struct cgval {
	struct avl_node avl;
	char *val;
};

struct avl_tree cgvals;
static char *cgroup_path;
static bool initialized;

void cgroups_prepare(void) {
	initialized = false;
}

void cgroups_init(const char *p) {
	avl_init(&cgvals, avl_strcmp, false, NULL);
	cgroup_path = strdup(p);
	initialized = true;
}

static void cgroups_set(const char *key, const char *val)
{
	struct cgval *valp;

	valp = avl_find_element(&cgvals, key, valp, avl);
	if (!valp) {
		valp = malloc(sizeof(struct cgval));
		if (!valp)
			exit(ENOMEM);

		valp->avl.key = strdup(key);
		avl_insert(&cgvals, &valp->avl);
	} else {
		DEBUG("overwriting previous cgroup2 assignment %s=\"%s\"!\n", key, valp->val);
		free(valp->val);
	}

	valp->val = strdup(val);
}

void cgroups_free(void)
{
	struct cgval *valp, *tmp;

	if (initialized) {
		avl_remove_all_elements(&cgvals, valp, avl, tmp) {
			free((void *)(valp->avl.key));
			free(valp->val);
			free(valp);
		}
		free(cgroup_path);
	}
}

void cgroups_apply(pid_t pid)
{
	struct cgval *valp;
	char *cdir, *ent;
	int fd;
	size_t maxlen = strlen("cgroup.subtree_control");

	bool cpuset = false,
	     cpu = false,
	     hugetlb = false,
	     io = false,
	     memory = false,
	     pids = false,
	     rdma = false;

	char subtree_control[64] = { 0 };

	DEBUG("using cgroup path %s\n", cgroup_path);
	mkdir_p(cgroup_path, 0700);

	/* find which controllers need to be enabled */
	avl_for_each_element(&cgvals, valp, avl) {
		ent = (char *)valp->avl.key;
		if (strlen(ent) > maxlen)
			maxlen = strlen(ent);

		if (!strncmp("cpuset.", ent, 7))
			cpuset = true;
		else if (!strncmp("cpu.", ent, 4))
			cpu = true;
		else if (!strncmp("hugetlb.", ent, 8))
			hugetlb = true;
		else if (!strncmp("io.", ent, 3))
			io = true;
		else if (!strncmp("memory.", ent, 7))
			memory = true;
		else if (!strncmp("pids.", ent, 5))
			pids = true;
		else if (!strncmp("rdma.", ent, 5))
			pids = true;
	}

	maxlen += strlen(cgroup_path) + 2;

	if (cpuset)
		strcat(subtree_control, "+cpuset ");

	if (cpu)
		strcat(subtree_control, "+cpu ");

	if (hugetlb)
		strcat(subtree_control, "+hugetlb ");

	if (io)
		strcat(subtree_control, "+io ");

	if (memory)
		strcat(subtree_control, "+memory ");

	if (pids)
		strcat(subtree_control, "+pids ");

	if (rdma)
		strcat(subtree_control, "+rdma ");

	/* remove trailing space */
	ent = strchr(subtree_control, '\0') - 1;
	*ent = '\0';

	ent = malloc(maxlen);
	if (!ent)
		exit(ENOMEM);

	DEBUG("recursively applying cgroup.subtree_control = \"%s\"\n", subtree_control);
	cdir = &cgroup_path[strlen(CGROUP_ROOT) - 2];
	while ((cdir = strchr(cdir + 1, '/'))) {
		*cdir = '\0';
		snprintf(ent, maxlen, "%s/cgroup.subtree_control", cgroup_path);
		DEBUG(" * %s\n", ent);
		if ((fd = open(ent, O_WRONLY)) < 0) {
			ERROR("can't open %s: %m\n", ent);
			continue;
		}

		if (write(fd, subtree_control, strlen(subtree_control)) == -1) {
			ERROR("can't write to %s: %m\n", ent);
			close(fd);
			continue;
		}

		close(fd);
		*cdir = '/';
	}

	avl_for_each_element(&cgvals, valp, avl) {
		DEBUG("applying cgroup2 %s=\"%s\"\n", (char *)valp->avl.key, valp->val);
		snprintf(ent, maxlen, "%s/%s", cgroup_path, (char *)valp->avl.key);
		fd = open(ent, O_WRONLY);
		if (fd < 0) {
			ERROR("can't open %s: %m\n", ent);
			continue;
		}
		if (dprintf(fd, "%s", valp->val) < 0) {
			ERROR("can't write to %s: %m\n", ent);
		};
		close(fd);
	}

	int dirfd = open(cgroup_path, O_DIRECTORY);
	if (dirfd < 0) {
		ERROR("can't open %s: %m\n", cgroup_path);
	} else {
		attach_cgroups_ebpf(dirfd);
		close(dirfd);
	}

	snprintf(ent, maxlen, "%s/%s", cgroup_path, "cgroup.procs");
	fd = open(ent, O_WRONLY);
	if (fd < 0) {
		ERROR("can't open %s: %m\n", cgroup_path);
	} else {
		dprintf(fd, "%d", pid);
		close(fd);
	}

	free(ent);
}

enum {
	OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_MAJOR,
	OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_MINOR,
	OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_WEIGHT,
	OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_LEAFWEIGHT,
	__OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_MAX,
};

static const struct blobmsg_policy oci_linux_cgroups_blockio_weightdevice_policy[] = {
	[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_MAJOR] = { "major", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_MINOR] = { "minor", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_WEIGHT] = { "weight", BLOBMSG_TYPE_INT32 },
	[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_LEAFWEIGHT] = { "leafWeight", BLOBMSG_TYPE_INT32 },
};

enum {
	OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAJOR,
	OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MINOR,
	OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_RATE,
	__OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAX,
};

static const struct blobmsg_policy oci_linux_cgroups_blockio_throttledevice_policy[] = {
	[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAJOR] = { "major", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MINOR] = { "minor", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_RATE] = { "rate", BLOBMSG_CAST_INT64 },
};

enum {
	OCI_LINUX_CGROUPS_BLOCKIO_WEIGHT,
	OCI_LINUX_CGROUPS_BLOCKIO_LEAFWEIGHT,
	OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE,
	OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEREADBPSDEVICE,
	OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEWRITEBPSDEVICE,
	OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEREADIOPSDEVICE,
	OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEWRITEIOPSDEVICE,
	__OCI_LINUX_CGROUPS_BLOCKIO_MAX,
};

static const struct blobmsg_policy oci_linux_cgroups_blockio_policy[] = {
	[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHT] = { "weight", BLOBMSG_TYPE_INT32 },
	[OCI_LINUX_CGROUPS_BLOCKIO_LEAFWEIGHT] = { "leafWeight", BLOBMSG_TYPE_INT32 },
	[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE] = { "weightDevice", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEREADBPSDEVICE] = { "throttleReadBpsDevice", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEWRITEBPSDEVICE] = { "throttleWriteBpsDevice", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEREADIOPSDEVICE] = { "throttleReadIOPSDevice", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEWRITEIOPSDEVICE] = { "throttleWriteIOPSDevice", BLOBMSG_TYPE_ARRAY },
};

struct posix_dev {
	uint64_t major;
	uint64_t minor;
};

struct iomax_line {
	struct avl_node avl;
	struct posix_dev dev;
	uint64_t rbps;
	uint64_t wbps;
	uint64_t riops;
	uint64_t wiops;
};

static int avl_devcmp(const void *k1, const void *k2, void *ptr)
{
	struct posix_dev *d1 = (struct posix_dev *)k1, *d2 = (struct posix_dev *)k2;

	if (d1->major < d2->major)
		return -1;

	if (d1->major > d2->major)
		return 1;

	if (d1->minor < d2->minor)
		return -1;

	if (d1->minor > d2->minor)
		return 1;

	return 0;
}

static struct iomax_line *get_iomax_line(struct avl_tree *iomax, uint64_t major, uint64_t minor)
{
	struct iomax_line *l;
	struct posix_dev d;
	d.major = major;
	d.minor = minor;
	l = avl_find_element(iomax, &d, l, avl);
	if (!l) {
		l = malloc(sizeof(struct iomax_line));
		if (!l)
			exit(ENOMEM);

		l->dev.major = d.major;
		l->dev.minor = d.minor;
		l->avl.key = &l->dev;
		l->rbps = -1;
		l->wbps = -1;
		l->riops = -1;
		l->wiops = -1;
		avl_insert(iomax, &l->avl);
	}

	return l;
}

static int parseOCIlinuxcgroups_legacy_blockio(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_CGROUPS_BLOCKIO_MAX],
			 *tbwd[__OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_MAX],
			 *tbtd[__OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAX],
			 *cur;
	int rem;
	int weight = -1, leafweight = -1;
	size_t numweightstrs = 0, numiomaxstrs = 0, strtotlen = 1;
	char **weightstrs = NULL, **iomaxstrs = NULL, **curstr;
	char *weightstr, *iomaxstr;
	struct avl_tree iomax;
	struct iomax_line *curiomax, *tmp;

	blobmsg_parse(oci_linux_cgroups_blockio_policy, __OCI_LINUX_CGROUPS_BLOCKIO_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHT]) {
		weight = blobmsg_get_u32(tb[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHT]);
		++numweightstrs;
	}

	if (weight > CGROUP_IO_WEIGHT_MAX)
		return ERANGE;

	if (tb[OCI_LINUX_CGROUPS_BLOCKIO_LEAFWEIGHT])
		leafweight = blobmsg_get_u32(tb[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHT]);

	if (leafweight > CGROUP_IO_WEIGHT_MAX)
		return ERANGE;

	blobmsg_for_each_attr(cur, tb[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE], rem)
		++numweightstrs;

	weightstrs = calloc(numweightstrs + 1, sizeof(char *));
	if (!weightstrs)
		exit(ENOMEM);

	numweightstrs = 0;

	if (weight > -1)
		if (asprintf(&weightstrs[numweightstrs++], "default %d", weight) < 0)
			return ENOMEM;

	blobmsg_for_each_attr(cur, tb[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE], rem) {
		uint64_t major, minor;
		int devweight = weight, devleafweight = leafweight;

		blobmsg_parse(oci_linux_cgroups_blockio_weightdevice_policy, __OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_MAX, tbwd, blobmsg_data(cur), blobmsg_len(cur));
		if (!tbwd[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_MAJOR] ||
		    !tbwd[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_MINOR])
			return ENODATA;

		if (!tbwd[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_WEIGHT] &&
		    !tbwd[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_LEAFWEIGHT])
			return ENODATA;

		if (tbwd[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_WEIGHT])
			devweight = blobmsg_get_u32(tbwd[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_WEIGHT]);

		if (devweight > CGROUP_IO_WEIGHT_MAX)
			return ERANGE;

		if (tbwd[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_LEAFWEIGHT])
			devleafweight = blobmsg_get_u32(tbwd[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_LEAFWEIGHT]);

		if (devleafweight > CGROUP_IO_WEIGHT_MAX)
			return ERANGE;

		if (tbwd[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_LEAFWEIGHT])
			return ENOTSUP;

		major = blobmsg_cast_u64(tbwd[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_MAJOR]);
		minor = blobmsg_cast_u64(tbwd[OCI_LINUX_CGROUPS_BLOCKIO_WEIGHTDEVICE_MINOR]);

		if (asprintf(&weightstrs[numweightstrs++], "%" PRIu64 ":%" PRIu64 " %u", major, minor, devweight) < 0)
			return ENOMEM;
	}

	if (numweightstrs) {
		curstr = weightstrs;
		while (*curstr)
			strtotlen += strlen(*(curstr++)) + 1;

		weightstr = calloc(strtotlen, sizeof(char));
		if (!weightstr)
			exit(ENOMEM);

		curstr = weightstrs;
		while (*curstr) {
			strcat(weightstr, *curstr);
			strcat(weightstr, "\n");
			free(*(curstr++));
		}

		cgroups_set("io.bfq.weight", weightstr);
		free(weightstr);
	};

	free(weightstrs);

	avl_init(&iomax, avl_devcmp, false, NULL);

	blobmsg_for_each_attr(cur, tb[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEREADBPSDEVICE], rem) {
		struct iomax_line *l;

		blobmsg_parse(oci_linux_cgroups_blockio_throttledevice_policy, __OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAX, tbtd, blobmsg_data(cur), blobmsg_len(cur));

		if (!tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAJOR] ||
		    !tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MINOR] ||
		    !tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_RATE])
			return ENODATA;

		l = get_iomax_line(&iomax,
				   blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAJOR]),
				   blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MINOR]));

		l->rbps = blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_RATE]);
	}

	blobmsg_for_each_attr(cur, tb[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEWRITEBPSDEVICE], rem) {
		struct iomax_line *l;

		blobmsg_parse(oci_linux_cgroups_blockio_throttledevice_policy, __OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAX, tbtd, blobmsg_data(cur), blobmsg_len(cur));

		if (!tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAJOR] ||
		    !tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MINOR] ||
		    !tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_RATE])
			return ENODATA;

		l = get_iomax_line(&iomax,
				   blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAJOR]),
				   blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MINOR]));

		l->wbps = blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_RATE]);
	}

	blobmsg_for_each_attr(cur, tb[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEREADIOPSDEVICE], rem) {
		struct iomax_line *l;

		blobmsg_parse(oci_linux_cgroups_blockio_throttledevice_policy, __OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAX, tbtd, blobmsg_data(cur), blobmsg_len(cur));

		if (!tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAJOR] ||
		    !tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MINOR] ||
		    !tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_RATE])
			return ENODATA;

		l = get_iomax_line(&iomax,
				   blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAJOR]),
				   blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MINOR]));

		l->riops = blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_RATE]);
	}

	blobmsg_for_each_attr(cur, tb[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEWRITEIOPSDEVICE], rem) {
		struct iomax_line *l;

		blobmsg_parse(oci_linux_cgroups_blockio_throttledevice_policy, __OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAX, tbtd, blobmsg_data(cur), blobmsg_len(cur));

		if (!tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAJOR] ||
		    !tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MINOR] ||
		    !tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_RATE])
			return ENODATA;

		l = get_iomax_line(&iomax,
				   blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MAJOR]),
				   blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_MINOR]));

		l->wiops = blobmsg_cast_u64(tbtd[OCI_LINUX_CGROUPS_BLOCKIO_THROTTLEDEVICE_RATE]);
	}

	avl_for_each_element(&iomax, curiomax, avl)
		++numiomaxstrs;

	if (!numiomaxstrs)
		return 0;

	iomaxstrs = calloc(numiomaxstrs + 1, sizeof(char *));
	if (!iomaxstrs)
		exit(ENOMEM);

	numiomaxstrs = 0;

	avl_for_each_element(&iomax, curiomax, avl) {
		char iomaxlstr[160];
		char lstr[32];

		sprintf(iomaxlstr, "%" PRIu64 ":%" PRIu64 " ", curiomax->dev.major, curiomax->dev.minor);

		if (curiomax->rbps != -1) {
			sprintf(lstr, "rbps=%" PRIu64 " ", curiomax->rbps);
			strcat(iomaxlstr, lstr);
		}
		if (curiomax->wbps != -1) {
			sprintf(lstr, "wbps=%" PRIu64 " ", curiomax->wbps);
			strcat(iomaxlstr, lstr);
		}
		if (curiomax->riops != -1) {
			sprintf(lstr, "riops=%" PRIu64 " ", curiomax->riops);
			strcat(iomaxlstr, lstr);
		}
		if (curiomax->wiops != -1) {
			sprintf(lstr, "wiops=%" PRIu64 " ", curiomax->wiops);
			strcat(iomaxlstr, lstr);
		}

		iomaxstrs[numiomaxstrs++] = strdup(iomaxlstr);
	}

	avl_for_each_element_safe(&iomax, curiomax, avl, tmp) {
		avl_delete(&iomax, &curiomax->avl);
		free(curiomax);
	}

	strtotlen = 1; /* 1 accounts for \0 at end of string */
	if (numiomaxstrs) {
		curstr = iomaxstrs;
		while (*curstr)
			strtotlen += strlen(*(curstr++)) + 1; /* +1 accounts for \n at end of line */

		iomaxstr = calloc(strtotlen, sizeof(char));
		if (!iomaxstr)
			exit(ENOMEM);

		curstr = iomaxstrs;

		while (*curstr) {
			strcat(iomaxstr, *curstr);
			strcat(iomaxstr, "\n");
			free(*(curstr++));
		}

		cgroups_set("io.max", iomaxstr);
		free(iomaxstr);
	};

	free(iomaxstrs);

	return 0;
}


enum {
	OCI_LINUX_CGROUPS_CPU_SHARES,
	OCI_LINUX_CGROUPS_CPU_PERIOD,
	OCI_LINUX_CGROUPS_CPU_QUOTA,
	OCI_LINUX_CGROUPS_CPU_REALTIMERUNTIME,
	OCI_LINUX_CGROUPS_CPU_REALTIMEPERIOD,
	OCI_LINUX_CGROUPS_CPU_CPUS,
	OCI_LINUX_CGROUPS_CPU_MEMS,
	__OCI_LINUX_CGROUPS_CPU_MAX,
};

static const struct blobmsg_policy oci_linux_cgroups_cpu_policy[] = {
	[OCI_LINUX_CGROUPS_CPU_SHARES] = { "shares", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_CGROUPS_CPU_PERIOD] = { "period", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_CGROUPS_CPU_QUOTA] = { "quota", BLOBMSG_CAST_INT64 }, /* signed int64! */
	[OCI_LINUX_CGROUPS_CPU_REALTIMEPERIOD] = { "realtimePeriod", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_CGROUPS_CPU_REALTIMERUNTIME] = { "realtimeRuntime", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_CGROUPS_CPU_CPUS] = { "cpus", BLOBMSG_TYPE_STRING },
	[OCI_LINUX_CGROUPS_CPU_MEMS] = { "mems", BLOBMSG_TYPE_STRING },
};

static int parseOCIlinuxcgroups_legacy_cpu(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_CGROUPS_CPU_MAX];
	uint64_t shares, period = 0;
	int64_t quota = -2; /* unset */
	char tmp[32] = { 0 };

	blobmsg_parse(oci_linux_cgroups_cpu_policy, __OCI_LINUX_CGROUPS_CPU_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_LINUX_CGROUPS_CPU_REALTIMEPERIOD] ||
	    tb[OCI_LINUX_CGROUPS_CPU_REALTIMERUNTIME])
		return ENOTSUP; /* no equivalent in cgroup2 */

	if (tb[OCI_LINUX_CGROUPS_CPU_SHARES]) {
		shares = blobmsg_cast_u64(tb[OCI_LINUX_CGROUPS_CPU_SHARES]);
		if ((shares < 2) || (shares > 262144))
			return ERANGE;

		snprintf(tmp, sizeof(tmp), "%" PRIu64, (((uint64_t)1) + ((shares - 2) * 9999) / 262142));
		cgroups_set("cpu.weight", tmp);
		tmp[0] = '\0';
	}

	if (tb[OCI_LINUX_CGROUPS_CPU_QUOTA])
		quota = blobmsg_cast_s64(tb[OCI_LINUX_CGROUPS_CPU_QUOTA]);

	if (tb[OCI_LINUX_CGROUPS_CPU_PERIOD])
		period = blobmsg_cast_u64(tb[OCI_LINUX_CGROUPS_CPU_PERIOD]);

	if (period) {
		if (quota >= 0)
			snprintf(tmp, sizeof(tmp), "%" PRId64 " %" PRIu64 , quota, period);
		else
			snprintf(tmp, sizeof(tmp), "max %" PRIu64, period); /* assume default */
	} else if (quota >= 0) {
		snprintf(tmp, sizeof(tmp), "%" PRId64, quota);
	} else if (quota == -1) {
		strcpy(tmp, "max");
	}

	if (tmp[0])
		cgroups_set("cpu.max", tmp);

	if (tb[OCI_LINUX_CGROUPS_CPU_CPUS])
		cgroups_set("cpuset.cpus", blobmsg_get_string(tb[OCI_LINUX_CGROUPS_CPU_CPUS]));

	if (tb[OCI_LINUX_CGROUPS_CPU_MEMS])
		cgroups_set("cpuset.mems", blobmsg_get_string(tb[OCI_LINUX_CGROUPS_CPU_MEMS]));

	return 0;
}


enum {
	OCI_LINUX_CGROUPS_MEMORY_LIMIT,
	OCI_LINUX_CGROUPS_MEMORY_RESERVATION,
	OCI_LINUX_CGROUPS_MEMORY_SWAP,
	OCI_LINUX_CGROUPS_MEMORY_KERNEL,
	OCI_LINUX_CGROUPS_MEMORY_KERNELTCP,
	OCI_LINUX_CGROUPS_MEMORY_SWAPPINESS,
	OCI_LINUX_CGROUPS_MEMORY_DISABLEOOMKILLER,
	OCI_LINUX_CGROUPS_MEMORY_USEHIERARCHY,
	__OCI_LINUX_CGROUPS_MEMORY_MAX,
};

static const struct blobmsg_policy oci_linux_cgroups_memory_policy[] = {
	[OCI_LINUX_CGROUPS_MEMORY_LIMIT] = { "limit", BLOBMSG_CAST_INT64 }, /* signed int64! */
	[OCI_LINUX_CGROUPS_MEMORY_RESERVATION] = { "reservation", BLOBMSG_CAST_INT64 }, /* signed int64! */
	[OCI_LINUX_CGROUPS_MEMORY_SWAP] = { "swap", BLOBMSG_CAST_INT64 }, /* signed int64! */
	[OCI_LINUX_CGROUPS_MEMORY_KERNEL] = { "kernel", BLOBMSG_CAST_INT64 }, /* signed int64! ignored */
	[OCI_LINUX_CGROUPS_MEMORY_KERNELTCP] = { "kernelTCP", BLOBMSG_CAST_INT64 }, /* signed int64! ignored */
	[OCI_LINUX_CGROUPS_MEMORY_SWAPPINESS] = { "swappiness", BLOBMSG_CAST_INT64 },
	[OCI_LINUX_CGROUPS_MEMORY_DISABLEOOMKILLER] = { "disableOOMKiller", BLOBMSG_TYPE_BOOL },
	[OCI_LINUX_CGROUPS_MEMORY_USEHIERARCHY] { "useHierarchy", BLOBMSG_TYPE_BOOL },
};

static int parseOCIlinuxcgroups_legacy_memory(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_CGROUPS_MEMORY_MAX];
	char tmp[32] = { 0 };
	int64_t limit = -1, swap, reservation;

	blobmsg_parse(oci_linux_cgroups_memory_policy, __OCI_LINUX_CGROUPS_MEMORY_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	/*
	 * not all properties of the OCI memory section can be mapped to cgroup2
	 * kernel memory accounting is always enabled and included in the set
	 *   memory limit, hence these options can be ignored
	 * disableOOMKiller could be emulated using oom_score_adj + seccomp eBPF
	 *   preventing self-upgrade (but allow downgrade)
	 *
	 * see also https://github.com/opencontainers/runtime-spec/issues/1005
	 */
	if (tb[OCI_LINUX_CGROUPS_MEMORY_SWAPPINESS] ||
	    tb[OCI_LINUX_CGROUPS_MEMORY_DISABLEOOMKILLER] ||
	    tb[OCI_LINUX_CGROUPS_MEMORY_USEHIERARCHY])
		return ENOTSUP;


	if (tb[OCI_LINUX_CGROUPS_MEMORY_LIMIT]) {
		limit = blobmsg_cast_s64(tb[OCI_LINUX_CGROUPS_MEMORY_LIMIT]);
		if (limit == -1)
			strcpy(tmp, "max");
		else
			snprintf(tmp, sizeof(tmp), "%" PRId64, limit);

		cgroups_set("memory.max", tmp);
	}

	if (tb[OCI_LINUX_CGROUPS_MEMORY_RESERVATION]) {
		reservation = blobmsg_cast_s64(tb[OCI_LINUX_CGROUPS_MEMORY_RESERVATION]);

		if (reservation == -1)
			strcpy(tmp, "max");
		else
			snprintf(tmp, sizeof(tmp), "%" PRId64, reservation);

		cgroups_set("memory.low", tmp);
	}

	/* OCI 'swap' acounts for memory+swap */
	if (tb[OCI_LINUX_CGROUPS_MEMORY_SWAP]) {
		swap = blobmsg_cast_s64(tb[OCI_LINUX_CGROUPS_MEMORY_SWAP]);

		if (swap == -1)
			strcpy(tmp, "max");
		else if (limit == -1 || (limit < swap))
			snprintf(tmp, sizeof(tmp), "%" PRId64, swap);
		else
			snprintf(tmp, sizeof(tmp), "%" PRId64, limit - swap);

		cgroups_set("memory.swap_max", tmp);
	}

	return 0;
}


enum {
	OCI_LINUX_CGROUPS_PIDS_LIMIT,
	__OCI_LINUX_CGROUPS_PIDS_MAX,
};

static const struct blobmsg_policy oci_linux_cgroups_pids_policy[] = {
	[OCI_LINUX_CGROUPS_PIDS_LIMIT] = { "limit", BLOBMSG_CAST_INT64 },
};

static int parseOCIlinuxcgroups_legacy_pids(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_CGROUPS_MEMORY_MAX];
	char tmp[32] = { 0 };

	blobmsg_parse(oci_linux_cgroups_pids_policy, __OCI_LINUX_CGROUPS_PIDS_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[OCI_LINUX_CGROUPS_PIDS_LIMIT])
		return EINVAL;

	snprintf(tmp, sizeof(tmp), "%" PRIu64, blobmsg_cast_u64(tb[OCI_LINUX_CGROUPS_PIDS_LIMIT]));

	cgroups_set("pids.max", tmp);

	return 0;
}

static int parseOCIlinuxcgroups_unified(struct blob_attr *msg)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, msg, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			return EINVAL;

		/* restrict keys */
		if (strchr(blobmsg_name(cur), '/') ||
		    !strcmp(blobmsg_name(cur), "cgroup.subtree_control") ||
		    !strcmp(blobmsg_name(cur), "cgroup.procs") ||
		    !strcmp(blobmsg_name(cur), "cgroup.threads") ||
		    !strcmp(blobmsg_name(cur), "cgroup.freeze"))
			return EINVAL;

		cgroups_set(blobmsg_name(cur), blobmsg_get_string(cur));
	}

	return 0;
}

enum {
	OCI_LINUX_CGROUPS_BLOCKIO,
	OCI_LINUX_CGROUPS_CPU,
	OCI_LINUX_CGROUPS_DEVICES,
	OCI_LINUX_CGROUPS_HUGEPAGELIMITS,
	OCI_LINUX_CGROUPS_INTELRDT,
	OCI_LINUX_CGROUPS_MEMORY,
	OCI_LINUX_CGROUPS_NETWORK,
	OCI_LINUX_CGROUPS_PIDS,
	OCI_LINUX_CGROUPS_RDMA,
	OCI_LINUX_CGROUPS_UNIFIED,
	__OCI_LINUX_CGROUPS_MAX,
};

static const struct blobmsg_policy oci_linux_cgroups_policy[] = {
	[OCI_LINUX_CGROUPS_BLOCKIO] = { "blockIO", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_CGROUPS_CPU] = { "cpu", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_CGROUPS_DEVICES] = { "devices", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_CGROUPS_HUGEPAGELIMITS] = { "hugepageLimits", BLOBMSG_TYPE_ARRAY },
	[OCI_LINUX_CGROUPS_INTELRDT] = { "intelRdt", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_CGROUPS_MEMORY] = { "memory", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_CGROUPS_NETWORK] = { "network", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_CGROUPS_PIDS] = { "pids", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_CGROUPS_RDMA] = { "rdma", BLOBMSG_TYPE_TABLE },
	[OCI_LINUX_CGROUPS_UNIFIED] = { "unified", BLOBMSG_TYPE_TABLE },
};

int parseOCIlinuxcgroups(struct blob_attr *msg)
{
	struct blob_attr *tb[__OCI_LINUX_CGROUPS_MAX];
	int ret;

	blobmsg_parse(oci_linux_cgroups_policy, __OCI_LINUX_CGROUPS_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if (tb[OCI_LINUX_CGROUPS_HUGEPAGELIMITS] ||
	    tb[OCI_LINUX_CGROUPS_INTELRDT] ||
	    tb[OCI_LINUX_CGROUPS_NETWORK] ||
	    tb[OCI_LINUX_CGROUPS_RDMA])
		return ENOTSUP;

	if (tb[OCI_LINUX_CGROUPS_BLOCKIO]) {
		ret = parseOCIlinuxcgroups_legacy_blockio(tb[OCI_LINUX_CGROUPS_BLOCKIO]);
		if (ret)
			return ret;
	}

	if (tb[OCI_LINUX_CGROUPS_CPU]) {
		ret = parseOCIlinuxcgroups_legacy_cpu(tb[OCI_LINUX_CGROUPS_CPU]);
		if (ret)
			return ret;
	}

	if (tb[OCI_LINUX_CGROUPS_DEVICES]) {
		ret = parseOCIlinuxcgroups_devices(tb[OCI_LINUX_CGROUPS_DEVICES]);
		if (ret)
			return ret;
	}

	if (tb[OCI_LINUX_CGROUPS_MEMORY]) {
		ret = parseOCIlinuxcgroups_legacy_memory(tb[OCI_LINUX_CGROUPS_MEMORY]);
		if (ret)
			return ret;
	}

	if (tb[OCI_LINUX_CGROUPS_PIDS]) {
		ret = parseOCIlinuxcgroups_legacy_pids(tb[OCI_LINUX_CGROUPS_PIDS]);
		if (ret)
			return ret;
	}

	if (tb[OCI_LINUX_CGROUPS_UNIFIED]) {
		ret = parseOCIlinuxcgroups_unified(tb[OCI_LINUX_CGROUPS_UNIFIED]);
		if (ret)
			return ret;
	}

	return 0;
}
