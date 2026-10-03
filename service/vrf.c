/*
 * Copyright (C) 2026 Nick Hainke <vincent@systemli.org>
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
 * Bind the sockets of a cgroup to a VRF device, the way 'ip vrf exec' does.
 */

#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "../log.h"
#include "vrf.h"

#define BPF_MOV64_IMM(DST, IMM) \
	((struct bpf_insn){ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = DST, .imm = IMM })

#define BPF_STX_MEM(SIZE, DST, SRC, OFF) \
	((struct bpf_insn){ .code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, .dst_reg = DST, .src_reg = SRC, .off = OFF })

#define BPF_EXIT_INSN() \
	((struct bpf_insn){ .code = BPF_JMP | BPF_EXIT })

static int
vrf_bpf(int cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static bool
vrf_linkinfo_is_vrf(struct rtattr *linkinfo)
{
	struct rtattr *rta = RTA_DATA(linkinfo);
	int len = RTA_PAYLOAD(linkinfo);

	for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
		if (rta->rta_type == IFLA_INFO_KIND)
			return RTA_PAYLOAD(rta) >= strlen("vrf") &&
			       !strncmp(RTA_DATA(rta), "vrf", RTA_PAYLOAD(rta));

	return false;
}

/* returns the ifindex of vrf_name, also checks that it is a VRF device */
static int
vrf_get_ifindex(const char *vrf_name)
{
	struct {
		struct nlmsghdr hdr;
		struct ifinfomsg ifi;
		char attrbuf[RTA_SPACE(IFNAMSIZ)];
	} req = {
		.hdr = {
			.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
			.nlmsg_type = RTM_GETLINK,
			.nlmsg_flags = NLM_F_REQUEST,
			.nlmsg_seq = 1,
		},
		.ifi = { .ifi_family = AF_UNSPEC },
	};
	size_t namelen = strlen(vrf_name) + 1;
	struct nlmsghdr *nh;
	struct ifinfomsg *ifi;
	struct rtattr *rta;
	bool is_vrf = false;
	char buf[16384];
	int sock, len, ret;
	ssize_t n;

	if (namelen > IFNAMSIZ)
		return -EINVAL;

	rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.hdr.nlmsg_len));
	rta->rta_type = IFLA_IFNAME;
	rta->rta_len = RTA_LENGTH(namelen);
	memcpy(RTA_DATA(rta), vrf_name, namelen);
	req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_ALIGN(rta->rta_len);

	sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (sock < 0)
		return -errno;

	if (send(sock, &req, req.hdr.nlmsg_len, 0) < 0) {
		ret = -errno;
		close(sock);
		return ret;
	}

	n = recv(sock, buf, sizeof(buf), 0);
	ret = -errno;
	close(sock);
	if (n < 0)
		return ret;

	nh = (struct nlmsghdr *)buf;
	if (!NLMSG_OK(nh, (size_t)n))
		return -EIO;

	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nh);

		if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(*err)) || !err->error)
			return -EIO;

		return err->error;
	}

	if (nh->nlmsg_type != RTM_NEWLINK || nh->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
		return -EIO;

	ifi = NLMSG_DATA(nh);
	len = IFLA_PAYLOAD(nh);
	for (rta = IFLA_RTA(ifi); RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
		if (rta->rta_type == IFLA_LINKINFO)
			is_vrf = vrf_linkinfo_is_vrf(rta);

	if (!is_vrf) {
		ERROR("%s is not a VRF device\n", vrf_name);
		return -EINVAL;
	}

	return ifi->ifi_index;
}

/*
 * Attach a program to the cgroup which binds every new AF_INET/AF_INET6
 * socket to the VRF. It replaces a program attached earlier.
 */
int
vrf_attach(int cgroup_fd, const char *vrf_name)
{
	int ifindex = vrf_get_ifindex(vrf_name);
	struct bpf_insn prog[] = {
		/* r1 = struct bpf_sock *; r1->bound_dev_if = ifindex */
		BPF_MOV64_IMM(BPF_REG_3, ifindex),
		BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_3,
			    offsetof(struct bpf_sock, bound_dev_if)),
		/* allow */
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	};
	union bpf_attr load_attr = {
		.prog_type = BPF_PROG_TYPE_CGROUP_SOCK,
		.expected_attach_type = BPF_CGROUP_INET_SOCK_CREATE,
		.license = (uint64_t)(uintptr_t)"GPL",
		.insns = (uint64_t)(uintptr_t)prog,
		.insn_cnt = sizeof(prog) / sizeof(prog[0]),
	};
	union bpf_attr attach_attr = {
		.attach_type = BPF_CGROUP_INET_SOCK_CREATE,
		.target_fd = cgroup_fd,
	};
	int prog_fd, ret = 0;

	if (ifindex < 0)
		return ifindex;

	prog_fd = vrf_bpf(BPF_PROG_LOAD, &load_attr);
	if (prog_fd < 0)
		return -errno;

	attach_attr.attach_bpf_fd = prog_fd;
	if (vrf_bpf(BPF_PROG_ATTACH, &attach_attr))
		ret = -errno;

	close(prog_fd);
	return ret;
}

void
vrf_detach(int cgroup_fd)
{
	union bpf_attr attr = {
		.attach_type = BPF_CGROUP_INET_SOCK_CREATE,
		.target_fd = cgroup_fd,
	};

	vrf_bpf(BPF_PROG_DETACH, &attr);
}
