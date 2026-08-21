/*
 * Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org>
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

#ifndef __STDIO_FDS_H
#define __STDIO_FDS_H

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define STDIO_FDS_NUM	3
#define FDS_NUM_MAX	(STDIO_FDS_NUM + 1)

/*
 * ubus carries a single file descriptor per request, so descriptor sets
 * travel as SCM_RIGHTS over a socket pair whose receiving end is what gets
 * passed to ubus_invoke_fd(). The payload byte carries the count.
 */
static inline int fds_send(const int *fds, int num)
{
	char cmsgbuf[CMSG_SPACE(FDS_NUM_MAX * sizeof(int))];
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	char count;
	int sp[2];

	if (num < 1 || num > FDS_NUM_MAX)
		return -1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp))
		return -1;

	count = num;
	iov.iov_base = &count;
	iov.iov_len = sizeof(count);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = CMSG_SPACE(num * sizeof(int));

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(num * sizeof(int));
	memcpy(CMSG_DATA(cmsg), fds, num * sizeof(int));

	if (sendmsg(sp[0], &msg, 0) < 0) {
		close(sp[0]);
		close(sp[1]);
		return -1;
	}

	close(sp[0]);

	return sp[1];
}

static inline int fds_recv(int sock, int *fds, int max)
{
	char cmsgbuf[CMSG_SPACE(FDS_NUM_MAX * sizeof(int))];
	int tmp[FDS_NUM_MAX];
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	char count;
	int num, i;

	iov.iov_base = &count;
	iov.iov_len = sizeof(count);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	if (recvmsg(sock, &msg, MSG_CMSG_CLOEXEC | MSG_DONTWAIT) < 1)
		return -1;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len < CMSG_LEN(sizeof(int)) ||
	    cmsg->cmsg_len > CMSG_LEN(FDS_NUM_MAX * sizeof(int)))
		return -1;

	num = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
	memcpy(tmp, CMSG_DATA(cmsg), num * sizeof(int));

	if (num != count || num > max) {
		for (i = 0; i < num; i++)
			close(tmp[i]);
		return -1;
	}

	memcpy(fds, tmp, num * sizeof(int));

	return num;
}

static inline int stdio_notify_fds_send(const int *stdio_fds, int notify_fd)
{
	int fds[FDS_NUM_MAX];
	int num = 0;

	if (stdio_fds) {
		memcpy(fds, stdio_fds, STDIO_FDS_NUM * sizeof(int));
		num = STDIO_FDS_NUM;
	}

	if (notify_fd > -1)
		fds[num++] = notify_fd;

	if (!num)
		return -1;

	return fds_send(fds, num);
}

static inline int stdio_notify_fds_recv(int sock, int *stdio_fds, int *notify_fd)
{
	int fds[FDS_NUM_MAX];
	int num;

	num = fds_recv(sock, fds, FDS_NUM_MAX);
	switch (num) {
	case 1:
		*notify_fd = fds[0];
		return 0;
	case STDIO_FDS_NUM + 1:
		*notify_fd = fds[STDIO_FDS_NUM];
		/* fallthrough */
	case STDIO_FDS_NUM:
		memcpy(stdio_fds, fds, STDIO_FDS_NUM * sizeof(int));
		return 0;
	default:
		while (num > 0)
			close(fds[--num]);
		return -1;
	}
}

static inline void stdio_fds_close(int *fds)
{
	int i;

	for (i = 0; i < STDIO_FDS_NUM; i++) {
		if (fds[i] < 0)
			continue;

		close(fds[i]);
		fds[i] = -1;
	}
}

#endif
