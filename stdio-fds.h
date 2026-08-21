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

/*
 * ubus carries a single file descriptor per request, so the three standard
 * descriptors travel as SCM_RIGHTS over a socket pair whose receiving end is
 * what gets passed to ubus_invoke_fd().
 */
static inline int stdio_fds_send(const int *fds)
{
	char cmsgbuf[CMSG_SPACE(STDIO_FDS_NUM * sizeof(int))];
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	char dummy = 0;
	int sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp))
		return -1;

	iov.iov_base = &dummy;
	iov.iov_len = sizeof(dummy);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(STDIO_FDS_NUM * sizeof(int));
	memcpy(CMSG_DATA(cmsg), fds, STDIO_FDS_NUM * sizeof(int));

	if (sendmsg(sp[0], &msg, 0) < 0) {
		close(sp[0]);
		close(sp[1]);
		return -1;
	}

	close(sp[0]);

	return sp[1];
}

static inline int stdio_fds_recv(int sock, int *fds)
{
	char cmsgbuf[CMSG_SPACE(STDIO_FDS_NUM * sizeof(int))];
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	char dummy;

	iov.iov_base = &dummy;
	iov.iov_len = sizeof(dummy);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	if (recvmsg(sock, &msg, MSG_CMSG_CLOEXEC) < 0)
		return -1;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(STDIO_FDS_NUM * sizeof(int)))
		return -1;

	memcpy(fds, CMSG_DATA(cmsg), STDIO_FDS_NUM * sizeof(int));

	return 0;
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
