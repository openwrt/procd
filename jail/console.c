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

#include <stdlib.h>
#include <fcntl.h>
#include <libubox/ustream.h>
#include <libubus.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <termios.h>

static inline int setup_tios(int fd, struct termios *oldtios)
{
	struct termios newtios;

	if (!isatty(fd)) {
		return -1;
	}

	/* Get current termios */
	if (tcgetattr(fd, oldtios))
		return -1;

	newtios = *oldtios;

	/* Remove the echo characters and signal reception, the echo
	 * will be done with master proxying */
	newtios.c_iflag &= ~IGNBRK;
	newtios.c_iflag &= BRKINT;
	newtios.c_lflag &= ~(ECHO|ICANON|ISIG);
	newtios.c_cc[VMIN] = 1;
	newtios.c_cc[VTIME] = 0;

	/* Set new attributes */
	if (tcsetattr(fd, TCSAFLUSH, &newtios))
	        return -1;

	return 0;
}



#define OPT_ARGS	"i:s:"

static struct ustream_fd cufd;
static struct ustream_fd lufd;

static void usage()
{
	fprintf(stderr, "ujail-console -s <service> [-i <instance>]\n");
	exit(1);
}

static void client_cb(struct ustream *s, int bytes)
{
	char *buf;
	int len, rv;

	do {
		buf = ustream_get_read_buf(s, &len);
		if (!buf)
			break;

		rv = ustream_write(&lufd.stream, buf, len, false);

		if (rv > 0)
			ustream_consume(s, rv);

		if (rv <= len)
			break;
	} while(1);
}

static void local_cb(struct ustream *s, int bytes)
{
	char *buf;
	int len, rv;

	do {
		buf = ustream_get_read_buf(s, &len);
		if (!buf)
			break;

		if ((len > 0) && (buf[0] == 2))
				uloop_end();

		rv = ustream_write(&cufd.stream, buf, len, false);

		if (rv > 0)
			ustream_consume(s, rv);

		if (rv <= len)
			break;
	} while(1);
}

int main(int argc, char **argv)
{
	struct ubus_context *ctx;
	uint32_t id;
	static struct blob_buf req;
	char *service_name = NULL, *instance_name = NULL;
	int client_fd, server_fd, tty_fd;
	struct termios oldtermios;
	int ch;

	while ((ch = getopt(argc, argv, OPT_ARGS)) != -1) {
		switch (ch) {
		case 'i':
			instance_name = optarg;
			break;
		case 's':
			service_name = optarg;
			break;
		default:
			usage();
		}
	}

	if (!service_name)
		usage();

	ctx = ubus_connect(NULL);
	if (!ctx) {
		fprintf(stderr, "can't connect to ubus!\n");
		return -1;
	}

	/* open pseudo-terminal pair */
	client_fd = posix_openpt(O_RDWR | O_NOCTTY);
	if (client_fd < 0) {
		fprintf(stderr, "can't create virtual console!\n");
		ubus_free(ctx);
		return -1;
	}
	setup_tios(client_fd, &oldtermios);
	grantpt(client_fd);
	unlockpt(client_fd);
	server_fd = open(ptsname(client_fd), O_RDWR | O_NOCTTY);
	if (server_fd < 0) {
		fprintf(stderr, "can't open virtual console!\n");
		close(client_fd);
		ubus_free(ctx);
		return -1;
	}

	setup_tios(server_fd, &oldtermios);
	tty_fd = open("/dev/tty", O_RDWR);
	setup_tios(tty_fd, &oldtermios);

	/* register server-side with procd */
	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "name", service_name);
	if (instance_name)
		blobmsg_add_string(&req, "instance", instance_name);

	if (ubus_lookup_id(ctx, "service", &id) ||
	    ubus_invoke_fd(ctx, id, "console_attach", req.head, NULL, NULL, 3000, server_fd)) {
		fprintf(stderr, "ubus request failed\n");
		close(server_fd);
		close(client_fd);
		blob_buf_free(&req);
		ubus_free(ctx);
		return -2;
	}

	close(server_fd);
	blob_buf_free(&req);
	ubus_free(ctx);

	uloop_init();

	/* forward between stdio and client_fd until detach is requested */
	lufd.stream.notify_read = local_cb;
	ustream_fd_init(&lufd, tty_fd);

	cufd.stream.notify_read = client_cb;
/* ToDo: handle remote close and other events */
//	cufd.stream.notify_state = client_state_cb;
	ustream_fd_init(&cufd, client_fd);

	fprintf(stderr, "attaching to jail console. press [CTRL]+[B] to exit.\n");
	close(0);
	close(1);
	close(2);
	uloop_run();

	tcsetattr(tty_fd, TCSAFLUSH, &oldtermios);
	ustream_free(&lufd.stream);
	ustream_free(&cufd.stream);
	close(client_fd);

	return 0;
}
