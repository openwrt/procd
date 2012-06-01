#ifndef __PROCD_H
#define __PROCD_H

#include <libubox/uloop.h>
#include <libubus.h>
#include <stdio.h>

#define DPRINTF(fmt, ...) do { \
	if (debug) \
		fprintf(stderr, "DEBUG %s(%d): " fmt, __func__, __LINE__, ## __VA_ARGS__); \
	} while (0)

extern int debug;
extern char *ubus_socket;
void procd_connect_ubus(void);
void procd_register_objects(struct ubus_context *ctx);

#endif
