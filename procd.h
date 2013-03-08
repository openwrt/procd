/*
 * Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2013 John Crispin <blogic@openwrt.org>
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

#ifndef __PROCD_H
#define __PROCD_H

#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>

#include <stdio.h>
#include <syslog.h>

#include "syslog.h"

#define __init __attribute__((constructor))

#define DEBUG(level, fmt, ...) do { \
	if (debug >= level) \
		fprintf(stderr, "procd: %s(%d): " fmt, __func__, __LINE__, ## __VA_ARGS__); \
	} while (0)

#define LOG(fmt, ...) do { \
	syslog(LOG_INFO, fmt, ## __VA_ARGS__); \
	fprintf(stderr, "procd: "fmt, ## __VA_ARGS__); \
	} while (0)

#define ERROR(fmt, ...) do { \
	syslog(LOG_ERR, fmt, ## __VA_ARGS__); \
	fprintf(stderr, "procd: "fmt, ## __VA_ARGS__); \
	} while (0)

extern char *ubus_socket;

extern unsigned int debug;
void debug_init(void);

void procd_connect_ubus(void);
void ubus_init_service(struct ubus_context *ctx);
void ubus_init_log(struct ubus_context *ctx);
void ubus_init_system(struct ubus_context *ctx);
void ubus_notify_log(struct log_head *l);

void procd_state_next(void);
void procd_shutdown(int event);
void procd_early(void);
void procd_preinit(void);
void procd_coldplug(void);
void procd_signal(void);
void procd_inittab(void);
void procd_inittab_run(const char *action);

int mkdev(const char *progname, int progmode);

#endif
