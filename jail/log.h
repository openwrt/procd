/*
 * Copyright (C) 2015 John Crispin <blogic@openwrt.org>
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
#ifndef _JAIL_LOG_H_
#define _JAIL_LOG_H_

extern int debug;
#include <syslog.h>
#include <libubox/ulog.h>

#define INFO(fmt, ...)		ULOG_INFO(fmt, ## __VA_ARGS__)
#define WARNING(fmt, ...)	ULOG_WARN(fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...)		ULOG_ERR(fmt, ## __VA_ARGS__)
#define DEBUG(fmt, ...) do { \
	if (debug) ulog(LOG_DEBUG, fmt, ## __VA_ARGS__); \
	} while (0)

struct blob_attr;

const struct blob_attr *jail_oci_root_get(void);
void jail_oci_root_restore(const struct blob_attr *root);

int jail_unsupported(const struct blob_attr *attr);
void jail_cgroup_refused(const char *attr);

#endif
