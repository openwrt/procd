/*
 * Copyright (C) 2015 John Crispin <blogic@openwrt.org>
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

#endif
