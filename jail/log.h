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
#include <stdio.h>
#include <syslog.h>

#define INFO(fmt, ...) do { \
	printf("jail: "fmt, ## __VA_ARGS__); \
	} while (0)
#define ERROR(fmt, ...) do { \
	syslog(LOG_ERR, "jail: "fmt, ## __VA_ARGS__); \
	fprintf(stderr,"jail: "fmt, ## __VA_ARGS__); \
	} while (0)
#define DEBUG(fmt, ...) do { \
	if (debug) printf("jail: "fmt, ## __VA_ARGS__); \
	} while (0)

#endif
