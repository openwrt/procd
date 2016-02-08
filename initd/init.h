/*
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

#ifndef _INIT_H__
#define _INIT_H__

#include <errno.h>

#include "../log.h"

#ifndef EARLY_PATH
#define EARLY_PATH "/usr/sbin:/sbin:/usr/bin:/bin"
#endif

void preinit(void);
void early(void);
int mkdev(const char *progname, int progmode);

#ifdef ZRAM_TMPFS
int mount_zram_on_tmp(void);
#else
static inline int mount_zram_on_tmp(void) {
	return -ENOSYS;
}
#endif
#endif
