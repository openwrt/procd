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
#ifndef _JAIL_SECCOMP_HELPERS_H_
#define _JAIL_SECCOMP_HELPERS_H_

static int find_syscall(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(__syscall_aliases); i++)
		if (!strcmp(__syscall_aliases[i].name, name))
			return __syscall_aliases[i].nr;

	return -1;
}

static void set_filter(struct sock_filter *filter, __u16 code, __u8 jt, __u8 jf, __u32 k)
{
	filter->code = code;
	filter->jt = jt;
	filter->jf = jf;
	filter->k = k;
}

#endif
