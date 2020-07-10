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
	int i;

	for (i = 0; i < SYSCALL_COUNT; i++) {
		int sc = syscall_index_to_number(i);
		if (syscall_name(sc) && !strcmp(syscall_name(sc), name))
			return sc;
	}

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
