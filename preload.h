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

#include <link.h>

#ifndef __unbounded
#define __unbounded
#endif

#ifndef attribute_unused
#define attribute_unused __attribute__ ((unused))
#endif
typedef int (*main_t)(int, char **, char **);

typedef int (*start_main_t)(main_t main, int, char *__unbounded *__unbounded,
			ElfW(auxv_t) *,
			__typeof (main),
			void (*fini) (void),
			void (*rtld_fini) (void),
			void *__unbounded stack_end);

int __libc_start_main(main_t main,
			int argc,
			char **argv,
			ElfW(auxv_t) *auxvec,
			__typeof (main) init,
			void (*fini) (void),
			void (*rtld_fini) (void),
			void *stack_end);


typedef void (*uClibc_main)(main_t main,
			int argc,
			char **argv,
			void (*app_init)(void),
			void (*app_fini)(void),
			void (*rtld_fini)(void),
			void *stack_end attribute_unused);

void __uClibc_main(main_t main,
			int argc,
			char **argv,
			void (*app_init)(void),
			void (*app_fini)(void),
			void (*rtld_fini)(void),
			void *stack_end attribute_unused);
