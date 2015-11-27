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

#define _GNU_SOURCE
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>

#include "seccomp.h"
#include "../preload.h"

static main_t __main__;

static int __preload_main__(int argc, char **argv, char **envp)
{
	char *env_file = getenv("SECCOMP_FILE");

	if (install_syscall_filter(*argv, env_file))
		return -1;

	unsetenv("LD_PRELOAD");
	unsetenv("SECCOMP_FILE");

	return (*__main__)(argc, argv, envp);
}

int __libc_start_main(main_t main,
			int argc,
			char **argv,
			ElfW(auxv_t) *auxvec,
			__typeof (main) init,
			void (*fini) (void),
			void (*rtld_fini) (void),
			void *stack_end)
{
	start_main_t __start_main__;

	__start_main__ = dlsym(RTLD_NEXT, "__libc_start_main");
	if (!__start_main__)
		INFO("failed to find __libc_start_main %s\n", dlerror());

	__main__ = main;

	return (*__start_main__)(__preload_main__, argc, argv, auxvec,
		init, fini, rtld_fini, stack_end);
}

void __uClibc_main(main_t main,
			int argc,
			char **argv,
			void (*app_init)(void),
			void (*app_fini)(void),
			void (*rtld_fini)(void),
			void *stack_end attribute_unused)
{
	uClibc_main __start_main__;

	__start_main__ = dlsym(RTLD_NEXT, "__uClibc_main");
	if (!__start_main__)
		INFO("failed to find __uClibc_main %s\n", dlerror());

	__main__ = main;

	return (*__start_main__)(__preload_main__, argc, argv,
		app_init, app_fini, rtld_fini, stack_end);
}
