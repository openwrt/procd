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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>
#include <unistd.h>

#include "procd.h"

unsigned int debug = 0;

void debug_init(void)
{
	char line[256];
	int r, fd = open("/proc/cmdline", O_RDONLY);
	regex_t pat_cmdline;
	regmatch_t matches[2];

	if (!fd)
		return;

	r = read(fd, line, sizeof(line) - 1);
	line[r] = '\0';
	close(fd);

	regcomp(&pat_cmdline, "init_debug=([0-9]*)", REG_EXTENDED);
	if (!regexec(&pat_cmdline, line, 2, matches, 0)) {
		line[matches[1].rm_eo] = '\0';
		debug = atoi(&line[matches[1].rm_so]);
	}
	regfree(&pat_cmdline);
}
