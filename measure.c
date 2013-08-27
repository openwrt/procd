/**
 *   Copyright (C) 2010 Steven Barth <steven@midlink.org>
 *   Copyright (C) 2013 John Crispin <blogic@openwrt.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <ctype.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <glob.h>
#include <libgen.h>

#include "procd.h"

static regex_t pat_vmsize, pat_ppid, pat_state, pat_uid;

static void __attribute__((constructor)) measure_init() {
	regcomp(&pat_vmsize, "VmSize:[ \t]*([0-9]*) kB", REG_EXTENDED);
	regcomp(&pat_uid, "Uid:[ \t]*([0-9]*).*", REG_EXTENDED);
	regcomp(&pat_ppid, "PPid:[ \t]*([0-9]+)", REG_EXTENDED);
	regcomp(&pat_state, "State:[ \t]*([A-Z])", REG_EXTENDED);
}

static void __attribute__((destructor)) measure_fini() {
	regfree(&pat_vmsize);
	regfree(&pat_ppid);
	regfree(&pat_uid);
	regfree(&pat_state);
}

int measure_process(pid_t pid, struct pid_info *pi) {
	int fd;
	char buffer[512] = "";
	ssize_t rxed;
	regmatch_t matches[2];
	glob_t gl;
	int i;

	memset(pi, 0, sizeof(*pi));

	snprintf(buffer, sizeof(buffer), "/proc/%i/fd/*", (int)pid);

	if (glob(buffer, GLOB_NOESCAPE | GLOB_MARK, NULL, &gl)) {
		fprintf(stderr, "glob failed on %s\n", buffer);
		return -1;
	}

	for (i = 0; i < gl.gl_pathc; i++)
		if (isdigit(basename(gl.gl_pathv[i])[0]))
			pi->fdcount++;
	globfree(&gl);

	snprintf(buffer, sizeof(buffer), "/proc/%i/status", (int)pid);
	fd = open(buffer, O_RDONLY);
	if (fd == -1)
		return -1;

	rxed = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (rxed == -1)
		return -1;

	buffer[rxed] = 0;

	if (!regexec(&pat_state, buffer, 2, matches, 0))
		pi->stat = buffer[matches[1].rm_so];

	if (!regexec(&pat_ppid, buffer, 2, matches, 0))
		pi->ppid = atoi(buffer + matches[1].rm_so);

	if (!regexec(&pat_uid, buffer, 2, matches, 0))
		pi->uid = atoi(buffer + matches[1].rm_so);

	if (!regexec(&pat_vmsize, buffer, 2, matches, 0))
		pi->vmsize = atoi(buffer + matches[1].rm_so) * 1024;

	return 0;
}
