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

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <ctype.h>

#include <libubox/utils.h>
#include <libubox/list.h>

#include "utils/utils.h"
#include "procd.h"
#include "rcS.h"

#ifndef O_PATH
#define O_PATH		010000000
#endif

#define TAG_ID		0
#define TAG_RUNLVL	1
#define TAG_ACTION	2
#define TAG_PROCESS	3

#define MAX_ARGS	8

struct init_action;
char *console = NULL;

struct init_handler {
	const char *name;
	void (*cb) (struct init_action *a);
	int multi;
};

struct init_action {
	struct list_head list;

	char *id;
	char *argv[MAX_ARGS];
	char *line;

	struct init_handler *handler;
	struct uloop_process proc;

	int respawn;
	struct uloop_timeout tout;
};

static const char *tab = "/etc/inittab";
static char *ask = "/sbin/askfirst";

static LIST_HEAD(actions);

static int dev_exist(const char *dev)
{
	int dfd, fd;

	dfd = open("/dev", O_PATH|O_DIRECTORY);

	if (dfd < 0)
		return 0;

	fd = openat(dfd, dev, O_RDONLY|O_NOCTTY);
	close(dfd);

	if (fd < 0)
		return 0;

	close(fd);
	return 1;
}

static void fork_worker(struct init_action *a)
{
	pid_t p;

	a->proc.pid = fork();
	if (!a->proc.pid) {
		p = setsid();

		if (patch_stdio(a->id))
			ERROR("Failed to setup i/o redirection\n");

		ioctl(STDIN_FILENO, TIOCSCTTY, 1);
		tcsetpgrp(STDIN_FILENO, p);

		execvp(a->argv[0], a->argv);
		ERROR("Failed to execute %s: %m\n", a->argv[0]);
		exit(-1);
	}

	if (a->proc.pid > 0) {
		DEBUG(4, "Launched new %s action, pid=%d\n",
					a->handler->name,
					(int) a->proc.pid);
		uloop_process_add(&a->proc);
	}
}

static void child_exit(struct uloop_process *proc, int ret)
{
	struct init_action *a = container_of(proc, struct init_action, proc);

	DEBUG(4, "pid:%d, exitcode:%d\n", proc->pid, ret);
	proc->pid = 0;

	if (a->respawn < 0)
		return;

	if (!dev_exist(a->id)) {
		DEBUG(4, "Skipping respawn: device '%s' does not exist anymore\n", a->id);
		return;
	}

	uloop_timeout_set(&a->tout, a->respawn);
}

static void respawn(struct uloop_timeout *tout)
{
	struct init_action *a = container_of(tout, struct init_action, tout);
	if (!a->proc.pid)
		fork_worker(a);
}

static void rcdone(struct runqueue *q)
{
	procd_state_next();
}

static void runrc(struct init_action *a)
{
	if (!a->argv[1] || !a->argv[2]) {
		ERROR("valid format is rcS <S|K> <param>\n");
		return;
	}

	/* proceed even if no init or shutdown scripts run */
	if (rcS(a->argv[1], a->argv[2], rcdone))
		rcdone(NULL);
}

static void askfirst(struct init_action *a)
{
	int i;

	if (!dev_exist(a->id) || (console && !strcmp(console, a->id))) {
		DEBUG(4, "Skipping %s\n", a->id);
		return;
	}

	a->tout.cb = respawn;
	/* shift arguments only if not yet done */
	if (a->argv[0] != ask) {
		for (i = MAX_ARGS - 1; i >= 1; i--)
			a->argv[i] = a->argv[i - 1];
		a->argv[0] = ask;
	}
	a->respawn = 500;

	a->proc.cb = child_exit;
	if (!a->proc.pid)
		fork_worker(a);
}

static void askconsole(struct init_action *a)
{
	char line[256], *tty, *split;
	int i;

	/* First, try console= on the kernel command line,
	 * then fallback to /sys/class/tty/console/active,
	 * which should work when linux,stdout-path (or equivalent)
	 * is in the device tree
	 */
	tty = get_cmdline_val("console", line, sizeof(line));
	if (tty == NULL ||
	    get_cmdline_val_offset("console", line, sizeof(line), 1)) {
		if (dev_exist("console"))
			tty = "console";
		else
			tty = get_active_console(line, sizeof(line));
	}
	if (tty != NULL) {
		split = strchr(tty, ',');
		if (split != NULL)
			*split = '\0';

		if (!dev_exist(tty)) {
			DEBUG(4, "skipping %s\n", tty);
			return;
		}

		console = strdup(tty);
		a->id = strdup(tty);
	}
	else {
		console = NULL;
		a->id = NULL;
	}

	a->tout.cb = respawn;
	/* shift arguments only if not yet done */
	if (a->argv[0] != ask) {
		for (i = MAX_ARGS - 1; i >= 1; i--)
			a->argv[i] = a->argv[i - 1];
		a->argv[0] = ask;
	}
	a->respawn = 500;

	a->proc.cb = child_exit;
	if (!a->proc.pid)
		fork_worker(a);
}

static void rcrespawn(struct init_action *a)
{
	a->tout.cb = respawn;
	a->respawn = 500;

	a->proc.cb = child_exit;
	if (!a->proc.pid)
		fork_worker(a);
}

static struct init_handler handlers[] = {
	{
		.name = "sysinit",
		.cb = runrc,
	}, {
		.name = "shutdown",
		.cb = runrc,
	}, {
		.name = "askfirst",
		.cb = askfirst,
		.multi = 1,
	}, {
		.name = "askconsole",
		.cb = askconsole,
		.multi = 1,
	}, {
		.name = "respawn",
		.cb = rcrespawn,
		.multi = 1,
	}, {
		.name = "askconsolelate",
		.cb = askconsole,
		.multi = 1,
	}, {
		.name = "respawnlate",
		.cb = rcrespawn,
		.multi = 1,
	}
};

static int add_action(struct init_action *a, const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(handlers); i++)
		if (!strcmp(handlers[i].name, name)) {
			a->handler = &handlers[i];
			list_add_tail(&a->list, &actions);
			return 0;
		}
	ERROR("Unknown init handler %s\n", name);
	return -1;
}

void procd_inittab_run(const char *handler)
{
	struct init_action *a;

	list_for_each_entry(a, &actions, list)
		if (!strcmp(a->handler->name, handler)) {
			a->handler->cb(a);
			if (!a->handler->multi)
				break;
		}
}

void procd_inittab_kill(void)
{
	struct init_action *a;

	list_for_each_entry(a, &actions, list) {
		a->respawn = -1;
		if (a->proc.pid)
			kill(a->proc.pid, SIGKILL);
	}
}

void procd_inittab(void)
{
#define LINE_LEN	128
	FILE *fp = fopen(tab, "r");
	struct init_action *a;
	regex_t pat_inittab;
	regmatch_t matches[5];
	char *line;

	if (!fp) {
		ERROR("Failed to open %s: %m\n", tab);
		return;
	}

	regcomp(&pat_inittab, "([a-zA-Z0-9]*):([a-zA-Z0-9]*):([a-zA-Z0-9]*):(.*)", REG_EXTENDED);
	line = malloc(LINE_LEN);
	a = calloc(1, sizeof(struct init_action));

	while (fgets(line, LINE_LEN, fp)) {
		char *tags[TAG_PROCESS + 1];
		char *tok;
		int i;
		int len = strlen(line);

		while (isspace(line[len - 1]))
			len--;
		line[len] = 0;

		if (*line == '#')
			continue;

		if (regexec(&pat_inittab, line, 5, matches, 0))
			continue;

		DEBUG(4, "Parsing inittab - %s\n", line);

		for (i = TAG_ID; i <= TAG_PROCESS; i++) {
			line[matches[i].rm_eo] = '\0';
			tags[i] = &line[matches[i + 1].rm_so];
		};

		tok = strtok(tags[TAG_PROCESS], " ");
		for (i = 0; i < (MAX_ARGS - 1) && tok; i++) {
			a->argv[i] = tok;
			tok = strtok(NULL, " ");
		}
		a->argv[i] = NULL;
		a->id = tags[TAG_ID];
		a->line = line;

		if (add_action(a, tags[TAG_ACTION]))
			continue;
		line = malloc(LINE_LEN);
		a = calloc(1, sizeof(struct init_action));
	}

	fclose(fp);
	free(line);
	free(a);
	regfree(&pat_inittab);
}
