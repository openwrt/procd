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

#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <pwd.h>
#include <stdbool.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>

#include <libubox/utils.h>

#include "container.h"
#include "procd.h"
#include "syslog.h"
#include "plug/hotplug.h"
#include "watchdog.h"
#include "service/service.h"
#include "utils/utils.h"

enum {
	STATE_NONE = 0,
	STATE_EARLY,
	STATE_UBUS,
	STATE_INIT,
	STATE_RUNNING,
	STATE_SHUTDOWN,
	STATE_HALT,
	__STATE_MAX,
};

static int state = STATE_NONE;
static int reboot_event;

static void set_stdio(const char* tty)
{
	if (patch_stdio(tty))
		ERROR("failed to set stdio\n");
	else
		fcntl(STDERR_FILENO, F_SETFL, fcntl(STDERR_FILENO, F_GETFL) | O_NONBLOCK);
}

static void set_console(void)
{
	const char* tty;
	char* split;
	char line[ 20 ];
	const char* try[] = { "tty0", "console", NULL }; /* Try the most common outputs */
	int f, i = 0;

	tty = get_cmdline_val("console",line,sizeof(line));
	if (tty != NULL) {
		split = strchr(tty, ',');
		if ( split != NULL )
			*split = '\0';
	} else {
		// Try a default
		tty=try[i];
		i++;
	}

	if (chdir("/dev")) {
		ERROR("failed to change dir to /dev: %m\n");
		return;
	}
	while (tty!=NULL) {
		f = open(tty, O_RDONLY|O_NOCTTY);
		if (f >= 0) {
			close(f);
			break;
		}

		tty=try[i];
		i++;
	}
	if (chdir("/"))
		ERROR("failed to change dir to /: %m\n");

	if (tty != NULL)
		set_stdio(tty);
}

/* SIGCHLD is ignored by now, so the kernel reaps the dead on its own and
 * waitpid() fails with ECHILD once nothing is left */
static void halt_reap(void)
{
	int i;

	for (i = 0; i < 50; i++) {
		if (waitpid(-1, NULL, WNOHANG) < 0 && errno == ECHILD)
			return;
		usleep(100000);
	}
	ERROR("some processes survived SIGKILL\n");
}

/* nothing to write back, or still needed until reboot() */
static bool halt_skip_fs(const char *type)
{
	static const char * const skip[] = {
		"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "ramfs",
		"cgroup", "cgroup2", "debugfs", "tracefs", "securityfs",
		"pstore", "bpf", "mqueue", "hugetlbfs", "configfs", "fusectl",
		"binfmt_misc", "nsfs", "autofs", "efivarfs", "selinuxfs",
		"rpc_pipefs",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(skip); i++)
		if (!strcmp(type, skip[i]))
			return true;

	return false;
}

/* the network is down by now, so anything that talks to a server hangs */
static bool halt_network_fs(const char *type)
{
	static const char * const net[] = {
		"nfs", "nfs4", "cifs", "smb3", "afs", "ceph", "9p", "glusterfs",
		"fuse.sshfs",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(net); i++)
		if (!strcmp(type, net[i]))
			return true;

	return false;
}

struct halt_mount {
	char *dir;
	bool rw;
	bool net;
};

/* deepest first, so that a stacked mount goes before what it sits on */
static int halt_mount_cmp(const void *a, const void *b)
{
	const struct halt_mount *ma = a, *mb = b;

	return (int)strlen(mb->dir) - (int)strlen(ma->dir);
}

static void halt_free_mounts(struct halt_mount *list, int n)
{
	while (n-- > 0)
		free(list[n].dir);
	free(list);
}

static int halt_read_mounts(struct halt_mount **list)
{
	struct halt_mount *m = NULL, *tmp;
	struct mntent *me;
	FILE *fp;
	int n = 0;

	*list = NULL;

	fp = setmntent("/proc/self/mounts", "r");
	if (!fp) {
		ERROR("failed to open /proc/self/mounts: %m\n");
		return -1;
	}

	while ((me = getmntent(fp))) {
		if (halt_skip_fs(me->mnt_type))
			continue;

		tmp = realloc(m, (n + 1) * sizeof(*m));
		if (!tmp)
			break;

		m = tmp;
		m[n].dir = strdup(me->mnt_dir);
		m[n].rw = !hasmntopt(me, "ro");
		m[n].net = halt_network_fs(me->mnt_type);
		if (!m[n].dir)
			break;
		n++;
	}
	endmntent(fp);

	qsort(m, n, sizeof(*m), halt_mount_cmp);
	*list = m;

	return n;
}

/*
 * sync() writes the data back but does not leave a filesystem clean: a
 * journalling filesystem only commits its superblock on remount or unmount.
 * The shutdown scripts run while every service is still alive, so their
 * attempts fail with EBUSY. Now that nothing is left to hold a file open,
 * remount everything read-only and unmount what can be unmounted, deepest
 * mount first, until a pass makes no progress. Unmounting matters where a
 * mount pins another filesystem, such as a loop device on a data partition.
 */
/* without a mount table, the root can at least still be made clean */
static void halt_root_only(void)
{
	if (mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY, NULL))
		ERROR("failed to remount / read-only: %m\n");
}

static void halt_mounts(void)
{
	struct halt_mount *list;
	int pass, i, n;

	/* the umount init script may have taken /proc down with the rest */
	if (access("/proc/self/mounts", R_OK) &&
	    mount("proc", "/proc", "proc", 0, NULL)) {
		ERROR("failed to mount /proc: %m\n");
		halt_root_only();
		return;
	}

	for (pass = 0; pass < 10; pass++) {
		bool progress = false;

		n = halt_read_mounts(&list);
		if (n < 0) {
			halt_root_only();
			return;
		}

		for (i = 0; i < n; i++) {
			const char *dir = list[i].dir;

			if (list[i].net) {
				if (!umount2(dir, MNT_DETACH))
					progress = true;
				continue;
			}

			if (list[i].rw &&
			    !mount(NULL, dir, NULL, MS_REMOUNT | MS_RDONLY, NULL)) {
				LOG("remounted %s read-only\n", dir);
				progress = true;
			}

			if (strcmp(dir, "/") && !umount(dir)) {
				LOG("unmounted %s\n", dir);
				progress = true;
			}
		}
		halt_free_mounts(list, n);

		if (!progress)
			break;
	}

	n = halt_read_mounts(&list);
	for (i = 0; i < n; i++)
		if (list[i].rw && !list[i].net)
			ERROR("%s is still mounted read-write\n", list[i].dir);
	halt_free_mounts(list, n);
}

static void perform_halt()
{
	if (reboot_event == RB_POWER_OFF)
		LOG("- power down -\n");
	else
		LOG("- reboot -\n");

	/* Allow time for last message to reach serial console, etc */
	sleep(1);

	if (is_container()) {
		reboot(reboot_event);
		exit(EXIT_SUCCESS);
		return;
	}

	/* We have to fork here, since the kernel calls do_exit(EXIT_SUCCESS)
	 * in linux/kernel/sys.c, which can cause the machine to panic when
	 * the init process exits... */
	if (!vfork()) { /* child */
		reboot(reboot_event);
		_exit(EXIT_SUCCESS);
	}

	while (1)
		sleep(1);
}

static void state_enter(void)
{
	char ubus_cmd[] = "/sbin/ubusd";
	struct passwd *p;

	switch (state) {
	case STATE_EARLY:
		LOG("- early -\n");
		watchdog_init(0);
		hotplug("/etc/hotplug.json");
		procd_coldplug();
		break;

	case STATE_UBUS:
		// try to reopen incase the wdt was not available before coldplug
		watchdog_init(0);
		set_stdio("console");
		p = getpwnam("ubus");
		if (p) {
			int ret;
			LOG("- ubus -\n");
			mkdir(p->pw_dir, 0755);
			ret = chown(p->pw_dir, p->pw_uid, p->pw_gid);
			if (ret)
				LOG("- ubus - failed to chown(%s)\n", p->pw_dir);
		} else {
			LOG("- ubus (running as root!) -\n");
		}

		procd_connect_ubus();
		service_start_early("ubus", ubus_cmd, p?"ubus":NULL, p?"ubus":NULL);
		break;

	case STATE_INIT:
		LOG("- init -\n");
		procd_inittab();
		procd_inittab_run("respawn");
		procd_inittab_run("askconsole");
		procd_inittab_run("askfirst");
		procd_inittab_run("sysinit");

		// switch to syslog log channel
		ulog_open(ULOG_SYSLOG, LOG_DAEMON, "procd");
		break;

	case STATE_RUNNING:
		LOG("- init complete -\n");
		procd_inittab_run("respawnlate");
		procd_inittab_run("askconsolelate");
		break;

	case STATE_SHUTDOWN:
		ulog_open(ULOG_KMSG, LOG_DAEMON, "procd");
		/* Redirect output to the console for the users' benefit */
		set_console();
		LOG("- shutdown -\n");
		procd_inittab_run("shutdown");
		sync();
		break;

	case STATE_HALT:
		/* logd is gone by now, log to the console instead */
		ulog_open(ULOG_STDIO, LOG_DAEMON, "procd");
		// To prevent killed processes from interrupting the sleep
		signal(SIGCHLD, SIG_IGN);
		LOG("- SIGTERM processes -\n");
		kill(-1, SIGTERM);
		sync();
		sleep(1);
		LOG("- SIGKILL processes -\n");
		kill(-1, SIGKILL);
		halt_reap();
		sync();
#ifndef DISABLE_INIT
		if (!is_container())
			halt_mounts();
		perform_halt();
#else
		exit(EXIT_SUCCESS);
#endif
		break;

	default:
		ERROR("Unhandled state %d\n", state);
		return;
	};
}

void procd_state_next(void)
{
	DEBUG(4, "Change state %d -> %d\n", state, state + 1);
	state++;
	state_enter();
}

void procd_state_ubus_connect(void)
{
	if (state == STATE_UBUS)
		procd_state_next();
}

void procd_shutdown(int event)
{
	if (state >= STATE_SHUTDOWN)
		return;
	DEBUG(2, "Shutting down system with event %x\n", event);
	reboot_event = event;
	state = STATE_SHUTDOWN;
	state_enter();
}
