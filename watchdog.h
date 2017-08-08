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

#ifndef __PROCD_WATCHDOG_H
#define __PROCD_WATCHDOG_H

#ifndef DISABLE_INIT
void watchdog_init(int preinit);
char* watchdog_fd(void);
int watchdog_timeout(int timeout);
int watchdog_frequency(int frequency);
void watchdog_set_magicclose(bool val);
bool watchdog_get_magicclose(void);
void watchdog_set_stopped(bool val);
bool watchdog_get_stopped(void);
void watchdog_no_cloexec(void);
void watchdog_ping(void);
#else
static inline void watchdog_init(int preinit)
{
}

static inline char* watchdog_fd(void)
{
	return "";
}

static inline int watchdog_timeout(int timeout)
{
	return 0;
}

static inline int watchdog_frequency(int frequency)
{
	return 0;
}

static inline void watchdog_set_magicclose(bool val)
{
}

static inline bool watchdog_get_magicclose(void)
{
	return false;
}

static inline void watchdog_set_stopped(bool val)
{
}

static inline bool watchdog_get_stopped(void)
{
	return true;
}

static inline void watchdog_no_cloexec(void)
{
}

static inline void watchdog_ping(void)
{
}

#endif

#endif
