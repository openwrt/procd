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

#ifndef __PROCD_HOTPLUG_H
#define __PROCD_HOTPLUG_H

#include <libubox/uloop.h>

#ifndef DISABLE_INIT
void hotplug(char *rules);
int hotplug_run(char *rules);
void hotplug_shutdown(void);
void hotplug_last_event(uloop_timeout_handler handler);
void procd_coldplug(void);
#else
static inline void hotplug(char *rules)
{
}

static inline int hotplug_run(char *rules)
{
	return 0;
}

static inline void hotplug_shutdown(void)
{
}

static inline void hotplug_last_event(uloop_timeout_handler handler)
{
}

static inline void procd_coldplug(void)
{
}
#endif

#endif
