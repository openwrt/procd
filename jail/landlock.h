/*
 * Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org>
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

#ifndef _JAIL_LANDLOCK_H
#define _JAIL_LANDLOCK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct landlock_rule {
	char *path;
	uint64_t access;
};

struct landlock_config {
	struct landlock_rule *rules;
	size_t n;
};

bool landlock_available(void);
int landlock_config_add(struct landlock_config *cfg, const char *path, uint64_t access);
int landlock_config_add_paths(struct landlock_config *cfg, const char *paths, uint64_t access);
int landlock_apply(const struct landlock_config *cfg);
void landlock_config_free(struct landlock_config *cfg);

#endif
