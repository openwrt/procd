/*
 * Copyright (C) 2019 Paul Spooren <mail@aparcar.de>
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

#ifndef __CONTAINER_H
#define __CONTAINER_H

#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>

static inline bool is_container() {
	struct stat s;
	return !!getenv("container") || !!stat("/.dockerenv", &s);
}

#endif
