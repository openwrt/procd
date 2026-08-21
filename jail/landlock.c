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

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/landlock.h>

#include "log.h"
#include "landlock.h"

static int landlock_abi_cached = -2;

static int sys_landlock_create_ruleset(const struct landlock_ruleset_attr *attr,
				       size_t size, uint32_t flags)
{
	return syscall(SYS_landlock_create_ruleset, attr, size, flags);
}

static int sys_landlock_add_rule(int ruleset_fd, enum landlock_rule_type type,
				 const void *rule_attr, uint32_t flags)
{
	return syscall(SYS_landlock_add_rule, ruleset_fd, type, rule_attr, flags);
}

static int sys_landlock_restrict_self(int ruleset_fd, uint32_t flags)
{
	return syscall(SYS_landlock_restrict_self, ruleset_fd, flags);
}

static int landlock_abi(void)
{
	if (landlock_abi_cached == -2)
		landlock_abi_cached = sys_landlock_create_ruleset(NULL, 0,
							   LANDLOCK_CREATE_RULESET_VERSION);
	return landlock_abi_cached;
}

bool landlock_available(void)
{
	return landlock_abi() >= 1;
}

int landlock_config_add(struct landlock_config *cfg, const char *path, uint64_t access)
{
	struct landlock_rule *r;

	r = realloc(cfg->rules, sizeof(*r) * (cfg->n + 1));
	if (!r)
		return -ENOMEM;
	cfg->rules = r;
	r[cfg->n].path = strdup(path);
	if (!r[cfg->n].path)
		return -ENOMEM;
	r[cfg->n].access = access;
	cfg->n++;
	return 0;
}

int landlock_config_add_paths(struct landlock_config *cfg, const char *paths,
			      uint64_t access)
{
	char *dup, *tok, *save;
	int rc = 0;

	if (!paths || !*paths)
		return 0;

	dup = strdup(paths);
	if (!dup)
		return -ENOMEM;

	for (tok = strtok_r(dup, ":", &save); tok; tok = strtok_r(NULL, ":", &save)) {
		rc = landlock_config_add(cfg, tok, access);
		if (rc)
			break;
	}
	free(dup);
	return rc;
}

int landlock_apply(const struct landlock_config *cfg)
{
	struct landlock_ruleset_attr ra = { 0 };
	int ruleset_fd, rc = 0;
	size_t i;

	if (cfg->n == 0)
		return 0;
	if (!landlock_available())
		return -ENOSYS;

	for (i = 0; i < cfg->n; i++)
		ra.handled_access_fs |= cfg->rules[i].access;

	ruleset_fd = sys_landlock_create_ruleset(&ra, sizeof(ra), 0);
	if (ruleset_fd < 0) {
		int saved_errno = errno;
		ERROR("landlock_create_ruleset: %s\n", strerror(saved_errno));
		return -saved_errno;
	}

	for (i = 0; i < cfg->n; i++) {
		struct landlock_path_beneath_attr pa = {
			.allowed_access = cfg->rules[i].access,
		};
		int saved_errno;

		pa.parent_fd = open(cfg->rules[i].path, O_PATH | O_CLOEXEC);
		if (pa.parent_fd < 0) {
			saved_errno = errno;
			ERROR("landlock: open(%s): %s\n", cfg->rules[i].path,
			      strerror(saved_errno));
			rc = -saved_errno;
			goto out;
		}
		if (sys_landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
					  &pa, 0)) {
			saved_errno = errno;
			ERROR("landlock_add_rule(%s): %s\n", cfg->rules[i].path,
			      strerror(saved_errno));
			rc = -saved_errno;
			close(pa.parent_fd);
			goto out;
		}
		close(pa.parent_fd);
	}

	if (sys_landlock_restrict_self(ruleset_fd, 0)) {
		int saved_errno = errno;
		ERROR("landlock_restrict_self: %s\n", strerror(saved_errno));
		rc = -saved_errno;
	}

out:
	close(ruleset_fd);
	return rc;
}

void landlock_config_free(struct landlock_config *cfg)
{
	size_t i;

	for (i = 0; i < cfg->n; i++)
		free(cfg->rules[i].path);
	free(cfg->rules);
	cfg->rules = NULL;
	cfg->n = 0;
}
