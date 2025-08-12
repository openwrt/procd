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
#include <sys/utsname.h>
#include <sys/types.h>
#include <fcntl.h>

#include <unistd.h>
#include <sched.h>

#include <libubox/blobmsg_json.h>
#include <libubox/avl-cmp.h>

#include "../procd.h"

#include "service.h"
#include "instance.h"

#include "../rcS.h"

AVL_TREE(services, avl_strcmp, false, NULL);
AVL_TREE(containers, avl_strcmp, false, NULL);
static struct blob_buf b;
static struct ubus_context *ctx;
static struct ubus_object main_object;

static void
service_instance_add(struct service *s, struct blob_attr *attr)
{
	struct service_instance *in;

	if (blobmsg_type(attr) != BLOBMSG_TYPE_TABLE)
		return;

	in = calloc(1, sizeof(*in));
	if (!in)
		return;

	instance_init(in, s, attr);
	vlist_add(&s->instances, &in->node, (void *) in->name);
}

void service_data_trigger(struct blobmsg_list *list)
{
	struct blobmsg_list_node *node;

	avl_for_each_element(&list->avl, node, avl) {
		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "name", blobmsg_name(node->data));
		trigger_event("service.data.update", b.head);
	}
}

static void
service_instance_update(struct vlist_tree *tree, struct vlist_node *node_new,
			struct vlist_node *node_old)
{
	struct service_instance *in_o = NULL, *in_n = NULL;

	if (node_old)
		in_o = container_of(node_old, struct service_instance, node);

	if (node_new)
		in_n = container_of(node_new, struct service_instance, node);

	if (in_o && in_n) {
		P_DEBUG(2, "Update instance %s::%s\n", in_o->srv->name, in_o->name);
		instance_update(in_o, in_n);
		instance_free(in_n);
	} else if (in_o) {
		P_DEBUG(2, "Stop instance %s::%s\n", in_o->srv->name, in_o->name);
		instance_stop(in_o, true);
	} else if (in_n && in_n->srv->autostart) {
		P_DEBUG(2, "Start instance %s::%s\n", in_n->srv->name, in_n->name);
		instance_start(in_n);
	}
	blob_buf_init(&b, 0);
	trigger_event("instance.update", b.head);
}

static struct service *
service_alloc(const char *name)
{
	struct service *s;
	char *new_name;

	s = calloc_a(sizeof(*s), &new_name, strlen(name) + 1);
	strcpy(new_name, name);

	vlist_init(&s->instances, avl_strcmp, service_instance_update);
	s->instances.no_delete = true;
	s->name = new_name;
	s->avl.key = s->name;
	INIT_LIST_HEAD(&s->validators);
	blobmsg_list_simple_init(&s->data_blob);

	return s;
}

enum {
	SERVICE_SET_NAME,
	SERVICE_SET_SCRIPT,
	SERVICE_SET_INSTANCES,
	SERVICE_SET_TRIGGER,
	SERVICE_SET_VALIDATE,
	SERVICE_SET_AUTOSTART,
	SERVICE_SET_DATA,
	__SERVICE_SET_MAX
};

static const struct blobmsg_policy service_set_attrs[__SERVICE_SET_MAX] = {
	[SERVICE_SET_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[SERVICE_SET_SCRIPT] = { "script", BLOBMSG_TYPE_STRING },
	[SERVICE_SET_INSTANCES] = { "instances", BLOBMSG_TYPE_TABLE },
	[SERVICE_SET_TRIGGER] = { "triggers", BLOBMSG_TYPE_ARRAY },
	[SERVICE_SET_VALIDATE] = { "validate", BLOBMSG_TYPE_ARRAY },
	[SERVICE_SET_AUTOSTART] = { "autostart", BLOBMSG_TYPE_BOOL },
	[SERVICE_SET_DATA] = { "data", BLOBMSG_TYPE_TABLE },
};

static int
service_update_data(struct service *s, struct blob_attr *data)
{
	if (blob_attr_equal(s->data, data))
		return 0;

	free(s->data);
	s->data = blob_memdup(data);
	if (!s->data)
		return -1;

	service_data_trigger(&s->data_blob);
	blobmsg_list_free(&s->data_blob);
	blobmsg_list_fill(&s->data_blob, blobmsg_data(s->data),
			blobmsg_data_len(s->data), false);
	service_data_trigger(&s->data_blob);

	return 0;
}

static int
service_update(struct service *s, struct blob_attr **tb, bool add, bool init)
{
	struct blob_attr *cur;
	int rem;

	if (tb[SERVICE_SET_AUTOSTART])
		s->autostart = blobmsg_get_bool(tb[SERVICE_SET_AUTOSTART]);
	else if (init)
		s->autostart = true;

	if (tb[SERVICE_SET_TRIGGER]) {
		free(s->trigger);
		s->trigger = blob_memdup(tb[SERVICE_SET_TRIGGER]);
		if (!s->trigger)
			return -1;

		trigger_del(s);
		trigger_add(s->trigger, s);
	}

	if (tb[SERVICE_SET_VALIDATE]) {
		service_validate_del(s);
		blobmsg_for_each_attr(cur, tb[SERVICE_SET_VALIDATE], rem)
			service_validate_add(s, cur);
	}

	if (tb[SERVICE_SET_INSTANCES]) {
		if (!add)
			vlist_update(&s->instances);
		blobmsg_for_each_attr(cur, tb[SERVICE_SET_INSTANCES], rem) {
			service_instance_add(s, cur);
		}
		if (!add)
			vlist_flush(&s->instances);
	}

	if (tb[SERVICE_SET_DATA] &&
	    service_update_data(s, tb[SERVICE_SET_DATA]) < 0)
		return -1;

	s->deleted = false;

	if (init || tb[SERVICE_SET_INSTANCES])
		rc(s->name, "running");

	return 0;
}

static void
service_delete(struct service *s, bool container)
{
	blobmsg_list_free(&s->data_blob);
	free(s->data);
	s->data = NULL;
	vlist_flush_all(&s->instances);
	s->deleted = true;
	service_stopped(s);
}

enum {
	SERVICE_ATTR_NAME,
	__SERVICE_ATTR_MAX,
};

static const struct blobmsg_policy service_attrs[__SERVICE_ATTR_MAX] = {
	[SERVICE_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
};

enum {
	SERVICE_DEL_ATTR_NAME,
	SERVICE_DEL_ATTR_INSTANCE,
	__SERVICE_DEL_ATTR_MAX,
};

static const struct blobmsg_policy service_del_attrs[__SERVICE_DEL_ATTR_MAX] = {
	[SERVICE_DEL_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[SERVICE_DEL_ATTR_INSTANCE] = { "instance", BLOBMSG_TYPE_STRING },
};

enum {
	SERVICE_LIST_ATTR_NAME,
	SERVICE_LIST_ATTR_VERBOSE,
	__SERVICE_LIST_ATTR_MAX,
};

static const struct blobmsg_policy service_list_attrs[__SERVICE_LIST_ATTR_MAX] = {
	[SERVICE_LIST_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[SERVICE_LIST_ATTR_VERBOSE] = { "verbose", BLOBMSG_TYPE_BOOL },
};

enum {
	SERVICE_SIGNAL_ATTR_NAME,
	SERVICE_SIGNAL_ATTR_INSTANCE,
	SERVICE_SIGNAL_ATTR_SIGNAL,
	__SERVICE_SIGNAL_ATTR_MAX,
};

static const struct blobmsg_policy service_signal_attrs[__SERVICE_SIGNAL_ATTR_MAX] = {
	[SERVICE_SIGNAL_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[SERVICE_SIGNAL_ATTR_INSTANCE] = { "instance", BLOBMSG_TYPE_STRING },
	[SERVICE_SIGNAL_ATTR_SIGNAL] = { "signal", BLOBMSG_TYPE_INT32 },
};

enum {
	SERVICE_STATE_ATTR_SPAWN,
	SERVICE_STATE_ATTR_NAME,
	__SERVICE_STATE_ATTR_MAX,
};

static const struct blobmsg_policy service_state_attrs[__SERVICE_STATE_ATTR_MAX] = {
	[SERVICE_STATE_ATTR_SPAWN] = { "spawn", BLOBMSG_TYPE_BOOL },
	[SERVICE_STATE_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
};

enum {
	EVENT_TYPE,
	EVENT_DATA,
	__EVENT_MAX
};

static const struct blobmsg_policy event_policy[__EVENT_MAX] = {
	[EVENT_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
	[EVENT_DATA] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	VALIDATE_PACKAGE,
	VALIDATE_TYPE,
	VALIDATE_SERVICE,
	__VALIDATE_MAX
};

static const struct blobmsg_policy validate_policy[__VALIDATE_MAX] = {
	[VALIDATE_PACKAGE] = { .name = "package", .type = BLOBMSG_TYPE_STRING },
	[VALIDATE_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
	[VALIDATE_SERVICE] = { .name = "service", .type = BLOBMSG_TYPE_STRING },
};

enum {
	DATA_NAME,
	DATA_INSTANCE,
	DATA_TYPE,
	__DATA_MAX
};

static const struct blobmsg_policy get_data_policy[] = {
	[DATA_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[DATA_INSTANCE] = { "instance", BLOBMSG_TYPE_STRING },
	[DATA_TYPE] = { "type", BLOBMSG_TYPE_STRING },
};

enum {
	CONTAINER_CONSOLE_NAME,
	CONTAINER_CONSOLE_INSTANCE,
	__CONTAINER_CONSOLE_MAX,
};

static const struct blobmsg_policy container_console_policy[__CONTAINER_CONSOLE_MAX] = {
	[CONTAINER_CONSOLE_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[CONTAINER_CONSOLE_INSTANCE] = { "instance", BLOBMSG_TYPE_STRING },
};

static inline bool is_container_obj(struct ubus_object *obj)
{
	return (obj && (strcmp(obj->name, "container") == 0));
}

static inline void put_namespace(struct blob_buf *b, char *name)
{
	char nsfname[32];
	struct stat statbuf;

	snprintf(nsfname, sizeof(nsfname), "/proc/self/ns/%s", name);

	if (!stat(nsfname, &statbuf))
		blobmsg_add_string(b, NULL, name);
}

static void put_cgroups(struct blob_buf *b)
{
	int fd, ret;
	static char buf[512] = "";
	char *t, *z;

	fd = open("/sys/fs/cgroup/cgroup.controllers", O_RDONLY);
	if (fd == -1)
		return;

	ret = read(fd, &buf, sizeof(buf));
	/* make sure buffer is NULL-terminated */
	buf[sizeof(buf)-1] = '\0';

	close(fd);

	if (ret < 2)
		return;

	t = buf;
	while(t) {
		z = t;
		/* replace space with \0 and direct next entry */
		t = strchr(z, ' ');
		if (t) {
			*(t++) = '\0';
		} else { /* replace trailing new-line with \0 */
			t = strchr(z, '\n');
			if (!t) /* shouldn't happen, but don't segfault if it does */
				break;

			*t = '\0';
			t = NULL;
		}
		blobmsg_add_string(b, NULL, z);
	}
}

static int
container_handle_features(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct utsname utsbuf;
	struct stat statbuf;
	void *nsarray, *cgarray;

	if (stat("/sbin/ujail", &statbuf))
		return UBUS_STATUS_NOT_SUPPORTED;

	if (uname(&utsbuf) < 0)
		return UBUS_STATUS_UNKNOWN_ERROR;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "machine", utsbuf.machine);

#ifdef SECCOMP_SUPPORT
	blobmsg_add_u8(&b, "seccomp", true);
#else
	blobmsg_add_u8(&b, "seccomp", false);
#endif

	cgarray = blobmsg_open_array(&b, "cgroup");
	put_cgroups(&b);
	blobmsg_close_array(&b, cgarray);

	nsarray = blobmsg_open_array(&b, "namespaces");
	put_namespace(&b, "cgroup");
	put_namespace(&b, "ipc");
	put_namespace(&b, "mnt");
	put_namespace(&b, "net");
	put_namespace(&b, "pid");
#ifdef CLONE_NEWTIME
	put_namespace(&b, "time");
#endif
	put_namespace(&b, "user");
	put_namespace(&b, "uts");
	blobmsg_close_array(&b, nsarray);
	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

static int
service_handle_set(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVICE_SET_MAX], *cur;
	struct service *s = NULL;
	const char *name;
	bool container = is_container_obj(obj);
	bool add = !strcmp(method, "add");
	int ret;

	blobmsg_parse(service_set_attrs, __SERVICE_SET_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	cur = tb[SERVICE_SET_NAME];
	if (!cur)
		return UBUS_STATUS_INVALID_ARGUMENT;

	name = blobmsg_data(cur);

	if (container)
		s = avl_find_element(&containers, name, s, avl);
	else
		s = avl_find_element(&services, name, s, avl);

	if (s) {
		P_DEBUG(2, "Update service %s\n", name);
		return service_update(s, tb, add, false);
	}

	P_DEBUG(2, "Create service %s\n", name);
	s = service_alloc(name);
	if (!s)
		return UBUS_STATUS_UNKNOWN_ERROR;

	s->container = container;

	ret = service_update(s, tb, add, true);
	if (ret)
		return ret;

	if (container) {
		avl_insert(&containers, &s->avl);

		service_event("container.start", s->name, NULL);
	} else {
		avl_insert(&services, &s->avl);

		service_event("service.start", s->name, NULL);
	}
	return 0;
}

static void
service_dump(struct service *s, bool verbose)
{
	struct service_instance *in;
	void *c, *i;

	c = blobmsg_open_table(&b, s->name);

	if (!s->autostart)
		blobmsg_add_u8(&b, "autostart", false);

	if (!avl_is_empty(&s->data_blob.avl)) {
		struct blobmsg_list_node *var;
		i = blobmsg_open_table(&b, "data");
		blobmsg_list_for_each(&s->data_blob, var)
			blobmsg_add_blob(&b, var->data);
		blobmsg_close_table(&b, i);
	}

	if (!avl_is_empty(&s->instances.avl)) {
		i = blobmsg_open_table(&b, "instances");
		vlist_for_each_element(&s->instances, in, node)
			instance_dump(&b, in, verbose);
		blobmsg_close_table(&b, i);
	}
	if (verbose && s->trigger)
		blobmsg_add_blob(&b, s->trigger);
	if (verbose && !list_empty(&s->validators))
		service_validate_dump(&b, s);
	blobmsg_close_table(&b, c);
}

static int
service_handle_list(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVICE_LIST_ATTR_MAX];
	struct service *s;
	const char *name = NULL;
	bool verbose = false;
	bool container = is_container_obj(obj);
	const struct avl_tree *tree = container?&containers:&services;

	blobmsg_parse(service_list_attrs, __SERVICE_LIST_ATTR_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	if (tb[SERVICE_LIST_ATTR_VERBOSE])
		verbose = blobmsg_get_bool(tb[SERVICE_LIST_ATTR_VERBOSE]);
	if (tb[SERVICE_LIST_ATTR_NAME])
		name = blobmsg_get_string(tb[SERVICE_LIST_ATTR_NAME]);

	blob_buf_init(&b, 0);
	avl_for_each_element(tree, s, avl) {
		if (name && strcmp(s->name, name) != 0)
			continue;

		service_dump(s, verbose);
	}

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
service_handle_delete(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVICE_DEL_ATTR_MAX], *cur;
	struct service *s;
	struct service_instance *in;
	bool container = is_container_obj(obj);

	blobmsg_parse(service_del_attrs, __SERVICE_DEL_ATTR_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	cur = tb[SERVICE_DEL_ATTR_NAME];
	if (!cur)
		return UBUS_STATUS_NOT_FOUND;

	if (container)
		s = avl_find_element(&containers, blobmsg_data(cur), s, avl);
	else
		s = avl_find_element(&services, blobmsg_data(cur), s, avl);

	if (!s)
		return UBUS_STATUS_NOT_FOUND;

	cur = tb[SERVICE_DEL_ATTR_INSTANCE];
	if (!cur) {
		service_delete(s, container);
		return 0;
	}

	in = vlist_find(&s->instances, blobmsg_data(cur), in, node);
	if (!in) {
		ERROR("instance %s not found\n", (char *) blobmsg_data(cur));
		return UBUS_STATUS_NOT_FOUND;
	}

	vlist_delete(&s->instances, &in->node);

	return 0;
}

static int
service_handle_kill(struct service_instance *in, int sig)
{
	if (kill(in->proc.pid, sig) == 0)
		return 0;

	switch (errno) {
	case EINVAL: return UBUS_STATUS_INVALID_ARGUMENT;
	case EPERM:  return UBUS_STATUS_PERMISSION_DENIED;
	case ESRCH:  return UBUS_STATUS_NOT_FOUND;
	}

	return UBUS_STATUS_UNKNOWN_ERROR;
}

static int
service_handle_signal(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVICE_SIGNAL_ATTR_MAX], *cur;
	struct service *s;
	struct service_instance *in;
	bool container = is_container_obj(obj);
	int sig = SIGHUP;
	int rv = 0;

	blobmsg_parse(service_signal_attrs, __SERVICE_SIGNAL_ATTR_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	cur = tb[SERVICE_SIGNAL_ATTR_SIGNAL];
	if (cur)
		sig = blobmsg_get_u32(cur);

	cur = tb[SERVICE_SIGNAL_ATTR_NAME];
	if (!cur)
		return UBUS_STATUS_NOT_FOUND;

	if (container)
		s = avl_find_element(&containers, blobmsg_data(cur), s, avl);
	else
		s = avl_find_element(&services, blobmsg_data(cur), s, avl);

	if (!s)
		return UBUS_STATUS_NOT_FOUND;

	cur = tb[SERVICE_SIGNAL_ATTR_INSTANCE];
	if (!cur) {
		vlist_for_each_element(&s->instances, in, node)
			rv = service_handle_kill(in, sig);

		return rv;
	}

	in = vlist_find(&s->instances, blobmsg_data(cur), in, node);
	if (!in) {
		ERROR("instance %s not found\n", blobmsg_get_string(cur));
		return UBUS_STATUS_NOT_FOUND;
	}

	return service_handle_kill(in, sig);
}

static int
service_handle_state(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVICE_STATE_ATTR_MAX];
	struct service *s;
	struct service_instance *in;
	bool container = is_container_obj(obj);
	int spawn;

	blobmsg_parse(service_state_attrs, __SERVICE_STATE_ATTR_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	if (!tb[SERVICE_STATE_ATTR_SPAWN])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!tb[SERVICE_STATE_ATTR_NAME])
		return UBUS_STATUS_NOT_FOUND;

	if (container)
		s = avl_find_element(&containers, blobmsg_data(tb[SERVICE_STATE_ATTR_NAME]), s, avl);
	else
		s = avl_find_element(&services, blobmsg_data(tb[SERVICE_STATE_ATTR_NAME]), s, avl);

	if (!s)
		return UBUS_STATUS_NOT_FOUND;

	spawn = !!blobmsg_get_u8(tb[SERVICE_STATE_ATTR_SPAWN]);
	vlist_for_each_element(&s->instances, in, node) {
		if (!!in->proc.pending == !!spawn)
			continue;
		else if (!in->proc.pending)
			instance_start(in);
		else
			instance_stop(in, false);
	}

	return UBUS_STATUS_OK;
}

static void
service_avl_stop_all(struct avl_tree *sctree, unsigned int *term_timeout)
{
	struct service *s;

	avl_for_each_element(sctree, s, avl) {
		struct service_instance *in, *ptr;

		vlist_for_each_element_safe(&s->instances, in, node, ptr) {
			if (in->term_timeout > *term_timeout)
				*term_timeout = in->term_timeout;
			instance_stop(in, true);
		}
	}
}

void
service_stop_all(void)
{
	unsigned int term_timeout = 0;

	service_avl_stop_all(&containers, &term_timeout);
	service_avl_stop_all(&services, &term_timeout);
	procd_inittab_kill();

	sleep(term_timeout);
}

static int
service_handle_update(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVICE_ATTR_MAX], *cur;
	struct service *s;
	bool container = is_container_obj(obj);

	blobmsg_parse(service_attrs, __SERVICE_ATTR_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	cur = tb[SERVICE_SET_NAME];
	if (!cur)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (container)
		s = avl_find_element(&containers, blobmsg_data(cur), s, avl);
	else
		s = avl_find_element(&services, blobmsg_data(cur), s, avl);

	if (!s)
		return UBUS_STATUS_NOT_FOUND;

	if (!strcmp(method, "update_start"))
		vlist_update(&s->instances);
	else
		vlist_flush(&s->instances);

	return 0;
}

static void ubus_event_bcast(const char *type, const char *param1, const char *val1,
			     const char *param2, const char *val2)
{
	if (!ctx)
		return;

	blob_buf_init(&b, 0);
	if (param1 && val1)
		blobmsg_add_string(&b, param1, val1);
	if (param2 && val2)
		blobmsg_add_string(&b, param2, val2);
	ubus_notify(ctx, &main_object, type, b.head, -1);
}

static int
service_handle_event(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__EVENT_MAX];
	const char *event;

	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_parse(event_policy, __EVENT_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[EVENT_TYPE] || !tb[EVENT_DATA])
		return UBUS_STATUS_INVALID_ARGUMENT;

	event = blobmsg_get_string(tb[EVENT_TYPE]);
	trigger_event(event, tb[EVENT_DATA]);

	if (!strcmp(event, "config.change")) {
		struct blob_attr *tb2[__VALIDATE_MAX];

		blobmsg_parse(validate_policy, __VALIDATE_MAX, tb2,
			      blobmsg_data(tb[EVENT_DATA]), blobmsg_data_len(tb[EVENT_DATA]));
		if (tb2[VALIDATE_PACKAGE])
			ubus_event_bcast("config.change", "config",
					 blobmsg_get_string(tb2[VALIDATE_PACKAGE]), NULL, NULL);
	}
	return 0;
}

static int
service_handle_validate(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__VALIDATE_MAX];
	char *p = NULL, *t = NULL;

	if (!msg)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blobmsg_parse(validate_policy, __VALIDATE_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (tb[VALIDATE_SERVICE]) {
		return 0;
	}
	if (tb[VALIDATE_PACKAGE])
		p = blobmsg_get_string(tb[VALIDATE_PACKAGE]);

	if (tb[VALIDATE_TYPE])
		t = blobmsg_get_string(tb[VALIDATE_TYPE]);

	blob_buf_init(&b, 0);
	service_validate_dump_all(&b, p, t);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
service_get_data(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	struct service_instance *in;
	struct service *s;
	struct blob_attr *tb[__DATA_MAX];
	const char *name = NULL;
	const char *instance = NULL;
	const char *type = NULL;

	blobmsg_parse(get_data_policy, __DATA_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (tb[DATA_NAME])
		name = blobmsg_data(tb[DATA_NAME]);
	if (tb[DATA_INSTANCE])
		instance = blobmsg_data(tb[DATA_INSTANCE]);
	if (tb[DATA_TYPE])
		type = blobmsg_data(tb[DATA_TYPE]);

	blob_buf_init(&b, 0);
	avl_for_each_element(&services, s, avl) {
		void *cs = NULL;
		void *ci = NULL;
		struct blobmsg_list_node *var;

		if (name && strcmp(name, s->name))
			continue;

		blobmsg_list_for_each(&s->data_blob, var) {
			if (type && strcmp(blobmsg_name(var->data), type))
				continue;

			if (!cs)
				cs = blobmsg_open_table(&b, s->name);
			if (!ci)
				ci = blobmsg_open_table(&b, "*");

			blobmsg_add_blob(&b, var->data);
		}

		if (ci)
			blobmsg_close_table(&b, ci);

		vlist_for_each_element(&s->instances, in, node) {
			ci = NULL;

			if (instance && strcmp(instance, in->name))
				continue;

			blobmsg_list_for_each(&in->data, var) {
				if (type &&
				    strcmp(blobmsg_name(var->data), type))
					continue;

				if (!cs)
					cs = blobmsg_open_table(&b, s->name);
				if (!ci)
					ci = blobmsg_open_table(&b, in->name);

				blobmsg_add_blob(&b, var->data);
			}

			if (ci)
				blobmsg_close_table(&b, ci);
		}

		if (cs)
			blobmsg_close_table(&b, cs);
	}

	ubus_send_reply(ctx, req, b.head);
	return 0;
}

static int
container_handle_console(struct ubus_context *ctx, struct ubus_object *obj,
			 struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg)
{
	bool attach = !strcmp(method, "console_attach");
	struct blob_attr *tb[__CONTAINER_CONSOLE_MAX];
	struct service *s;
	struct service_instance *in;
	int console_fd = -1;

	console_fd = ubus_request_get_caller_fd(req);
	if (console_fd < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!msg)
		goto err_console_fd;

	blobmsg_parse(container_console_policy, __CONTAINER_CONSOLE_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[CONTAINER_CONSOLE_NAME])
		goto err_console_fd;

	s = avl_find_element(&containers, blobmsg_data(tb[CONTAINER_CONSOLE_NAME]), s, avl);
	if (!s)
		goto err_console_fd;

	if (tb[CONTAINER_CONSOLE_INSTANCE]) {
		in = vlist_find(&s->instances, blobmsg_data(tb[CONTAINER_CONSOLE_INSTANCE]), in, node);
	} else {
		/* use first element in instances list */
		vlist_for_each_element(&s->instances, in, node)
			break;
	}
	if (!in)
		goto err_console_fd;

	if (attach) {
		if (in->console.fd.fd < 0) {
			close(console_fd);
			return UBUS_STATUS_NOT_SUPPORTED;
		}

		/* close and replace existing attached console */
		if (in->console_client.fd.fd > -1)
			close(in->console_client.fd.fd);

		ustream_fd_init(&in->console_client, console_fd);
	} else {
		ustream_fd_init(&in->console, console_fd);
	}

	return UBUS_STATUS_OK;
err_console_fd:
	close(console_fd);
	return UBUS_STATUS_INVALID_ARGUMENT;
}

enum {
	SERVICE_WATCHDOG_MODE,
	SERVICE_WATCHDOG_TIMEOUT,
	SERVICE_WATCHDOG_NAME,
	SERVICE_WATCHDOG_INSTANCE,
	__SERVICE_WATCHDOG_MAX,
};

static const struct blobmsg_policy service_watchdog_policy[__SERVICE_WATCHDOG_MAX] = {
	[SERVICE_WATCHDOG_MODE] = { "mode", BLOBMSG_TYPE_INT32 },
	[SERVICE_WATCHDOG_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[SERVICE_WATCHDOG_TIMEOUT] = { "timeout", BLOBMSG_TYPE_INT32 },
	[SERVICE_WATCHDOG_INSTANCE] = { "instance", BLOBMSG_TYPE_STRING },
};

static int
service_handle_watchdog(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVICE_WATCHDOG_MAX] = {0};
	struct service *s;
	struct blob_attr *cur;
	struct service_instance *in;

	blobmsg_parse(service_watchdog_policy, __SERVICE_WATCHDOG_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));
	cur = tb[SERVICE_WATCHDOG_NAME];
	if (!cur)
		return UBUS_STATUS_NOT_FOUND;

	s = avl_find_element(&services, blobmsg_data(cur), s, avl);
	if (!s)
		return UBUS_STATUS_NOT_FOUND;

	cur = tb[SERVICE_WATCHDOG_INSTANCE];
	if (!cur)
		return UBUS_STATUS_NOT_FOUND;

	in = vlist_find(&s->instances, blobmsg_data(cur), in, node);
	if (!in) {
		ERROR("instance %s not found\n", blobmsg_get_string(cur));
		return UBUS_STATUS_NOT_FOUND;
	}

	if (tb[SERVICE_WATCHDOG_MODE])
		in->watchdog.mode = blobmsg_get_u32(tb[SERVICE_WATCHDOG_MODE]);

	if (tb[SERVICE_WATCHDOG_TIMEOUT])
		in->watchdog.freq = blobmsg_get_u32(tb[SERVICE_WATCHDOG_TIMEOUT]);

	if (in->watchdog.mode == INSTANCE_WATCHDOG_MODE_DISABLED)
		uloop_timeout_cancel(&in->watchdog.timeout);
	else
		uloop_timeout_set(&in->watchdog.timeout, in->watchdog.freq * 1000);

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", blobmsg_get_string(tb[SERVICE_WATCHDOG_NAME]));
	blobmsg_add_string(&b, "instance", blobmsg_get_string(tb[SERVICE_WATCHDOG_INSTANCE]));
	blobmsg_add_u32(&b, "mode", in->watchdog.mode);
	blobmsg_add_u32(&b, "timeout", in->watchdog.freq);

	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

static struct ubus_method main_object_methods[] = {
	UBUS_METHOD("set", service_handle_set, service_set_attrs),
	UBUS_METHOD("add", service_handle_set, service_set_attrs),
	UBUS_METHOD("list", service_handle_list, service_list_attrs),
	UBUS_METHOD("delete", service_handle_delete, service_del_attrs),
	UBUS_METHOD("signal", service_handle_signal, service_signal_attrs),
	UBUS_METHOD("update_start", service_handle_update, service_attrs),
	UBUS_METHOD("update_complete", service_handle_update, service_attrs),
	UBUS_METHOD("event", service_handle_event, event_policy),
	UBUS_METHOD("validate", service_handle_validate, validate_policy),
	UBUS_METHOD("get_data", service_get_data, get_data_policy),
	UBUS_METHOD("state", service_handle_state, service_state_attrs),
	UBUS_METHOD("watchdog", service_handle_watchdog, service_watchdog_policy),
};

static struct ubus_object_type main_object_type =
	UBUS_OBJECT_TYPE("service", main_object_methods);

static struct ubus_object main_object = {
	.name = "service",
	.type = &main_object_type,
	.methods = main_object_methods,
	.n_methods = ARRAY_SIZE(main_object_methods),
};

int
service_start_early(char *name, char *cmdline, char *user, char *group)
{
	void *instances, *instance, *command, *respawn;
	char *t;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", name);
	instances = blobmsg_open_table(&b, "instances");
	instance = blobmsg_open_table(&b, "instance1");
	command = blobmsg_open_array(&b, "command");
	t = strtok(cmdline, " ");
	while (t) {
		blobmsg_add_string(&b, NULL, t);
		t = strtok(NULL, " ");
	}
	blobmsg_close_array(&b, command);
	respawn = blobmsg_open_array(&b, "respawn");
	blobmsg_add_string(&b, NULL, "3600");
	blobmsg_add_string(&b, NULL, "1");
	blobmsg_add_string(&b, NULL, "0");
	blobmsg_close_array(&b, respawn);
	if (user)
		blobmsg_add_string(&b, "user", user);
	if (group)
		blobmsg_add_string(&b, "group", group);

	blobmsg_close_table(&b, instance);
	blobmsg_close_table(&b, instances);

	return service_handle_set(NULL, NULL, NULL, "add", b.head);
}

void service_stopped(struct service *s)
{
	if (s->deleted && avl_is_empty(&s->instances.avl)) {
		if (s->container) {
			service_event("container.stop", s->name, NULL);
			avl_delete(&containers, &s->avl);
		} else {
			service_event("service.stop", s->name, NULL);
			avl_delete(&services, &s->avl);
		}
		trigger_del(s);
		service_validate_del(s);
		free(s->trigger);
		free(s);
	}
}

void service_event(const char *type, const char *service, const char *instance)
{
	ubus_event_bcast(type, "service", service, "instance", instance);
}

static struct ubus_method container_object_methods[] = {
	UBUS_METHOD("set", service_handle_set, service_set_attrs),
	UBUS_METHOD("add", service_handle_set, service_set_attrs),
	UBUS_METHOD("list", service_handle_list, service_list_attrs),
	UBUS_METHOD("delete", service_handle_delete, service_del_attrs),
	UBUS_METHOD("state", service_handle_state, service_state_attrs),
	UBUS_METHOD_NOARG("get_features", container_handle_features),
	UBUS_METHOD("console_set", container_handle_console, container_console_policy),
	UBUS_METHOD("console_attach", container_handle_console, container_console_policy),
};

static struct ubus_object_type container_object_type =
	UBUS_OBJECT_TYPE("container", container_object_methods);

static struct ubus_object container_object = {
	.name = "container",
	.type = &container_object_type,
	.methods = container_object_methods,
	.n_methods = ARRAY_SIZE(container_object_methods),
};

void ubus_init_service(struct ubus_context *_ctx)
{
	struct stat statbuf;

	ctx = _ctx;
	ubus_add_object(ctx, &main_object);

	if (!stat("/sbin/ujail", &statbuf))
		ubus_add_object(ctx, &container_object);
}
