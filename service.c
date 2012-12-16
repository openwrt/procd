#include <libubox/avl-cmp.h>
#include "procd.h"
#include "service.h"
#include "instance.h"

struct avl_tree services;
static struct blob_buf b;

static void
service_instance_add(struct service *s, struct blob_attr *attr)
{
	struct service_instance *in;
	const char *name = blobmsg_name(attr);

	if (blobmsg_type(attr) != BLOBMSG_TYPE_TABLE)
		return;

	in = calloc(1, sizeof(*in));
	if (!in)
		return;

	instance_init(in, s, attr);
	vlist_add(&s->instances, &in->node, (void *) name);
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
		DPRINTF("Update instance %s::%s\n", in_o->srv->name, in_o->name);
		instance_update(in_o, in_n);
		instance_free(in_n);
	} else if (in_o) {
		DPRINTF("Free instance %s::%s\n", in_o->srv->name, in_o->name);
		instance_stop(in_o, false);
		instance_free(in_o);
	} else if (in_n) {
		DPRINTF("Create instance %s::%s\n", in_n->srv->name, in_n->name);
		instance_start(in_n);
	}
}

static struct service *
service_alloc(const char *name)
{
	struct service *s;
	char *new_name;

	s = calloc(1, sizeof(*s) + strlen(name) + 1);

	new_name = (char *) (s + 1);
	strcpy(new_name, name);

	vlist_init(&s->instances, avl_strcmp, service_instance_update);
	s->instances.keep_old = true;
	s->name = new_name;
	s->avl.key = s->name;

	return s;
}

enum {
	SERVICE_SET_NAME,
	SERVICE_SET_SCRIPT,
	SERVICE_SET_INSTANCES,
	__SERVICE_SET_MAX
};

static const struct blobmsg_policy service_set_attrs[__SERVICE_SET_MAX] = {
	[SERVICE_SET_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[SERVICE_SET_SCRIPT] = { "script", BLOBMSG_TYPE_STRING },
	[SERVICE_SET_INSTANCES] = { "instances", BLOBMSG_TYPE_TABLE },
};


static int
service_update(struct service *s, struct blob_attr *config, struct blob_attr **tb, bool add)
{
	struct blob_attr *cur;
	int rem;

	if (tb[SERVICE_SET_INSTANCES]) {
		if (!add)
			vlist_update(&s->instances);
		blobmsg_for_each_attr(cur, tb[SERVICE_SET_INSTANCES], rem) {
			service_instance_add(s, cur);
		}
		if (!add)
			vlist_flush(&s->instances);
	}

	return 0;
}

static void
service_delete(struct service *s)
{
	vlist_flush_all(&s->instances);
	avl_delete(&services, &s->avl);
	free(s->config);
	free(s);
}

enum {
	SERVICE_ATTR_NAME,
	__SERVICE_ATTR_MAX,
};

static const struct blobmsg_policy service_attrs[__SERVICE_ATTR_MAX] = {
	[SERVICE_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
};


static int
service_handle_set(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVICE_SET_MAX], *cur;
	struct service *s = NULL;
	const char *name;
	int ret = UBUS_STATUS_INVALID_ARGUMENT;
	bool add = !strcmp(method, "add");

	blobmsg_parse(service_set_attrs, __SERVICE_SET_MAX, tb, blob_data(msg), blob_len(msg));
	cur = tb[SERVICE_ATTR_NAME];
	if (!cur)
		goto free;

	name = blobmsg_data(cur);

	s = avl_find_element(&services, name, s, avl);
	if (s) {
		DPRINTF("Update service %s\n", name);
		return service_update(s, msg, tb, add);
	}

	DPRINTF("Create service %s\n", name);
	s = service_alloc(name);
	if (!s)
		return UBUS_STATUS_UNKNOWN_ERROR;

	ret = service_update(s, msg, tb, add);
	if (ret)
		goto free;

	avl_insert(&services, &s->avl);

	return 0;

free:
	free(msg);
	return ret;
}

static void
service_dump(struct service *s)
{
	struct service_instance *in;
	void *c, *i;

	c = blobmsg_open_table(&b, s->name);
	i = blobmsg_open_table(&b, "instances");
	vlist_for_each_element(&s->instances, in, node)
		instance_dump(&b, in);
	blobmsg_close_table(&b, i);
	blobmsg_close_table(&b, c);
}

static int
service_handle_list(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct service *s;

	blob_buf_init(&b, 0);
	avl_for_each_element(&services, s, avl)
		service_dump(s);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
service_handle_delete(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVICE_ATTR_MAX], *cur;
	struct service *s, *tmp;

	blobmsg_parse(service_attrs, __SERVICE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	cur = tb[SERVICE_ATTR_NAME];
	if (!cur) {
		avl_for_each_element_safe(&services, s, avl, tmp)
			service_delete(s);
		return 0;
	}

	s = avl_find_element(&services, blobmsg_data(cur), s, avl);
	if (!s)
		return UBUS_STATUS_NOT_FOUND;

	service_delete(s);
	return 0;
}

static int
service_handle_update(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVICE_ATTR_MAX], *cur;
	struct service *s;

	blobmsg_parse(service_attrs, __SERVICE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	cur = tb[SERVICE_ATTR_NAME];
	if (!cur)
		return UBUS_STATUS_INVALID_ARGUMENT;

	s = avl_find_element(&services, blobmsg_data(cur), s, avl);
	if (!s)
		return UBUS_STATUS_NOT_FOUND;

	if (!strcmp(method, "update_start"))
		vlist_update(&s->instances);
	else
		vlist_flush(&s->instances);

	return 0;
}

static struct ubus_method main_object_methods[] = {
	UBUS_METHOD("set", service_handle_set, service_set_attrs),
	UBUS_METHOD("add", service_handle_set, service_set_attrs),
	UBUS_METHOD("list", service_handle_list, service_attrs),
	UBUS_METHOD("delete", service_handle_delete, service_attrs),
	UBUS_METHOD("update_start", service_handle_update, service_attrs),
	UBUS_METHOD("update_complete", service_handle_update, service_attrs),
};

static struct ubus_object_type main_object_type =
	UBUS_OBJECT_TYPE("service", main_object_methods);

static struct ubus_object main_object = {
	.name = "service",
	.type = &main_object_type,
	.methods = main_object_methods,
	.n_methods = ARRAY_SIZE(main_object_methods),
};

void procd_init_service(struct ubus_context *ctx)
{
	avl_init(&services, avl_strcmp, false, NULL);
	ubus_add_object(ctx, &main_object);
}
