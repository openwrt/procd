#include "procd.h"

static int
service_handle_list(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method,
		    struct blob_attr *msg)
{
	return 0;
}

static struct ubus_method main_object_methods[] = {
	{ .name = "list", .handler = service_handle_list },
};

static struct ubus_object_type main_object_type =
	UBUS_OBJECT_TYPE("service", main_object_methods);

static struct ubus_object main_object = {
	.name = "service",
	.type = &main_object_type,
	.methods = main_object_methods,
	.n_methods = ARRAY_SIZE(main_object_methods),
};


void procd_register_objects(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &main_object);
}
