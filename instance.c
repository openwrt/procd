#include "procd.h"
#include "service.h"
#include "instance.h"

void
instance_start(struct service_instance *in)
{
	in->restart = false;
}

static void
instance_timeout(struct uloop_timeout *t)
{
	struct service_instance *in;

	in = container_of(t, struct service_instance, timeout);
	kill(in->proc.pid, SIGKILL);
	uloop_process_delete(&in->proc);
	in->proc.cb(&in->proc, -1);
}

static void
instance_exit(struct uloop_process *p, int ret)
{
	struct service_instance *in;

	in = container_of(p, struct service_instance, proc);
	uloop_timeout_cancel(&in->timeout);
	if (in->restart)
		instance_start(in);
}

void
instance_stop(struct service_instance *in, bool restart)
{
	if (!in->proc.pending)
		return;

	kill(in->proc.pid, SIGTERM);
}

static bool
instance_config_changed(struct service_instance *in, struct service_instance *in_new)
{
	int len = blob_pad_len(in->config);

	if (len != blob_pad_len(in_new->config))
		return true;

	if (memcmp(in->config, in_new->config, blob_pad_len(in->config)) != 0)
		return true;

	return false;
}

bool
instance_update(struct service_instance *in, struct service_instance *in_new)
{
	bool changed = instance_config_changed(in, in_new);

	in->config = in_new->config;
	if (!changed)
		return false;

	instance_stop(in, true);
	return true;
}

void
instance_free(struct service_instance *in)
{
	uloop_process_delete(&in->proc);
	uloop_timeout_cancel(&in->timeout);
	free(in);
}

void
instance_init(struct service_instance *in, struct blob_attr *config)
{
	in->config = config;
	in->timeout.cb = instance_timeout;
	in->proc.cb = instance_exit;
}


