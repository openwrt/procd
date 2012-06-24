#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

#include "procd.h"
#include "service.h"
#include "instance.h"

enum {
	INSTANCE_ATTR_COMMAND,
	INSTANCE_ATTR_ENV,
	INSTANCE_ATTR_DATA,
	INSTANCE_ATTR_NETDEV,
	__INSTANCE_ATTR_MAX
};

static const struct blobmsg_policy instance_attr[__INSTANCE_ATTR_MAX] = {
	[INSTANCE_ATTR_COMMAND] = { "command", BLOBMSG_TYPE_ARRAY },
	[INSTANCE_ATTR_ENV] = { "env", BLOBMSG_TYPE_TABLE },
	[INSTANCE_ATTR_DATA] = { "data", BLOBMSG_TYPE_TABLE },
	[INSTANCE_ATTR_NETDEV] = { "netdev", BLOBMSG_TYPE_ARRAY },
};

struct instance_netdev {
	struct blobmsg_list_node node;
	int ifindex;
};

static void
instance_run(struct service_instance *in)
{
	struct blobmsg_list_node *var;
	struct blob_attr *cur;
	char **argv;
	int argc = 1; /* NULL terminated */
	int rem;

	blobmsg_for_each_attr(cur, in->command, rem)
		argc++;

	blobmsg_list_for_each(&in->env, var)
		setenv(blobmsg_name(var->data), blobmsg_data(var->data), 1);

	argv = alloca(sizeof(char *) * argc);
	argc = 0;

	blobmsg_for_each_attr(cur, in->command, rem)
		argv[argc++] = blobmsg_data(cur);

	argv[argc] = NULL;
	execvp(argv[0], argv);
	exit(127);
}

void
instance_start(struct service_instance *in)
{
	int pid;

	if (in->proc.pending)
		return;

	in->restart = false;
	if (!in->valid)
		return;

	pid = fork();
	if (pid < 0)
		return;

	if (!pid) {
		instance_run(in);
		return;
	}

	DPRINTF("Started instance %s::%s\n", in->srv->name, in->name);
	in->proc.pid = pid;
	uloop_process_add(&in->proc);
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
	DPRINTF("Instance %s::%s exit with error code %d\n", in->srv->name, in->name, ret);
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
	if (!in->valid)
		return true;

	if (!blob_attr_equal(in->command, in_new->command))
		return true;

	if (!blobmsg_list_equal(&in->env, &in_new->env))
		return true;

	if (!blobmsg_list_equal(&in->data, &in_new->data))
		return true;

	if (!blobmsg_list_equal(&in->netdev, &in_new->netdev))
		return true;

	return false;
}

static bool
instance_netdev_cmp(struct blobmsg_list_node *l1, struct blobmsg_list_node *l2)
{
	struct instance_netdev *n1 = container_of(l1, struct instance_netdev, node);
	struct instance_netdev *n2 = container_of(l2, struct instance_netdev, node);

	return n1->ifindex == n2->ifindex;
}

static void
instance_netdev_update(struct blobmsg_list_node *l)
{
	struct instance_netdev *n = container_of(l, struct instance_netdev, node);

	n->ifindex = if_nametoindex(n->node.avl.key);
}

static bool
instance_config_parse(struct service_instance *in)
{
	struct blob_attr *tb[__INSTANCE_ATTR_MAX];
	struct blob_attr *cur, *cur2;
	int argc = 0;
	int rem;

	blobmsg_parse(instance_attr, __INSTANCE_ATTR_MAX, tb,
		blobmsg_data(in->config), blobmsg_data_len(in->config));

	cur = tb[INSTANCE_ATTR_COMMAND];
	if (!cur)
		return false;

	if (!blobmsg_check_attr_list(cur, BLOBMSG_TYPE_STRING))
		return false;

	blobmsg_for_each_attr(cur2, cur, rem) {
		argc++;
		break;
	}
	if (!argc)
		return false;

	in->command = cur;

	if ((cur = tb[INSTANCE_ATTR_ENV])) {
		if (!blobmsg_check_attr_list(cur, BLOBMSG_TYPE_STRING))
			return false;

		blobmsg_list_fill(&in->env, blobmsg_data(cur), blobmsg_data_len(cur), false);
	}

	if ((cur = tb[INSTANCE_ATTR_DATA])) {
		if (!blobmsg_check_attr_list(cur, BLOBMSG_TYPE_STRING))
			return false;

		blobmsg_list_fill(&in->data, blobmsg_data(cur), blobmsg_data_len(cur), false);
	}

	if ((cur = tb[INSTANCE_ATTR_NETDEV])) {
		struct blobmsg_list_node *ndev;

		if (!blobmsg_check_attr_list(cur, BLOBMSG_TYPE_STRING))
			return false;

		blobmsg_list_fill(&in->netdev, blobmsg_data(cur), blobmsg_data_len(cur), true);
		blobmsg_list_for_each(&in->netdev, ndev)
			instance_netdev_update(ndev);
	}

	return true;
}

static void
instance_config_cleanup(struct service_instance *in)
{
	blobmsg_list_free(&in->env);
	blobmsg_list_free(&in->data);
	blobmsg_list_free(&in->netdev);
}

static void
instance_config_move(struct service_instance *in, struct service_instance *in_src)
{
	instance_config_cleanup(in);
	blobmsg_list_move(&in->env, &in_src->env);
	blobmsg_list_move(&in->data, &in_src->data);
	blobmsg_list_move(&in->netdev, &in_src->netdev);
	in->command = in_src->command;
	in->name = in_src->name;
	in->node.avl.key = in_src->node.avl.key;
	in->config = in_src->config;
	in_src->config = NULL;
}

bool
instance_update(struct service_instance *in, struct service_instance *in_new)
{
	bool changed = instance_config_changed(in, in_new);

	if (!changed)
		return false;

	in->restart = true;
	instance_stop(in, true);
	instance_config_move(in, in_new);
	return true;
}

void
instance_free(struct service_instance *in)
{
	uloop_process_delete(&in->proc);
	uloop_timeout_cancel(&in->timeout);
	instance_config_cleanup(in);
	free(in);
}

void
instance_init(struct service_instance *in, struct service *s, struct blob_attr *config)
{
	in->srv = s;
	in->name = blobmsg_name(config);
	in->config = config;
	in->timeout.cb = instance_timeout;
	in->proc.cb = instance_exit;

	blobmsg_list_init(&in->netdev, struct instance_netdev, node, instance_netdev_cmp);
	blobmsg_list_simple_init(&in->env);
	blobmsg_list_simple_init(&in->data);
	in->valid = instance_config_parse(in);
}

void instance_dump(struct blob_buf *b, struct service_instance *in)
{
	void *i;

	i = blobmsg_open_table(b, in->name);
	blobmsg_add_u8(b, "running", in->proc.pending);
	if (in->proc.pending)
		blobmsg_add_u32(b, "pid", in->proc.pid);
	blobmsg_add_blob(b, in->command);
	blobmsg_close_table(b, i);
}
