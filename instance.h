#ifndef __PROCD_INSTANCE_H
#define __PROCD_INSTANCE_H

void instance_start(struct service_instance *in);
void instance_stop(struct service_instance *in, bool restart);
bool instance_update(struct service_instance *in, struct service_instance *in_new);
void instance_init(struct service_instance *in, struct blob_attr *config);
void instance_free(struct service_instance *in);

#endif
