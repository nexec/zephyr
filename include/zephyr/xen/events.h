/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __XEN_EVENTS_H__
#define __XEN_EVENTS_H__

#include <zephyr/xen/public/event_channel.h>

#include <zephyr/kernel.h>

typedef void (*evtchn_cb_t)(void *priv);

struct event_channel_handle {
	evtchn_cb_t cb;
	void *priv;
};

typedef struct event_channel_handle evtchn_handle_t;

int notify_evtchn(evtchn_port_t port);
int bind_event_channel(evtchn_port_t port, evtchn_cb_t cb, void *data);
int evtchn_status(evtchn_status_t *status);
int unbind_event_channel(evtchn_port_t port);
int check_channel_mask(evtchn_port_t port);
int check_channel_event(evtchn_port_t port);
int check_upcall_pending(int vcpu);
int check_upcall_masked(int vcpu);

int xen_events_init(void);

#endif /* __XEN_EVENTS_H__ */
