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

/*
 * Following functions just wrap Xen hypercalls, detailed description
 * of parameters and return values are located in include/xen/public/event_channel.h
 */
int evtchn_alloc_unbound(domid_t dom, domid_t remote_dom);
int evtchn_bind_interdomain(domid_t remote_dom, evtchn_port_t remote_port);
int evtchn_status(evtchn_status_t *status);
int evtchn_unmask(evtchn_port_t port);
int evtchn_close(evtchn_port_t port);
int evtchn_reset(domid_t dom);
int evtchn_set_priority(evtchn_port_t port, uint32_t priority);
void notify_evtchn(evtchn_port_t port);

/*
 * Bind user-defined handler to specified event-channel
 *
 * @port - event channel number
 * @cb - pointer to event channel handler
 * @data - private data, that will be passed to handler as parameter
 * @return - zero on success
 */
int bind_event_channel(evtchn_port_t port, evtchn_cb_t cb, void *data);

/*
 * Unbind handler from event channel, substitute it with empty callback
 *
 * @port - event channel number to unbind
 * @return - zero on success
 */
int unbind_event_channel(evtchn_port_t port);

int xen_events_init(void);

#endif /* __XEN_EVENTS_H__ */
