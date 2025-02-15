/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/arch/arm64/hypercall.h>
#include <zephyr/xen/public/xen.h>
#include <zephyr/xen/public/event_channel.h>
#include <zephyr/xen/events.h>
#include <xen/xenbus/xs.h>

#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(xen_events);

extern shared_info_t *HYPERVISOR_shared_info;

static evtchn_handle_t event_channels[EVTCHN_2L_NR_CHANNELS];

static void empty_callback(void *data) { }

/* One bit per port, sets to 1 during binding */
//static uint64_t evtchn_states[EVTCHN_2L_NR_CHANNELS / (8 * sizeof(uint64_t))];

int notify_evtchn(evtchn_port_t port)
{
	struct evtchn_send send;

	__ASSERT(port < EVTCHN_2L_NR_CHANNELS,
		"%s: trying to send notify for invalid evtchn #%u\n",
		__func__, port);

	send.port = port;

	return HYPERVISOR_event_channel_op(EVTCHNOP_send, &send);
}

static void clear_event_channel(evtchn_port_t port)
{
	shared_info_t *s = HYPERVISOR_shared_info;

	sys_bitfield_clear_bit((mem_addr_t) s->evtchn_pending, port);
}

int unmask_event_channel(evtchn_port_t port)
{
	shared_info_t *s = HYPERVISOR_shared_info;

	__ASSERT(port < EVTCHN_2L_NR_CHANNELS,
		"%s: trying to unmask invalid evtchn #%u\n",
		__func__, port);

	sys_bitfield_clear_bit((mem_addr_t) s->evtchn_mask, port);

	return 0;
}

int bind_event_channel(evtchn_port_t port, evtchn_cb_t cb, void *data)
{
	__ASSERT(port < EVTCHN_2L_NR_CHANNELS,
		"%s: trying to bind invalid evtchn #%u\n",
		__func__, port);
	__ASSERT(cb != NULL, "%s: NULL callback for evtchn #%u\n",
		__func__, port);


	if (event_channels[port].cb != empty_callback)
		LOG_WRN("%s: re-bind callback for evtchn #%u\n",
				__func__, port);

	event_channels[port].priv = data;
	event_channels[port].cb = cb;
//	unmask_event_channel(port);
//	clear_event_channel(port);

	return 0;
}

int unbind_event_channel(evtchn_port_t port)
{
	__ASSERT(port < EVTCHN_2L_NR_CHANNELS,
		"%s: trying to unbind invalid evtchn #%u\n",
		__func__, port);

	event_channels[port].cb = empty_callback;
	event_channels[port].priv = NULL;

	return 0;
}

int mask_event_channel(evtchn_port_t port)
{
	shared_info_t *s = HYPERVISOR_shared_info;

	__ASSERT(port < EVTCHN_2L_NR_CHANNELS,
		"%s: trying to mask invalid evtchn #%u\n",
		__func__, port);

	sys_bitfield_set_bit((mem_addr_t) s->evtchn_mask, port);

	return 0;
}

int check_upcall_masked(int vcpu)
{
	shared_info_t *s = HYPERVISOR_shared_info;
	return s->vcpu_info[vcpu].pad0;
}

int check_upcall_pending(int vcpu)
{
	shared_info_t *s = HYPERVISOR_shared_info;
	return s->vcpu_info[vcpu].evtchn_upcall_pending;
}

int check_channel_mask(evtchn_port_t port)
{
	shared_info_t *s = HYPERVISOR_shared_info;

	__ASSERT(port < EVTCHN_2L_NR_CHANNELS,
		"%s: trying to unmask invalid evtchn #%u\n",
		__func__, port);

	return sys_bitfield_test_bit((mem_addr_t) s->evtchn_mask, port);
}

int check_channel_event(evtchn_port_t port)
{
	shared_info_t *s = HYPERVISOR_shared_info;

	__ASSERT(port < EVTCHN_2L_NR_CHANNELS,
		"%s: trying to mask invalid evtchn #%u\n",
		__func__, port);


        return sys_bitfield_test_bit((mem_addr_t) s->evtchn_pending, port);
}

static inline xen_ulong_t get_pending_events(xen_ulong_t pos)
{
	shared_info_t *s = HYPERVISOR_shared_info;

	return (s->evtchn_pending[pos] & ~(s->evtchn_mask[pos]));
}

static void process_event(evtchn_port_t port)
{
	evtchn_handle_t channel = event_channels[port];

	clear_event_channel(port);
	channel.cb(channel.priv);
}

static void events_isr(void *data)
{
	ARG_UNUSED(data);

	/* Needed for 2-level unwrapping */
	xen_ulong_t pos_selector;   /* bits are positions in pending array */
	xen_ulong_t events_pending; /* bits - events in pos_selector element */
	uint32_t pos_index, event_index; /* bit indexes */

	evtchn_port_t port; /* absolute event index */

	/* TODO: SMP? XEN_LEGACY_MAX_VCPUS == 1*/
	vcpu_info_t *vcpu = &HYPERVISOR_shared_info->vcpu_info[0];

	/*
	 * Need to set it to 0 /before/ checking for pending work, thus
	 * avoiding a set-and-check race (check struct vcpu_info_t)
	 */
	vcpu->evtchn_upcall_pending = 0;

	compiler_barrier();

	/* Can not use system atomic_t/atomic_set() due to 32-bit casting */
	pos_selector = __atomic_exchange_n(&vcpu->evtchn_pending_sel,
					0, __ATOMIC_SEQ_CST);

	while (pos_selector) {
		/* Find first position, clear it in selector and process */
		pos_index = __builtin_ffsl(pos_selector) - 1;
		pos_selector &= ~(1 << pos_index);

		/* Find all active evtchn on selected position */
		while ((events_pending = get_pending_events(pos_index)) != 0) {
			event_index =  __builtin_ffsl(events_pending) - 1;
			events_pending &= (1 << event_index);

			port = (pos_index * 8 * sizeof(xen_ulong_t))
					+ event_index;
			process_event(port);
		}
	}
}

int xen_events_init(void)
{
	int i;

	if (!HYPERVISOR_shared_info) {
		/* shared info was not mapped */
		LOG_ERR("%s: shared_info - NULL, can't setup events\n", __func__);
		return -EINVAL;
	}

	/* bind all ports with default callback */
	for (i = 0; i < EVTCHN_2L_NR_CHANNELS; i++) {
		event_channels[i].cb = empty_callback;
		event_channels[i].priv = NULL;
	}

	IRQ_CONNECT(DT_IRQ_BY_IDX(DT_INST(0, xen_xen), 0, irq),
		DT_IRQ_BY_IDX(DT_INST(0, xen_xen), 0, priority), events_isr,
		NULL, DT_IRQ_BY_IDX(DT_INST(0, xen_xen), 0, flags));

	irq_enable(DT_IRQ_BY_IDX(DT_INST(0, xen_xen), 0, irq));

	LOG_INF("%s: events inited\n", __func__);
	xenbus_printk("%s: events inited\n", __func__);
	return 0;
}

int evtchn_status(evtchn_status_t *status)
{
	return HYPERVISOR_event_channel_op(EVTCHNOP_status, status);
}
