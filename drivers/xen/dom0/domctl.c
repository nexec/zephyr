/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <arch/arm64/hypercall.h>
#include <xen/dom0/domctl.h>
#include <xen/generic.h>
#include <xen/public/domctl.h>
#include <xen/public/sysctl.h>
#include <xen/public/xen.h>
#include <cache.h>

#include <init.h>
#include <kernel.h>
#include <string.h>

int xen_domctl_scheduler_op(int domid, struct xen_domctl_scheduler_op *sched_op)
{
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.cmd = XEN_DOMCTL_scheduler_op;
	domctl.domain = domid;
	domctl.u.scheduler_op = *sched_op;

	return do_domctl(&domctl);
}

int xen_domctl_unpausedomain(int domid)
{
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.cmd = XEN_DOMCTL_unpausedomain;
	domctl.domain = domid;

	return do_domctl(&domctl);
}

int xen_domctl_resumedomain(int domid)
{
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.cmd = XEN_DOMCTL_resumedomain;
	domctl.domain = domid;

	return do_domctl(&domctl);
}

int xen_domctl_getvcpucontext(int domid, int vcpu, vcpu_guest_context_t *ctxt)
{
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.cmd = XEN_DOMCTL_getvcpucontext;
	domctl.domain = domid;
	domctl.u.vcpucontext.vcpu = 0;
	set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);

	return do_domctl(&domctl);
}

int xen_domctl_setvcpucontext(int domid, int vcpu, vcpu_guest_context_t *ctxt)
{
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.cmd = XEN_DOMCTL_setvcpucontext;
	domctl.domain = domid;
	domctl.u.vcpucontext.vcpu = 0;
	set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);

	return do_domctl(&domctl);
}

int xen_domctl_getdomaininfo(int domid, xen_domctl_getdomaininfo_t *dom_info)
{
	int rc;
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.cmd = XEN_DOMCTL_getdomaininfo;
	domctl.domain = domid;

	rc = do_domctl(&domctl);
	if (rc) {
		return rc;
	}

	memcpy(dom_info, &domctl.u.getdomaininfo, sizeof(*dom_info));

	return 0;
}

int xen_domctl_max_mem(int domid, uint64_t max_memkb)
{
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.cmd = XEN_DOMCTL_max_mem;
	domctl.domain = domid;
	domctl.u.max_mem.max_memkb = max_memkb;

	return do_domctl(&domctl);
}

int xen_domctl_set_address_size(int domid, int addr_size)
{
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.domain = domid;
	domctl.cmd = XEN_DOMCTL_set_address_size;
	domctl.u.address_size.size = addr_size;

	return do_domctl(&domctl);
}

int xen_domctl_max_vcpus(int domid, int max_vcpus)
{
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.cmd = XEN_DOMCTL_max_vcpus;
	domctl.domain = domid;
	domctl.u.max_vcpus.max = max_vcpus;

	return do_domctl(&domctl);
}

int xen_domctl_createdomain(int domid, struct xen_domctl_createdomain *config)
{
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.cmd = XEN_DOMCTL_createdomain;
	domctl.domain = domid;
	domctl.u.createdomain = *config;

	return do_domctl(&domctl);
}

int xen_domctl_destroydomain(int domid)
{
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.cmd = XEN_DOMCTL_destroydomain;
	domctl.domain = domid;

	return do_domctl(&domctl);
}

int xen_domctl_cacheflush(int domid,  struct xen_domctl_cacheflush *cacheflush)
{
	xen_domctl_t domctl;

	memset(&domctl, 0, sizeof(domctl));
	domctl.cmd = XEN_DOMCTL_cacheflush;
	domctl.domain = domid;
	domctl.u.cacheflush = *cacheflush;

	return do_domctl(&domctl);
}

int do_domctl(xen_domctl_t *domctl)
{
	domctl->interface_version = XEN_DOMCTL_INTERFACE_VERSION;
	return HYPERVISOR_domctl(domctl);
}
