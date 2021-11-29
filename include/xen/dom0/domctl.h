/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __XEN_DOM0_DOMCTL_H__
#define __XEN_DOM0_DOMCTL_H__

#include <xen/generic.h>
#include <xen/public/domctl.h>
#include <xen/public/xen.h>

#include <kernel.h>

int xen_domctl_scheduler_op(int domid, struct xen_domctl_scheduler_op *sched_op);
int xen_domctl_unpausedomain(int domid);
int xen_domctl_resumedomain(int domid);
int xen_domctl_getvcpucontext(int domid, int vcpu, vcpu_guest_context_t *ctxt);
int xen_domctl_setvcpucontext(int domid, int vcpu, vcpu_guest_context_t *ctxt);
int xen_domctl_getdomaininfo(int domid, xen_domctl_getdomaininfo_t *dom_info);
int xen_domctl_max_mem(int domid, uint64_t max_memkb);
int xen_domctl_set_address_size(int domid, int addr_size);
int xen_domctl_max_vcpus(int domid, int max_vcpus);
int xen_domctl_createdomain(int domid, struct xen_domctl_createdomain *config);
int xen_domctl_cacheflush(int domid,  struct xen_domctl_cacheflush *cacheflush);
int xen_domctl_destroydomain(int domid);
int do_domctl(xen_domctl_t *domctl);

#endif /* __XEN_DOM0_DOMCTL_H__ */
