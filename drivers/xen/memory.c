#include <arch/arm64/hypercall.h>
#include <zephyr/xen/generic.h>
#include <zephyr/xen/public/memory.h>
#include <zephyr/xen/public/xen.h>

#include <init.h>
#include <kernel.h>
#include <string.h>


int xendom_add_to_physmap(int domid, unsigned long idx,
		unsigned int space, xen_pfn_t gpfn)
{
	struct xen_add_to_physmap xatp;

	memset(&xatp, 0, sizeof(xatp));
	xatp.domid = domid;
	xatp.idx = idx;
	xatp.space = space;
	xatp.gpfn = gpfn;

	return HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
}

int xendom_add_to_physmap_batch(int domid, int foreign_domid,
			unsigned int space, unsigned int size,
			xen_ulong_t *idxs, xen_pfn_t *gpfns,
			int *errs)
{
	struct xen_add_to_physmap_batch xatpb;

	memset(&xatpb, 0, sizeof(xatpb));
	set_xen_guest_handle(xatpb.gpfns, gpfns);
	set_xen_guest_handle(xatpb.idxs, idxs);
	set_xen_guest_handle(xatpb.errs, errs);
	xatpb.domid = domid;
	xatpb.u.foreign_domid = foreign_domid;
	xatpb.space = space;
	xatpb.size = size;

	return HYPERVISOR_memory_op(XENMEM_add_to_physmap_batch, &xatpb);
}

int xendom_remove_from_physmap(int domid, xen_pfn_t gpfn)
{
	struct xen_remove_from_physmap xrfp;

	xrfp.domid = domid;
	xrfp.gpfn = gpfn;
	return HYPERVISOR_memory_op(XENMEM_remove_from_physmap, &xrfp);
}

int xendom_populate_physmap(int domid, unsigned int extent_order,
		unsigned int nr_extents, unsigned int mem_flags,
		xen_pfn_t *extent_start)
{
	struct xen_memory_reservation reservation;

	memset(&reservation, 0, sizeof(reservation));
	reservation.domid = domid;
	reservation.extent_order = extent_order;
	reservation.nr_extents = nr_extents;
	reservation.mem_flags = mem_flags;
	set_xen_guest_handle(reservation.extent_start, extent_start);

	return HYPERVISOR_memory_op(XENMEM_populate_physmap, &reservation);
}
