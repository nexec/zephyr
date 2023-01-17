/* SPDX-License-Identifier: MIT */
/*
 ****************************************************************************
 * (C) 2006 - Cambridge University
 * (C) 2021 - EPAM Systems
 ****************************************************************************
 *
 *        File: gnttab.c
 *      Author: Steven Smith (sos22@cam.ac.uk)
 *     Changes: Grzegorz Milos (gm281@cam.ac.uk)
 *
 *        Date: July 2006
 *
 * Environment: Xen Minimal OS
 * Description: Simple grant tables implementation. About as stupid as it's
 *  possible to be and still work.
 *
 ****************************************************************************
 */
#include <arch/arm64/hypercall.h>
#include <xen/generic.h>
#include <xen/gnttab.h>
#include <xen/public/grant_table.h>
#include <xen/public/memory.h>
#include <xen/public/xen.h>

#include <init.h>
#include <kernel.h>
#include <logging/log.h>

LOG_MODULE_REGISTER(xen_gnttab);

/* NR_GRANT_FRAMES must be less than or equal to that configured in Xen */
#define NR_GRANT_FRAMES			1
#define NR_GRANT_ENTRIES \
	(NR_GRANT_FRAMES * XEN_PAGE_SIZE / sizeof(grant_entry_v1_t))

static struct gnttab {
	struct k_sem sem;
	grant_entry_v1_t *table;
	grant_ref_t gref_list[NR_GRANT_ENTRIES];
} gnttab;


static grant_ref_t get_free_entry(void)
{
	grant_ref_t gref;
	unsigned int flags;

	k_sem_take(&gnttab.sem, K_FOREVER);

	flags = irq_lock();
	gref = gnttab.gref_list[0];
	__ASSERT((gref >= GNTTAB_NR_RESERVED_ENTRIES &&
		gref < NR_GRANT_ENTRIES), "Invalid gref = %d", gref);
	gnttab.gref_list[0] = gnttab.gref_list[gref];
	irq_unlock(flags);

	return gref;
}

static void put_free_entry(grant_ref_t gref)
{
	unsigned int flags;

	flags = irq_lock();
	gnttab.gref_list[gref] = gnttab.gref_list[0];
	gnttab.gref_list[0] = gref;
	irq_unlock(flags);

	k_sem_give(&gnttab.sem);
}

static void gnttab_grant_init(grant_ref_t gref, domid_t domid,
		unsigned long mfn)
{
	gnttab.table[gref].frame = mfn;
	gnttab.table[gref].domid = domid;

	compiler_barrier();
}

static void gnttab_grant_permit_access(grant_ref_t gref, domid_t domid,
		unsigned long mfn, int readonly)
{
	gnttab_grant_init(gref, domid, mfn);
	readonly *= GTF_readonly;
	gnttab.table[gref].flags = GTF_permit_access | readonly;
}

grant_ref_t gnttab_grant_access(domid_t domid, unsigned long mfn,
		int readonly)
{
	grant_ref_t gref = get_free_entry();

	gnttab_grant_permit_access(gref, domid, mfn, readonly);

	return gref;
}

grant_ref_t gnttab_grant_transfer(domid_t domid, unsigned long mfn)
{
	grant_ref_t gref = get_free_entry();

	gnttab_grant_init(gref, domid, mfn);
	gnttab.table[gref].flags = GTF_accept_transfer;

	return gref;
}

/* Reset flags to zero in order to stop using the grant */
static int gnttab_reset_flags(grant_ref_t gref)
{
	uint16_t flags, nflags;
	uint16_t *pflags;

	pflags = &gnttab.table[gref].flags;
	nflags = *pflags;

	do {
		flags = nflags;
		if (flags & (GTF_reading | GTF_writing)) {
			LOG_WRN("gref = %u still in use! (0x%x)\n",
				gref, flags);
			return 0;
		}
		nflags = synch_cmpxchg(pflags, flags, 0);
	} while (nflags != flags);

	return 1;
}

int gnttab_update_grant(grant_ref_t gref,
		domid_t domid, unsigned long mfn,
		int readonly)
{
	int rc;

	__ASSERT((gref >= GNTTAB_NR_RESERVED_ENTRIES &&
		gref < NR_GRANT_ENTRIES), "Invalid gref = %d", gref);

	rc = gnttab_reset_flags(gref);
	if (!rc)
		return rc;

	gnttab_grant_permit_access(gref, domid, mfn, readonly);

	return 1;
}

int gnttab_end_access(grant_ref_t gref)
{
	int rc;

	__ASSERT((gref >= GNTTAB_NR_RESERVED_ENTRIES &&
		gref < NR_GRANT_ENTRIES), "Invalid gref = %d", gref);

	rc = gnttab_reset_flags(gref);
	if (!rc) {
		return rc;
	}

	put_free_entry(gref);

	return 1;
}

unsigned long gnttab_end_transfer(grant_ref_t gref)
{
	unsigned long frame;
	uint16_t flags;
	uint16_t *pflags;

	__ASSERT((gref >= GNTTAB_NR_RESERVED_ENTRIES &&
		gref < NR_GRANT_ENTRIES), "Invalid gref = %d", gref);

	pflags = &gnttab.table[gref].flags;
	flags = *pflags;
	while (!(flags & GTF_transfer_committed)) {
		if (synch_cmpxchg(pflags, flags, 0) == flags) {
			LOG_WRN("Release unused transfer grant.\n");
			put_free_entry(gref);
			return 0;
		}
		flags = *pflags;
	}

	/* If a transfer is in progress then wait until it is completed. */
	while (!(flags & GTF_transfer_completed)) {
		flags = *pflags;
	}

	/* Read the frame number /after/ reading completion status. */
	compiler_barrier();
	frame = gnttab.table[gref].frame;

	put_free_entry(gref);

	return frame;
}

grant_ref_t gnttab_alloc_and_grant(void **map)
{
	void *page;
	unsigned long mfn;
	grant_ref_t gref;

	__ASSERT_NO_MSG(map != NULL);

	page = k_aligned_alloc(XEN_PAGE_SIZE, XEN_PAGE_SIZE);
	if (page == NULL) {
		return -ENOMEM;
	}

	mfn = virt_to_mfn(page);
	gref = gnttab_grant_access(0, mfn, 0);

	*map = page;

	return gref;
}

static const char * const gnttab_error_msgs[] = GNTTABOP_error_msgs;

const char *gnttabop_error(int16_t status)
{
	status = -status;
	if (status < 0 || (uint16_t) status >= ARRAY_SIZE(gnttab_error_msgs)) {
		return "bad status";
	} else {
		return gnttab_error_msgs[status];
	}
}

/* TODO: remove test code */
/*-----------------------------------------------------*/
static uint8_t gnttab_buf[XEN_PAGE_SIZE]
			__attribute__((aligned(XEN_PAGE_SIZE)));

static void *test_page;

void gnttab_test(void)
{
	grant_ref_t alloc_ref, static_ref;
	uintptr_t buf_mfn = virt_to_mfn(gnttab_buf);

	static_ref = gnttab_grant_access(0, buf_mfn, 0);
	memset(gnttab_buf, 0xAC, 256);
	LOG_INF("%s: static page grant ref = %d\n", __func__, static_ref);


	alloc_ref = gnttab_alloc_and_grant(&test_page);
	memset(test_page, 0xAB, 256);
	LOG_INF("%s: alloc and grant page with ref = %d\n", __func__, alloc_ref);
}
/*-----------------------------------------------------*/

static int gnttab_init(const struct device *d)
{
	grant_ref_t gref;
	struct xen_add_to_physmap xatp;
	struct gnttab_setup_table setup;
	xen_pfn_t frames[NR_GRANT_FRAMES];
	int rc = 0, i;

	/* Will be taken/given during gnt_refs allocation/release */
	k_sem_init(&gnttab.sem, 0, NR_GRANT_ENTRIES - 1);

	for (
		gref = GNTTAB_NR_RESERVED_ENTRIES;
		gref < NR_GRANT_ENTRIES;
		gref++
	    ) {
		put_free_entry(gref);
	}

	gnttab.table = (grant_entry_v1_t *)
			DT_REG_ADDR_BY_IDX(DT_INST(0, xen_xen), 0);

	for (i = 0; i < NR_GRANT_FRAMES; i++) {
		xatp.domid = DOMID_SELF;
		xatp.size = 0;
		xatp.space = XENMAPSPACE_grant_table;
		xatp.idx = i;
		xatp.gpfn = PFN_DOWN((unsigned long)gnttab.table) + i;
		rc = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
		__ASSERT(!rc, "add_to_physmap failed; status = %d\n", rc);
	}

	setup.dom = DOMID_SELF;
	setup.nr_frames = NR_GRANT_FRAMES;
	set_xen_guest_handle(setup.frame_list, frames);
	rc = HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &setup, 1);
	__ASSERT(!(rc || setup.status), "Table setup failed; status = %s\n",
		gnttabop_error(setup.status));

	LOG_DBG("%s: grant table mapped\n", __func__);

	/* TODO: remove this */
	/* gnttab_test(); */

	return 0;
}

SYS_INIT(gnttab_init, POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEVICE);
