/* SPDX-License-Identifier: MIT */
/*
 ****************************************************************************
 * (C) 2006 - Cambridge University
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
#include <init.h>
#include <kernel.h>
#include <xen/generic.h>
#include <xen/gnttab.h>
#include <xen/public/grant_table.h>
#include <xen/public/memory.h>
#include <xen/public/xen.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef DBGGNT
#include <string.h>
#endif

/* NR_GRANT_FRAMES must be less than or equal to that configured in Xen */
#define NR_GRANT_FRAMES			1
#define NR_GRANT_ENTRIES \
	(NR_GRANT_FRAMES * XEN_PAGE_SIZE / sizeof(grant_entry_v1_t))

static struct gnttab {
	int initialized;
	struct k_sem sem;
	grant_entry_v1_t *table;
	grant_ref_t gref_list[NR_GRANT_ENTRIES];
#ifdef DBGGNT
	char inuse[NR_GRANT_ENTRIES];
#endif
} gnttab;


static grant_ref_t get_free_entry(void)
{
	grant_ref_t gref;
	unsigned int flags;

	/* TODO: should wait only when no free entries left */
//	k_sem_take(&gnttab.sem, K_FOREVER);

	flags = irq_lock();
	gref = gnttab.gref_list[0];
	__ASSERT_NO_MSG(gref >= GNTTAB_NR_RESERVED_ENTRIES &&
		gref < NR_GRANT_ENTRIES);
	gnttab.gref_list[0] = gnttab.gref_list[gref];
#ifdef DBGGNT
	__ASSERT_NO_MSG(!gnttab.inuse[gref]);
	gnttab.inuse[gref] = 1;
#endif
	irq_unlock(flags);

	return gref;
}

static void put_free_entry(grant_ref_t gref)
{
	unsigned int flags;

	flags = irq_lock();
#ifdef DBGGNT
	__ASSERT_NO_MSG(gnttab.inuse[gref]);
	gnttab.inuse[gref] = 0;
#endif
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

	/* Memory barrier */
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
		if ((flags = nflags) & (GTF_reading | GTF_writing)) {
			printk("gref=%u still in use! (0x%x)\n",
				   gref, flags);
			return 0;
		}
	/* TODO: Fix this, logic changed*/
	} while (!atomic_cas((atomic_t *) pflags, flags, 0));

	return 1;
}

int gnttab_update_grant(grant_ref_t gref,
		domid_t domid, unsigned long mfn,
		int readonly)
{
	int rc;

	__ASSERT_NO_MSG(gref >= GNTTAB_NR_RESERVED_ENTRIES &&
		gref < NR_GRANT_ENTRIES);

	rc = gnttab_reset_flags(gref);
	if (!rc)
		return rc;

	gnttab_grant_permit_access(gref, domid, mfn, readonly);

	return 1;
}

int gnttab_end_access(grant_ref_t gref)
{
	int rc;

	__ASSERT_NO_MSG(gref >= GNTTAB_NR_RESERVED_ENTRIES &&
		gref < NR_GRANT_ENTRIES);

	rc = gnttab_reset_flags(gref);
	if (!rc)
		return rc;

	put_free_entry(gref);

	return 1;
}

unsigned long gnttab_end_transfer(grant_ref_t gref)
{
	unsigned long frame;
	uint16_t flags;
	uint16_t *pflags;

	__ASSERT_NO_MSG(gref >= GNTTAB_NR_RESERVED_ENTRIES &&
		gref < NR_GRANT_ENTRIES);

	pflags = &gnttab.table[gref].flags;
	while (!((flags = *pflags) & GTF_transfer_committed)) {
		if (atomic_cas((atomic_t *) pflags, flags, 0)) {
			printk("Release unused transfer grant.\n");
			put_free_entry(gref);
			return 0;
		}
	}

	/* If a transfer is in progress then wait until it is completed. */
	while (!(flags & GTF_transfer_completed))
		flags = *pflags;

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
	if (page == NULL)
		return -ENOMEM;

	mfn = ((unsigned long) page >> XEN_PAGE_SHIFT);
	gref = gnttab_grant_access(0, mfn, 0);

	*map = page;

	return gref;
}

static const char * const gnttabop_error_msgs[] = GNTTABOP_error_msgs;

const char *gnttabop_error(int16_t status)
{
	status = -status;
	if (status < 0 || (uint16_t) status >= ARRAY_SIZE(gnttabop_error_msgs))
		return "bad status";
	else
		return gnttabop_error_msgs[status];
}

#define PFN_UP(x)		(unsigned long)(((x) + XEN_PAGE_SIZE-1) >> XEN_PAGE_SHIFT)
#define PFN_DOWN(x)		(unsigned long)((x) >> XEN_PAGE_SHIFT)
#define PFN_PHYS(x)		((unsigned long)(x) << XEN_PAGE_SHIFT)
#define PHYS_PFN(x)		(unsigned long)((x) >> XEN_PAGE_SHIFT)

static uint8_t gnttab_buf[XEN_PAGE_SIZE]
			__attribute__((aligned(XEN_PAGE_SIZE)));

static void *test_page;

void gnttab_test(void) {
	grant_ref_t alloc_ref, static_ref;
	uintptr_t buf_mfn = ((uintptr_t) gnttab_buf) >> XEN_PAGE_SHIFT;
	static_ref = gnttab_grant_access(0, buf_mfn, 0);
	memset(gnttab_buf, 0xAC, 256);
	printk("%s: static page grant ref = %d\n", __func__, static_ref);


	alloc_ref = gnttab_alloc_and_grant(&test_page);
	memset(test_page, 0xAB, 256);
	printk("%s: alloc and grant page with ref = %d\n", __func__, alloc_ref);
}

int gnttab_init(const struct device *d)
{
	grant_ref_t gref;
	struct xen_add_to_physmap xatp;
	struct gnttab_setup_table setup;
	xen_pfn_t frames[NR_GRANT_FRAMES];
	int rc = 0, i;

//	printk(">>>>>>>>>>>>>>>>>>>>>%s: in\n", __func__);
	__ASSERT_NO_MSG(!gnttab.initialized);

	k_sem_init(&gnttab.sem, 0, 1);

	for (gref = GNTTAB_NR_RESERVED_ENTRIES; gref < NR_GRANT_ENTRIES; gref++)
		put_free_entry(gref);

//	gnttab.table = (grant_entry_v1_t *) gnttab_buf;
	gnttab.table = (grant_entry_v1_t *) 0x38000000;

	for (i = 0; i < NR_GRANT_FRAMES; i++) {
		xatp.domid = DOMID_SELF;
		xatp.size = 0;
		xatp.space = XENMAPSPACE_grant_table;
		xatp.idx = i;
		xatp.gpfn = PFN_DOWN((unsigned long)gnttab.table) + i;
		rc = HYPERVISOR_memory_op(XENMEM_add_to_physmap, &xatp);
		if (rc)
			printk("XENMEM_add_to_physmap failed; status = %d\n",
			       rc);
//		BUG_ON(rc != 0);
	}

	setup.dom = DOMID_SELF;
	setup.nr_frames = NR_GRANT_FRAMES;
	set_xen_guest_handle(setup.frame_list, frames);
	rc = HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &setup, 1);
	if (rc || setup.status) {
		printk("GNTTABOP_setup_table failed; status = %s\n",
		       gnttabop_error(setup.status));
//		BUG();
	}

//	printk(">>>>>>>>>>>>>>>>>>>>>%s: out\n", __func__);
	gnttab.initialized = 1;

	gnttab_test();

	return 0;




//	grant_ref_t gref;
//
//	__ASSERT_NO_MSG(gnttab.initialized == 0);
//
//	k_sem_init(&gnttab.sem, 0, 1);
//
//#ifdef DBGGNT
//	memset(gnttab.inuse, 1, sizeof(gnttab.inuse));
//#endif
//	for (gref = GNTTAB_NR_RESERVED_ENTRIES; gref < NR_GRANT_ENTRIES; gref++)
//		put_free_entry(gref);
//
//	gnttab.table = gnttab_arch_init(NR_GRANT_FRAMES);
////	if (gnttab.table == NULL)
////		UK_CRASH("Failed to initialize grant table\n");
//
//	printk("Grant table mapped at %p.\n", gnttab.table);
//
//	gnttab.initialized = 1;
}

void gnttab_fini(void)
{
	struct gnttab_setup_table setup;
	int rc;

	setup.dom = DOMID_SELF;
	setup.nr_frames = 0;

	rc = HYPERVISOR_grant_table_op(GNTTABOP_setup_table, &setup, 1);
	if (rc) {
		printk("Hypercall error: %d\n", rc);
		return;
	}

	gnttab.initialized = 0;
}

SYS_INIT(gnttab_init, POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEVICE);
