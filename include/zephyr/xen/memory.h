

/* TODO: fix headers including and add docs for functions */


int xendom_add_to_physmap(int domid, unsigned long idx,
		unsigned int space, xen_pfn_t gpfn);

int xendom_add_to_physmap_batch(int domid, int foreign_domid,
			unsigned int space, unsigned int size,
			xen_ulong_t *idxs, xen_pfn_t *gpfns,
			int *errs);

int xendom_remove_from_physmap(int domid, xen_pfn_t gpfn);

int xendom_populate_physmap(int domid, unsigned int extent_order,
		unsigned int nr_extents, unsigned int mem_flags,
		xen_pfn_t *extent_start);
