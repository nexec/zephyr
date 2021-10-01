/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __XEN_GENERIC_H__
#define __XEN_GENERIC_H__

#include <zephyr/xen/public/xen.h>

#define XEN_PAGE_SIZE		4096
#define XEN_PAGE_SHIFT		12

#define PFN_UP(x)              (unsigned long)(((x) + XEN_PAGE_SIZE-1) >> XEN_PAGE_SHIFT)
#define PFN_DOWN(x)            (unsigned long)((x) >> XEN_PAGE_SHIFT)
#define PFN_PHYS(x)            ((unsigned long)(x) << XEN_PAGE_SHIFT)
#define PHYS_PFN(x)            (unsigned long)((x) >> XEN_PAGE_SHIFT)

#define to_phys(x)             ((unsigned long)(x))
#define to_virt(x)             ((void *)(x))

#define virt_to_pfn(_virt)     (PFN_DOWN(to_phys(_virt)))
#define virt_to_mfn(_virt)     (PFN_DOWN(to_phys(_virt)))
#define mfn_to_virt(_mfn)      (to_virt(PFN_PHYS(_mfn)))
#define pfn_to_virt(_pfn)      (to_virt(PFN_PHYS(_pfn)))

/*
 * If *ptr == old, then store new there (and return new).
 * Otherwise, return the old value. Atomic.
 */
#define synch_cmpxchg(ptr, old, new) \
({ __typeof__(*ptr) stored = old; \
       __atomic_compare_exchange_n(ptr, &stored, new, 0, __ATOMIC_SEQ_CST, \
                               __ATOMIC_SEQ_CST) ? new : old; \
})

#endif /* __XEN_GENERIC_H__ */
