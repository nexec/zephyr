/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __XEN_GNTTAB_H__
#define __XEN_GNTTAB_H__

#include <xen/public/grant_table.h>

grant_ref_t gnttab_alloc_and_grant(void **map);
grant_ref_t gnttab_grant_access(domid_t domid, unsigned long frame,
				int readonly);
grant_ref_t gnttab_grant_transfer(domid_t domid, unsigned long pfn);
int gnttab_end_access(grant_ref_t ref);
const char *gnttabop_error(int16_t status);

#endif /* __XEN_GNTTAB_H__ */
