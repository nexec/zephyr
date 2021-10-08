/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* TODO: re-check all headers */

#include <xen/events.h>
#include <xen/generic.h>
#include <xen/hvm.h>
#include <xen/public/hvm/params.h>
#include <xen/public/io/xs_wire.h>
#include <xen/public/xen.h>
#include <xen/xenbus/xs.h>
#include <xen/xenbus/xs_watch.h>

#include <string.h>
#include <stdio.h>
#include <kernel.h>
#include <init.h>
#include <errno.h>
#include <device.h>
#include <logging/log.h>
#include <kernel/thread.h>
#include <sys/slist.h>

LOG_MODULE_DECLARE(xenbus);

static sys_slist_t watch_list;

/* TODO: check what is going on here, substitute with safe functions if possible */
static int xs_watch_info_equal(const struct xs_watch_info *xswi,
	const char *path, const char *token)
{
	return (strcmp(xswi->path, path) == 0 &&
		strcmp(xswi->token, token) == 0);
}

struct xs_watch *xs_watch_create(const char *path)
{
	struct xs_watch *xsw;
	const int token_size = sizeof(xsw) * 2 + 1;
	char *tmpstr;
	int stringlen;

	__ASSERT_NO_MSG(path != NULL);

	stringlen = token_size + strlen(path) + 1;

	xsw = k_malloc(sizeof(*xsw) + stringlen);
	if (!xsw)
		return NULL;

	xsw->base.pending_events = 0;
	k_sem_init(&xsw->base.sem, 0, 1);

	/* TODO: check what is going on here, substitute with safe functions if possible */
	/* set path */
	tmpstr = (char *) (xsw + 1);
	strcpy(tmpstr, path);
	xsw->xs.path = tmpstr;

	/* set token (watch address as string) */
	tmpstr += strlen(path) + 1;
	sprintf(tmpstr, "%lx", (long) xsw);
	xsw->xs.token = tmpstr;

	sys_slist_prepend(&watch_list, &xsw->base.node);

	return xsw;
}

int xs_watch_destroy(struct xs_watch *watch)
{
	struct xenbus_watch *xbw;
	struct xenbus_watch *prev = NULL;
	struct xs_watch *xsw;
	int err = -ENOENT;

	__ASSERT_NO_MSG(watch != NULL);

	SYS_SLIST_FOR_EACH_CONTAINER(&watch_list, xbw, node) {
		xsw = CONTAINER_OF(xbw, struct xs_watch, base);

		if (xsw == watch) {
			sys_slist_remove(&watch_list,
					(prev ? &prev->node : NULL),
					&xbw->node);
			k_free(xsw);
			err = 0;
			break;
		}

		/*
		 * Needed to optimize removal process in single-linked list
		 * (to not use sys_slist_find_and_remove()). Can be NULL
		 * if xbw is a list head.
		 */
		prev = xbw;
	}

	return err;
}

struct xs_watch *xs_watch_find(const char *path, const char *token)
{
	struct xenbus_watch *xbw;
	struct xs_watch *xsw;

	SYS_SLIST_FOR_EACH_CONTAINER(&watch_list, xbw, node) {
		xsw = CONTAINER_OF(xbw, struct xs_watch, base);

		if (xs_watch_info_equal(&xsw->xs, path, token))
			return xsw;
	}

	return NULL;
}
