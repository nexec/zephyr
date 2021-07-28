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

/* Common function used for sending requests when replies aren't handled */
static inline int xs_msg(enum xsd_sockmsg_type type, xenbus_transaction_t xbt,
		struct xs_iovec *reqs, int reqs_num)
{
	return xs_msg_reply(type, xbt, reqs, reqs_num, NULL);
}

/* TODO: fix error handling */
char *xs_read(xenbus_transaction_t xbt, const char *path)
{
	struct xs_iovec req, rep;
	char *value = NULL;
	int err;

	if (path == NULL)
		return NULL;

	req = INIT_XS_IOVEC_STR_NULL((char *) path);
	err = xs_msg_reply(XS_READ, xbt, &req, 1, &rep);
	if (err == 0)
		value = rep.data;
	else
		printk("%s: err = %d!\n", __func__, err);

	return value;
}

int xs_write(xenbus_transaction_t xbt, const char *path, const char *value)
{
	struct xs_iovec req[2];
	int err;

	if (path == NULL || value == NULL)
		return -EINVAL;

	req[0] = INIT_XS_IOVEC_STR_NULL((char *) path);
	req[1] = INIT_XS_IOVEC_STR((char *) value);

	err = xs_msg(XS_WRITE, xbt, req, ARRAY_SIZE(req));

	return err;
}


/* TODO: fix error handling */
/* Returns an array of strings out of the serialized reply */
static char **reply_to_string_array(struct xs_iovec *rep, int *size)
{
	int strings_num, offs, i;
	char *rep_strings, *strings, **res = NULL;

	rep_strings = rep->data;

	/* count the strings */
	for (offs = strings_num = 0; offs < (int) rep->len; offs++)
		strings_num += (rep_strings[offs] == 0);

	/* one alloc for both string addresses and contents */
	res = k_malloc((strings_num + 1) * sizeof(char *) + rep->len);
//	if (!res)
//		return ERR2PTR(-ENOMEM);

	/* copy the strings to the end of the array */
	strings = (char *) &res[strings_num + 1];
	memcpy(strings, rep_strings, rep->len);

	/* fill the string array */
	for (offs = i = 0; i < strings_num; i++) {
		char *string = strings + offs;
		int string_len = strlen(string);

		res[i] = string;

		offs += string_len + 1;
	}
	res[i] = NULL;

	if (size)
		*size = strings_num;

	return res;
}

char **xs_ls(xenbus_transaction_t xbt, const char *path)
{
	struct xs_iovec req, rep;
	char **res = NULL;
	int err;

	if (path == NULL)
		return NULL;

	req = INIT_XS_IOVEC_STR_NULL((char *) path);
	err = xs_msg_reply(XS_DIRECTORY, xbt, &req, 1, &rep);
	if (err)
		return NULL;

	res = reply_to_string_array(&rep, NULL);
	k_free(rep.data);

	return res;
}


