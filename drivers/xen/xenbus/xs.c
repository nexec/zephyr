/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* TODO: re-check all headers */

#include <xen/events.h>
#include <xen/public/xen.h>
#include <xen/xenbus/xs.h>
#include <xen/xenbus/xs_watch.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <kernel.h>
#include <init.h>
#include <errno.h>
#include <device.h>
#include <logging/log.h>


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
	if (err == 0) {
		value = rep.data;
	} else {
		printk("%s: xs_msg_reply returned err = %d!\n", __func__, err);
	}

	return value;
}

int xs_write(xenbus_transaction_t xbt, const char *path, const char *value)
{
	struct xs_iovec req[2];

	if (path == NULL || value == NULL)
		return -EINVAL;

	req[0] = INIT_XS_IOVEC_STR_NULL((char *) path);
	req[1] = INIT_XS_IOVEC_STR((char *) value);

	return xs_msg(XS_WRITE, xbt, req, ARRAY_SIZE(req));
}


/* TODO: fix error handling */
/* Returns an array of strings out of the serialized reply */
static char **reply_to_string_array(struct xs_iovec *rep, int *size)
{
	int strings_num, offs, i;
	char *rep_strings, *strings, **res = NULL;

	rep_strings = rep->data;

	/* count the strings */
	for (offs = strings_num = 0; offs < (int) rep->len; offs++) {
		strings_num += (rep_strings[offs] == 0);
	}

	/* one alloc for both string addresses and contents */
	res = k_malloc((strings_num + 1) * sizeof(char *) + rep->len);
	if (!res) {
		return NULL;
	}

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

	if (size) {
		*size = strings_num;
	}

	return res;
}

char **xs_ls(xenbus_transaction_t xbt, const char *path)
{
	struct xs_iovec req, rep;
	char **res = NULL;
	int err;

	if (path == NULL) {
		return NULL;
	}

	req = INIT_XS_IOVEC_STR_NULL((char *) path);
	err = xs_msg_reply(XS_DIRECTORY, xbt, &req, 1, &rep);
	if (err) {
		return NULL;
	}

	res = reply_to_string_array(&rep, NULL);
	k_free(rep.data);

	return res;
}

int xs_rm(xenbus_transaction_t xbt, const char *path)
{
	struct xs_iovec req;

	if (path == NULL) {
		return -EINVAL;
	}

	req = INIT_XS_IOVEC_STR_NULL((char *) path);

	return xs_msg(XS_RM, xbt, &req, 1);
}

/*
 * Permissions
 */

static const char xs_perm_tbl[] = {
	[XS_PERM_NONE]    = 'n',
	[XS_PERM_READ]    = 'r',
	[XS_PERM_WRITE]   = 'w',
	[XS_PERM_BOTH]    = 'b',
};

int xs_char_to_perm(char c, enum xs_perm *perm)
{
	int err = -EINVAL;

	if (perm == NULL) {
		return err;
	}

	for (int i = 0; i < (int) ARRAY_SIZE(xs_perm_tbl); i++) {
		if (c == xs_perm_tbl[i]) {
			*perm = i;
			err = 0;
			break;
		}
	}

	return err;
}

int xs_perm_to_char(enum xs_perm perm, char *c)
{
	if (c == NULL || perm >= ARRAY_SIZE(xs_perm_tbl)) {
		return -EINVAL;
	}

	*c = xs_perm_tbl[perm];

	return 0;
}

int xs_str_to_perm(const char *str, domid_t *domid, enum xs_perm *perm)
{
	int err = 0;

	if (str == NULL || domid == NULL || perm == NULL) {
		err = -EINVAL;
		goto out;
	}

	err = xs_char_to_perm(str[0], perm);
	if (err) {
		goto out;
	}

	*domid = (domid_t) strtoul(&str[1], NULL, 10);

out:
	return err;
}

#define PERM_MAX_SIZE 32
char *xs_perm_to_str(domid_t domid, enum xs_perm perm)
{
	int err = 0;
	char permc, *value;

	value = k_malloc(PERM_MAX_SIZE);
	if (!value) {
		return NULL;
	}

	err = xs_perm_to_char(perm, &permc);
	if (err) {
		return NULL;
	}

	snprintf(value, PERM_MAX_SIZE, "%c%hu", permc, domid);

	return value;
}

/*
 * Returns the ACL for input path. An extra number of empty entries may be
 * requested if caller intends to extend the list.
 */
static struct xs_acl *__xs_get_acl(xenbus_transaction_t xbt, const char *path,
	int extra)
{
	struct xs_acl *acl = NULL;
	struct xs_iovec req, rep;
	char **values;
	int values_num, err;

	if (path == NULL) {
		return NULL;
	}

	req = INIT_XS_IOVEC_STR_NULL((char *) path);
	err = xs_msg_reply(XS_GET_PERMS, xbt, &req, 1, &rep);
	if (err) {
		return NULL;
	}

	values = reply_to_string_array(&rep, &values_num);
	k_free(rep.data);
	if (!values) {
		return NULL;
	}

	acl = k_malloc(sizeof(struct xs_acl) +
		(values_num + extra) * sizeof(struct xs_acl_entry));
	if (acl == NULL) {
		err = ENOMEM;
		goto out_values;
	}

	/* set owner id and permissions for others */
	err = xs_str_to_perm(values[0],
		&acl->ownerid, &acl->others_perm);
	if (err)
		goto out_values;

	/* set ACL entries */
	acl->entries_num = values_num - 1;
	for (int i = 0; i < acl->entries_num; i++) {
		err = xs_str_to_perm(values[i + 1],
			&acl->entries[i].domid, &acl->entries[i].perm);
		if (err)
			goto out_values;
	}

out_values:
	k_free(values);

	if (err) {
		if (acl)
			k_free(acl);
	}
	return NULL;
}

struct xs_acl *xs_get_acl(xenbus_transaction_t xbt, const char *path)
{
	return __xs_get_acl(xbt, path, 0);
}

int xs_set_acl(xenbus_transaction_t xbt, const char *path, struct xs_acl *acl)
{
	struct xs_iovec req[2 + acl->entries_num];
	char *s;
	int i, err;

	if (path == NULL || acl == NULL) {
		return -EINVAL;
	}

	req[0] = INIT_XS_IOVEC_STR_NULL((char *) path);

	s = xs_perm_to_str(acl->ownerid, acl->others_perm);
	if (s == NULL) {
		return -EINVAL;
	}

	req[1] = INIT_XS_IOVEC_STR_NULL(s);

	for (i = 0; i < acl->entries_num; i++) {
		struct xs_acl_entry *acle = &acl->entries[i];

		s = xs_perm_to_str(acle->domid, acle->perm);
		if (s == NULL) {
			err = -EINVAL;
			goto out_req;
		}

		req[i + 2] = INIT_XS_IOVEC_STR_NULL(s);
	}

	err = xs_msg(XS_SET_PERMS, xbt, req, ARRAY_SIZE(req));

out_req:
	for (i--; i > 0; i--) {
		k_free(req[i].data);
	}

	return err;
}

int xs_get_perm(xenbus_transaction_t xbt, const char *path,
	domid_t domid, enum xs_perm *perm)
{
	struct xs_acl *acl;
	int err = 0;

	if (perm == NULL) {
		return -EINVAL;
	}

	acl = xs_get_acl(xbt, path);
	if (!acl) {
		return -EINVAL;
	}

	if (acl->ownerid == domid) {
		*perm = XS_PERM_BOTH;
		goto out_acl;
	}

	for (int i = 0; i < acl->entries_num; i++) {
		struct xs_acl_entry *acle = &acl->entries[i];

		if (acle->domid == domid) {
			*perm = acle->perm;
			goto out_acl;
		}
	}

	*perm = acl->others_perm;

out_acl:
	k_free(acl);

	return err;
}

static int acl_find_entry_index(struct xs_acl *acl, domid_t domid)
{
	struct xs_acl_entry *acle;
	int i;

	if (acl->ownerid == domid) {
		/*
		 * let's say the function isn't called correctly considering
		 * that the owner domain has all the rights, all the time
		 */
		return -EINVAL;
	}

	for (i = 0; i < acl->entries_num; i++) {
		acle = &acl->entries[i];
		if (acle->domid == domid)
			break;
	}

	if (i == acl->entries_num) {
		/* no entry found for domid */
		return -ENOENT;
	}

	return i;
}

int xs_set_perm(xenbus_transaction_t xbt, const char *path,
	domid_t domid, enum xs_perm perm)
{
	struct xs_acl *acl;
	struct xs_acl_entry *acle;
	int err, idx;

	__ASSERT_NO_MSG(xbt != XBT_NIL);

	/* one extra entry in case a new one will be added */
	acl = __xs_get_acl(xbt, path, 1);
	if (!acl) {
		return -EINVAL;
	}

	idx = acl_find_entry_index(acl, domid);
	if (idx == -ENOENT) {
		/* new entry */
		acle = &acl->entries[acl->entries_num];
		acle->domid = domid;
		acle->perm = perm;
		acl->entries_num++;

	} else if (idx < 0) {
		/* some other error */
		err = idx;
		goto out_acl;

	} else {
		/* update entry */
		acle = &acl->entries[idx];
		acle->perm = perm;
	}

	err = xs_set_acl(xbt, path, acl);

out_acl:
	k_free(acl);

	return err;
}

int xs_del_perm(xenbus_transaction_t xbt, const char *path,
	domid_t domid)
{
	struct xs_acl *acl;
	int idx, err = 0;

	__ASSERT_NO_MSG(xbt != XBT_NIL);

	acl = __xs_get_acl(xbt, path, 0);
	if (!acl) {
		return -EINVAL;
	}

	idx = acl_find_entry_index(acl, domid);
	if (idx < 0) {
		return idx;
	}

	/* remove entry */
	acl->entries_num--;
	memmove(&acl->entries[idx], &acl->entries[idx + 1],
		(acl->entries_num - idx) * sizeof(struct xs_acl_entry));

	err = xs_set_acl(xbt, path, acl);

	k_free(acl);

	return err;
}

/*
 * Watches
 */

struct xenbus_watch *xs_watch_path(xenbus_transaction_t xbt, const char *path)
{
	struct xs_watch *xsw;
	struct xs_iovec req[2];
	int err;

	if (path == NULL)
		return NULL;

	xsw = xs_watch_create(path);
	if (!xsw)
		return NULL;

	req[0] = INIT_XS_IOVEC_STR_NULL(xsw->xs.path);
	req[1] = INIT_XS_IOVEC_STR_NULL(xsw->xs.token);

	err = xs_msg(XS_WATCH, xbt, req, ARRAY_SIZE(req));
	if (err) {
		xs_watch_destroy(xsw);
		return NULL;
	}

	return &xsw->base;
}

int xs_unwatch(xenbus_transaction_t xbt, struct xenbus_watch *watch)
{
	struct xs_watch *xsw, *_xsw;
	struct xs_iovec req[2];
	int err;

	if (watch == NULL) {
		err = -EINVAL;
		return err;
	}

	xsw = CONTAINER_OF(watch, struct xs_watch, base);

	_xsw = xs_watch_find(xsw->xs.path, xsw->xs.token);
	if (_xsw != xsw) {
		/* this watch was not registered */
		err = -ENOENT;
		return err;
	}

	req[0] = INIT_XS_IOVEC_STR_NULL(xsw->xs.path);
	req[1] = INIT_XS_IOVEC_STR_NULL(xsw->xs.token);

	err = xs_msg(XS_UNWATCH, xbt, req, ARRAY_SIZE(req));
	if (err)
		return err;

	err = xs_watch_destroy(xsw);

	return err;
}

/*
 * Transactions
 */

int xs_transaction_start(xenbus_transaction_t *xbt)
{
	/*
	 * xenstored becomes angry if you send a length 0 message,
	 * so just shove a nul terminator on the end
	 */
	struct xs_iovec req, rep;
	int err;

	if (xbt == NULL)
		return -EINVAL;

	req = INIT_XS_IOVEC_STR_NULL("");
	err = xs_msg_reply(XS_TRANSACTION_START, 0, &req, 1, &rep);
	if (err)
		return err;

	*xbt = strtoul(rep.data, NULL, 10);
	k_free(rep.data);

	return err;
}

int xs_transaction_end(xenbus_transaction_t xbt, int abort)
{
	struct xs_iovec req;

	req.data = abort ? "F" : "T";
	req.len = 2;

	return xs_msg(XS_TRANSACTION_END, xbt, &req, 1);
}

/*
 * Misc
 */

/* Send a debug message to xenbus. Can block. */
int xs_debug_msg(const char *msg)
{
	struct xs_iovec req[3], rep;
	int err;

	if (msg == NULL)
		return -EINVAL;

	req[0] = INIT_XS_IOVEC_STR_NULL("print");
	req[1] = INIT_XS_IOVEC_STR((char *) msg);
	req[2] = INIT_XS_IOVEC_STR_NULL("");

	err = xs_msg_reply(XS_DEBUG, XBT_NIL, req, ARRAY_SIZE(req), &rep);
	if (err)
		return err;

	LOG_DBG("Got a debug reply %s\n", (char *) rep.data);
	k_free(rep.data);

	return err;
}

int xs_read_integer(xenbus_transaction_t xbt, const char *path, int *value)
{
	char *value_str;

	if (path == NULL || value == NULL)
		return -EINVAL;

	value_str = xs_read(xbt, path);
	if (!value_str)
		return -EINVAL;

	*value = atoi(value_str);

	k_free(value_str);

	return 0;
}

int xs_printf(xenbus_transaction_t xbt, const char *dir, const char *node,
	const char *fmt, ...)
{
#define VAL_SIZE 256
	char val[VAL_SIZE];
	char *path;
	va_list args;
	int err = 0, _err, path_len = 0;

	if (fmt == NULL)
		return -EINVAL;

	path_len = strlen(dir) + strlen(node) + 1;
	path = k_malloc(path_len);
	if (!path) {
		return -ENOMEM;
	}
	snprintf(path, path_len, "%s/%s", dir, node);

	va_start(args, fmt);
	_err = vsnprintf(val, VAL_SIZE, fmt, args);
	va_end(args);

	/* send to Xenstore if vsnprintf was successful */
	if (_err > 0)
		err = xs_write(xbt, path, val);

	k_free(path);

	/*
	 * if message sent to Xenstore was successful,
	 * return the number of characters
	 */
	if (err == 0)
		err = _err;

	return err;
}

domid_t xs_get_self_id(void)
{
	char *domid_str;
	domid_t domid;

	domid_str = xs_read(XBT_NIL, "domid");
	if (!domid_str)
		LOG_ERR("Error reading domain id.");

	domid = (domid_t) strtoul(domid_str, NULL, 10);

	k_free(domid_str);

	return domid;
}
