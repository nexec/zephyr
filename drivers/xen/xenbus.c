/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <xen/events.h>
#include <xen/generic.h>
#include <xen/hvm.h>
#include <xen/public/hvm/params.h>
#include <xen/public/io/xs_wire.h>
#include <xen/public/xen.h>
#include <xen/xs.h>
#include <xen/xs_watch.h>

#include <string.h>
#include <stdio.h>
#include <kernel.h>
#include <init.h>
#include <errno.h>
#include <device.h>
#include <logging/log.h>
#include <kernel/thread.h>
#include <sys/slist.h>

LOG_MODULE_REGISTER(xenstore);

K_KERNEL_STACK_DEFINE(xenstore_thrd_stack, 1024);
struct k_thread xenstore_thrd;
k_tid_t xenstore_tid;

K_KERNEL_STACK_DEFINE(read_thrd_stack, 1024);
struct k_thread read_thrd;
k_tid_t read_tid;

K_KERNEL_STACK_DEFINE(read_thrd2_stack, 1024);
struct k_thread read_thrd2;
k_tid_t read_tid2;

#define DEBUG_XENBUS

#ifdef DEBUG_XENBUS
#define xenbus_printk printk
#else
static void xenbus_printk(const char *fmt, ...) {};
#endif

static struct xs_handler xs_hdlr;

/* TODO:REMOVE IT! */
#define xsh xs_hdlr



static struct xs_request_pool xs_req_pool;

static sys_slist_t watch_list;


/* TODO: Fix memory allocation, test with ASSERT on! */

static void xs_bitmap_init(struct xs_request_pool *pool)
{
	int i;
	/* bitmap length in bits */
	int bm_len = XS_REQ_BM_SIZE * sizeof(*pool->entries_bm) * __CHAR_BIT__;

	for (i = 0; i < XS_REQ_BM_SIZE; i++) {
		/* fill request bitmap with "1" */
		pool->entries_bm[i] = ULONG_MAX;
	}

	/* Clear last bits in bitmap, that are outside of XS_REQ_POLL_SIZE */
	for (i = XS_REQ_POOL_SIZE + 1; i < bm_len; i++) {
		sys_bitfield_clear_bit((mem_addr_t) pool->entries_bm, i);
	}
}

static void xs_request_pool_init(struct xs_request_pool *pool)
{
	struct xs_request *xs_req;
	int i;

	pool->num_live = 0;
	k_sem_init(&pool->sem, 0, 1);
	sys_slist_init(&pool->queued);

	xs_bitmap_init(pool);

	for (i = 0; i < XS_REQ_POOL_SIZE; i++) {
		xs_req = &pool->entries[i];
		xs_req->hdr.req_id = i;
		k_sem_init(&xs_req->sem, 0, 1);
	}
}

/*
 * Searches first available entry in bitmap (first marked with 1).
 */
static int get_free_entry_idx(struct xs_request_pool *pool)
{
	int i, res;

	/* Bit at pos XS_REQ_POOL_SIZE is a border, it always stays "1". */
	for (i = 0; i < XS_REQ_BM_SIZE; i++) {
		if (pool->entries_bm[i]) {
			/* contain at least one fired bit ("1") */
			break;
		}
	}

	/*
	 * Now we have "i" which points to element in bitmap with
	 * free entry. Calculating offset of this element in bitmap.
	 */
	res = i * sizeof(*pool->entries_bm) * __CHAR_BIT__;

	/* Add exact fired bit position */
	res += __builtin_ctzl(pool->entries_bm[i]);

	xenbus_printk("%s: returning entry #%d, i = %d\n", __func__, res, i);
	return res;
}

/*
 * Allocate an identifier for a Xenstore request.
 * Blocks if none are available.
 */
static struct xs_request *xs_request_get(void)
{
	unsigned long entry_idx;
	k_spinlock_key_t key;

	xenbus_printk("%s: in\n", __func__);
	/* wait for an available entry */
	while (1) {
		key = k_spin_lock(&xs_req_pool.lock);

		if (xs_req_pool.num_live < XS_REQ_POOL_SIZE)
			break;

		k_spin_unlock(&xs_req_pool.lock, key);

		/* Wait for events in request pool */
		k_sem_take(&xs_req_pool.sem, K_FOREVER);
	}

	entry_idx = get_free_entry_idx(&xs_req_pool);

	/*
	 * Getting of free entry is called after num_live is less than pool
	 * size (spinlock is still held), so we do not expect to reach the
	 * bitmap border. If so, something went totally wrong.
	 */
	__ASSERT(entry_idx != XS_REQ_POOL_SIZE,
		"Received border entry index for xs_req_pool!\n");

	sys_bitfield_clear_bit((mem_addr_t) xs_req_pool.entries_bm, entry_idx);
	xs_req_pool.num_live++;

	k_spin_unlock(&xs_req_pool.lock, key);

	return &xs_req_pool.entries[entry_idx];
}

/* Release a request identifier */
static void xs_request_put(struct xs_request *xs_req)
{
	uint32_t reqid = xs_req->hdr.req_id;
	k_spinlock_key_t key;

	xenbus_printk("%s: in, reqid = %d, xs_req - %p\n", __func__,
			reqid, xs_req);
	key = k_spin_lock(&xs_req_pool.lock);

	__ASSERT(sys_test_bit((mem_addr_t) xs_req_pool.entries_bm, reqid) == 1,
			"trying to put free request!");

	sys_bitfield_set_bit((mem_addr_t) xs_req_pool.entries_bm, reqid);
	xs_req_pool.num_live--;

	/* Someone probably is now waiting for free xs_request from pool */
	if (xs_req_pool.num_live == XS_REQ_POOL_SIZE - 1) {
		k_sem_give(&xs_req_pool.sem);
	}

	k_spin_unlock(&xs_req_pool.lock, key);
}

static struct xs_request *xs_request_peek(void)
{
	struct xs_request *xs_req;
	k_spinlock_key_t key;
	sys_snode_t *node;

	key = k_spin_lock(&xs_req_pool.lock);
	node = sys_slist_get(&xs_req_pool.queued);
	xenbus_printk("%s: get request node from list - %p\n", __func__, node);
	xs_req = SYS_SLIST_CONTAINER(node, xs_req, next);
	k_spin_unlock(&xs_req_pool.lock, key);

	return xs_req;
}

static void xs_request_enqueue(struct xs_request *xs_req)
{
	k_spinlock_key_t key;

	key = k_spin_lock(&xs_req_pool.lock);
	xenbus_printk("%s: in, xs_req->next = %p\n", __func__, &xs_req->next);
	sys_slist_append(&xs_req_pool.queued, &xs_req->next);
	k_spin_unlock(&xs_req_pool.lock, key);
}

static struct xs_request *xs_request_dequeue(void)
{
	struct xs_request *xs_req = NULL;
	sys_snode_t *node;
	k_spinlock_key_t key;

	xenbus_printk("%s: in\n", __func__);
	key = k_spin_lock(&xs_req_pool.lock);
	node = sys_slist_peek_head(&xs_req_pool.queued);
	if (node) {
		xs_req = SYS_SLIST_CONTAINER(node, xs_req, next);

		/* "node" is list head, so prev_node can be passed as NULL */
		sys_slist_remove(&xs_req_pool.queued, NULL, node);
	}
	k_spin_unlock(&xs_req_pool.lock, key);

	return xs_req;
}





static int xs_avail_to_read(void)
{
	return (xsh.buf->rsp_prod != xsh.buf->rsp_cons);
}

static int xs_avail_space_for_read(unsigned int size)
{
	return (xsh.buf->rsp_prod - xsh.buf->rsp_cons >= size);
}

static int xs_avail_to_write(void)
{
	xenbus_printk("%s: is empty = %d\n", __func__, sys_slist_is_empty(&xs_req_pool.queued));
	return (xsh.buf->req_prod - xsh.buf->req_cons != XENSTORE_RING_SIZE &&
		!sys_slist_is_empty(&xs_req_pool.queued));
}

static int xs_avail_space_for_write(unsigned int size)
{
	return (xsh.buf->req_prod - xsh.buf->req_cons +
		size <= XENSTORE_RING_SIZE);
}

static int xs_avail_work(void)
{
	return (xs_avail_to_read() || xs_avail_to_write());
}

/*
 * Send request to Xenstore. A request is made of multiple iovecs which are
 * preceded by a single iovec referencing the request header. The iovecs are
 * seen by Xenstore as if sent atomically. This can block.
 */
static int xs_msg_write(struct xsd_sockmsg *xsd_req,
	const struct xs_iovec *iovec)
{
	XENSTORE_RING_IDX prod;
	const struct xs_iovec *crnt_iovec;
	struct xs_iovec hdr_iovec;
	unsigned int req_size, req_off;
	unsigned int buf_off;
	unsigned int this_chunk_len;

	req_size = sizeof(*xsd_req) + xsd_req->len;
	if (req_size > XENSTORE_RING_SIZE)
		return -ENOSPC;

	if (!xs_avail_space_for_write(req_size))
		return -ENOSPC;

	/* We must write requests after reading the consumer index. */
	compiler_barrier();

	/*
	 * We're now guaranteed to be able to send the message
	 * without overflowing the ring. Do so.
	 */

	hdr_iovec.data = xsd_req;
	hdr_iovec.len  = sizeof(*xsd_req);

	/* The batched iovecs are preceded by a single header. */
	crnt_iovec = &hdr_iovec;

	prod = xsh.buf->req_prod;
	req_off = 0;
	buf_off = 0;
	while (req_off < req_size) {
		this_chunk_len = MIN(crnt_iovec->len - buf_off,
			XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod));

		memcpy(
			(char *) xsh.buf->req + MASK_XENSTORE_IDX(prod),
			(char *) crnt_iovec->data + buf_off,
			this_chunk_len
		);

		prod += this_chunk_len;
		req_off += this_chunk_len;
		buf_off += this_chunk_len;

		if (buf_off == crnt_iovec->len) {
			buf_off = 0;
			if (crnt_iovec == &hdr_iovec)
				crnt_iovec = iovec;
			else
				crnt_iovec++;
		}
	}

	xenbus_printk("%s: complete\n", __func__);
	LOG_ERR("Complete main loop of %s.\n", __func__);
	__ASSERT_NO_MSG(buf_off == 0);
	__ASSERT_NO_MSG(req_off == req_size);
	__ASSERT_NO_MSG(prod <= xsh.buf->req_cons + XENSTORE_RING_SIZE);

	/* Remote must see entire message before updating indexes */
	compiler_barrier();

	xsh.buf->req_prod += req_size;

	/* Send evtchn to notify remote */
	notify_evtchn(xsh.evtchn);

	return 0;
}

int xs_msg_reply(enum xsd_sockmsg_type msg_type, xenbus_transaction_t xbt,
	const struct xs_iovec *req_iovecs, int req_iovecs_num,
	struct xs_iovec *rep_iovec)
{
	struct xs_request *xs_req;
	int err;

	if (req_iovecs == NULL)
		return -EINVAL;

	xs_req = xs_request_get();
	xs_req->hdr.type = msg_type;
	/* req_id was set on pool init  */
	xs_req->hdr.tx_id = xbt;
	xs_req->hdr.len = 0;
	for (int i = 0; i < req_iovecs_num; i++)
		xs_req->hdr.len += req_iovecs[i].len;

	xs_req->payload_iovecs = req_iovecs;
	xs_req->reply.recvd = 0;

	/* enqueue the request */
	xs_request_enqueue(xs_req);
	/* wake xenstore thread to send it */
	k_sem_give(&xsh.sem);

	/* wait reply */
	while (1) {
		k_sem_take(&xs_req->sem, K_FOREVER);
		if (xs_req->reply.recvd != 0) {
			break;
		}
	}

	err = -xs_req->reply.errornum;
	if (err == 0) {
		if (rep_iovec)
			*rep_iovec = xs_req->reply.iovec;
		else
			k_free(xs_req->reply.iovec.data);
	}

	xs_request_put(xs_req);

	return err;
}

void xs_send(void)
{
	struct xs_request *xs_req;
	int err;

	xs_req = xs_request_peek();
	xenbus_printk("%s: peeked req - %p\n", __func__, xs_req);
	while (xs_req != NULL) {
		err = xs_msg_write(&xs_req->hdr, xs_req->payload_iovecs);
		if (err) {
			if (err != -ENOSPC)
				LOG_WRN("Error sending message err=%d\n",
					   err);
			break;
		}

		/* remove it from queue */
		xs_request_dequeue();

		xs_req = xs_request_peek();
	}
}

/*
 * Converts a Xenstore reply error to a positive error number.
 * Returns 0 if the reply is successful.
 */
static int reply_to_errno(const char *reply)
{
	int err = 0;

	for (int i = 0; i < (int) ARRAY_SIZE(xsd_errors); i++) {
		if (!strcmp(reply, xsd_errors[i].errstring)) {
			err = xsd_errors[i].errnum;
			goto out;
		}
	}

	LOG_WRN("Unknown Xenstore error: %s\n", reply);
	err = -EINVAL;

out:
	return err;
}

/* Process an incoming xs reply */
static void process_reply(struct xsd_sockmsg *hdr, char *payload)
{
	struct xs_request *xs_req;

	if (sys_test_bit((mem_addr_t) xs_req_pool.entries_bm, hdr->req_id)) {
		LOG_WRN("Invalid reply id=%d\n", hdr->req_id);
		k_free(payload);
		return;
	}

	xs_req = &xs_req_pool.entries[hdr->req_id];

	if (hdr->type == XS_ERROR) {
		xs_req->reply.errornum = reply_to_errno(payload);
		k_free(payload);

	} else if (hdr->type != xs_req->hdr.type) {
		LOG_WRN("Mismatching message type: %d\n", hdr->type);
		k_free(payload);
		return;

	} else {
		/* set reply */
		xs_req->reply.iovec.data = payload;
		xs_req->reply.iovec.len = hdr->len;
		xs_req->reply.errornum = 0;
	}

	xs_req->reply.recvd = 1;

	/* notify waiting requester */
	k_sem_give(&xs_req->sem);
}







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

/* Process an incoming xs watch event */
static void process_watch_event(char *watch_msg)
{
	struct xs_watch *watch;
	char *path, *token;

	path  = watch_msg;
	token = watch_msg + strlen(path) + 1;

	watch = xs_watch_find(path, token);
	k_free(watch_msg);

	/* TODO: Fix it when client.c will be ported */
//	if (watch)
//		xenbus_watch_notify_event(&watch->base);
//	else
//		LOG_ERR("Invalid watch event.");
}

static void memcpy_from_ring(const char *ring, char *dest, int off, int len)
{
	int c1, c2;

	c1 = MIN(len, XENSTORE_RING_SIZE - off);
	c2 = len - c1;

	memcpy(dest, ring + off, c1);
	if (c2)
		memcpy(dest + c1, ring, c2);
}

static void xs_msg_read(struct xsd_sockmsg *hdr)
{
	XENSTORE_RING_IDX cons;
	char *payload;

	payload = k_malloc(hdr->len + 1);
	if (payload == NULL) {
		LOG_WRN("No memory available for saving Xenstore message!\n");
		return;
	}

	cons = xsh.buf->rsp_cons;

	/* copy payload */
	memcpy_from_ring(
		xsh.buf->rsp,
		payload,
		MASK_XENSTORE_IDX(cons + sizeof(*hdr)),
		hdr->len
	);
	payload[hdr->len] = '\0';

	/* Remote must not see available space until we've copied the reply */
	compiler_barrier();
	xsh.buf->rsp_cons += sizeof(*hdr) + hdr->len;

	if (xsh.buf->rsp_prod - cons >= XENSTORE_RING_SIZE)
		notify_evtchn(xsh.evtchn);

	if (hdr->type == XS_WATCH_EVENT)
		process_watch_event(payload);
	else
		process_reply(hdr, payload);
}


static void xs_recv(void)
{
	struct xsd_sockmsg msg;

	while (1) {
		LOG_DBG("Rsp_cons %d, rsp_prod %d.\n",
			    xsh.buf->rsp_cons, xsh.buf->rsp_prod);

		if (!xs_avail_space_for_read(sizeof(msg)))
			break;

		/* Make sure data is read after reading the indexes */
		compiler_barrier();

		/* copy the message header */
		memcpy_from_ring(
			xsh.buf->rsp,
			(char *) &msg,
			MASK_XENSTORE_IDX(xsh.buf->rsp_cons),
			sizeof(msg)
		);

		LOG_DBG("Msg len %lu, %u avail, id %u.\n",
			    msg.len + sizeof(msg),
			    xsh.buf->rsp_prod - xsh.buf->rsp_cons,
			    msg.req_id);

		if (!xs_avail_space_for_read(sizeof(msg) + msg.len))
			break;

		/* Make sure data is read after reading the indexes */
		compiler_barrier();

		LOG_DBG("Message is good.\n");
		xs_msg_read(&msg);
	}
}

static void xenbus_isr(void *data)
{
	struct xs_handler *xs = data;
	k_sem_give(&xs->sem);
}

static void xenbus_main_thrd(void *p1, void *p2, void *p3)
{
	while (1) {
		xenbus_printk("%s: taking semaphore\n", __func__);
		k_sem_take(&xs_hdlr.sem, K_FOREVER);
		if (!xs_avail_work()) {
			xenbus_printk("%s: took semaphore, queue empty!\n", __func__);
			continue;
		}

		if (xs_avail_to_write()) {
			xenbus_printk("%s: avail to write\n", __func__);
			xs_send();
		}

		if (xs_avail_to_read()) {
			xenbus_printk("%s: avail to read\n", __func__);
			xs_recv();
		}
	}
}

/* TODO: move in to header and rename */
/* Helper macros for initializing xs requests from strings */
#define XS_IOVEC_STR_NULL(str) \
	((struct xs_iovec) { str, strlen(str) + 1 })
#define XS_IOVEC_STR(str) \
	((struct xs_iovec) { str, strlen(str) })

/* TODO: fix error handling */
char *xs_read(xenbus_transaction_t xbt, const char *path)
{
	struct xs_iovec req, rep;
	char *value = NULL;
	int err;

	if (path == NULL)
		return NULL;


	req = XS_IOVEC_STR_NULL(path);
	err = xs_msg_reply(XS_READ, xbt, &req, 1, &rep);
	if (err == 0)
		value = rep.data;
	else
		printk("%s: err = %d!\n", __func__, err);

	return value;
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

	req = XS_IOVEC_STR_NULL((char *) path);
	err = xs_msg_reply(XS_DIRECTORY, xbt, &req, 1, &rep);
	if (err)
		return NULL;

	res = reply_to_string_array(&rep, NULL);
	k_free(rep.data);

	return res;
}

static void xenbus_read_thrd(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	char **dirs;
	int x;

	char *pre = "domid", buf[50];
	char *domid = xs_read(XBT_NIL, pre);

	if (!domid) {
		printk("NULL domid\n");
		return;
	}

	printk("%s: domid returned = %s\n", __func__, domid);

	snprintf(buf, 50, "/local/domain/%s", domid);
	printk("%s: running xenbus ls for %s\n", __func__, buf);
	dirs = xs_ls(XBT_NIL, buf);

	/* TODO: check what is wrong with k_free() and who allocates memory for dirs */
	printk("xenbus_ls test results for pre = %s\n", buf);
	for (x = 0; dirs[x]; x++)
	{
		printk("ls %s[%d] -> %s\n", buf, x, dirs[x]);
		//k_free(dirs[x]);
	}
//	k_free(dirs);
}


static void xenbus_read_thrd2(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	char **dirs;
	int x;

	char *pre = "domid", buf[50];
	char *domid = xs_read(XBT_NIL, pre);

	if (!domid) {
		printk("NULL domid\n");
		return;
	}

	printk("%s: second domid returned = %s\n", __func__, domid);

	snprintf(buf, 50, "/local/domain/%s", domid);
	printk("%s: running xenbus ls for %s\n", __func__, buf);
	dirs = xs_ls(XBT_NIL, buf);

	/* TODO: check what is wrong with k_free() and who allocates memory for dirs */
	printk("xenbus_ls test results for pre = %s\n", buf);
	for (x = 0; dirs[x]; x++)
	{
		printk("ls %s[%d] -> %s\n", buf, x, dirs[x]);
		//k_free(dirs[x]);
	}
//	k_free(dirs);
}

static int xenbus_init(const struct device *dev)
{
	ARG_UNUSED(dev);
	int ret = 0;
	uint64_t xs_pfn = 0, xs_evtchn = 0;
	uintptr_t xs_addr = 0;
	struct xs_handler *data = dev->data;

	data->dev = dev;

	ret = hvm_get_parameter(HVM_PARAM_STORE_EVTCHN, &xs_evtchn);
	if (ret) {
		printk("%s: failed to get Xenbus evtchn, ret = %d\n",
				__func__, ret);
		return ret;
	}
	data->evtchn = (evtchn_port_t) xs_evtchn;

	ret = hvm_get_parameter(HVM_PARAM_STORE_PFN, &xs_pfn);
	if (ret) {
		printk("%s: failed to get Xenbus PFN, ret = %d\n",
				__func__, ret);
		return ret;
	}

	xs_addr = (uintptr_t) (xs_pfn << XEN_PAGE_SHIFT);
	device_map(DEVICE_MMIO_RAM_PTR(dev), xs_addr, XEN_PAGE_SIZE,
		K_MEM_CACHE_WB);
	data->buf = (struct xenstore_domain_interface *) DEVICE_MMIO_GET(dev);

	k_sem_init(&data->sem, 0, 1);

	xs_request_pool_init(&xs_req_pool);

	bind_event_channel(data->evtchn, xenbus_isr, data);

	data->thread = k_thread_create(&xenstore_thrd, xenstore_thrd_stack,
			K_KERNEL_STACK_SIZEOF(xenstore_thrd_stack),
			xenbus_main_thrd, NULL, NULL, NULL, 7, 0, K_NO_WAIT);
	if (!data->thread) {
		printk("%s: Failed to create Xenstore thread\n", __func__);
		return -1;
	}
	k_thread_name_set(data->thread, "xenstore_thread");
	printk("%s: xenstore thread inited\n", __func__);

	read_tid = k_thread_create(&read_thrd, read_thrd_stack,
			K_KERNEL_STACK_SIZEOF(read_thrd_stack),
			xenbus_read_thrd, NULL, NULL, NULL, 7, 0, K_NO_WAIT);
	if (!read_tid) {
		printk("%s: Failed to create read thread\n", __func__);
		k_thread_abort(xenstore_tid);
		return -1;
	}
	k_thread_name_set(read_tid, "read_thread");
	printk("%s: read thread inited, stack defined at %p\n", __func__, read_thrd_stack);

	read_tid2 = k_thread_create(&read_thrd2, read_thrd2_stack,
			K_KERNEL_STACK_SIZEOF(read_thrd2_stack),
			xenbus_read_thrd2, NULL, NULL, NULL, 6, 0, K_NO_WAIT);
	if (read_tid2) {
		k_thread_name_set(read_tid2, "read_thread2");
		printk("%s: read thread 2 inited, stack defined at %p\n", __func__, read_thrd2_stack);
	} else {
		printk("%s: Failed to create read thread 2\n", __func__);
	}


	return ret;
}

/*
 * Xenbus logic requires threads, so it should be inited when their creation
 * will be possible (POST_KERNEL)
 */
DEVICE_DEFINE(xenbus, "xenbus", xenbus_init, NULL, &xs_hdlr, NULL,
		POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT, NULL);
